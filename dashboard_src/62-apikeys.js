/* ---- api key handling ---- */
const KEY_STORE = 'codearts-hub-api-key';
const PANEL_STORE = 'codearts-hub-panel-token';
let API_KEY = '';
let PANEL_TOKEN = '';
try { PANEL_TOKEN = sessionStorage.getItem(PANEL_STORE) || ''; } catch(e) { PANEL_TOKEN = ''; }
let PANEL_STATUS = {};
(function initKey(){
  try {
    const fromUrl = new URLSearchParams(window.location.search).get('key');
    if(fromUrl){
      API_KEY = fromUrl.trim();
      localStorage.setItem(KEY_STORE, API_KEY);
      // Drop the key from the address bar, but keep any other parameters:
      // this used to clear the whole query string, which also discarded a
      // ?tab= the user had been given.
      const rest = new URLSearchParams(window.location.search);
      rest.delete('key');
      const qs = rest.toString();
      history.replaceState(null, '', window.location.pathname + (qs ? '?' + qs : ''));
    } else {
      API_KEY = (localStorage.getItem(KEY_STORE) || '').trim();
    }
  } catch(e){ API_KEY = ''; }
})();

// A key with non-ASCII characters cannot go into an HTTP header at all: fetch
// throws "String contains non ISO-8859-1 code point" before the request is
// sent. Such a value is never a real gateway key, so drop it and let the panel
// session carry the request.
function usableKey(value){
  return value && /^[\x20-\x7e]+$/.test(value) ? value : '';
}

function authHeaders(base){
  const h = Object.assign({}, base || {});
  const key = usableKey(API_KEY);
  if(key) h['Authorization'] = 'Bearer ' + key;
  if(PANEL_TOKEN) h['X-Panel-Token'] = PANEL_TOKEN;
  return h;
}

// 同一 URL 的在飞请求只保留一份（单飞）。5 秒轮询、手动切页/切窗口、可见性回调
// 叠在一起时，同一个 URL 会同时发出好几份完全相同的请求：冷窗口的 /usage 扫描
// 要十几秒，这几份就全在服务端重跑一遍聚合，还占着浏览器的连接池，把后面的
// /accounts、/scheduler 一起堵住——"切窗口后面板像死了"有一半是这里自己放大的。
// 登记表按 URL 键控，后来者直接等第一份的结果；请求落定（无论成败）就摘掉登记项，
// 下一次轮询照常发新请求，所以不会把"每次都要新数据"的语义变成缓存。
const GETJSON_INFLIGHT = new Map();
// 挂死保护：网络层僵住时 fetch 可能永远不落定，登记项会一直占着这个 URL，之后
// 每一轮轮询都陪它一起等。超过这个时长就把登记项视为已死，放行新请求。
const GETJSON_STALE_MS = 60000;
async function getJSON(url, opts){
  // cache 模式分两档，按"响应体在服务端是否有一份 TTL 缓存"来选：
  //
  //  - 默认 no-store：不落盘、每次整份重取。登录轮询（/accounts/login/poll）、
  //    密钥类读取（/settings/reveal）以及任何"写完之后立刻回读"都必须走这档。
  //  - opts.revalidate（见 POLL_READ）：允许浏览器存一份、每次使用前回源校验。
  //    用量那几个读接口在服务端带 _STATS_TTL 缓存，同一份缓存期间响应体逐字节
  //    不变，服务端会发 ETag + Cache-Control: no-cache。no-cache 的语义正是
  //    "可以存、每次使用前必须回源校验"，于是浏览器自动带上 If-None-Match：
  //    数字没变就只回一个 304（无 body），省下 10~100KB 的重复传输。
  //    这里绝不能写 no-store——那会让浏览器连副本都不存，条件请求无从谈起，
  //    服务端的 ETag 也就永远用不上。
  const cache = (opts && opts.revalidate) ? 'no-cache' : 'no-store';
  // 键里带上 cache 档位：同一 URL 若一处走可校验、一处走 no-store，两者语义不同
  // （前者允许浏览器回 304 复用副本），合并会让其中一方悄悄拿到不该拿的副本。
  const key = cache + ' ' + url;
  const hit = GETJSON_INFLIGHT.get(key);
  if(hit && (Date.now() - hit.at) < GETJSON_STALE_MS) return hit.p;
  const run = async () => {
    const r = await fetch(url, {cache: cache, headers: authHeaders()});
    if(r.status === 401 || r.status === 403){ panelSessionLost(); throw new Error('unauthorized'); }
    if(!r.ok) throw new Error(r.status);
    return r.json();
  };
  // 落定即摘除；只摘自己那一份，别误删后来顶替的登记项（上面超时换新时会顶替）。
  const entry = {p: null, at: Date.now()};
  entry.p = run().finally(() => { if(GETJSON_INFLIGHT.get(key) === entry) GETJSON_INFLIGHT.delete(key); });
  GETJSON_INFLIGHT.set(key, entry);
  return entry.p;
}
// 轮询读取的 fetch 选项：这些接口的响应体由服务端的 TTL 缓存决定，同一份缓存
// 期间不变，所以可以让浏览器存一份、每次回源校验（服务端 ETag 命中即 304）。
// 只有真的会被轮询、且服务端确实发 ETag 的只读接口才用它；其余读取保持默认的
// no-store，免得"顺手加上"之后把必须每次都新的响应也变成可缓存校验的。
const POLL_READ = {revalidate: true};
async function postJSON(url, body, opts){
  const r = await fetch(url, {method:'POST', headers: authHeaders({'Content-Type':'application/json'}),
                              body: JSON.stringify(body || {})});
  const t = await r.text();
  let parsed = {};
  try { parsed = t ? JSON.parse(t) : {}; } catch(e) { parsed = {raw: t}; }
  // opts.localAuth：这个接口的 401 由调用方自己处理。改密码时「当前密码
  // 不对」也回 401——别在这里开登录闸门，否则一次输错就变成掉线。
  const localAuth = !!(opts && opts.localAuth);
  if((r.status === 401 || r.status === 403) && !localAuth){ panelSessionLost(); throw new Error('unauthorized'); }
  if(!r.ok){
    const err = new Error((parsed.error && parsed.error.message) || r.status);
    // 带上状态码，调用方才能区分「会话失效」和「参数不对」。
    err.status = r.status;
    throw err;
  }
  return parsed;
}
function toast(msg, kind){
  console.log('[wb]', msg);
  // An expired session already raised the gate; a toast per failing poll
  // would repeat the same line every few seconds until the user logs in.
  if(String(msg).indexOf('unauthorized') !== -1) return;
  let box = document.getElementById('toastBox');
  if(!box){
    box = document.createElement('div');
    box.id = 'toastBox';
    box.style.cssText = 'position:fixed;right:20px;bottom:20px;z-index:9999;'
      + 'display:flex;flex-direction:column;gap:10px;align-items:flex-end;pointer-events:none';
    document.body.appendChild(box);
  }
  const item = document.createElement('div');
  const isBad = (kind === 'bad' || kind === 'err' || kind === 'error');
  const isWarn = (kind === 'warn' || kind === 'warning');
  const isOk = (kind === 'ok' || kind === 'success');
  const borderColor = isBad ? 'var(--bad)' : (isWarn ? 'var(--warn)' : (isOk ? 'var(--accent2)' : 'var(--accent)'));
  const textColor = isBad ? 'var(--bad)' : (isWarn ? 'var(--warn)' : (isOk ? 'var(--accent2)' : 'var(--fg)'));
  const icon = '';
  const bg = isBad ? 'rgba(254,242,242,.98)' : (isWarn ? 'rgba(255,251,235,.98)' : 'var(--panel)');

  item.textContent = icon + msg;
  item.style.cssText = 'background:' + bg + ';border:1px solid var(--line);'
    + 'border-left:4px solid ' + borderColor + ';'
    + 'border-radius:8px;padding:10px 16px;font-size:13px;font-weight:500;color:' + textColor + ';'
    + 'box-shadow:0 10px 25px -5px rgba(0,0,0,.15),0 8px 10px -6px rgba(0,0,0,.1);'
    + 'max-width:380px;word-break:break-all;pointer-events:auto;transition:all .2s ease;';
  box.appendChild(item);
  setTimeout(() => {
    item.style.opacity = '0';
    item.style.transform = 'translateY(6px)';
    setTimeout(() => item.remove(), 250);
  }, 4200);
}

