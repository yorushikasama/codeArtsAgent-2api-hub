/* ---- 签到与活跃记录（GET /activity/history，issue #176）----
   国内版签到的每一次真实尝试，都由 ca_activity.py 落成一行：
   时间 / uid / 昵称 / 区域 / 任务 / 触发来源 / 结果 / 说明。筛选全部交给服务端
   （range/task/result/uid/limit），它还会校验认不出来的值并回 400——前端不再
   自己过滤一遍，两处各写一份筛选规则迟早会跑偏。
   这份历史是按需读的日志视图，不跟着 15 秒轮询走：轮询会每轮把「加载更多」翻
   出来的页码重置回第一页，操作者正看着的记录会跳走。 */
const ACTIVITY_PAGE = 100;
const ACTIVITY_MAX_LIMIT = 1000;
let ACTIVITY_LIMIT = ACTIVITY_PAGE;
let ACTIVITY_LOADING = false;

const ACTIVITY_TASK_LABEL = {checkin: '国内版签到'};
const ACTIVITY_TRIGGER_LABEL = {scheduler: '定时', manual: '手动', account_add: '添加账号',
                                account_import: '导入', unknown: '未知'};
const ACTIVITY_REALM_LABEL = {cn: '国内版'};

function activityValue(id){
  const el = document.getElementById(id);
  return el ? String(el.value == null ? '' : el.value) : '';
}

function activityQuery(limit){
  const q = new URLSearchParams();
  q.set('range', activityValue('activityRange') || '7d');
  const task = activityValue('activityTask');
  if(task) q.set('task', task);
  const result = activityValue('activityResult');
  if(result) q.set('result', result);
  const uid = activityValue('activityAccount');
  if(uid) q.set('uid', uid);
  q.set('limit', String(limit));
  return '/activity/history?' + q.toString();
}

/* 账号下拉的选项取自当前账号池（/accounts）。账号轮询每 15 秒刷一次窗口，这里
   每次重建选项都要把操作者已选中的 uid 放回去，否则筛选条件会被悄悄清掉。 */
function renderActivityAccounts(){
  const sel = document.getElementById('activityAccount');
  if(!sel) return;
  const keep = String(sel.value || '');
  const opts = ['<option value="">全部账号</option>'];
  (window.ACCOUNTS || []).forEach(a => {
    if(!a || !a.uid) return;
    const name = a.nickname || String(a.uid).slice(0, 8);
    // 昵称是数据不是界面文案，别让 i18n 按汉字逐字转换它。
    opts.push('<option value="' + esc(a.uid) + '" data-no-i18n>' + esc(name) + '</option>');
  });
  sel.innerHTML = opts.join('');
  if(keep) sel.value = keep;
}

/* 时间按记录里写的墙上时间显示（服务端落盘时带本机偏移量），所以这里只做字符串
   截取，不做时区换算：换算一次就等于把运维看到的本地时间再挪一遍。 */
function activityTime(ts){
  const m = String(ts || '').match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})/);
  if(!m) return String(ts || '') || '—';
  return m[2] + '-' + m[3] + ' ' + m[4] + ':' + m[5];
}

function activityWho(r){
  const nick = String((r && r.nickname) || '').trim();
  if(nick) return nick;
  return (r && r.uid) ? String(r.uid).slice(0, 8) : '—';
}

function renderActivityBoard(data){
  const box = document.getElementById('activityList');
  if(!box) return;
  const rows = (data && data.rows) || [];
  const total = Number((data && data.total) || 0);
  const count = document.getElementById('activityCount');
  if(count) count.textContent = total ? '(共 ' + total + ' 条)' : '';
  const more = document.getElementById('activityMore');
  const info = document.getElementById('activityMoreInfo');
  if(more) more.style.display = (rows.length < total) ? 'flex' : 'none';
  if(info) info.textContent = (rows.length < total)
    ? ('已显示最新 ' + rows.length + ' 条 / 共 ' + total + ' 条') : '';
  if(!rows.length){
    box.innerHTML = '<div class="legend" style="margin:0"><span>这个区间里没有签到或活跃记录。</span></div>';
    return;
  }
  const resultBadge = ok => ok ? '<span class="badge ok">成功</span>'
                               : '<span class="badge bad">失败</span>';
  box.innerHTML = '<table class="data-cards"><thead><tr>'
    + '<th style="text-align:left;width:132px">时间</th>'
    + '<th style="text-align:left">账号</th>'
    + '<th style="text-align:center;width:76px">区域</th>'
    + '<th style="text-align:left;width:132px">任务</th>'
    + '<th style="text-align:center;width:76px">来源</th>'
    + '<th style="text-align:center;width:76px">结果</th>'
    + '<th style="text-align:left">说明</th>'
    + '</tr></thead><tbody>'
    + rows.map(r => '<tr>'
        + '<td class="mono" data-label="时间">' + esc(activityTime(r.ts)) + '</td>'
        + '<td data-label="账号" title="' + esc(r.uid || '') + '">'
          + '<span data-no-i18n>' + esc(activityWho(r)) + '</span></td>'
        + '<td style="text-align:center" data-label="区域">'
          + esc(ACTIVITY_REALM_LABEL[r.realm] || '—') + '</td>'
        + '<td data-label="任务">' + esc(ACTIVITY_TASK_LABEL[r.task] || r.task || '—') + '</td>'
        + '<td style="text-align:center" data-label="来源">'
          + esc(ACTIVITY_TRIGGER_LABEL[r.trigger] || r.trigger || '—') + '</td>'
        + '<td style="text-align:center" data-label="结果">' + resultBadge(r.ok) + '</td>'
        // 上游原文可能很长：在 span 上做行内截断（td 自身不吃 max-width，撑宽的是
        // 整张表），完整内容留在 title 里，表格不会被一条 429 原文拉出横向滚动。
        + '<td data-label="说明" style="text-align:left">'
        +   (r.message
              ? '<span style="display:inline-block;max-width:520px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom" title="' + esc(r.message) + '">' + esc(r.message) + '</span>'
              : '<span style="color:var(--dim)">—</span>')
        + '</td>'
        + '</tr>').join('')
    + '</tbody></table>';
}

async function loadActivityBoard(showToast, more){
  // 签到与活跃记录区块已删；保留函数体供历史调用方安全返回。
  if(!document.getElementById('activityList')) return;
  if(ACTIVITY_LOADING) return;
  ACTIVITY_LOADING = true;
  const btn = document.getElementById('btnActivityRefresh');
  if(btn) btn.disabled = true;
  const box = document.getElementById('activityList');
  if(more) ACTIVITY_LIMIT = Math.min(ACTIVITY_MAX_LIMIT, ACTIVITY_LIMIT + ACTIVITY_PAGE);
  else ACTIVITY_LIMIT = ACTIVITY_PAGE;
  if(box && !more) box.innerHTML = '<div class="legend" style="margin:0"><span>加载中…</span></div>';
  try {
    renderActivityAccounts();
    const data = await getJSON(activityQuery(ACTIVITY_LIMIT));
    renderActivityBoard(data);
    if(showToast) toast('签到记录已刷新', 'ok');
  } catch(e) {
    if(box) box.innerHTML = '<div class="legend" style="margin:0"><span>读取签到记录失败: '
      + esc(e && e.message ? e.message : e) + '</span></div>';
    if(showToast) toast('读取签到记录失败: ' + (e && e.message ? e.message : e), 'bad');
  } finally {
    ACTIVITY_LOADING = false;
    if(btn) btn.disabled = false;
  }
}







/* 一键测试：区域内每个已启用账号 + 本机连通性一次看全。
   池子出问题时最需要分辨的就是「账号真不行」与「本机没网 / 只是被本地窗口关着」，
   红点一屏的时候，逐个点测出来的结论往往是错的。 */









/* ---- 账号导出 / 导入 ---- */




/* ------------------------------- dashboard ------------------------------ */
let REFRESH_RUNNING = false;
let REFRESH_QUEUED = false;
let REFRESH_GEN = 0;
async function refresh(){
  // 5 秒轮询。撞上正在飞的那一轮时**排队补跑**，而不是直接丢掉：早先的实现是
  // `if(REFRESH_BUSY) return;`，切区域/切账号那一下如果正好撞上轮询在飞，这次
  // 刷新就没了下文，只能干等下一个 5 秒周期——"点了要过几秒才变"就是这么来的。
  REFRESH_GEN++;
  if(REFRESH_RUNNING){ REFRESH_QUEUED = true; return; }
  REFRESH_RUNNING = true;
  const gen = REFRESH_GEN;
  try { await refreshInner(gen); }
  finally {
    REFRESH_RUNNING = false;
    if(REFRESH_QUEUED){ REFRESH_QUEUED = false; refresh(); }
  }
}
// 展示货币切换后，把带费用的视图就地重画：各接口有服务端 TTL 缓存，
// 重新拉取的代价很小，不必为每处维护一份数据副本。

async function refreshInner(gen){
  let usage, recent, perf;
  try{
    [usage, recent, perf] = await Promise.all([
      getJSON('/usage?realm=' + encodeURIComponent(window.VIEW_REALM), POLL_READ),
      // /usage/recent 不在这里改成可校验：它没有服务端缓存，每次新请求都进榜，
      // 响应体每轮都在变，服务端也就没有稳定的校验符可发——照旧整份重取。
      getJSON('/usage/recent?limit=' + RECENT_LIMIT + '&page=' + RECENT_PAGE + '&realm=' + encodeURIComponent(window.VIEW_REALM)),
      getJSON('/usage/perf?realm=' + encodeURIComponent(window.VIEW_REALM), POLL_READ),
    ]);
    // 取数期间又发起了更新的一轮（例如刚切了区域），这批结果已经过期，
    // 直接扔掉，交给排队的那一轮渲染，免得把旧区域的数字画上去。
    if(gen !== REFRESH_GEN) return;
    document.getElementById('statusDot').className = 'dot';
  }catch(e){
    if(gen === REFRESH_GEN){
      document.getElementById('statusDot').className = 'dot err';
      if(String(e.message) !== 'unauthorized'){
        document.getElementById('meta').innerHTML = '<b>无法连接反代</b>';
      }
    }
    return;
  }

  const t = usage;
  const metaEl = document.getElementById('meta');
  if(metaEl) metaEl.innerHTML = '';
  document.getElementById('logfile').textContent = t.log_file || '';
  const rEl = document.getElementById('realm'); if(rEl) rEl.textContent = t.realm ? ' · ' + t.realm : '';

  // 账号与积分统计：账号卡片由 loadCodeartsAccounts() → caUpdateCardSummary()
  // 按 /accounts/codearts 的实时结果画。这里原来还从 window.ACCOUNTS 里筛
  // realm === 'cn' 拼一份 poolHtml / credHtml —— 那个数组从来没有被填充过
  // （账号池移除后没人写它），两个变量也没有任何使用点，等于每次刷新都白算
  // 一遍并把「国内 0/0」的空字符串留在页面上。
  const succStr = (perf.success_rate_pct != null ? pct(perf.success_rate_pct) : '100.0%');

  // 这三张卡的数字都按当前视图区域取（/usage 等接口带 realm）。原先标题带
  // 「（国内版）」后缀，但这个部署只剩码道一个出口，加后缀反而让人以为还有
  // 另一个区域没看到，所以留空。
  const realmTag = '';
  // 「积分消耗」优先用**账号的已用积分**（上游 snap-manager 给的累计实数，
  // 和客户端显示一致）。/usage 的 credit 总数是网关按计费档逐条估算的 --
  // 接入网关之前的消耗它攒不到，误差也会滚进总数，所以只作账号读取失败时
  // 的兜底，不当主数展示。
  const creditUsed = (caAccountCredit != null) ? caAccountCredit : t.credit;
  const creditSub = caAccountCredit != null ? '账号累计已用' : '';
  document.getElementById('cards').innerHTML =
    card('网关调用量' + realmTag, fmt(t.requests) + ' <span style="font-size:13px;font-weight:500;color:var(--dim);margin-left:4px">次</span>', '', '') +
    card('积分消耗' + realmTag, (creditUsed != null ? Number(creditUsed).toFixed(2) : '—') + ' <span style="font-size:13px;font-weight:500;color:var(--dim);margin-left:4px">积分</span>', creditSub, 'warn') +
    card('请求成功率' + realmTag, '<span style="color:' + (perf.errors ? 'var(--warn)' : 'var(--accent2)') + '">' + succStr + '</span>', '', '');

  const total = recent.total || 0;
  RECENT_PAGE = recent.page || 1;
  RECENT_TOTAL_PAGES = recent.total_pages || Math.max(1, Math.ceil(total / RECENT_LIMIT));

  const pageInfo = document.getElementById('recentPageInfo');
  if(pageInfo){
    pageInfo.textContent = '第 ' + RECENT_PAGE + ' / ' + RECENT_TOTAL_PAGES + ' 页 · 共 ' + fmt(total) + ' 条记录';
  }
  const btnPrev = document.getElementById('btnRecentPrev');
  if(btnPrev) btnPrev.disabled = (RECENT_PAGE <= 1);
  const btnNext = document.getElementById('btnRecentNext');
  if(btnNext) btnNext.disabled = (RECENT_PAGE >= RECENT_TOTAL_PAGES);
  const btnBox = document.getElementById('recentPageButtons');
  if(btnBox){
    const pages = generatePageList(RECENT_PAGE, RECENT_TOTAL_PAGES);
    btnBox.innerHTML = pages.map(p => {
      if(p === '...'){
        return '<span style="color:var(--dim);padding:0 3px">…</span>';
      }
      const active = (p === RECENT_PAGE);
      return '<button class="range-btn' + (active ? ' active' : '') + '" style="min-width:26px;padding:3px 6px;font-size:11px" onclick="gotoRecentPage(' + p + ')">' + p + '</button>';
    }).join('');
  }

  const rows = recent.rows || [];
  // Terminal state of a request. Rows written before the outcome field only
  // carry error/status, so fall back to that; a client cancellation is shown
  // apart from a real failure because the gateway did nothing wrong.
  const outcomeBadge = r => {
    const o = r.outcome || (r.error ? 'failed' : 'completed');
    if(o === 'completed') return '<span class="badge ok">完成</span>';
    if(o === 'client_aborted') return '<span class="badge off">客户端取消</span>';
    if(o === 'upstream_aborted') return '<span class="badge warn">上游中断</span>';
    // 失败行带着 status/message 落账（record_error 写的），以前只躺在网关日志里 ——
    // 悬浮看一眼失败原因，不用跑去翻日志。
    const tip = (r.status ? 'HTTP ' + r.status : '')
      + (r.message ? ((r.status ? ' · ' : '') + r.message) : '');
    return '<span class="badge bad"' + (tip ? ' title="' + esc(tip) + '"' : '') + '>失败</span>';
  };
  const countEl = document.getElementById('recentCount');
  if(countEl) countEl.textContent = '(第 ' + RECENT_PAGE + ' 页 / 共 ' + fmt(total) + ' 条)';
  // 推理强度：这次请求实际跑在哪个档位（网关写入 usage 行时的 reasoning_effort）。
  // v1.6.16 拆分为独立「推理强度」列展示。
  // 账号列显示昵称：uid -> 昵称取自 /usage 的 accounts_map（当前账号池）。
  // 已删除/不存在的账号回退到 uid 前 8 位，避免留空。
  const acctName = (uid) => {
    if(!uid) return '—';
    const m = (t.accounts_map && t.accounts_map[uid]);
    return (m && m.nickname) ? m.nickname : String(uid).slice(0,8);
  };
  // 5 秒一轮的重画里，内容没变就不碰 DOM：实测 100 行时一次 innerHTML 重写要花
  // ~10ms 解析 + 50~65ms 强制布局（每个 tick 一个 57~77ms 的长任务），而相邻两轮
  // 里有 1/4~1/2 的轮次数据逐字节相同——代价全白付。指纹覆盖所有会画进表格的
  // 输入：行数据本身（JSON 快照，任何字段变化都算）、页码/每页条数/区域、账号
  // 昵称（来自 /usage 的 accounts_map，与行分开变化）。相同就整段跳过：
  // 不重拼 HTML、不重排。
  const recentFp = [
    total, RECENT_PAGE, RECENT_LIMIT, window.VIEW_REALM,
    rows.map(r => acctName(r.account)).join('\u0001'),
    JSON.stringify(rows),
  ].join('\u0002');
  if(recentFp === lastRecentFp) return;
  lastRecentFp = recentFp;
  document.getElementById('recent').innerHTML = rows.length ?
    '<table class="data-cards"><thead><tr><th>时间</th><th>模型</th><th>推理强度</th><th>账号</th><th>模式</th><th>结果</th><th>耗时</th><th>首字</th><th>速度</th><th>输入</th><th>输出</th><th>思考</th><th>缓存</th><th>总 token</th><th>积分</th></tr></thead><tbody>'
    + rows.map((r, i) => {
        return '<tr>'
        + '<td class="mono" data-label="时间">' + esc((r.iso||'').replace('T',' ').slice(5)) + '</td>'
        + '<td class="mono" data-label="模型">' + esc(r.model) + '</td>'
        + '<td data-label="推理强度">' + (r.reasoning_effort ? ('<span class="badge-effort">' + esc(r.reasoning_effort) + '</span>') : '<span style="color:var(--dim)">—</span>') + '</td>'
        + '<td class="mono" style="font-size:11px;color:var(--dim)" data-label="账号" title="' + esc(r.account||'') + '">' + esc(acctName(r.account)) + '</td>'
        + '<td data-label="模式"><span class="badge ' + (r.stream?'s':'') + '">' + (r.stream?'流式':'非流式') + '</span></td>'
        + '<td data-label="结果">' + outcomeBadge(r) + '</td>'
        + '<td data-label="耗时">' + ms(r.elapsed_ms) + '</td>'
        + '<td data-label="首字">' + ms(r.ttft_ms) + '</td>'
        + '<td data-label="速度">' + (r.tokens_per_sec ? r.tokens_per_sec.toFixed(1) : '—') + '</td>'
        + '<td data-label="输入">' + fmt(r.prompt_tokens) + '</td>'
        + '<td data-label="输出">' + fmt(r.completion_tokens) + '</td>'
        + '<td style="color:var(--think)" data-label="思考">' + fmt(r.reasoning_tokens) + '</td>'
        + '<td data-label="缓存">' + (r.cache_hit_pct!=null ? r.cache_hit_pct+'%' : '—') + '</td>'
        // usage_missing：上游没回 usage 块时行也照落（请求计数/时延不丢），
        // 但 token 四列全是 0 —— 不标注的话看起来就像「这条请求 0 token」。
        + '<td data-label="总 token">'
        + '<b' + (r.usage_missing ? ' title="上游没回 usage，token 数缺失" style="cursor:help"' : '') + '>'
        + fmt(r.total_tokens) + '</b>' + (r.usage_missing ? ' <span class="badge warn" style="font-size:10px">无用量</span>' : '') + '</td>'
        // 积分：按码道自己的计费档逐条算（compute in ca_codearts.credit_for_usage），
        // 与账号级的「总已用积分」同一口径。估算价格那一列已移除 —— 两套价格
        // 并排显示只会让人不知道该信哪个。
        + '<td data-label="积分" style="color:var(--accent2)" title="按码道计费档算出的单条积分（与客户端「总已用积分」同口径）">' + (r.credit ? Number(r.credit).toFixed(2) : '—') + '</td>'
      + '</tr>';
      }).join('') + '</tbody></table>'
    : '<div class="empty">还没有请求记录</div>';
}

(async function initDashboard(){
  await bootPanel();
})();

/* 侧栏尽早建：区块是静态标记，现场生成不依赖任何接口。原来只在
   switchMainTab() 里建，而它排在启动链的末端——/panel/status、/settings、
   /realm 三趟串行往返，再加 Promise.all 里那批数据加载（含走上游的
   /v1/models 与国内版成长任务）之后才轮到，所以刷新时左侧要先空一列、
   过一会儿才补上。这里在 DOMContentLoaded 就建（head 里那段已按 ?tab=
   与上次选择定好 .active），switchMainTab() 那次会因清单未变直接返回，
   不会重建、也不会闪。 */
document.addEventListener('DOMContentLoaded', function(){
  initPageNav(document.querySelector('.main-page.active'));
});

let RECENT_LIMIT = parseInt(localStorage.getItem('WB_RECENT_LIMIT') || '20', 10);
if(![10, 20, 50, 100].includes(RECENT_LIMIT)) RECENT_LIMIT = 20;
let RECENT_PAGE = 1;
let RECENT_TOTAL_PAGES = 1;
// 最近请求表上次真正画进 DOM 的内容指纹（见 refreshInner 里的 recentFp）。
// 5 秒一轮的重画代价几乎全在布局（100 行实测 50~65ms），数据没变就不该重画。
let lastRecentFp = null;

function updateRecentLimitButtons(){
  [10, 20, 50, 100].forEach(n => {
    const btn = document.getElementById('btnRecentLimit' + n);
    if(btn) btn.classList.toggle('active', RECENT_LIMIT === n);
  });
}

function setRecentLimit(n){
  RECENT_LIMIT = n;
  RECENT_PAGE = 1;
  try { localStorage.setItem('WB_RECENT_LIMIT', String(n)); } catch(e){}
  updateRecentLimitButtons();
  refresh();
}

async function changeRecentPage(delta){
  const next = RECENT_PAGE + delta;
  if(next < 1 || next > RECENT_TOTAL_PAGES) return;
  RECENT_PAGE = next;
  await refresh();
}

async function gotoRecentPage(p){
  if(p < 1 || p > RECENT_TOTAL_PAGES || p === RECENT_PAGE) return;
  RECENT_PAGE = p;
  await refresh();
}

function generatePageList(current, total){
  if(total <= 7){
    return Array.from({length: total}, (_, i) => i + 1);
  }
  const pages = [1];
  let start = Math.max(2, current - 2);
  let end = Math.min(total - 1, current + 2);
  if(current <= 4){
    end = 5;
  }
  if(current >= total - 3){
    start = total - 4;
  }
  if(start > 2) pages.push('...');
  for(let i = start; i <= end; i++){
    pages.push(i);
  }
  if(end < total - 1) pages.push('...');
  pages.push(total);
  return pages;
}

// Tab ids in nav order. One list so the restore path and the nav cannot
// drift apart.
const MAIN_TABS = ['gateway', 'accounts', 'analytics', 'settings', 'logs'];
const MAIN_TAB_STORE = 'codearts-hub-main-tab';
let currentMainTab = 'gateway';
let analyticsRange = 'today';
let cachedMatrixData = null;
let matrixAcctFilter = '';
let matrixModelFilter = '';
// Model allowlist for the combined matrix; filled by loadAnalyticsMatrix().
let MATRIX_MODELS = new Set();


/* ---- panel password gate ---- */
function isAuthError(err){
  // Every 401/403 from the JSON helpers carries this message; the gate is
  // the single place that explains it, so callers stay quiet instead of
  // stacking an identical toast on top of it.
  return !!err && String(err.message) === 'unauthorized';
}

function panelNeedsLogin(){
  const gate = document.getElementById('panelGate');
  if(gate) gate.style.display = 'flex';
  const input = document.getElementById('panelPwdInput');
  if(input){ input.focus(); }
}

// 登录闸门下面那行提示。tone='ok' 用正文色（例如「密码已更新，请重新登录」），
// 其余用错误色；下一次登录失败时 submitPanelLogin 会把它改回错误色。
function setPanelLoginMessage(text, tone){
  const msg = document.getElementById('panelLoginMsg');
  if(!msg) return;
  msg.textContent = text || '';
  msg.style.color = tone === 'ok' ? 'var(--dim)' : 'var(--bad)';
}

function panelSessionLost(message, tone){
  // The session this tab holds is no longer valid - the gateway restarted,
  // the token expired, or the password was just changed. Drop it and stop
  // every poller: leaving them running means each tick fails, re-opens the
  // gate and logs another 401 server-side, which is how a stale tab ends up
  // filling the log.
  PANEL_READY = false;
  PANEL_TIMERS.forEach(t => clearInterval(t));
  PANEL_TIMERS = [];
  if(typeof stopLogPolling === 'function') stopLogPolling();
  // 「+ 添加账号 (OAuth)」弹窗里的登录轮询不在 PANEL_TIMERS 里，是它自己的一条
  // 2.5s 定时器。不清它的话：网关重启/会话过期时弹窗还开着，pollLogin 每 2.5 秒
  // 打一次 /accounts/login/poll，每次 401 又回到这里开闸门，这个标签页就会永远
  // 每 2.5 秒刷一次 401（实测 9 秒内又发 3 次，永不停止）。
  if(loginTimer){ clearInterval(loginTimer); loginTimer = null; }
  PANEL_TOKEN = '';
  try { sessionStorage.removeItem(PANEL_STORE); } catch(e) {}
  setPanelLoginMessage(message || '会话已失效，请重新输入密码', tone);
  panelNeedsLogin();
}

function panelHideGate(){
  const gate = document.getElementById('panelGate');
  if(gate) gate.style.display = 'none';
}

async function submitPanelLogin(){
  const input = document.getElementById('panelPwdInput');
  const password = (input && input.value) || '';
  if(!password){ setPanelLoginMessage('请输入面板密码'); return; }
  setPanelLoginMessage('');
  try {
    const r = await fetch('/panel/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({password: password})
    });
    const data = await r.json().catch(() => ({}));
    if(!r.ok){
      setPanelLoginMessage((data.error && data.error.message) || '密码错误');
      return;
    }
    PANEL_TOKEN = data.token || '';
    try { sessionStorage.setItem(PANEL_STORE, PANEL_TOKEN); } catch(e) {}
    if(input) input.value = '';
    // 登录后整页重载：登录闸门可能在部署很久之后才出现（例如网关重启让内存
    // 令牌失效），这个标签页里跑的 JS 可能已经比服务端旧。旧版把改密码的
    // 401 当成掉线处理，就是旧页面造成的。重载一次让脚本与网关对齐；新页面
    // 会从 sessionStorage 取回令牌，直接进面板。
    location.reload();
  } catch(e) {
    if(msg) msg.textContent = '登录失败: ' + e.message;
  }
}

async function panelLogout(){
  try { await postJSON('/panel/logout', {}); } catch(e) {}
  PANEL_READY = false;
  PANEL_TIMERS.forEach(t => clearInterval(t));
  PANEL_TIMERS = [];
  PANEL_TOKEN = '';
  try { sessionStorage.removeItem(PANEL_STORE); } catch(e) {}
  location.reload();
}

async function bootPanel(){
  try {
    const r = await fetch('/panel/status', {cache: 'no-store', headers: authHeaders()});
    PANEL_STATUS = await r.json().catch(() => ({}));
  } catch(e) { PANEL_STATUS = {}; }
  const hint = document.getElementById('panelDefaultHint');
  if(hint && PANEL_STATUS.panel_password_is_default) hint.style.display = 'block';
  if(PANEL_STATUS.authenticated){
    panelHideGate();
    await startDashboard();
  } else {
    const pwdFromUrl = new URLSearchParams(window.location.search).get('pwd');
    if(pwdFromUrl){
      const input = document.getElementById('panelPwdInput');
      if(input) input.value = pwdFromUrl;
      await submitPanelLogin();
    } else {
      panelNeedsLogin();
    }
  }
}

let PANEL_READY = false;
let PANEL_TIMERS = [];
let visHookInstalled = false;

async function startDashboard(){
  if(PANEL_READY) return;
  PANEL_READY = true;
  // 设置先回来，它决定下面各自查什么；之后就并行。
  await loadSettings();
  await Promise.all([loadModels(), refresh()]);
  updateRecentLimitButtons();
  // The head script already resolved this before first paint; re-apply it
  // here so the data loaders for the active page actually run.
  // 账号区块默认是「合并到网关页」。以前只有 /settings 成功返回后才搬一次，
  // 那个请求一失败/超时，区块就留在隐藏的 pageAccounts 里 —— 页面上看起来
  // 就是「账号与积分汇总整块消失」。先按默认摆一遍，设置回来再按真实值调整。
  applyAccountsTabLayout(false);
  switchMainTab(MAIN_TABS.includes(window.__MAIN_TAB__) ? window.__MAIN_TAB__ : 'gateway');
  // 首屏把数据表接上排序：静态标记里就有的表不会被任何 loader 触发 render，
  // 轮询那条兜底要等 5 秒才轮到它。
  applyAllTableSorts();
  // Polling only starts after the panel is unlocked, so a locked browser
  // never hammers the server with 401s.
  PANEL_TIMERS.forEach(t => clearInterval(t));
  // 后台标签页不再轮询：浏览器停止绘制后台页，但定时器照跑——实测网关页在后台
  // 仍有 50 次/分钟、统计页 110 次/分钟的请求，全是白跑的。可见性变化时下面会
  // 补一次刷新，所以切回前台看到的数据仍是新的。
  PANEL_TIMERS = [
    setInterval(() => {
      if(!PANEL_READY || document.hidden) return;
      if(currentMainTab === 'analytics'){ loadAnalytics(); loadAnalyticsMatrix(); }
    }, 5000),
    // 每 5 秒在任何页面都跑，顺带把页面上的数据表接上排序（见
    // applyAllTableSorts）：表本来就是 5 秒重画一次，扫描跟同一个节奏走，新加
    // 一张表不必在它的 render 函数里再写一行，下一轮自己就接上了。
    setInterval(() => { if(!document.hidden){ refresh(); applyAllTableSorts(); } }, 5000),
  ];
  if(!visHookInstalled){
    visHookInstalled = true;
    // 回到前台补一次：按当前所在页刷新，复用 refresh 自身的并发合并（撞上在飞
    // 的那一轮会排队补跑），所以不会与刚跑完的一轮重复。
    document.addEventListener('visibilitychange', () => {
      if(document.hidden || !PANEL_READY) return;
      refresh();
      if(currentMainTab === 'analytics'){ loadAnalytics(); loadAnalyticsMatrix(); }
      if(currentMainTab === 'logs' && logAutoRefresh) fetchNewLogs(false);
    });
  }
}

/* ---- 页面区块导航 ----
   导航项完全由页面内的 section 现场生成：标题取该 section 首个 h2 的文本
   （忽略用于显示状态的 <em>），锚点 id 由标题内容哈希得到。对所有
   .main-page 生效，所以新增页面、增删区块或调整顺序都不需要改这里。 */
const PAGE_NAV_TOP_VAR = '--page-nav-top';
/* 侧栏收起状态跨页面、跨刷新共用一份 */
const PAGE_NAV_COLLAPSE_KEY = 'ca-page-nav-collapsed';
/* 只有一项的页面不给侧栏：白占一列宽度，也没什么可跳的 */
const PAGE_NAV_MIN_SECTIONS = 2;
let pageNavLock = 0;
let pageNavTimer = 0;

/* 参与导航的区块：页面内最外层的 section（嵌套的 section 属于父区块的内容，
   不单独成项），自身没被 display:none 隐藏，且带 h2 标题。判据用 computed
   display 而不是 offsetParent —— 后者在整页隐藏（切到其它标签页）时会把所有
   区块都判成不可见，导航会整个空掉。 */
function pageNavSections(page){
  if(!page) return [];
  return Array.from(page.querySelectorAll('section')).filter(function(sec){
    if(getComputedStyle(sec).display === 'none') return false;
    if(!sec.querySelector('h2')) return false;
    for(let p = sec.parentElement; p && p !== page; p = p.parentElement){
      if(p.tagName === 'SECTION') return false;
    }
    return true;
  });
}

function pageNavLabel(section, index){
  const h2 = section.querySelector('h2');
  if(h2){
    const clone = h2.cloneNode(true);
    clone.querySelectorAll('em').forEach(el => el.remove());
    const text = (clone.textContent || '').replace(/\s+/g, ' ').trim();
    if(text) return text;
  }
  return '未命名区块 ' + (index + 1);
}

/* 由标题内容导出稳定 id：与区块顺序无关，链接可长期复用 */
function pageNavAnchorId(label, taken){
  let hash = 5381;
  for(let i = 0; i < label.length; i++) hash = ((hash << 5) + hash + label.charCodeAt(i)) >>> 0;
  const base = 'page-sec-' + hash.toString(36);
  let id = base, n = 2;
  while(taken.has(id)) id = base + '-' + (n++);
  return id;
}

/* 区块清单的指纹：只有它变了才重建导航，免得轮询重建表格时把高亮抖掉 */
function pageNavSignature(page){
  return pageNavSections(page).map(function(sec, i){ return pageNavLabel(sec, i); }).join('\u0001');
}

/* 跳转时要让开的距离：吸顶 header，窄屏下再加上同样吸顶的导航条本身 */
function pageNavHeaderOffset(page){
  const header = document.querySelector('header');
  const base = (header ? header.offsetHeight : 64) + 14;
  const sidebar = page ? page.querySelector('.page-sidebar') : null;
  if(sidebar && window.matchMedia('(max-width:860px)').matches){
    return base + sidebar.offsetHeight + 10;
  }
  return base;
}

function syncPageNavOffset(){
  const header = document.querySelector('header');
  const top = (header ? header.offsetHeight : 64) + 14;
  document.documentElement.style.setProperty(PAGE_NAV_TOP_VAR, top + 'px');
}

function setActivePageNav(page, id){
  const nav = page ? page.querySelector('.page-nav') : null;
  if(!nav) return;
  nav.querySelectorAll('.page-nav-item').forEach(function(item){
    item.classList.toggle('active', !!id && item.dataset.target === id);
  });
}

function scrollToPageSection(page, id, smooth){
  const section = document.getElementById(id);
  if(!section) return;
  const top = section.getBoundingClientRect().top + window.pageYOffset - pageNavHeaderOffset(page);
  window.scrollTo({ top: Math.max(0, top), behavior: smooth === false ? 'auto' : 'smooth' });
  setActivePageNav(page, id);
  // 平滑滚动期间抑制滚动高亮，避免中途掠过其它区块把高亮抢走
  pageNavLock = Date.now() + 700;
  section.classList.add('page-nav-flash');
  setTimeout(() => section.classList.remove('page-nav-flash'), 900);
  try {
    const url = new URL(window.location.href);
    url.hash = id;
    history.replaceState(null, '', url.toString());
  } catch(e){}
}

/* 回到顶部：和区块跳转一样在平滑滚动期间抑制滚动高亮，免得中途掠过其它区块
   把高亮抢走；顺便清掉锚点，免得刷新后又落回刚才那个区块。滚完不会再触发滚动
   事件，所以高亮得自己收尾到第一项。 */
function scrollPageToTop(page){
  window.scrollTo({ top: 0, behavior: 'smooth' });
  pageNavLock = Date.now() + 700;
  const first = page ? page.querySelector('.page-nav-item') : null;
  if(first) setActivePageNav(page, first.dataset.target);
  try {
    const url = new URL(window.location.href);
    history.replaceState(null, '', url.pathname + url.search);
  } catch(e){}
}

function pageNavSpy(){
  if(Date.now() < pageNavLock) return;
  const page = document.querySelector('.main-page.active.page-nav-on');
  if(!page) return;
  const nav = page.querySelector('.page-nav');
  if(!nav) return;
  const items = Array.from(nav.querySelectorAll('.page-nav-item'));
  if(!items.length) return;
  const threshold = pageNavHeaderOffset(page) + 8;
  let activeId = items[0].dataset.target;
  for(const item of items){
    const section = document.getElementById(item.dataset.target);
    if(!section) continue;
    if(section.getBoundingClientRect().top - threshold <= 0) activeId = item.dataset.target;
    else break;
  }
  // 滚到底时高亮最后一项，否则末尾区块永远点不亮
  if(window.innerHeight + window.pageYOffset >= document.documentElement.scrollHeight - 4){
    activeId = items[items.length - 1].dataset.target;
  }
  setActivePageNav(page, activeId);
}

/* 滚动高亮：滚动事件本身已按帧节流，这里不再叠一层 requestAnimationFrame
   （后台标签页会挂起 rAF，反而让高亮停在旧位置）。 */
function onPageNavScroll(){
  pageNavSpy();
}

function pageNavCollapsedPref(){
  try { return localStorage.getItem(PAGE_NAV_COLLAPSE_KEY) === '1'; } catch(e){ return false; }
}

/* 收起与否只体现为页面上的一个类，样式和窄屏回退都由 CSS 决定；按钮的
   文字/标题跟着状态走，收起后它就是唯一的入口。 */
function applyPageNavCollapse(page, collapsed){
  if(!page) return;
  page.classList.toggle('page-nav-collapsed', !!collapsed);
  const btn = page.querySelector('.page-sidebar-toggle');
  if(!btn) return;
  const label = collapsed ? '展开本页导航' : '收起本页导航';
  btn.textContent = collapsed ? '»' : '«';
  btn.title = label;
  btn.setAttribute('aria-label', label);
  btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
}

function togglePageNavCollapse(page){
  const collapsed = !page.classList.contains('page-nav-collapsed');
  try { localStorage.setItem(PAGE_NAV_COLLAPSE_KEY, collapsed ? '1' : '0'); } catch(e){}
  applyPageNavCollapse(page, collapsed);
}

function initPageNav(page){
  if(!page) return;
  syncPageNavOffset();
  const sections = pageNavSections(page);
  const signature = pageNavSignature(page);
  let sidebar = page.querySelector('.page-sidebar');

  // 区块不足两项（例如日志页只有一个视图）就不给侧栏，页面保持单栏
  if(sections.length < PAGE_NAV_MIN_SECTIONS){
    if(sidebar) sidebar.remove();
    page.classList.remove('page-nav-on', 'page-nav-collapsed');
    delete page.dataset.pageNavSignature;
    return;
  }
  // 清单没变就不动 DOM，保留现有高亮
  if(sidebar && page.dataset.pageNavSignature === signature) return;

  const taken = new Set(Array.from(document.querySelectorAll('[id]')).map(el => el.id));
  const anchors = [];
  sections.forEach(function(section, i){
    const label = pageNavLabel(section, i);
    let id = section.id;
    if(!id){
      id = pageNavAnchorId(label, taken);
      section.id = id;
    }
    taken.add(id);
    anchors.push({ id: id, label: label });
  });

  // 重建时保留原来的高亮，别因为一次重建就闪回第一项
  const prevActive = sidebar ? sidebar.querySelector('.page-nav-item.active') : null;
  const prevTarget = prevActive ? prevActive.dataset.target : null;

  // 内容整体包一层：grid 里只剩「侧栏 + 内容」两项，侧栏才跨得满整个内容区，
  // 区块之间的间距也不会被网格行间距再叠一次。
  let body = page.querySelector('.page-nav-body');
  if(!body){
    body = document.createElement('div');
    body.className = 'page-nav-body';
    Array.from(page.children).forEach(function(el){ if(el !== sidebar) body.appendChild(el); });
    page.appendChild(body);
  }

  if(!sidebar){
    sidebar = document.createElement('aside');
    sidebar.className = 'page-sidebar';
    sidebar.setAttribute('aria-label', '本页区块导航');
    page.insertBefore(sidebar, page.firstChild);
  }
  sidebar.textContent = '';
  const head = document.createElement('div');
  head.className = 'page-sidebar-head';
  const title = document.createElement('div');
  title.className = 'page-sidebar-title';
  title.textContent = '本页导航';
  head.appendChild(title);
  const collapseBtn = document.createElement('button');
  collapseBtn.type = 'button';
  collapseBtn.className = 'page-sidebar-toggle';
  collapseBtn.addEventListener('click', function(){ togglePageNavCollapse(page); });
  head.appendChild(collapseBtn);
  sidebar.appendChild(head);
  applyPageNavCollapse(page, pageNavCollapsedPref());

  // 排在区块清单之外：它不是一个区块，不参与高亮与滚动侦测；窄屏下也就能
  // 留在横向胶囊行的左端，不跟着一起滚走。
  const toTop = document.createElement('button');
  toTop.type = 'button';
  toTop.className = 'page-nav-top';
  toTop.textContent = '↑ 回到顶部';
  toTop.title = '回到顶部';
  toTop.addEventListener('click', function(){ scrollPageToTop(page); });
  sidebar.appendChild(toTop);

  const nav = document.createElement('nav');
  nav.className = 'page-nav';
  anchors.forEach(function(a){
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'page-nav-item';
    btn.dataset.target = a.id;
    btn.textContent = a.label;
    btn.title = a.label;
    btn.addEventListener('click', function(){ scrollToPageSection(page, a.id); });
    nav.appendChild(btn);
  });
  sidebar.appendChild(nav);

  page.classList.add('page-nav-on');
  page.dataset.pageNavSignature = signature;

  if(!window.__pageNavBound){
    window.__pageNavBound = true;
    window.addEventListener('scroll', onPageNavScroll, { passive: true });
    window.addEventListener('resize', function(){
      syncPageNavOffset();
      initPageNav(document.querySelector('.main-page.active'));
      onPageNavScroll();
    });
  }
  observePageNav();
  const keep = prevTarget && anchors.some(function(a){ return a.id === prevTarget; });
  setActivePageNav(page, keep ? prevTarget : anchors[0].id);
  onPageNavScroll();
}

/* 区块在运行时可能增删或整块显隐（例如国内版的成长任务区块），让导航跟上，
   免得侧栏停在旧清单上。只盯当前页：非当前页的变化在切过去时由 initPageNav()
   重算，没必要在后台一直扫。 */
function refreshPageNav(){
  pageNavTimer = 0;
  initPageNav(document.querySelector('.main-page.active'));
}

function observePageNav(){
  if(window.__pageNavObserved || typeof MutationObserver === 'undefined') return;
  window.__pageNavObserved = true;
  const schedule = function(records){
    // 导航自身重建/改高亮引起的变更不必再算一遍，否则滚动时会自激
    if(records && records.every(function(r){
      const el = r.target;
      return el && el.closest && el.closest('.page-sidebar');
    })) return;
    if(pageNavTimer) clearTimeout(pageNavTimer);
    pageNavTimer = setTimeout(refreshPageNav, 200);
  };
  new MutationObserver(schedule).observe(document.body, {
    childList: true, subtree: true, attributes: true, attributeFilter: ['style', 'class'],
  });
}

/* 带 #锚点 打开时直接落到对应区块 */
function restorePageNavHash(){
  const page = document.querySelector('.main-page.active.page-nav-on');
  if(!page) return;
  const id = (window.location.hash || '').slice(1);
  if(!id) return;
  // 被隐藏的区块不进导航，也不该作为锚点落点（否则会滚到一个不可见的位置）
  const navigable = pageNavSections(page).some(function(s){ return s.id === id; });
  if(navigable) scrollToPageSection(page, id, false);
}

// ==== 账号区折叠开始 ====
// 折叠纯粹是呈现：realm 切换、签到/启用停用等逻辑
// 都不碰这里，所以收起之后它们照常跑，也不会把区域顶开。偏好存在服务端的
// accounts/settings.json（accounts_collapsed），不用 localStorage。
let _accountsCollapsed = false;

function accountsSectionBody(){
  return document.getElementById('accountsBody');
}

// 唯一的写入口：aria-expanded、正文的 collapsed 类与内存状态一起改，
// 三者不可能不同步。
function applyAccountsCollapsed(collapsed){
  _accountsCollapsed = collapsed === true;
  const body = accountsSectionBody();
  const btn = document.getElementById('accountsToggle');
  if(body) body.classList.toggle('collapsed', _accountsCollapsed);
  if(btn) btn.setAttribute('aria-expanded', _accountsCollapsed ? 'false' : 'true');
  return _accountsCollapsed;
}



// 显式选择走既有的 settings save 通道（一个键的 patch，不动别的设置）。

// ==== 账号区折叠结束 ====

// ==== 顶部页签显示开始 ====
// 顶部页签的显隐偏好。清单不写死：按 .main-nav 里现有的按钮现场生成，上游以后
// 增删页面这里自动跟上，不必同步改这份代码。
// 偏好存在服务端（accounts/settings.json 的 hidden_pages），与账号区折叠、
// 「(切换前)」行是同一套通道，换浏览器、重启服务都记得，不用 localStorage。

/* 「设置」固定保留：它是这个开关自己的入口，收起来之后面板里再没有别的地方能把它
   放回来。其余页面都能自由选择。 */
const PAGE_KEEP_VISIBLE = 'settings';
/* 页签 key 由按钮 id 推出（btnNavGateway → gateway），与 switchMainTab() 和启动
   脚本用的是同一套命名；id 不是这个形状的按钮直接跳过，不猜。 */
const NAV_BUTTON_PREFIX = 'btnNav';
/* 页面 key 的合法形状，与 ca_settings.PAGE_KEY_RE 一致 */
const PAGE_KEY_SHAPE = /^[a-z][a-z0-9_-]{0,31}$/;

let _hiddenPages = [];

function navPageKey(btn){
  const id = (btn && btn.id) || '';
  if(id.indexOf(NAV_BUTTON_PREFIX) !== 0) return '';
  return id.slice(NAV_BUTTON_PREFIX.length).toLowerCase();
}

function navPageRows(){
  const nav = document.querySelector('.main-nav');
  if(!nav) return [];
  const rows = [];
  Array.from(nav.querySelectorAll('.main-nav-btn')).forEach(function(btn){
    const key = navPageKey(btn);
    if(!key) return;
    rows.push({
      key: key,
      btn: btn,
      page: document.getElementById('page' + key.charAt(0).toUpperCase() + key.slice(1)),
    });
  });
  return rows;
}

/* 清单上的标签取页签按钮的文案。i18n 把原文留在文本节点的 __wbSrc 上（译文写在
   data 上），所以这里读 __wbSrc 拿到的一律是中文原文——插进设置页后由面板自己的
   i18n 观察者翻译，切语言时也跟着 restore/walk 走，不用在这里额外重建一次。
   没被 walk 过的节点（界面一直是中文）没有 __wbSrc，textContent 本身就是原文。 */
function navPageLabel(row){
  const btn = row.btn;
  const node = btn ? btn.firstChild : null;
  const source = (node && node.nodeType === 3 && node.__wbSrc != null)
    ? node.__wbSrc : (btn ? btn.textContent : '');
  return String(source || '').replace(/\s+/g, ' ').trim() || row.key;
}



/* 「设置」固定可见，所以一定有结果；真到了没有可见页面那一步，退回网关页。 */
function firstVisiblePage(){
  const rows = navPageRows();
  for(let i = 0; i < rows.length; i++){
    if(!pageHidden(rows[i].key)) return rows[i].key;
  }
  return 'gateway';
}

/* 这一页是否被收起。判断散在六个地方，两个方向写反一次就是「点一下收起来、
   再点一下还是收起来」，收进这里只留一处。 */
function pageHidden(key){
  return _hiddenPages.indexOf(key) >= 0;
}

/* 服务端下发的清单照单收下，但仍过一遍归一化：手改过的文件、将来的客户端或上游
   新增的页面都可能带来这里不认识的 key，不认识的忽略即可。「设置」无论从哪个来源
   来都不收起——不这样兜底，手改 settings.json 就能把面板唯一的入口关掉。
   归一化口径与 ca_settings._clean_page_keys 对齐（形状、去重、丢掉「设置」），
   免得两边记的清单不是一回事；条数上限只在服务端，面板一次最多提交自己那几个页签。 */
function normaliseHiddenPages(hidden){
  if(!Array.isArray(hidden)) return [];
  const out = [];
  hidden.forEach(function(key){
    if(typeof key !== 'string') return;
    const page = key.trim();
    if(!PAGE_KEY_SHAPE.test(page) || page === PAGE_KEEP_VISIBLE) return;
    if(out.indexOf(page) >= 0) return;
    out.push(page);
  });
  return out;
}

/* 唯一写内存状态的入口：页签按钮、页面容器与设置页的勾选框一起改，三者不可能不同步。 */
function applyHiddenPages(hidden){
  _hiddenPages = normaliseHiddenPages(hidden);
  navPageRows().forEach(function(row){
    const off = pageHidden(row.key);
    row.btn.hidden = off;
    if(row.page) row.page.hidden = off;
  });
  // 当前所在页被收起来了（书签、上次停留的页签）就退到第一个还看得见的页面，
  // 免得停在一个顶部没有任何入口的页面上。「设置」固定可见，所以一定有落点。
  if(pageHidden(currentMainTab)){
    const visible = navPageRows().filter(function(row){ return !pageHidden(row.key); });
    if(visible.length) switchMainTab(visible[0].key);
  }
  renderPageVisibility();
  return _hiddenPages;
}

function pageVisibilityBox(list, key){
  const items = Array.from(list.children);
  for(let i = 0; i < items.length; i++){
    const box = items[i].firstElementChild;
    if(box && box.dataset && box.dataset.pageKey === key) return box;
  }
  return null;
}

function pageVisibilityItem(row){
  const item = document.createElement('label');
  item.style.cssText = 'display:flex;align-items:center;gap:6px;font-size:13px;min-height:32px;cursor:pointer';
  const box = document.createElement('input');
  box.type = 'checkbox';
  box.style.cssText = 'width:16px;height:16px';
  box.dataset.pageKey = row.key;
  box.disabled = (row.key === PAGE_KEEP_VISIBLE);
  if(box.disabled) item.title = '「设置」是页面显示开关自己的入口，收起来就放不回去了，固定保留。';
  box.addEventListener('change', function(){ togglePageVisibility(row.key); });
  const text = document.createElement('span');
  text.textContent = navPageLabel(row);
  item.appendChild(box);
  item.appendChild(text);
  return item;
}

/* 重建只在清单变了的时候做：其余情况只同步勾选状态，免得每次 loadSettings 都把
   焦点和滚动位置抖掉。指纹的写法与侧栏导航的 pageNavSignature 一致。 */
function renderPageVisibility(){
  const list = document.getElementById('setPagesList');
  if(!list) return;
  const rows = navPageRows();
  const stamp = rows.map(function(row){ return row.key + '\u0001' + navPageLabel(row); }).join('\u0002');
  if(list.dataset.pagesStamp !== stamp){
    while(list.firstChild) list.removeChild(list.firstChild);
    rows.forEach(function(row){ list.appendChild(pageVisibilityItem(row)); });
    list.dataset.pagesStamp = stamp;
  }
  rows.forEach(function(row){
    const box = pageVisibilityBox(list, row.key);
    if(box) box.checked = !pageHidden(row.key);
  });
  const state = document.getElementById('setPagesState');
  if(state){
    const shown = rows.length - _hiddenPages.length;
    state.textContent = _hiddenPages.length ? ('(显示 ' + shown + '/' + rows.length + ')') : '(全部显示)';
    state.style.color = _hiddenPages.length ? 'var(--warn)' : 'var(--dim)';
  }
}

/* 显式选择走既有的 settings save 通道（一个键的 patch，不动别的设置）。 */
async function togglePageVisibility(key){
  const before = _hiddenPages.slice();
  const next = before.filter(function(k){ return k !== key; });
  if(before.indexOf(key) < 0) next.push(key);
  applyHiddenPages(next);
  try {
    const res = await postJSON('/settings/save', {hidden_pages: next});
    // 服务端会丢掉不合法的 key，以它存的为准，免得两边记的不是一回事
    if(res && Array.isArray(res.hidden_pages)) applyHiddenPages(res.hidden_pages);
  } catch(e) {
    applyHiddenPages(before);
    toast('页面显示设置保存失败: ' + e.message, 'bad');
  }
}
// ==== 顶部页签显示结束 ====

// ==== 账号页签模式开始 ====
// 「账号」是独立成一个主菜单，还是留在「网关与账号」页，由服务端设置
// accounts_separate_tab 决定（默认关闭 = 合并，与拆分前一致）。
//
// 三个账号区块始终是同一批 DOM 节点，只是挂在不同页下面：合并时挂到
// #pageGateway 的锚点处（控制栏之后、最近请求之前，也就是拆分前的位置），
// 拆分时挂回 #pageAccounts 的页头之后。挂在谁下面就归谁的侧栏——区块侧栏是
// initPageNav() 现场扫描本页区块生成的，所以搬完不用另外维护导航。
let _accountsSeparateTab = false;
let _accountsSections = null;

function accountsPageSections(){
  // 区块可能已经被 initPageNav() 包进 .page-nav-body（页面内容整体包一层，
  // grid 里才只剩「侧栏 + 内容」两项），所以页面 div 与那层包裹都要找一遍。
  // 只在拿到非空结果时才记住：搬走之后账号页里就只剩页头了，那时再找也找不回来。
  if(_accountsSections && _accountsSections.length) return _accountsSections;
  const page = document.getElementById('pageAccounts');
  if(!page) return [];
  const scopes = [page];
  Array.from(page.children).forEach(el => {
    if(el.classList && el.classList.contains('page-nav-body')) scopes.push(el);
  });
  const found = [];
  scopes.forEach(scope => Array.from(scope.children).forEach(el => {
    if(el.tagName === 'SECTION' && found.indexOf(el) === -1) found.push(el);
  }));
  if(found.length) _accountsSections = found;
  return found;
}



// 插到锚点前面——插在锚点**所在的那个容器**里，而不是插到页面 div 上：
// 锚点被 .page-nav-body 包起来之后就不再是页面 div 的直接子节点了，直接对页面
// div 调 insertBefore 会抛 NotFoundError（而 loadSettings 的 try/catch 会把它
// 吞掉，表现成「开关没反应」这种最难查的样子）。
function insertBeforeAnchor(sections, anchor){
  const host = anchor && anchor.parentNode;
  if(!host || !sections.length) return false;
  sections.forEach(s => host.insertBefore(s, anchor));
  return true;
}

function applyAccountsTabLayout(separate){
  _accountsSeparateTab = (separate === true);
  const pageGateway = document.getElementById('pageGateway');
  const pageAccounts = document.getElementById('pageAccounts');
  if(!pageGateway || !pageAccounts) return _accountsSeparateTab;

  const sections = accountsPageSections();
  // 版本切换跟着账号区块走：拆分时回到账号页页头右侧，合并时搬到网关页的账号
  // 区块正上方。合并模式下网关页最上面那两张出口卡片也能切版本，但账号区在页面
  // 中段，要换一版得先滚回页首——跟着搬一次就不必了。
  // 先摆它再摆区块：两者都是「插到锚点前面」，谁先插谁在前，顺序才是控件 → 区块。
  const realmSwitch = document.getElementById('accountsRealmSwitch');
  if(realmSwitch){
    if(_accountsSeparateTab){
      const home = document.getElementById('accountsHeader');
      if(home && realmSwitch.parentNode !== home) home.appendChild(realmSwitch);
    } else {
      insertBeforeAnchor([realmSwitch], document.getElementById('accountsSectionsAnchor'));
    }
  }

  if(_accountsSeparateTab){
    // 两个页签：区块回账号页的页头之后，按原顺序。
    insertBeforeAnchor(sections, document.getElementById('accountsHomeAnchor'));
  } else {
    // 一个页签：区块挂到网关页的锚点处，位置与拆分前一致。
    insertBeforeAnchor(sections, document.getElementById('accountsSectionsAnchor'));
  }

  const btnAccounts = document.getElementById('btnNavAccounts');
  if(btnAccounts) btnAccounts.style.display = _accountsSeparateTab ? '' : 'none';
  // 名字跟着走：账号已经不在这一页了，就不能再叫「网关与账号」。
  const gatewayLabel = document.getElementById('navGatewayLabel');
  if(gatewayLabel) gatewayLabel.textContent = _accountsSeparateTab ? '网关' : '网关与账号';
  // 页头（标题 + 一行说明）跟着走：账号在不在这一页，名字与说明都得对得上。
  const pageTitle = document.getElementById('gatewayPageTitle');
  if(pageTitle) pageTitle.textContent = _accountsSeparateTab ? '网关' : '网关与账号';
  const pageDesc = document.getElementById('gatewayPageDesc');
  if(pageDesc){
    pageDesc.textContent = _accountsSeparateTab
      ? '管理网关模型，查看当日调用量、积分消耗、成功率与最近请求。'
      : '管理码道账号与网关模型，查看当日调用量、积分消耗、成功率、最近请求与模型清单。';
  }
  return _accountsSeparateTab;
}

// 显式选择走既有的 settings save 通道（一个键的 patch，不动别的设置）。
async function saveAccountsSeparateTab(btn){
  const el = document.getElementById('setAccountsSeparate');
  const value = !!(el && el.checked);
  if(btn) btn.disabled = true;
  try {
    await postJSON('/settings/save', {accounts_separate_tab: value});
    applyAccountsTabLayout(value);
    // 布局换了，导航、侧栏与当前页都要按新布局重算一遍；正停在「账号」页而
    // 刚关掉开关时，switchMainTab 会把这一页退回「网关与账号」。
    switchMainTab(currentMainTab);
    toast(value ? '已开启：账号独立成一个页签' : '已关闭：账号与网关回到同一页');
    loadSettings();
  } catch(e) {
    toast('保存失败: ' + e.message, 'bad');
  } finally {
    if(btn) btn.disabled = false;
  }
}
// ==== 账号页签模式结束 ====

// ==== 面板窗口限高开始 ====
// 每个窗口（区块 + 日志终端）超过限高时在窗口内部滚动、标题行吸顶，整页不再被
// 单个窗口拉长。限高存在服务端（accounts/settings.json 的 section_max_height，
// 0 = 不限），这里只负责把它落到 CSS 变量与 body 类上：CSS 那三条规则全部挂在
// body.win-capped 之下，没挂类时版式与从前逐像素一致。loadSettings 每次都按服务端
// 存的值重放一遍，所以多个标签页之间不会各说各话。
function applyWinMaxHeight(px){
  const value = Number(px);
  const on = Number.isFinite(value) && value > 0;
  const root = document.documentElement;
  if(on) root.style.setProperty('--win-max-h', Math.round(value) + 'px');
  else root.style.removeProperty('--win-max-h');
  document.body.classList.toggle('win-capped', on);
  const state = document.getElementById('setWinMaxHeightState');
  if(state) state.textContent = on ? ('(当前 ' + Math.round(value) + 'px)') : '(不限)';
  return on;
}

async function saveWinMaxHeight(btn){
  const el = document.getElementById('setWinMaxHeight');
  // 空值必须显式拦下：Number('') 是 0，放过去就是「清空输入框」静默把限高关掉。
  const raw = el ? String(el.value) : '';
  const value = Number(raw);
  if(raw.trim() === '' || !Number.isFinite(value) || value < 0){
    toast('请填写 0 或正数（像素）', 'warn'); return;
  }
  if(btn) btn.disabled = true;
  try {
    const res = await postJSON('/settings/save', {section_max_height: Math.round(value)});
    // 回包里的才是服务端最终存下的（超上限会被夹到 4000），按它重放。
    const stored = res && res.section_max_height !== undefined
      ? Number(res.section_max_height) : Math.round(value);
    applyWinMaxHeight(stored);
    toast(stored > 0 ? ('已限高：窗口最高 ' + stored + 'px') : '已取消窗口限高（不限）', 'ok');
    loadSettings();
  } catch(e) {
    toast('保存失败: ' + e.message, 'bad');
  } finally {
    if(btn) btn.disabled = false;
  }
}
// ==== 面板窗口限高结束 ====

async function loadSettings(showToast){
  try {
    const data = await getJSON('/settings');
    const pwdState = document.getElementById('setPwdState');
    if(pwdState){
      pwdState.textContent = data.panel_password_is_default ? '(当前为默认密码)' : '(已自定义)';
      pwdState.style.color = data.panel_password_is_default ? 'var(--warn)' : 'var(--accent2)';
    }
    const keyState = document.getElementById('setKeyState');
    if(keyState){
      const count = (data.api_keys || []).filter(k => k.enabled).length;
      keyState.textContent = count ? ('(' + count + ' 个生效)') : '(当前不校验)';
      keyState.style.color = count ? 'var(--accent2)' : 'var(--dim)';
    }

    applyUiLanguageSelect(data.ui_language || 'zh');

    // 账号区折叠：服务端没存过、存坏了，或后端根本没这个字段，都按展开算。
    applyAccountsCollapsed(data.accounts_collapsed === true);
    // 「(切换前)」行开关同理：只有明确存过 true 才收起，其余都照常显示。
    applyKeyBeforeHidden(data.key_before_hidden === true);
    // 顶部页签显示：字段缺失或存坏了都按「全部显示」算，见 normaliseHiddenPages。
    applyHiddenPages(data.hidden_pages);
    // 账号页签模式：同样只有明确存过 true 才拆开，其余（没存过、存坏了、
    // 后端没这个字段）都保持上游那个合并的「网关与账号」页。
    const separateTab = data.accounts_separate_tab === true;
    applyAccountsTabLayout(separateTab);
    const separateState = document.getElementById('setAccountsSeparateState');
    if(separateState) separateState.textContent = separateTab ? '(已开启)' : '(默认：合并)';
    const separateInput = document.getElementById('setAccountsSeparate');
    if(separateInput) separateInput.checked = separateTab;

    // 面板窗口限高：字段缺失（后端旧一点）或存坏了都按默认 640px 算，0 = 不限。
    // 坏值回落默认状态这条口径与「顶部页签显示」「账号区折叠」一致，见
    // ca_settings.section_max_height 与 applyWinMaxHeight。
    const rawWinMax = data.section_max_height;
    const winMax = (typeof rawWinMax === 'number' && Number.isFinite(rawWinMax) && rawWinMax >= 0)
      ? rawWinMax : 640;
    applyWinMaxHeight(winMax);
    const winMaxInput = document.getElementById('setWinMaxHeight');
    if(winMaxInput) winMaxInput.value = String(Math.round(winMax));

      const anthropicMsg = data.enable_anthropic_messages === true;
      const anthropicMsgInput = document.getElementById('setAnthropicMessages');
      if(anthropicMsgInput) anthropicMsgInput.checked = anthropicMsg;
      const anthropicMsgState = document.getElementById('setAnthropicMessagesState');
      if(anthropicMsgState){
        anthropicMsgState.textContent = anthropicMsg ? '(已启用)' : '(未启用)';
        anthropicMsgState.style.color = anthropicMsg ? 'var(--accent2)' : 'var(--dim)';
      }
      const egressBackoff = data.egress_backoff_enabled === true;
      const egressBackoffInput = document.getElementById('setEgressBackoff');
      if(egressBackoffInput) egressBackoffInput.checked = egressBackoff;
      const egressBackoffState = document.getElementById('setEgressBackoffState');
      if(egressBackoffState){
        egressBackoffState.textContent = egressBackoff ? '(已启用)' : '(未启用)';
        egressBackoffState.style.color = egressBackoff ? 'var(--accent2)' : 'var(--dim)';
      }
      // 上游响应头超时：没改过时后端给的就是默认 120，所以「等于 120」按默认态
      // 显示，只有被改过才标出实际秒数。
      const headerTimeout = (data.upstream || {}).header_timeout_seconds;
      const headerTimeoutInput = document.getElementById('setHeaderTimeout');
      if(headerTimeoutInput){
        headerTimeoutInput.value = (typeof headerTimeout === 'number') ? headerTimeout : 120;
      }
      const headerTimeoutState = document.getElementById('setHeaderTimeoutState');
      if(headerTimeoutState){
        const headerTimeoutDefault = (typeof headerTimeout !== 'number') || headerTimeout === 120;
        headerTimeoutState.textContent = headerTimeoutDefault ? '(默认 120 秒)' : '(' + headerTimeout + ' 秒)';
        headerTimeoutState.style.color = headerTimeoutDefault ? 'var(--dim)' : 'var(--accent2)';
      }
      // 码道可调项：后端总是给全四个值，所以直接填。
      const limitsInputs = {
        setLimitTokens: data.daily_token_limit,
        setLimitCredits: data.daily_credit_limit,
        setLimitModelTokens: data.model_daily_token_limit,
      };
      Object.keys(limitsInputs).forEach(function(id){
        const el = document.getElementById(id);
        const v = limitsInputs[id];
        if(el) el.value = (typeof v === 'number' && v > 0) ? v : 0;
      });
      const codeartsCfg = data.codearts || {};
      const codeartsInputs = {
        setCodeartsConcurrency: codeartsCfg.concurrency,
        setCodeartsPing: codeartsCfg.session_ping,
        setCodeartsBusy: codeartsCfg.busy_cooldown,
        setCodeartsTpm: codeartsCfg.tpm_cooldown,
      };
      // 模型降级链：开关 + 顺序输入框 + 可点选追加的模型 chips。
      const fbEnabled = codeartsCfg.model_fallback_enabled !== false;
      const fbEnabledInput = document.getElementById('setFallbackEnabled');
      if(fbEnabledInput) fbEnabledInput.checked = fbEnabled;
      const fbState = document.getElementById('setFallbackState');
      if(fbState){
        fbState.textContent = fbEnabled ? '(已启用)' : '(未启用)';
        fbState.style.color = fbEnabled ? 'var(--accent2)' : 'var(--dim)';
      }
      const fbChainInput = document.getElementById('setFallbackChain');
      if(fbChainInput) fbChainInput.value = codeartsCfg.model_fallbacks || '';
      renderFallbackChips();
      Object.keys(codeartsInputs).forEach(function(id){
        const el = document.getElementById(id);
        if(el && typeof codeartsInputs[id] === 'number') el.value = codeartsInputs[id];
      });
      const logDbEnabled = data.log_db_enabled === true;
      const logDbEnabledInput = document.getElementById('setLogDbEnabled');
      if(logDbEnabledInput) logDbEnabledInput.checked = logDbEnabled;
      const logDbState = document.getElementById('setLogDbState');
      if(logDbState){
        logDbState.textContent = logDbEnabled ? '(已启用)' : '(未启用)';
        logDbState.style.color = logDbEnabled ? 'var(--accent2)' : 'var(--dim)';
      }
      fillCapInput('setLogDbMaxRows', data.log_db_max_rows);
      fillCapInput('setLogDbMaxDays', data.log_db_max_days);
      fillCapInputMB('setLogDbMaxMB', data.log_db_max_bytes);
    // Rebuild the editable rows, keeping stored values so an untouched field
    // is not accidentally blanked.
    API_KEY_ROWS = (data.api_keys || []).map(k => ({
      id: k.id || '',
      name: k.name || '',
      key: '',
      // The server keeps the stored value when a row comes back blank, so
      // leaving the field untouched will not wipe an existing key.
      stored_key: '',
      masked: k.masked || '',
      models: Array.isArray(k.models) ? k.models.slice() : [],
      concurrency_limit: parseInt(k.concurrency_limit || 0, 10) || 0,
      enabled: k.enabled !== false,
      created_at: k.created_at || '',
      _editing: false,
    }));
    window.API_KEY_ROWS = API_KEY_ROWS;
    DELETED_KEY_ROWS = (data.deleted_api_keys || []).map(k => ({
      id: k.id || '',
      name: k.name || '',
      created_at: k.created_at || '',
      deleted_at: k.deleted_at || '',
    }));
    renderKeyRows();
    updateUI();
    const set = (id, value) => { const el = document.getElementById(id); if(el) el.textContent = value || '-'; };
    set('setVersion', data.version);
    set('setAccountsDir', data.accounts_dir);
    set('setUsageDir', data.usage_dir);
    set('setFile', data.settings_file);
    set('setSettingsFile', data.settings_file);
    // 更新状态来自 /updates 而不是 /settings，单独拉一次；它自带兜底，
    // 失败只写在自己的状态行里，不会把上面这些区块一起带走。
    loadUpdateStatus();
      // 用量聚合保留窗口：没改过时后端给的就是内置默认（小时层 48 / 日桶 32），
      // 所以「等于默认」按默认态显示，只有被调过才标出实际值。
      const usageKeep = data.usage || {};
      const usageHourKeep = usageKeep.hour_keep_hours;
      const usageDayKeep = usageKeep.day_keep_days;
      const usageHourInput = document.getElementById('setUsageHourKeep');
      if(usageHourInput){
        usageHourInput.value = (typeof usageHourKeep === 'number') ? usageHourKeep : 48;
      }
      const usageDayInput = document.getElementById('setUsageDayKeep');
      if(usageDayInput){
        usageDayInput.value = (typeof usageDayKeep === 'number') ? usageDayKeep : 32;
      }
      const usageKeepState = document.getElementById('setUsageKeepState');
      if(usageKeepState){
        const hourDefault = (typeof usageHourKeep !== 'number') || usageHourKeep === 48;
        const dayDefault = (typeof usageDayKeep !== 'number') || usageDayKeep === 32;
        const isDefault = hourDefault && dayDefault;
        usageKeepState.textContent = isDefault
          ? '(默认 48 小时 / 32 天)'
          : '(' + (typeof usageHourKeep === 'number' ? usageHourKeep : 48) + ' 小时 / '
              + (typeof usageDayKeep === 'number' ? usageDayKeep : 32) + ' 天)';
        usageKeepState.style.color = isDefault ? 'var(--dim)' : 'var(--accent2)';
      }
    if(showToast) toast('设置已刷新', 'ok');
  } catch(e) {
    if(showToast) toast('读取设置失败: ' + e.message, 'bad');
  }
}

function applyUiLanguageSelect(value){
  const select = document.getElementById('setUiLanguage');
  if(select) select.value = value || 'zh';
  const state = document.getElementById('setUiLanguageState');
  if(state){
    const label = value === 'zh-Hant' ? '(正體中文)' : (value === 'en' ? '(English)' : '(简体中文)');
    state.textContent = label;
    state.style.color = 'var(--dim)';
  }
}

async function saveUiLanguage(btn){
  const select = document.getElementById('setUiLanguage');
  const value = select ? select.value : 'zh';
  if(btn) btn.disabled = true;
  try {
    await postJSON('/settings/save', {ui_language: value});
    toast('实例默认语言已保存', 'ok');
    loadSettings();
  } catch(e) {
    toast('保存失败: ' + e.message, 'bad');
  } finally {
    if(btn) btn.disabled = false;
  }
}

function clearUiLanguageOverride(btn){
  try { localStorage.removeItem('ca-lang'); } catch(e){}
  if(btn) btn.disabled = true;
  location.reload();
}

// 改密码的结果留在表单下面，不只用 4 秒就消失的 toast：失败原因（当前密码
// 不对、新密码与旧密码相同、会话失效）必须一直看得见。
function setPwdMessage(text, kind){
  const box = document.getElementById('setPwdMsg');
  if(!box) return;
  box.textContent = text || '';
  box.style.color = kind === 'bad' ? 'var(--bad)'
                  : kind === 'warn' ? 'var(--warn)'
                  : kind === 'ok' ? 'var(--accent2)' : 'var(--dim)';
}
// 输入框右侧的睁眼/闭眼：只切换这一个框，方便对照检查旧密码和新密码各自
// 有没有多打空格、全角字符。
function togglePwdVisibility(btn, inputId){
  const el = document.getElementById(inputId);
  if(!el) return;
  const show = el.type === 'password';
  el.type = show ? 'text' : 'password';
  const label = show ? '隐藏密码' : '显示密码';
  if(btn){
    btn.setAttribute('title', label);
    btn.setAttribute('aria-label', label);
    btn.setAttribute('aria-pressed', show ? 'true' : 'false');
    const icons = btn.querySelectorAll ? btn.querySelectorAll('svg') : [];
    for(let i = 0; i < icons.length; i++){
      const svg = icons[i];
      const isOpen = svg.classList.contains('pwd-eye-open');
      svg.style.display = (isOpen === show) ? '' : 'none';
    }
  }
}
async function savePanelPassword(btn){
  const cur = (document.getElementById('setPwdCurrent') || {}).value || '';
  const nw = (document.getElementById('setPwdNew') || {}).value || '';
  if(!cur || !nw){ setPwdMessage('请填写当前密码和新密码', 'warn'); return; }
  // 两栏被密码管理器填成同一个值时，服务端会接受但对用户来说「什么都没变」，
  // 先在本地拦住并说清楚。
  if(cur === nw){ setPwdMessage('新密码与当前密码相同，密码不会变化', 'warn'); return; }
  setPwdMessage('');
  btn.disabled = true;
  try {
    // localAuth：这条路由的 401 是「当前密码不对」，不是会话失效。绝不能让
    // 它触发 panelSessionLost——那会清掉令牌、弹出登录页，把一次输错变成
    // 掉线。错误文案由下面的 catch 持久显示在表单里。
    const data = await postJSON('/panel/password', {current: cur, new: nw}, {localAuth: true});
    document.getElementById('setPwdCurrent').value = '';
    document.getElementById('setPwdNew').value = '';
    // 服务端改完密码会吊销所有会话，也不再下发新令牌。直接回到登录闸门，
    // 让用户用新密码重新登录；留在面板里会让人以为还是旧密码在生效。
    const okMsg = data.synced_env === false
      ? '面板密码已更新（未能同步 .credentials，重启后仍以面板为准），请用新密码重新登录'
      : '面板密码已更新，请用新密码重新登录';
    setPwdMessage(okMsg, 'ok');
    panelSessionLost(okMsg, 'ok');
  } catch(e) {
    const msg = String((e && e.message) || e || '');
    // 「panel password required」是路由最前面的会话检查；其余 401 都是
    // 当前密码不对。会话真失效时，下一次轮询也会把登录页打开，这里只负责
    // 把原因说清楚，不主动踢人。
    if(e && e.status === 401 && /panel password required/.test(msg)){
      setPwdMessage('面板会话已失效，请重新登录后再改密码', 'bad');
    } else if(e && e.status === 401){
      setPwdMessage(msg, 'bad');
      const input = document.getElementById('setPwdCurrent');
      if(input) input.focus();
    } else {
      setPwdMessage('修改失败: ' + msg, 'bad');
    }
  } finally {
    btn.disabled = false;
  }
}

// ---- 限额（全局生效） ---------------------------------------------------




async function saveAnthropicMessages(btn){
  const el = document.getElementById('setAnthropicMessages');
  const value = !!(el && el.checked);
  if(btn) btn.disabled = true;
  try {
    await postJSON('/settings/save', {enable_anthropic_messages: value});
    toast(value ? '已启用：Anthropic Messages 接口' : '已关闭：Anthropic Messages 接口', 'ok');
    loadSettings();
  } catch(e) {
    toast('保存失败: ' + e.message, 'bad');
  } finally {
    if(btn) btn.disabled = false;
  }
}


async function saveEgressBackoff(btn){
  const el = document.getElementById('setEgressBackoff');
  const value = !!(el && el.checked);
  if(btn) btn.disabled = true;
  try {
    await postJSON('/settings/save', {egress_backoff_enabled: value});
    toast(value ? '已启用：出口级瞬时失败退避' : '已关闭出口级瞬时失败退避', 'ok');
    loadSettings();
  } catch(e) {
    toast('保存失败: ' + e.message, 'bad');
  } finally {
    if(btn) btn.disabled = false;
  }
}

/* 用量聚合保留窗口（空间换时间）。后端只接受 >=1 的整数，且各有上限，所以
   先把输入收成整数再发；空值/小数/非数字就地拦下，不送上去换 400。 */
async function saveUsageKeep(btn){
  const hourEl = document.getElementById('setUsageHourKeep');
  const dayEl = document.getElementById('setUsageDayKeep');
  const hours = Math.floor(Number(hourEl && hourEl.value));
  const days = Math.floor(Number(dayEl && dayEl.value));
  if(!isFinite(hours) || hours < 1 || !isFinite(days) || days < 1){
    toast('请输入不小于 1 的整数', 'bad');
    return;
  }
  if(btn) btn.disabled = true;
  try {
    await postJSON('/settings/save', {usage: {hour_keep_hours: hours, day_keep_days: days}});
    toast('已保存：小时层 ' + hours + ' 小时 / 日桶 ' + days + ' 天', 'ok');
    loadSettings();
  } catch(e) {
    toast('保存失败: ' + e.message, 'bad');
  } finally {
    if(btn) btn.disabled = false;
  }
}
/* 上游响应头超时。后端只接受 >=1 的整数秒，所以先把输入收成整数再发：空值、
   小数、非数字就地拦下，而不是送上去换一个 400 回来。 */
/* 码道并发 / 续期 / 冷却。四项一起提交：后端按区间校验，越界会回 400。
   并发上限是 3 —— 上游每个账号只给 3 个会话名额（CODEARTS_UPSTREAM_SLOTS），
   配到 4 以上必然撞 TM.00001041。前端区间必须和后端 CODEARTS_RANGES 一致：
   以前这里写 8，用户设 4 能存进去，后端却按 1~3 校验，于是那个值被当成坏值
   退回上一级（默认 2）—— 存了 4，实际是 2，面板上还显示 4。 */
async function saveLimits(btn){
  const fields = [
    ['setLimitTokens', 'daily_token_limit', '日 token 限额'],
    ['setLimitCredits', 'daily_credit_limit', '日积分限额'],
    ['setLimitModelTokens', 'model_daily_token_limit', '单模型日 token 限额'],
  ];
  const payload = {};
  for(const [id, key, label] of fields){
    const el = document.getElementById(id);
    const value = Math.floor(Number(el && el.value) || 0);
    if(!isFinite(value) || value < 0 || value > 1e12){
      toast(label + ' 需要 0 ~ 10^12 之间的整数（0 = 不限）', 'bad');
      return;
    }
    payload[key] = value;
  }
  if(btn) btn.disabled = true;
  try {
    await postJSON('/settings/save', {limits: payload});
    toast('已保存：每日限额（下一个请求即生效）', 'ok');
    loadSettings();
  } catch(e) {
    toast('保存失败: ' + e.message, 'bad');
  } finally {
    if(btn) btn.disabled = false;
  }
}

async function saveCodeartsTuning(btn){
  const fields = [
    ['setCodeartsConcurrency', 'concurrency', '并发', 1, 3],
    ['setCodeartsPing', 'session_ping', '续期间隔', 5, 600],
    ['setCodeartsBusy', 'busy_cooldown', '并发满冷却', 1, 300],
    ['setCodeartsTpm', 'tpm_cooldown', 'TPM 冷却', 5, 3600],
  ];
  const payload = {};
  for(const [id, key, label, low, high] of fields){
    const el = document.getElementById(id);
    const value = Math.floor(Number(el && el.value));
    if(!isFinite(value) || value < low || value > high){
      toast(label + ' 需要 ' + low + '~' + high + ' 之间的整数', 'bad');
      return;
    }
    payload[key] = value;
  }
  if(btn) btn.disabled = true;
  try {
    await postJSON('/settings/save', {codearts: payload});
    toast('已保存：码道并发与冷却', 'ok');
    loadSettings();
  } catch(e) {
    toast('保存失败: ' + e.message, 'bad');
  } finally {
    if(btn) btn.disabled = false;
  }
}

function renderFallbackChips(){
  const host = document.getElementById('setFallbackChips');
  const input = document.getElementById('setFallbackChain');
  if(!host || !input) return;
  const inChain = new Set(
    input.value.split(',').map(x => x.trim()).filter(Boolean));
  host.textContent = '';
  (window.MODELS_DATA || []).forEach(function(m){
    if(!m || !m.id) return;
    const chip = document.createElement('span');
    chip.textContent = m.id;
    chip.title = '点击追加到链尾';
    chip.dataset.modelId = m.id;
    chip.style.cssText = ('display:inline-block;margin:2px 6px 2px 0;padding:1px 8px;'
        + 'border:1px solid var(--border);border-radius:10px;font-size:12px;cursor:pointer;'
        + (inChain.has(m.id) ? 'color:var(--accent2);border-color:var(--accent2);' : ''));
    chip.onclick = function(){
      const parts = input.value.split(',').map(x => x.trim()).filter(Boolean);
      if(parts.indexOf(m.id) < 0) parts.push(m.id);
      input.value = parts.join(',');
      renderFallbackChips();
    };
    host.appendChild(chip);
  });
  if(!host.childNodes.length){
    host.textContent = '（模型清单加载后可点选）';
  }
}

async function saveModelFallback(btn){
  const enabledInput = document.getElementById('setFallbackEnabled');
  const chainInput = document.getElementById('setFallbackChain');
  const enabled = !!(enabledInput && enabledInput.checked);
  const segs = (chainInput && chainInput.value || '').split(',')
    .map(x => x.trim()).filter(Boolean);
  for(const seg of segs){
    if(!/^[A-Za-z0-9._-]+$/.test(seg)){
      toast('链里有非法模型名：' + seg, 'bad');
      return;
    }
  }
  if(btn) btn.disabled = true;
  try {
    await postJSON('/settings/save', {codearts: {
      model_fallbacks: segs.join(','),
      model_fallback_enabled: enabled,
    }});
    toast('已保存：模型降级链' + (enabled ? '' : '（未启用）'), 'ok');
    loadSettings();
  } catch(e) {
    toast('保存失败: ' + e.message, 'bad');
  } finally {
    if(btn) btn.disabled = false;
  }
}

async function saveHeaderTimeout(btn){
  const el = document.getElementById('setHeaderTimeout');
  const value = Math.floor(Number(el && el.value));
  if(!isFinite(value) || value < 1){
    toast('请输入不小于 1 的整数秒', 'bad');
    return;
  }
  if(btn) btn.disabled = true;
  try {
    await postJSON('/settings/save', {upstream: {header_timeout_seconds: value}});
    toast('已保存：上游响应头超时 ' + value + ' 秒', 'ok');
    loadSettings();
  } catch(e) {
    toast('保存失败: ' + e.message, 'bad');
  } finally {
    if(btn) btn.disabled = false;
  }
}

/* ---- 日志落库 ----
   开关与三条保留上限一次提交；上限框留空就发 null，服务端存成「不限」。
   大小框以 MB 输入，发出去时换算成字节（服务端一律以字节记）。 */
function capInputValue(id){
  const el = document.getElementById(id);
  if(!el) return null;
  const raw = String(el.value == null ? '' : el.value).trim();
  if(raw === '') return null;
  const n = Number(raw);
  if(!isFinite(n) || n <= 0) return null;
  return Math.floor(n);
}
function fillCapInput(id, value){
  const el = document.getElementById(id);
  if(!el) return;
  el.value = (value === null || value === undefined || value === '') ? '' : String(value);
}
function fillCapInputMB(id, bytes){
  const el = document.getElementById(id);
  if(!el) return;
  el.value = (bytes === null || bytes === undefined || bytes === '' || bytes <= 0)
    ? '' : String(Math.max(1, Math.round(bytes / 1048576)));
}
async function saveLogDb(btn){
  const enabledEl = document.getElementById('setLogDbEnabled');
  const rows = capInputValue('setLogDbMaxRows');
  const days = capInputValue('setLogDbMaxDays');
  const mb = capInputValue('setLogDbMaxMB');
  const payload = {
    log_db_enabled: !!(enabledEl && enabledEl.checked),
    log_db_max_rows: rows,
    log_db_max_days: days,
    log_db_max_bytes: mb === null ? null : mb * 1048576,
  };
  if(btn) btn.disabled = true;
  try {
    await postJSON('/settings/save', payload);
    toast(payload.log_db_enabled ? '已启用日志落库' : '已关闭日志落库', 'ok');
    loadSettings();
  } catch(e) {
    toast('保存失败: ' + e.message, 'bad');
  } finally {
    if(btn) btn.disabled = false;
  }
}

/* ---- 更新检查 ----
   面板只负责「问一句、把结论显示出来」：真正的查询由后端匿名拉取公开
   Release 列表完成，浏览器不直接接触 GitHub，也不需要任何凭证。

   这一版是**只检查**：没有下载、没有安装、没有重启，所以「安装更新」按钮
   固定禁用并说明原因——与其给一个点了会假装成功的按钮，不如让它看起来
   就是还没有。 */
const UPDATE_INSTALL_AVAILABLE = false;

/* 200 不等于成功：后端把「检查根本没跑起来」（ok=false）和「这一次查询失败」
   （last_error 非空）都放在 200 的响应体里回来。两处都要看，否则按钮会对着
   一次失败的检查报「已是最新版本」——这正是它以前做的事。 */
function updateCheckFailure(data){
  if(!data) return '响应为空';
  if(data.ok === false) return data.msg || '更新检查未运行';
  return data.last_error || '';
}

function updateStateLabel(data){
  if(!data) return '未知';
  if(updateCheckFailure(data)) return '检查失败';
  if(data.update_available) return '发现新版本';
  if(data.latest_version) return '已是最新';
  return '尚未检查';
}

function applyUpdateStatus(data){
  data = data || {};
  const failure = updateCheckFailure(data);
  const set = (id, value) => { const el = document.getElementById(id); if(el) el.textContent = value || '-'; };
  set('setUpdateCurrent', data.current_version);
  set('setUpdateLatest', data.latest_version);
  set('setUpdateLastCheck', data.last_attempt);
  const state = document.getElementById('setUpdateState');
  if(state){
    state.textContent = '(' + updateStateLabel(data) + ')';
    state.style.color = failure ? 'var(--warn)'
      : data.update_available ? 'var(--accent2)' : 'var(--dim)';
  }
  const enabled = document.getElementById('setUpdateCheckEnabled');
  if(enabled) enabled.checked = data.enabled === true;
  const err = document.getElementById('setUpdateError');
  if(err) err.textContent = failure ? ('上次检查失败：' + failure) : '';
  const install = document.getElementById('setUpdateInstallBtn');
  if(install){
    install.disabled = !UPDATE_INSTALL_AVAILABLE;
    install.title = UPDATE_INSTALL_AVAILABLE ? '' : '本版只做检查，安装更新尚未提供';
  }
}

async function loadUpdateStatus(){
  try {
    applyUpdateStatus(await getJSON('/updates'));
  } catch(e) {
    // 读不到更新状态不该影响设置页的其它区块，也不该谎报「已是最新」。
    const state = document.getElementById('setUpdateState');
    if(state){ state.textContent = '(读取失败)'; state.style.color = 'var(--warn)'; }
  }
}

async function checkUpdateNow(btn){
  if(btn) btn.disabled = true;
  try {
    const data = await postJSON('/updates/check', {});
    applyUpdateStatus(data);
    const failure = updateCheckFailure(data);
    if(failure){ toast('检查更新失败: ' + failure, 'bad'); return; }
    toast(data.update_available ? ('发现新版本 ' + data.latest_version) : '已是最新版本', 'ok');
  } catch(e) {
    toast('检查更新失败: ' + e.message, 'bad');
  } finally {
    if(btn) btn.disabled = false;
  }
}

async function saveUpdateCheckEnabled(btn){
  const el = document.getElementById('setUpdateCheckEnabled');
  const value = !!(el && el.checked);
  if(btn) btn.disabled = true;
  try {
    await postJSON('/settings/save', {update_check_enabled: value});
    toast(value ? '已启用：每天自动检查更新' : '已关闭：不再自动检查更新', 'ok');
    loadSettings();
  } catch(e) {
    toast('保存失败: ' + e.message, 'bad');
  } finally {
    if(btn) btn.disabled = false;
  }
}

/* ---- API key list: several keys, each with its own model / concurrency cap ---- */
let API_KEY_ROWS = [];
let DELETED_KEY_ROWS = [];
/* Ids the user removed but that are still stored server-side, pending the
   next save. Deletion is sent explicitly (rather than by leaving the row out
   of the list) so a submission that is stale or incomplete - a second tab, a
   save that raced the post-save reload - can never retire a key nobody
   removed. */
let DELETED_KEY_IDS = [];

function randomKeyValue(){
  const bytes = new Uint8Array(18);
  if(window.crypto && crypto.getRandomValues) crypto.getRandomValues(bytes);
  const raw = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  // crypto.getRandomValues is present in every supported browser; the
  // timestamp fallback only exists so the field is never left empty.
  return raw || ('ca-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10));
}

/* Model allow-list per key. Patterns are matched case-insensitively with `*`
   wildcards ("deepseek*", "gpt-6-astra"). An empty list means no limit, which
   is how every key saved before this field existed comes back. */
function parseModelPatterns(text){
  const out = [];
  String(text || '').split(/[,;]/).forEach(part => {
    const pattern = part.trim().toLowerCase();
    if(pattern && out.indexOf(pattern) === -1) out.push(pattern);
  });
  return out;
}
function modelPatternsText(patterns){
  return Array.isArray(patterns) ? patterns.join(', ') : '';
}

/* 已删除的 Key 是只读历史：密钥已被抹掉，所以这里不提供复制，也不提供恢复。 */
function renderDeletedKeyRows(){
  const box = document.getElementById('deletedKeySection');
  if(!box) return;
  if(!DELETED_KEY_ROWS.length){ box.innerHTML = ''; return; }
  const rows = DELETED_KEY_ROWS.map(k => {
    return '<div style="font-size:12px;color:var(--dim);display:flex;gap:14px;flex-wrap:wrap;padding:7px 0;border-top:1px solid var(--line)">'
      + '<span style="color:var(--fg);font-weight:600">' + esc(k.name || '未命名') + '</span>'
      + (k.created_at ? '<span>创建 ' + esc(k.created_at) + '</span>' : '')
      + (k.deleted_at ? '<span>删除 ' + esc(k.deleted_at) + '</span>' : '')
      + '<span class="mono">' + esc(k.id) + '</span>'
      + '</div>';
  }).join('');
  box.innerHTML = '<details style="margin-top:14px">'
    + '<summary style="cursor:pointer;font-size:12px;color:var(--dim);font-weight:600">已删除的 API Key（'
    + DELETED_KEY_ROWS.length + '）· 只读</summary>'
    + '<div style="margin-top:4px">' + rows + '</div>'
    + '<div style="font-size:11px;color:var(--dim);margin-top:8px">'
    + '删除时密钥已被抹掉，无法恢复、也无法再用于请求。保留这条记录是为了让「按 API Key 的消耗归属」里这些 Key 的历史用量仍然显示名字。'
    + '</div></details>';
}

function renderKeyRows(){
  renderDeletedKeyRows();
  const box = document.getElementById('keyList');
  if(!box) return;
  if(!API_KEY_ROWS.length){
    box.innerHTML = '<div class="empty" style="padding:24px 0">还没有配置 API Key，点击右上角「+ 添加 API Key」创建。</div>';
    return;
  }
  box.innerHTML = API_KEY_ROWS.map((row, i) => {
    if(row._editing){
      return '<div class="key-card" style="border-color:var(--accent);background:var(--panel);box-shadow:0 0 0 1px var(--accent), var(--shadow-md)">'
        + '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">'
        +   '<div style="font-size:14px;font-weight:700;color:var(--fg)">' + (row.id ? '编辑 API Key' : '新建 API Key') + '</div>'
        + '</div>'
        + '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:14px">'
        +   '<div>'
        +     '<div style="font-size:12px;color:var(--dim);margin-bottom:4px;font-weight:500">备注名称</div>'
        +     '<input type="text" id="editKeyName_' + i + '" value="' + esc(row.name || '') + '" placeholder="如: Cursor / DSH / 本地测试" '
        +       'style="width:100%;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font:inherit;color:var(--fg)">'
        +   '</div>'
        +   '<div>'
        +     '<div style="font-size:12px;color:var(--dim);margin-bottom:4px;font-weight:500">最大并发限制 <span style="color:var(--dim-light)">(选填，0 = 不限)</span></div>'
        +     '<input type="number" min="0" max="1000" id="editKeyConc_' + i + '" value="' + (row.concurrency_limit || '') + '" placeholder="0 代表不限制" '
        +       'style="width:100%;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font:inherit;color:var(--fg)">'
        +   '</div>'
        +   '<div style="grid-column:1 / -1">'
        +     '<div style="font-size:12px;color:var(--dim);margin-bottom:4px;font-weight:500">模型限制 <span style="color:var(--dim-light)">(选填，留空 = 不限制)</span></div>'
          +     '<input type="text" id="editKeyModels_' + i + '" value="' + esc(modelPatternsText(row.models)) + '" placeholder="如 deepseek* 或 gpt-6-astra；多个用逗号分隔，支持 * 通配" '
        +       'style="width:100%;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font:inherit;color:var(--fg)">'
        +   '</div>'
        +   '<div style="grid-column:1 / -1">'
        +     '<div style="font-size:12px;color:var(--dim);margin-bottom:4px;font-weight:500">API Key 内容 ' + (row.masked ? '<span style="color:var(--dim-light)">(已保存: ' + esc(row.masked) + '，留空表示不改)</span>' : '') + '</div>'
        +     '<div style="display:flex;gap:8px">'
        +       '<input type="text" id="editKeyValue_' + i + '" value="' + esc(row.key || '') + '" placeholder="' + (row.masked ? '留空表示保持原 Key 不变' : '输入自定义密钥，或点击右侧生成') + '" '
        +         'style="flex:1;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font:inherit;color:var(--fg)">'
        +       '<button class="sec mini" style="white-space:nowrap;border-radius:8px;padding:7px 14px" onclick="generateKeyForEdit(' + i + ')">随机生成</button>'
        +     '</div>'
        +   '</div>'
        + '</div>'
        + '<div style="display:flex;gap:8px;justify-content:flex-end">'
        +   '<button class="sec mini" style="border-radius:8px;padding:6px 16px" onclick="cancelEditKey(' + i + ')">取消</button>'
        +   '<button class="mini" style="border-radius:8px;padding:6px 18px" onclick="saveSingleKey(' + i + ', this)">保存</button>'
        + '</div>'
        + '</div>';
    }

    const statusBadge = row.enabled
      ? '<span class="badge ok" style="font-size:11px;font-weight:600;padding:2px 10px">已启用</span>'
      : '<span class="badge off" style="font-size:11px;font-weight:600;padding:2px 10px">已禁用</span>';

    const concBadge = (row.concurrency_limit && row.concurrency_limit > 0)
      ? '<span class="badge s mini" style="font-size:11px">并发上限 ' + row.concurrency_limit + '</span>'
      : '';
    const modelBadge = (Array.isArray(row.models) && row.models.length)
      ? '<span class="badge s" style="font-size:11px">限 ' + esc(modelPatternsText(row.models)) + '</span>'
      : '';

    const displayKey = row.masked || (row.key ? (row.key.slice(0, 4) + '******' + row.key.slice(-4)) : '未设置');
    const createdStr = row.created_at ? ('创建时间 ' + esc(row.created_at)) : '';

    return '<div class="key-card' + (row.enabled ? '' : ' disabled') + '">'
      + '<div class="key-card-main">'
      +   '<div>'
      +     '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">'
      +       '<span style="font-size:15px;font-weight:700;color:var(--fg)">' + esc(row.name || '未命名') + '</span>'
      +       statusBadge
      +       modelBadge
        +       concBadge
      +     '</div>'
      +     '<div style="font-size:12px;color:var(--dim);display:flex;align-items:center;gap:16px;flex-wrap:wrap">'
      +       '<span>Key: <span class="mono" style="color:var(--fg);font-weight:500">' + esc(displayKey) + '</span></span>'
      +       (createdStr ? ('<span>' + createdStr + '</span>') : '')
      +     '</div>'
      +   '</div>'
      +   '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">'
      +     '<button class="key-action-btn" id="copyBtn' + i + '" onclick="copyKeyRow(' + i + ')">复制</button>'
      +     '<button class="key-action-btn" onclick="openEditKey(' + i + ')">编辑</button>'
      +     '<button class="key-action-btn" onclick="toggleKeyRow(' + i + ')">' + (row.enabled ? '禁用' : '启用') + '</button>'
      +     '<button class="key-action-btn danger" onclick="removeKeyRow(' + i + ')">删除</button>'
      +   '</div>'
      + '</div>'
      + '</div>';
  }).join('');
}

function openEditKey(index){
  if(!API_KEY_ROWS[index]) return;
  API_KEY_ROWS[index]._editing = true;
  renderKeyRows();
}

function cancelEditKey(index){
  if(!API_KEY_ROWS[index]) return;
  if(!API_KEY_ROWS[index].id && !API_KEY_ROWS[index].masked){
    API_KEY_ROWS.splice(index, 1);
  } else {
    API_KEY_ROWS[index]._editing = false;
  }
  renderKeyRows();
}

function generateKeyForEdit(index){
  const el = document.getElementById('editKeyValue_' + index);
  if(el){
    el.value = randomKeyValue();
  }
}

async function saveSingleKey(index, btn){
  const row = API_KEY_ROWS[index];
  if(!row) return;
  const nameInput = document.getElementById('editKeyName_' + index);
  const keyInput = document.getElementById('editKeyValue_' + index);
  const modelsInput = document.getElementById('editKeyModels_' + index);
    const concInput = document.getElementById('editKeyConc_' + index);

  const name = nameInput ? nameInput.value.trim() : (row.name || '');
  const keyVal = keyInput ? keyInput.value.trim() : (row.key || '');

  if(!keyVal && !row.masked){
    toast('API Key 不能为空', 'warn');
    return;
  }

  row.name = name || '未命名';
  row.models = parseModelPatterns(modelsInput ? modelsInput.value : modelPatternsText(row.models));
    row.concurrency_limit = Math.max(0, parseInt((concInput ? concInput.value : row.concurrency_limit) || 0, 10) || 0);
  if(keyVal) row.key = keyVal;
  row._editing = false;

  if(btn) btn.disabled = true;
  try {
    if(!await saveApiKeys()) return;
    toast('API Key [' + row.name + '] 已保存', 'ok');
  } catch(e){
    toast('保存失败: ' + e.message, 'bad');
  }
}

async function toggleKeyRow(index){
  const row = API_KEY_ROWS[index];
  if(!row) return;
  row.enabled = !row.enabled;
  try {
    if(!await saveApiKeys()){
      // The save was rejected; put the switch back so the row does not lie.
      row.enabled = !row.enabled;
      renderKeyRows();
      return;
    }
    toast(row.enabled ? 'Key [' + row.name + '] 已启用' : 'Key [' + row.name + '] 已禁用', 'ok');
  } catch(e){
    row.enabled = !row.enabled;
    renderKeyRows();
    toast('操作失败: ' + e.message, 'bad');
  }
}

async function removeKeyRow(index){
  const row = API_KEY_ROWS[index];
  if(!row) return;
  if(!confirm('确定删除 API Key [' + (row.name || '未命名') + '] 吗？密钥会被抹掉且无法恢复；看板里它已经产生的历史用量仍会保留这个名字。')) return;
  if(row.id && DELETED_KEY_IDS.indexOf(row.id) === -1) DELETED_KEY_IDS.push(row.id);
  API_KEY_ROWS.splice(index, 1);
  try {
    if(!await saveApiKeys()){
      // The server kept the key; drop the pending delete and resync the list
      // so the row comes back instead of lingering as a phantom.
      DELETED_KEY_IDS = DELETED_KEY_IDS.filter(id => id !== row.id);
      await loadSettings();
      return;
    }
    toast('已删除 API Key', 'ok');
  } catch(e){
    toast('删除失败: ' + e.message, 'bad');
  }
}

function addApiKeyRow(){
  API_KEY_ROWS.push({
    id: '',
    name: '',
    key: randomKeyValue(),
    models: [],
      concurrency_limit: 0,
    enabled: true,
    masked: '',
    _editing: true
  });
  renderKeyRows();
  setTimeout(() => {
    const el = document.getElementById('editKeyName_' + (API_KEY_ROWS.length - 1));
    if(el) el.focus();
  }, 50);
}
/* Copy the key in a row, fetching the stored value when the field is blank
   (the panel only ever displays a masked key). */
async function copyKeyRow(index){
  const row = API_KEY_ROWS[index];
  if(!row) return;
  const btn = document.getElementById('copyBtn' + index);
  let value = (row.key || '').trim();
  try {
    if(!value && row.id){
      const data = await getJSON('/settings/reveal?id=' + encodeURIComponent(row.id));
      value = data.key || '';
    }
    if(!value){
      toast('这一行还没有 Key，点「随机生成」或直接填写', 'warn');
      return;
    }
    await writeClipboard(value);
    if(btn){
      const old = btn.textContent;
      btn.textContent = '已复制';
      setTimeout(() => { btn.textContent = old; }, 1600);
    }
    toast('已复制到剪贴板', 'ok');
  } catch(e) {
    toast('复制失败: ' + e.message, 'bad');
  }
}

async function writeClipboard(text){
  // navigator.clipboard needs a secure context; plain http on a LAN address
  // does not qualify, so fall back to a temporary textarea.
  if(navigator.clipboard && window.isSecureContext){
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.cssText = 'position:fixed;top:-1000px;opacity:0';
  document.body.appendChild(area);
  area.select();
  area.setSelectionRange(0, area.value.length);
  const ok = document.execCommand('copy');
  document.body.removeChild(area);
  if(!ok) throw new Error('浏览器拒绝了复制操作');
}

/* Save the whole visible list, plus the ids the user explicitly removed.
   Returns true when the server accepted the save.

   The submit is an upsert: the server retires only the ids named in
   `deleted_api_key_ids` and leaves every other stored key alone. That is what
   keeps a stale or incomplete list from wiping keys the user never removed,
   which is how "adding a new key" used to lose the old ones. */
async function saveApiKeys(btn){
  const payload = API_KEY_ROWS
    .filter(row => !row.id || DELETED_KEY_IDS.indexOf(row.id) === -1)
    .map(row => ({
      id: row.id || '',
      name: row.name || '',
      models: row.models || [],
        concurrency_limit: parseInt(row.concurrency_limit || 0, 10) || 0,
      enabled: row.enabled !== false,
      // Blank means "keep the stored key", which the server honours per row.
      key: (row.key || '').trim(),
    }));
  if(API_KEY_ROWS.some(row => !row.masked && !row.id && !(row.key || '').trim())){
    toast('新增的行还没有填写 Key', 'warn');
    return false;
  }
  // Several callers save without going through a button (saveSingleKey,
  // toggleKeyRow, removeKeyRow), so a missing button must not abort the save.
  if(btn) btn.disabled = true;
  try {
    await postJSON('/settings/save', {
      api_keys: payload,
      deleted_api_key_ids: DELETED_KEY_IDS.slice(),
    });
    DELETED_KEY_IDS = [];
    toast('已保存 ' + payload.length + ' 个 Key', 'ok');
    // Reload before returning: the next edit must start from the ids the
    // server just minted, or a quick second save would resubmit the rows with
    // empty ids and duplicate them.
    await loadSettings();
    return true;
  } catch(e) {
    toast('保存失败: ' + e.message, 'bad');
    return false;
  } finally {
    if(btn) btn.disabled = false;
  }
}

function switchMainTab(tab){
  // 任务与福利页已随旧账号子系统一起删掉；老书签 ?tab=tasks
  // 不能停在空白页，直接退回网关。
  if(tab === 'tasks' && !document.getElementById('pageTasks')) tab = 'gateway';
  // 被「顶部页签显示」收起来的页面同理：书签与上次停留的页签都不能把内容调出来，
  // 否则页面容器带着 hidden 被点亮，屏幕上一片空白。
  if(pageHidden(tab)) tab = firstVisiblePage();
  // 账号页被合并掉之后（设置里的「账号独立成一个页签」关闭，默认），
  // ?tab=accounts 的书签与上次停留的页签都退回「网关与账号」页——区块就在那一页里。
  if(tab === 'accounts' && !_accountsSeparateTab) tab = 'gateway';
  currentMainTab = tab;
  // Remember the page across reloads. The URL is updated so the address bar
  // matches what is on screen and a copied link reopens the same page;
  // storage covers a plain reload and the ?key= link, which strips the
  // query string on load.
  try {
    const url = new URL(window.location.href);
    url.searchParams.set('tab', tab);
    history.replaceState(null, '', url.toString());
  } catch(e){}
  try { localStorage.setItem(MAIN_TAB_STORE, tab); } catch(e){}
  const btnGateway = document.getElementById('btnNavGateway');
  const btnTasks = document.getElementById('btnNavTasks');
  const btnAccounts = document.getElementById('btnNavAccounts');
  const btnAnalytics = document.getElementById('btnNavAnalytics');
  const btnLogs = document.getElementById('btnNavLogs');
  const btnSettings = document.getElementById('btnNavSettings');
  const pageGateway = document.getElementById('pageGateway');
  const pageTasks = document.getElementById('pageTasks');
  const pageAccounts = document.getElementById('pageAccounts');
  const pageAnalytics = document.getElementById('pageAnalytics');
  const pageLogs = document.getElementById('pageLogs');
  const pageSettings = document.getElementById('pageSettings');
  const tabs = [
    ['gateway', btnGateway, pageGateway],
    ['accounts', btnAccounts, pageAccounts],
    ['tasks', btnTasks, pageTasks],
    ['analytics', btnAnalytics, pageAnalytics],
    ['logs', btnLogs, pageLogs],
    ['settings', btnSettings, pageSettings]
  ];
  tabs.forEach(([name, btn, page]) => {
    if(!btn || !page) return;
    const on = (name === tab);
    btn.classList.toggle('active', on);
    page.classList.toggle('active', on);
    // 每个页面各自按自己的区块重建侧栏；非当前页的区块变化在切过来时补上
    if(on) initPageNav(page);
  });
  if(tab === 'accounts' || (!_accountsSeparateTab && tab === 'gateway')){
    loadActivityBoard();
    loadCodeartsAccounts();
  }
  if(tab === 'analytics'){ loadAnalytics(); loadAnalyticsMatrix(); }
  if(tab === 'settings'){ loadSettings(); }
  if(tab === 'logs'){
    startLogPolling();
    fetchNewLogs(true);
  } else {
    stopLogPolling();
  }
  restorePageNavHash();
}

/* ---- 系统运行日志模块 ---- */
let logEntries = [];
let lastLogId = 0;
let logFilterLevel = '';
let logFilterTag = '';
let logSearchText = '';
let logAutoRefresh = true;
let logAutoScroll = true;
let logPollTimer = null;
let logFetching = false;
let logUserScrolledUp = false;
// 增量渲染的簿记：DOM 里此刻画着的是"哪个过滤条件下的多少行"。轮询带回新行时
// 只 append 新增的几行；过滤/搜索变化或状态对不上时才整表重画。
let logDomKey = null;     // 上次渲染时的过滤条件指纹（logFilterKey()）
let logDomCount = 0;      // DOM 中当前的 .log-line 行数
const LOG_DOM_MAX = 2000; // 与 logEntries 的缓冲上限一致，超出就从头部裁

// 过滤谓词抽出来共用：整表渲染与增量 append 必须用同一套判据，否则会出现
// "新行画上去了、但按当前过滤条件它本不该显示"这类两套逻辑漂移出来的脏数据。
function logMatchesFilter(item){
  if(logFilterLevel && item.level !== logFilterLevel) return false;
  if(logFilterTag && item.tag !== logFilterTag) return false;
  if(logSearchText){
    const haystack = ((item.msg || '') + ' ' + (item.tag || '') + ' ' + (item.time || '')).toLowerCase();
    if(!haystack.includes(logSearchText)) return false;
  }
  return true;
}
function logFilterKey(){ return logFilterLevel + '|' + logFilterTag + '|' + logSearchText; }
/* 顶部文案跟着模式走：落库时报告库里累计多少条历史、并指向设置页的上限；纯内存
   时保持上游原话。data.mode 由 /logs 带回（后端按当前开关判定）。 */
function updateLogPageHint(data){
  const hint = document.getElementById('logPageHint');
  if(!hint) return;
  if(data && data.mode === 'db'){
    const stored = (typeof data.stored === 'number') ? data.stored : null;
    hint.textContent = '实时捕获反向代理请求、流式转发、调度巡检、任务打卡与异常告警'
      + ' (已落库' + (stored === null ? '' : '，共 ' + stored + ' 条历史')
      + '，可在设置页调整保留上限)';
  } else {
    hint.textContent = '实时捕获反向代理请求、流式转发、调度巡检、任务打卡与异常告警 (内存保留最新 2000 条)';
  }
}
// 单行 HTML 只有这一处定义，整表渲染和增量 append 都用它。
function logLineHtml(item){
  const lvlCls = 'lvl-' + (item.level || 'INFO');
  const tagCls = 'tag-' + (item.tag || 'system');
  return '<div class="log-line">' +
    '<span class="log-ts">' + escapeHtml(item.time || '') + '</span>' +
    '<span class="log-lvl ' + lvlCls + '">' + escapeHtml(item.level || 'INFO') + '</span>' +
    '<span class="log-tag ' + tagCls + '">[' + escapeHtml(item.tag || 'system') + ']</span>' +
    '<span class="log-msg">' + escapeHtml(item.msg || '') + '</span>' +
  '</div>';
}

function startLogPolling(){
  if(logPollTimer) clearInterval(logPollTimer);
  logPollTimer = setInterval(() => {
    if(logAutoRefresh && currentMainTab === 'logs' && !document.hidden){
      fetchNewLogs(false);
    }
  }, 2000);
}

function stopLogPolling(){
  if(logPollTimer){
    clearInterval(logPollTimer);
    logPollTimer = null;
  }
}

async function fetchNewLogs(forceReset){
  if(logFetching) return;
  logFetching = true;
  const statusEl = document.getElementById('logTerminalStatus');
  if(statusEl && forceReset) statusEl.textContent = '正在拉取...';
  try {
    const since = forceReset ? 0 : lastLogId;
    const limit = forceReset ? 500 : 200;
    const data = await getJSON('/logs?since_id=' + since + '&limit=' + limit);
    if(data && data.logs){
      updateLogPageHint(data);
      let fresh = null;     // 本轮真正新增的条目（去重后）
      let dropped = null;   // 因超上限被挤出缓冲的最旧条目
      if(forceReset){
        logEntries = data.logs;
      } else if(data.logs.length > 0){
        const existingIds = new Set(logEntries.map(x => x.id));
        fresh = data.logs.filter(item => !existingIds.has(item.id));
        fresh.forEach(item => logEntries.push(item));
        if(logEntries.length > 2000){
          dropped = logEntries.slice(0, logEntries.length - 2000);
          logEntries = logEntries.slice(-2000);
        }
      }
      if(data.max_id){
        lastLogId = Math.max(lastLogId, data.max_id);
      } else if(logEntries.length > 0){
        lastLogId = logEntries[logEntries.length - 1].id;
      }
      // 渲染策略：只有真的带着新行回来才碰 DOM。
      //  - 首次进入 / 手动刷新（forceReset）、过滤条件与上次渲染不一致、或 DOM
      //    里现在是空态：整表重画，顺带把簿记校正回来；
      //  - 有新增行且条件一致：只把新增的几行 append 上去，被挤出的旧行从头部
      //    等量删掉；
      //  - 没有任何新行：直接跳过——旧实现里 `data.logs` 为空数组也真，于是每
      //    2 秒把整个终端重写一遍，2000 行时每次约 700KB 的 HTML 解析 + 布局
      //    （实测 layout 254~324ms）全白烧，忙碌时"每 2 秒卡 0.3 秒"就是它。
      if(forceReset || logDomKey !== logFilterKey() || logDomCount === 0){
        renderLogs();
      } else {
        if(dropped && dropped.length) dropLogDomHead(dropped);
        if(fresh && fresh.length) appendLogLines(fresh);
      }
      // 统计徽章的数字只由 logEntries 决定，缓冲没变就不用重写（少一次 DOM 写）。
      if(forceReset || (fresh && fresh.length)) updateLogStats();
    }
    if(statusEl) statusEl.textContent = '就绪 · ' + new Date().toLocaleTimeString();
  } catch(e) {
    if(statusEl) statusEl.textContent = '连接中断: ' + e.message;
  } finally {
    logFetching = false;
  }
}

function updateLogStats(){
  const badge = document.getElementById('logStatsBadge');
  if(!badge) return;
  let errors = 0, warns = 0;
  logEntries.forEach(x => {
    if(x.level === 'ERROR') errors++;
    else if(x.level === 'WARN') warns++;
  });
  let txt = '共 ' + logEntries.length + ' 条';
  if(errors > 0) txt += ' · <span style="color:var(--bad)">' + errors + ' 错误</span>';
  if(warns > 0) txt += ' · <span style="color:var(--warn)">' + warns + ' 警告</span>';
  badge.innerHTML = txt;
}

function setLogFilterLevel(lvl){
  logFilterLevel = lvl;
  ['All', 'Info', 'Warn', 'Error'].forEach(name => {
    const btn = document.getElementById('btnLogLvl' + name);
    if(btn){
      const match = (lvl === '' && name === 'All') || (lvl.toUpperCase() === name.toUpperCase());
      btn.classList.toggle('active', match);
    }
  });
  renderLogs();
}

/* 模块筛选按钮的固定顺序与中文名。顺序按「排查时最常先看哪个模块」排，未列出
   的 tag 排到最后并按字母序补上——后端新增 tag 时这里不改也能用。 */
const LOG_TAG_ORDER = ['chat', 'tasks', 'scheduler', 'accounts',
                       'egress', 'upstream', 'webtools', 'catalog', 'auth', 'settings',
                       'update', 'usage', 'system'];
const LOG_TAG_LABELS = {
  chat: '对话', tasks: '任务福利', scheduler: '调度器', accounts: '账号',
  egress: '出口', upstream: '上游',
  webtools: '网络工具', catalog: '模型', auth: '鉴权', settings: '设置',
  update: '更新', usage: '用量', system: '系统'
};
let logTagBtnKey = null;
/* 按当前缓冲里真正出现过的 tag 重建按钮组。集合没变就不动 DOM——这个函数每
   次渲染都会调，重建本身会让正在点的按钮闪一下。 */
function renderLogTagFilters(){
  const bar = document.getElementById('logTagBar');
  if(!bar) return;
  const seen = new Set();
  logEntries.forEach(x => { if(x.tag) seen.add(x.tag); });
  // 当前筛选的 tag 即使暂时没有日志也留在栏里，否则按钮一消失就不知道自己在
  // 筛什么，也没法一眼切回去。
  if(logFilterTag) seen.add(logFilterTag);
  const ordered = LOG_TAG_ORDER.filter(t => seen.has(t))
    .concat(Array.from(seen).filter(t => LOG_TAG_ORDER.indexOf(t) < 0).sort());
  const key = ordered.join(',');
  if(key !== logTagBtnKey){
    logTagBtnKey = key;
    bar.innerHTML = '';
    [{tag: '', label: '全部模块'}]
      .concat(ordered.map(t => ({tag: t, label: LOG_TAG_LABELS[t] || t})))
      .forEach(item => {
        const btn = document.createElement('button');
        btn.className = 'range-btn';
        btn.dataset.tag = item.tag;
        btn.textContent = item.label;
        btn.onclick = () => setLogFilterTag(item.tag);
        bar.appendChild(btn);
      });
  }
  bar.querySelectorAll('button').forEach(b => {
    b.classList.toggle('active', (b.dataset.tag || '') === logFilterTag);
  });
}

function setLogFilterTag(tag){
  logFilterTag = tag;
  renderLogTagFilters();
  renderLogs();
}

let logSearchDebounce = null;
function onLogSearchInput(){
  clearTimeout(logSearchDebounce);
  logSearchDebounce = setTimeout(() => {
    const input = document.getElementById('logSearchInput');
    logSearchText = input ? input.value.trim().toLowerCase() : '';
    renderLogs();
  }, 200);
}

function toggleLogAuto(){
  logAutoRefresh = !logAutoRefresh;
  const btn = document.getElementById('btnToggleLogAuto');
  if(btn){
    if(logAutoRefresh){
      btn.textContent = '实时监听中';
      btn.style.color = 'var(--accent2)';
      startLogPolling();
    } else {
      btn.textContent = '已暂停监听';
      btn.style.color = 'var(--dim)';
      stopLogPolling();
    }
  }
}

function toggleLogScroll(){
  logAutoScroll = !logAutoScroll;
  const btn = document.getElementById('btnToggleLogScroll');
  if(btn){
    btn.textContent = logAutoScroll ? '自动滚屏: 开' : '自动滚屏: 关';
  }
  if(logAutoScroll){
    const body = document.getElementById('logTerminalBody');
    if(body) body.scrollTop = body.scrollHeight;
  }
}

function handleLogTerminalScroll(){
  const body = document.getElementById('logTerminalBody');
  if(!body) return;
  const atBottom = (body.scrollHeight - body.scrollTop - body.clientHeight) < 40;
  if(!atBottom && logAutoScroll){
    logUserScrolledUp = true;
  } else if(atBottom && logUserScrolledUp){
    logUserScrolledUp = false;
  }
}

function escapeHtml(s){
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function renderLogs(){
  const body = document.getElementById('logTerminalBody');
  if(!body) return;

  renderLogTagFilters();
  const filtered = logEntries.filter(logMatchesFilter);

  if(filtered.length === 0){
    body.innerHTML = '<div class="log-empty">暂无匹配的日志记录</div>';
    logDomKey = logFilterKey();
    logDomCount = 0;
    return;
  }

  body.innerHTML = filtered.map(logLineHtml).join('');
  logDomKey = logFilterKey();
  logDomCount = filtered.length;

  if(logAutoScroll && !logUserScrolledUp){
    body.scrollTop = body.scrollHeight;
  }
}

// 只把新到的行追加到终端末尾（insertAdjacentHTML 只解析这一段，不碰已有行）。
// 旧实现每次轮询都把全部行重拼一遍再整体 innerHTML，2000 行时约 700KB/次；
// 忙碌时新行通常只有几行，append 的代价与新增量成正比。
function appendLogLines(items){
  const body = document.getElementById('logTerminalBody');
  if(!body) return;
  const visible = items.filter(logMatchesFilter);
  if(!visible.length) return;   // 新行全被过滤掉：DOM 一个字节都不动
  body.insertAdjacentHTML('beforeend', visible.map(logLineHtml).join(''));
  logDomCount += visible.length;
  // 兜底上限：正常情况下头部裁剪由 dropLogDomHead 按"被挤出的条目"精确完成，
  // 这里只防簿记与 DOM 万一脱节（比如有人在控制台里手动改过 DOM）。
  while(logDomCount > LOG_DOM_MAX){
    const first = body.firstElementChild;
    if(!first){ logDomCount = 0; break; }
    body.removeChild(first);
    logDomCount--;
  }
  if(logAutoScroll && !logUserScrolledUp){
    body.scrollTop = body.scrollHeight;
  }
}

// 缓冲超上限时，最旧的条目被挤出 logEntries；DOM 头部也要把"其中当前过滤条件
// 下曾经画出来的那些行"删掉，否则开着过滤时终端会攒下已经不在缓冲里的旧行，
// 和切一次过滤后的整表重画结果对不上。按条数从头部删即可：DOM 顺序与条目顺序
// 一致，被挤出的条目必然是最老的，也就是 DOM 头部的那几行。
function dropLogDomHead(droppedEntries){
  const body = document.getElementById('logTerminalBody');
  if(!body) return;
  let cut = 0;
  for(let i = 0; i < droppedEntries.length; i++){
    if(logMatchesFilter(droppedEntries[i])) cut++;
  }
  while(cut > 0){
    const first = body.firstElementChild;
    if(!first){ logDomCount = 0; return; }
    body.removeChild(first);
    logDomCount--;
    cut--;
  }
}

function copyFilteredLogs(){
  const filtered = logEntries.filter(item => {
    if(logFilterLevel && item.level !== logFilterLevel) return false;
    if(logFilterTag && item.tag !== logFilterTag) return false;
    if(logSearchText){
      const haystack = ((item.msg || '') + ' ' + (item.tag || '') + ' ' + (item.time || '')).toLowerCase();
      if(!haystack.includes(logSearchText)) return false;
    }
    return true;
  });
  const text = filtered.map(x => '[' + (x.ts || x.time) + '] [' + x.level + '] [' + x.tag + '] ' + x.msg).join('\n');
  navigator.clipboard.writeText(text).then(() => {
    toast('已复制 ' + filtered.length + ' 行日志', 'ok');
  }).catch(e => {
    toast('复制失败: ' + e.message, 'bad');
  });
}

async function exportLogsFile(){
  try {
    const data = await getJSON('/logs?limit=5000');
    if(!data || !data.logs || !data.logs.length){
      toast('暂无日志可导出', 'warn');
      return;
    }
    const lines = data.logs.map(x => '[' + (x.ts || x.time) + '] [' + x.level + '] [' + x.tag + '] ' + x.msg);
    const text = lines.join('\n');
    const blob = new Blob([text], {type: 'text/plain;charset=utf-8'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    a.download = 'codearts-hub-' + ts + '.log';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toast('已导出 ' + data.logs.length + ' 行日志', 'ok');
  } catch(e) {
    toast('导出日志失败: ' + e.message, 'bad');
  }
}

async function clearServerLogs(){
  if(!confirm('确定要清空网关日志吗？内存缓冲会被清空；若已启用日志落库，数据库里的历史记录也会一并删除。')) return;
  try {
    await postJSON('/logs/clear', {});
    logEntries = [];
    lastLogId = 0;
    renderLogs();
    updateLogStats();
    toast('网关日志已清空', 'ok');
  } catch(e) {
    toast('清空失败: ' + e.message, 'bad');
  }
}

/* 时间范围：每个窗口都是服务端的一段切片，切换即重新取数。
 *
 * 只有「今日 / 全部历史」时，一次 /usage/analytics 同时带回两个桶，切换按钮
 * 重渲染缓存就够了；窗口变多之后一个 payload 装不下所有窗口，继续重渲染缓存
 * 只会把上一个窗口的数字挂到新标签下面，所以一律重取。 */


/* 自定义区间的输入框初始为空，而空 = 不限，画面会和「全部历史」一模一样，看起来
 * 像按钮坏了。第一次点开时把起点填成今天零点：一个能看懂的默认窗口，操作者再自己
 * 放宽或收窄；终点留空表示「到现在」。 */




/* datetime-local 与 epoch 互转：输入框里是操作者按日历读到的本地墙上时间，所以
 * 转换用浏览器自己的时区；服务端拿 epoch 与它自己的时钟比较。 */


function fromLocalInputValue(value){
  if(!value) return null;
  const t = new Date(value).getTime();
  return isNaN(t) ? null : Math.floor(t / 1000);
}



/* 三个取数端点共用同一个查询串，避免 /usage 与 /usage/perf 各拼一份而漏掉自定义
 * 区间——那正是「卡片与表格口径不一致」的复发路径。 */
function analyticsQuery(){
  let q = '?realm=all&range=' + encodeURIComponent(analyticsRange || 'today');
  if(analyticsRange === 'custom'){
    const sEl = document.getElementById('rangeCustomSince');
    const uEl = document.getElementById('rangeCustomUntil');
    const s = fromLocalInputValue(sEl ? sEl.value : '');
    const u = fromLocalInputValue(uEl ? uEl.value : '');
    if(s !== null) q += '&since=' + s;
    if(u !== null) q += '&until=' + u;
  }
  return q;
}

/* 模型性能指标与用量一览
 *
 * Reads the combined view on purpose. The table carries its own 区域
 * column, so scoping it to the gateway's current exit would hide exactly the
 * models this page exists to compare. */
// /v1/models?realm=all 的目录在这里只作展示白名单（哪些模型算"已知模型"），
// 内容变化极慢，却跟着 5 秒轮询每轮重取一份（实测统计页开着约 12~15 次/分钟、
// 约 24KB/次）。改成一个 TTL：进统计页时取一次，之后最多每 10 分钟回源一次；
// 取失败不刷新时间戳，下一轮继续重试（和原来"失败也不清空白名单"一致）。
let matrixModelsAt = 0;
const MATRIX_MODELS_TTL_MS = 10 * 60 * 1000;
async function loadAnalyticsMatrix(){
  try{
      const q = analyticsQuery();
    const needModels = !MATRIX_MODELS.size || (Date.now() - matrixModelsAt) >= MATRIX_MODELS_TTL_MS;
    const [usage, perf, models] = await Promise.all([
      getJSON('/usage' + q, POLL_READ),
      getJSON('/usage/perf' + q, POLL_READ),
      // The catalog is only a display filter, so a failure here must not
      // blank the table; null keeps the previous allowlist.
      needModels ? getJSON('/v1/models?realm=all').catch(() => null) : Promise.resolve(null),
    ]);
    if(models && models.data){
      MATRIX_MODELS = new Set(models.data.map(m => m.id));
      matrixModelsAt = Date.now();
    }
    cachedMatrixData = { usage: usage, perf: perf };
    fillMatrixFilters(usage);
    renderPerfMatrix(usage, perf);
  }catch(err){
    if(!isAuthError(err)) console.error('loadAnalyticsMatrix failed:', err);
  }
}

/* Rebuild the two matrix filter dropdowns from the payload just fetched.
 *
 * Options are derived from the data rather than from the account pool, so the
 * list only offers accounts and models that actually have rows - a filter that
 * can only ever yield an empty table is worse than no filter. A previously
 * chosen value is kept when it is still present, and cleared when it is not,
 * which is what happens when the range flips and an account drops out.
 */
function fillMatrixFilters(usage){
  const acctSel = document.getElementById('matrixAcctFilter');
  const modelSel = document.getElementById('matrixModelFilter');
  const names = (usage && usage.accounts_map) || {};
  const modelCount = {};
  Object.keys((usage && usage.by_model) || {}).forEach(id => {
    if(!id.endsWith('-model')) modelCount[id] = (usage.by_model[id] || {}).requests || 0;
  });
  if(acctSel){
    const seen = new Set();
    Object.values((usage && usage.by_model_acct) || {}).forEach(byRealm => {
      Object.values(byRealm || {}).forEach(byAcct => {
        Object.keys(byAcct || {}).forEach(uid => {
          if(uid && uid !== '(unattributed)') seen.add(uid);
        });
      });
    });
    const opts = Array.from(seen).sort((a, b) => {
      const na = (names[a] || {}).nickname || a;
      const nb = (names[b] || {}).nickname || b;
      return na.localeCompare(nb);
    });
    if(matrixAcctFilter && !seen.has(matrixAcctFilter)) matrixAcctFilter = '';
    acctSel.innerHTML = '<option value="">全部账号</option>' + opts.map(uid => {
      const info = names[uid] || {};
      const label = (info.nickname || uid.slice(0, 8)) + ' (' + uid.slice(0, 6) + ')';
      return '<option value="' + esc(uid) + '"' + (uid === matrixAcctFilter ? ' selected' : '') + '>' + esc(label) + '</option>';
    }).join('');
  }
  if(modelSel){
    const ids = Object.keys(modelCount).filter(id => modelCount[id] > 0).sort();
    if(matrixModelFilter && ids.indexOf(matrixModelFilter) === -1) matrixModelFilter = '';
    modelSel.innerHTML = '<option value="">全部模型</option>' + ids.map(id =>
      '<option value="' + esc(id) + '"' + (id === matrixModelFilter ? ' selected' : '') + '>' + esc(id) + '</option>'
    ).join('');
  }
}

function renderPerfMatrix(usage, perf){
  const matrixEl = document.getElementById("perfMatrix");
  if(!matrixEl) return;
  const bmPerf = (perf && perf.by_model) || {};
  const validModels = MATRIX_MODELS;
  const modelMap = {};
  Object.entries(usage.by_model || {}).forEach(([id, m]) => {
    if((!validModels.size || validModels.has(id)) && m.requests > 0 && !id.endsWith('-model')){
      modelMap[id] = Object.assign({id: id}, m);
    }
  });
  Object.entries(bmPerf).forEach(([id, p]) => {
    if((!validModels.size || validModels.has(id)) && p.requests > 0 && !id.endsWith('-model') && !modelMap[id]){
      modelMap[id] = {
        id: id,
        requests: p.requests || 0,
        prompt_tokens: 0,
        completion_tokens: 0,
        reasoning_tokens: 0,
        cached_tokens: 0,
        total_tokens: 0
      };
    }
  });
  // One row per (model, exit). A model served by both exits gets two rows,
  // each carrying its own tokens, latency and speed; the region column then
  // describes exactly the numbers next to it instead of collapsing both.
  const realmMap = (usage && usage.by_model_realm) || {};
  const acctMap = (usage && usage.by_model_acct) || {};
  const perfAcctMap = (perf && perf.by_model_acct) || {};
  const rowsData = [];
  Object.values(modelMap)
    .sort((a,b) => (b.total_tokens || b.requests) - (a.total_tokens || a.requests))
    .forEach(m => {
      if(matrixModelFilter && m.id !== matrixModelFilter) return;
      const per = realmMap[m.id];
      const realms = per ? Object.keys(per).filter(r => (per[r].requests || 0) > 0) : [];
      if(realms.length > 1){
        // Most-used exit first, so the ordering stays meaningful.
        realms.sort((x, y) => (per[y].total_tokens || 0) - (per[x].total_tokens || 0));
      }
      // Within an exit, one row per account: two accounts sharing an exit are
      // two different consumers, and merging them hid which one spent what.
      const parts = [];
      (realms.length ? realms : ['']).forEach(r => {
        const accts = ((acctMap[m.id] || {})[r]) || {};
        const perfAccts = ((perfAcctMap[m.id] || {})[r]) || {};
        // Union of both maps: a bucket holding only failures exists in perf
        // alone, and dropping it would hide failures the total counts.
        const keys = Array.from(new Set(
          Object.keys(accts).concat(Object.keys(perfAccts))
        )).filter(a => {
          const u = accts[a] || {};
          const p = perfAccts[a] || {};
          return (u.requests || 0) > 0 || (u.errors || 0) > 0 ||
                 (p.requests || 0) > 0 || (p.errors || 0) > 0 ||
                 (p.client_aborted || 0) > 0;
        });
        // The account filter narrows the rows themselves, not just their
        // visibility, so the summary below always matches what is shown.
        const shown = matrixAcctFilter ? keys.filter(a => a === matrixAcctFilter) : keys;
        if(shown.length){
          shown.sort((x, y) =>
            ((accts[y] || {}).total_tokens || 0) - ((accts[x] || {}).total_tokens || 0));
          shown.forEach(a => {
            // Tokens come from usage; a failure-only bucket has none.
            const u = accts[a] || {requests: 0, prompt_tokens: 0, completion_tokens: 0,
                                   reasoning_tokens: 0, cached_tokens: 0, total_tokens: 0};
            parts.push({ stat: u, realm: r, acct: a,
                         accts: { [a]: u.requests || 0 } });
          });
        } else if(!matrixAcctFilter){
          // No per-account data for this exit (an older log, say): fall back
          // to the exit totals rather than dropping the row.
          const fallback = per ? per[r] : m;
          parts.push({ stat: fallback, realm: r, acct: '',
                       accts: fallback.accounts || {} });
        }
      });
      parts.forEach((p, i) => {
        rowsData.push(Object.assign({}, p.stat, {
          id: m.id, realm: p.realm, acct: p.acct, accts: p.accts,
          split: parts.length > 1, first: i === 0,
        }));
      });
    });

  const countEm = document.getElementById("matrixModelCount");
  if(countEm){
    const nModels = new Set(rowsData.map(r => r.id)).size;
    const anyFilter = !!(matrixAcctFilter || matrixModelFilter);
    countEm.textContent = nModels ? ("(有调用的模型: " + nModels +
      " 个·共 " + rowsData.length + " 行明细" + (anyFilter ? " · 已筛选" : "") + ")") : "";
  }

  if(!rowsData.length){
    matrixEl.innerHTML = '<div class="empty">当前版本暂无模型请求或性能数据</div>';
  } else {
    /* Summary row (Total / All Models).
     *
     * With no filter this is the endpoint-wide figure, as before. With a
     * filter active it is recomputed from the visible rows instead, because a
     * total that ignores the filter contradicts the rows directly beneath it -
     * the exact confusion the filter is meant to remove. Latency, speed and
     * wall time are averages over the filtered rows' own sample counts, so a
     * barely-used row cannot outvote a heavily-used one.
     */
    const filtering = !!(matrixAcctFilter || matrixModelFilter);
    let sumReq, sumErr, sumTok, sumP, sumC, sumR, totTtft, totTps, totWall, totCache;
    if(!filtering){
      sumReq = usage.requests; sumErr = perf.errors; sumTok = usage.total_tokens;
      sumP = usage.prompt_tokens; sumC = usage.completion_tokens; sumR = usage.reasoning_tokens;
      totTtft = perf.ttft_ms ? (ms(perf.ttft_ms.avg) + " (P50 " + ms(perf.ttft_ms.p50) + ")") : "-";
      totTps = perf.tokens_per_sec ? (perf.tokens_per_sec.avg.toFixed(1) + " tok/s") : "-";
      totWall = perf.wall_ms ? ms(perf.wall_ms.avg) : "-";
      totCache = perf.cache_hit_pct ? (perf.cache_hit_pct.avg.toFixed(1) + "%") : "-";
    } else {
      sumReq = 0; sumErr = 0; sumTok = 0; sumP = 0; sumC = 0; sumR = 0;
      let ttftW = 0, ttftN = 0, tpsW = 0, tpsN = 0, wallW = 0, wallN = 0, cacheW = 0, cacheN = 0;
      rowsData.forEach(m => {
        sumReq += m.requests || 0;
        sumTok += m.total_tokens || 0;
        sumP += m.prompt_tokens || 0;
        sumC += m.completion_tokens || 0;
        sumR += m.reasoning_tokens || 0;
        const mp = ((perf && perf.by_model_realm) || {})[m.id] || {};
        const mpAcctAll = ((perf && perf.by_model_acct) || {})[m.id] || {};
        const mpRealm = m.realm ? (mp[m.realm] || null) : null;
        const mpAcct = (m.realm && m.acct && mpAcctAll[m.realm])
          ? (mpAcctAll[m.realm][m.acct] || null) : null;
        const e = mpAcct || mpRealm || bmPerf[m.id] || {};
        sumErr += e.errors || 0;
        if(e.ttft_ms && e.ttft_ms.samples){ ttftW += e.ttft_ms.avg * e.ttft_ms.samples; ttftN += e.ttft_ms.samples; }
        if(e.tokens_per_sec && e.tokens_per_sec.samples){ tpsW += e.tokens_per_sec.avg * e.tokens_per_sec.samples; tpsN += e.tokens_per_sec.samples; }
        if(e.wall_ms && e.wall_ms.samples){ wallW += e.wall_ms.avg * e.wall_ms.samples; wallN += e.wall_ms.samples; }
        if(e.cache_hit_pct && e.cache_hit_pct.samples){ cacheW += e.cache_hit_pct.avg * e.cache_hit_pct.samples; cacheN += e.cache_hit_pct.samples; }
      });
      totTtft = ttftN ? ms(ttftW / ttftN) : "-";
      totTps = tpsN ? (((tpsW / tpsN)).toFixed(1) + " tok/s") : "-";
      totWall = wallN ? ms(wallW / wallN) : "-";
      totCache = cacheN ? ((cacheW / cacheN).toFixed(1) + "%") : "-";
    }
    const summaryRow = '<tr style="background:color-mix(in srgb,var(--accent) 7%,transparent);font-weight:600">'
      + '<td style="text-align:left" data-label="模型"><b>' + (filtering ? '筛选结果合计 (Filtered)' : '全部模型合计 (Total)') + '</b></td>'
      + '<td style="text-align:left" data-label="账号"><span style="color:var(--dim)">' + (filtering ? '已筛选' : '全部账号') + '</span></td>'
      + '<td data-label="请求数">' + fmt(sumReq) + '</td>'
      + '<td data-label="失败">' + (sumErr
          ? ('<span style="color:var(--bad)">' + fmt(sumErr) + '</span>')
          : '<span style="color:var(--dim)">0</span>') + '</td>'
      + '<td data-label="总 Token"><b style="color:var(--accent)">' + fmt(sumTok) + '</b></td>'
      + '<td class="triple" data-label="输入 / 输出 / 思考">' + tripleTokens(sumP, sumC, sumR) + '</td>'
      + '<td data-label="思考占比">' + (sumC > 0 ? pctThink(sumR, sumC) : '<span style="color:var(--dim)">—</span>') + '</td>'
      + '<td data-label="首字延迟">' + totTtft + '</td>'
      + '<td data-label="生成速度"><b style="color:var(--accent2)">' + totTps + '</b></td>'
      + '<td data-label="端到端耗时">' + totWall + '</td>'
      + '<td data-label="缓存命中">' + totCache + '</td>'
      + '<td data-label="用量占比">100%</td>'
      + '</tr>';

    const rows = rowsData.map(m => {
      // Latency/speed come from the matching (model, exit) bucket when the
      // backend supplied one; otherwise fall back to the model-wide figure.
      const mp = ((perf && perf.by_model_realm) || {})[m.id] || {};
      const mpAcctAll = ((perf && perf.by_model_acct) || {})[m.id] || {};
      const mpRealm = m.realm ? (mp[m.realm] || null) : null;
      // Most specific first: this account on this exit, then the exit, then
      // the model. A split row must not borrow another account's latency.
      const mpAcct = (m.realm && m.acct && mpAcctAll[m.realm])
        ? (mpAcctAll[m.realm][m.acct] || null) : null;
      const mpEff = mpAcct || mpRealm || bmPerf[m.id] || {};
      const m_ttft = mpEff.ttft_ms ? (ms(mpEff.ttft_ms.avg) + " <span style='color:var(--dim);font-size:11px'>(P50 " + ms(mpEff.ttft_ms.p50) + ")</span>") : "-";
      const m_tps = mpEff.tokens_per_sec ? ('<b style="color:var(--accent2)">' + mpEff.tokens_per_sec.avg.toFixed(1) + '</b> <span style="font-size:11px;color:var(--dim)">tok/s</span>') : "-";
      const m_wall = mpEff.wall_ms ? ms(mpEff.wall_ms.avg) : "-";
      const m_cache = (m.prompt_tokens > 0) ? pct(m.cached_tokens / m.prompt_tokens * 100) : (mpEff.cache_hit_pct ? mpEff.cache_hit_pct.avg.toFixed(1) + "%" : "-");
      /* Share of the table's own total - the figure in the summary row -
       * rather than of the largest row. Dividing by the maximum made the
       * biggest model read 100% and every other row a fraction of it, which
       * is a relative ranking, not the share the column name promises.
       * One decimal, like every other percentage on the page: a whole-percent
       * reading collapses a model that spent millions of tokens to "0%". */
      const pctTok = sumTok > 0 ? Math.round(m.total_tokens / sumTok * 1000) / 10 : 0;
      // 0 is a real result (the model ran and never failed), so it stays
      // visible as a muted zero rather than the dash used for no data.
      const errCell = mpEff.errors
        ? ('<span style="color:var(--bad)">' + fmt(mpEff.errors) + '</span>')
        : '<span style="color:var(--dim)">0</span>';
      const acctsMap = usage.accounts_map || {};
      // This row's own accounts, not every account that touched the model.
      const mAccts = m.accts || m.accounts || {};
      const acctEntries = Object.entries(mAccts);
      let acctCell = '<span style="color:var(--dim)">—</span>';
      if(acctEntries.length === 1 && acctEntries[0][0] === '(unattributed)'){
        acctCell = '<span style="color:var(--dim)">—</span>';
      } else if(acctEntries.length === 1){
        const [uid, count] = acctEntries[0];
        const info = acctsMap[uid] || {};
        const name = esc(info.nickname || uid.slice(0, 8));
        acctCell = '<b>' + name + '</b>';
      } else if(acctEntries.length > 1){
        acctCell = acctEntries.map(([uid, count]) => {
          const info = acctsMap[uid] || {};
          const name = esc(info.nickname || uid.slice(0, 6));
          return '<span class="badge mini" style="margin:1px 2px">' + name + ' <span style="color:var(--dim)">(' + count + ')</span></span>';
        }).join('');
      }
      return '<tr>'
        + '<td style="text-align:left" class="mono" data-label="模型"><b>' + esc(m.id) + '</b></td>'
        + '<td style="text-align:left" data-label="账号">' + acctCell + '</td>'
        + '<td data-label="请求数">' + fmt(m.requests) + '</td>'
        + '<td data-label="失败">' + errCell + '</td>'
        + '<td data-label="总 Token"><b>' + fmt(m.total_tokens) + '</b></td>'
        + '<td class="triple" data-label="输入 / 输出 / 思考">' + tripleTokens(m.prompt_tokens, m.completion_tokens, m.reasoning_tokens) + '</td>'
        + '<td data-label="思考占比">' + ((m.completion_tokens || 0) > 0 ? pctThink(m.reasoning_tokens || 0, m.completion_tokens) : '<span style="color:var(--dim)">—</span>') + '</td>'
        + '<td data-label="首字延迟">' + m_ttft + '</td>'
        + '<td data-label="生成速度">' + m_tps + '</td>'
        + '<td data-label="端到端耗时">' + m_wall + '</td>'
        + '<td data-label="缓存命中">' + m_cache + '</td>'
        + '<td style="min-width:90px" data-label="用量占比"><span class="bar-fill" style="width:' + Math.max(3, pctTok).toFixed(1) + '%"></span> <span style="font-size:11px;color:var(--dim)">' + pctTok.toFixed(1) + '%</span></td>'
        + '</tr>';
    }).join('');

    // 延迟 / 速度列取自日志末尾的采样，窗口比采样更宽时它们只覆盖最新的那一段。
    // 明说覆盖范围，比让局部数字冒充整个窗口要好。
    let coverageNote = '';
    if(perf && perf.sample_capped && perf.sample_from){
      coverageNote = '<div style="font-size:12px;color:var(--dim);margin-bottom:8px">'
        + '延迟 / 速度列只覆盖日志末尾的部分请求（自 '
        + esc(new Date(perf.sample_from * 1000).toLocaleString())
        + ' 起），更早的请求未纳入这三列。</div>';
    }
    matrixEl.innerHTML = coverageNote + '<table class="data-cards"><thead><tr>'
      + '<th style="text-align:left">模型名称</th>'
      + '<th style="text-align:left">账号</th>'
      + '<th>请求数</th><th>失败</th><th>总 Token</th><th style="min-width:190px">输入 / 输出 / 思考</th>'
      + '<th title="思考 token 占输出 token 的比例——越高说明这个模型越「先想后说」，直接拉高延迟与积分（思考型模型长任务实测可过七成）">思考占比</th>'
      + '<th>首字延迟 (TTFT)</th><th>生成速度</th><th>端到端耗时</th><th>缓存命中率</th><th>用量占比</th>'
      + '</tr></thead><tbody>' + summaryRow + rows + '</tbody></table>';
    applyTableSort('perfMatrix');
  }

}

async function loadAnalytics(){
  try {
    // 载荷永远按当前选中的窗口取，它的 window 桶就是第一列要展示的数字。
    const data = await getJSON('/usage/analytics' + analyticsQuery(), POLL_READ);
    renderAnalytics(data);
    loadUsageSeries();
    loadRemainingUsage();
  } catch(err) {
    console.error('loadAnalytics failed:', err);
  }
}

// ---------------------------------------------------------------------------
// 剩余用量估算（/usage/remaining）
//
// 上游按 24 小时窗口给「账号 × 模型」配额，预算 = 撞线账号窗口用量的平均；
// 这个区块把每个账号当前窗口的剩余列出来。数字随用量实时变化，不跟时间窗
// 选择器联动（它只描述「现在」），所以载荷不带 range 参数。
// ---------------------------------------------------------------------------
async function loadRemainingUsage(){
  try {
    const data = await getJSON('/usage/remaining', POLL_READ);
    renderRemainingUsage(data);
  } catch(err) {
    if(!isAuthError(err)) console.error('loadRemainingUsage failed:', err);
  }
}

function fmtTok(v){
  if(v == null) return '—';
  const n = Number(v) || 0;
  if(Math.abs(n) >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if(Math.abs(n) >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}

/* 思考占比：reasoning_tokens / completion_tokens（usage 行里思考是输出的一部分）。
   这个数直接决定延迟与积分——glm-5.3 的长任务实测 71-77% 花在思考上。
   过半标红，提醒「这个模型先想后说」；否则用思考色。 */
function pctThink(r, c){
  const cc = Number(c) || 0;
  if(cc <= 0) return '—';
  const v = (Number(r) || 0) / cc * 100;
  const color = v >= 50 ? 'var(--bad)' : 'var(--think)';
  return '<span style="color:' + color + '">' + v.toFixed(1) + '%</span>';
}

// 上一轮真正画进 DOM 的载荷指纹（同 refreshInner 里的 recentFp 那套）。
let lastRemainingFp = null;
// 模型筛选（点「模型总量」徽章只看那个模型，再点一次显示全部）与最近一次载荷
// ——切换筛选要立刻重画，不能等下一轮轮询。
let remainingModelFilter = '';
let lastRemainingData = null;

function toggleRemainingModelFilter(model){
  remainingModelFilter = (remainingModelFilter === model) ? '' : (model || '');
  if(lastRemainingData) renderRemainingUsage(lastRemainingData);
}

// 剩余用量按区域分块：各自的徽章、统计与表格；区域列
// 因此不再需要——区块标签已经说明了区域。
const REMAINING_REALMS = [
  {realm: 'codearts', budgets: 'remainingBudgetsCn',
   summary: 'remainingSummaryCn', tbody: 'remainingTbodyCn'},
];

function renderRemainingUsage(data){
  const bodies = REMAINING_REALMS.map(r => document.getElementById(r.tbody));
  if(!bodies[0]) return;
  const tbody = bodies[0];   // 指纹守卫只关心「这一块画过没有」
  // 5 秒一轮的重画里，载荷没变就不碰 DOM：接口挂了 15 秒 TTL，同一个缓存
  // 条目会连着命中好几轮轮询，每轮重写三十行 innerHTML 是白付的解析与布局。
  // 指纹取载荷本身——它包含所有会画进表格的输入，而同一缓存条目的两次响应
  // 逐字节相同。tbody 为空时照常重画（换页签/清空后不能停在空白上）。
  // 筛选状态也算指纹的一部分：切换筛选必须立刻重画。
  const fp = remainingModelFilter + '\u0000' + JSON.stringify(data);
  if(fp === lastRemainingFp && tbody.innerHTML) return;
  lastRemainingFp = fp;
  lastRemainingData = data;
  const rows = (data && data.rows) || [];
  const budgets = (data && data.budgets) || [];
  // 模型筛选：徽章选中的模型只留它自己的行（'' = 全部）。统计行按可见行算，
  // 免得「表里 3 行、上面写 20 项」。
  const visible = remainingModelFilter
    ? rows.filter(r => r.model === remainingModelFilter) : rows;

  const winEm = document.getElementById('remainingUsageWindow');
  if(winEm){
    winEm.textContent = data ? ('窗口 ' + (data.window_seconds / 3600) + 'h') : '';
  }
  // 预算样本与按模型总剩余并成同一个徽章：同一个 (区域, 模型) 的两个指标
  // （预算来自撞线样本；总剩余 = 可用组的剩余之和，冷却/已满记 0、只加不减），
  // 分两行展示会被当成重复条目。徽章按区域各画一块。
  const models = (data && data.models) || [];
  const merged = new Map();
  budgets.forEach(b => merged.set(b.realm + '\u0000' + b.model, {budget: b}));
  models.forEach(m => {
    const key = m.realm + '\u0000' + m.model;
    const entry = merged.get(key) || {};
    entry.model = m;
    merged.set(key, entry);
  });
  REMAINING_REALMS.forEach(({realm, budgets: elId}) => {
    const el = document.getElementById(elId);
    if(!el) return;
    const chips = [];
    merged.forEach(entry => {
      const budget = entry.budget, model = entry.model;
      const src = model || budget;
      if(src.realm !== realm) return;
      // 近两日没消耗的模型不参与剩余计算（服务端过滤），但预算样本保留并
      // 标「未参与」——预算要撞线才学得到，不能因为暂时没用就从面板消失。
      const off = budget && budget.active === false;
      const bits = [];
      const tips = [];
      if(budget){
        bits.push('预算 ≈ <b>' + fmtTok(budget.avg) + '</b>'
                  + ' <span style="color:var(--dim)">(n=' + budget.n + ')</span>'
                  + (off ? ' <span style="color:var(--dim)">未参与</span>' : ''));
        tips.push('样本 ' + budget.n + ' · 区间 ' + fmtTok(budget.min) + ' ~ ' + fmtTok(budget.max)
                  + (off ? ' · 近两日未使用，未参与剩余用量' : ''));
      }
      if(model){
        bits.push('总剩余 <b>'
                  + (model.total_remaining == null ? '—' : fmtTok(model.total_remaining)) + '</b>'
                  + ' <span style="color:var(--dim)">(可用 ' + (model.available || 0)
                  + ' · 冷却 ' + (model.cooling || 0)
                  + (model.unknown ? ' · 未知 ' + model.unknown : '') + ')</span>');
        tips.push('按模型汇总：可用组的剩余之和；冷却/用完的组记 0，不拉低别的组');
      }
      chips.push('<span class="badge" style="font-size:11px;cursor:pointer'
        + (off ? ';opacity:.55' : '')
        + (remainingModelFilter === src.model
           ? ';outline:2px solid var(--accent);outline-offset:1px' : '')
        + '" title="' + esc(tips.join('；') + ' · 点击只看这个模型，再点一次显示全部') + '"'
        + ' data-model="' + esc(src.model) + '"'
        + ' onclick="toggleRemainingModelFilter(this.dataset.model)">'
        + esc(src.model) + ' · ' + bits.join(' · ') + '</span>');
    });
    el.innerHTML = chips.length
      ? chips.join(' ')
      : '<span style="font-size:12px;color:var(--dim)">暂无预算样本：等某个账号把某个模型的窗口用满（撞线）后自动出现。</span>';
  });

  const countLine = list => {
    const cooling = list.filter(r => r.cooling).length;
    const tight = list.filter(r => !r.cooling && r.used_pct != null && r.used_pct >= 80).length;
    return list.length
      ? (list.length + ' 项 · 冷却中 ' + cooling + ' · 用量 ≥80% ' + tight)
      : '暂无数据';
  };
  const summary = document.getElementById('remainingUsageSummary');
  if(summary) summary.textContent = countLine(visible);
  REMAINING_REALMS.forEach(({realm, summary: elId}) => {
    const el = document.getElementById(elId);
    if(el) el.textContent = countLine(visible.filter(r => r.realm === realm));
  });

const emptyRow = '<tr><td colspan="6" style="text-align:center;color:var(--dim)">'
    + (remainingModelFilter
       ? esc('「' + remainingModelFilter + '」在当前范围内没有记录（再点一次选中的徽章显示全部）')
       : '暂无数据（需要账号先有用量或撞线记录）')
    + '</td></tr>';
  REMAINING_REALMS.forEach(({realm, tbody: bodyId}) => {
    const body = document.getElementById(bodyId);
    if(!body) return;
    const realmRows = visible.filter(r => r.realm === realm);
    if(!realmRows.length){
      body.innerHTML = emptyRow;
      return;
    }
    body.innerHTML = realmRows.map(r => {
      const pct = r.used_pct == null ? null : Math.max(0, Math.min(100, r.used_pct));
      const color = r.cooling || (pct != null && pct >= 90) ? 'var(--bad)'
        : (pct != null && pct >= 70 ? 'var(--warn)' : 'var(--accent2)');
      const bar = '<div style="display:flex;align-items:center;gap:6px">'
        + '<div style="flex:1;height:6px;background:var(--panel2);border:1px solid var(--line);border-radius:3px;overflow:hidden">'
        + '<div style="height:100%;width:' + (pct == null ? 0 : pct) + '%;background:' + color + ';transition:width .3s ease"></div>'
        + '</div>'
        + '<span style="font-size:11px;color:var(--dim);min-width:44px;text-align:right">'
        + (r.used_pct == null ? '—' : r.used_pct.toFixed(1) + '%') + '</span></div>';
      const flags = [];
      if(r.cooling) flags.push('<span class="badge" style="font-size:10px;color:var(--bad)">冷却至 '
        + esc((r.reset_iso || '').slice(5, 16)) + '</span>');
        else if(r.estimated) flags.push('<span class="badge" style="font-size:10px;color:var(--dim)" '
        + 'title="当前窗口的起点未知（没有撞线记录，或记录已过期），已用按最近 24 小时统计，是剩余量的下界">按 24h 估算</span>');
      const remainCell = r.remaining == null ? '—'
        : (r.cooling ? '<b style="color:var(--bad)">0</b>' : '<b>' + fmtTok(r.remaining) + '</b>');
      // 分段明细不在这张表里展示：两段相加的总量看「各账号用量透视与模型消耗
      // 分布」（原始消耗本来就含两段）。这里只保留冷却行的悬停提示——窗口的
      // 记账在撞线处截止。
      const segs = Array.isArray(r.segments) ? r.segments : [];
      const usedTitle = r.cooling && segs.length
        ? ' title="' + esc('已用到撞线时刻为止（' + (segs[0].end_iso || '').slice(5, 16)
                           + '），额度 ' + (r.reset_iso || '').slice(5, 16) + ' 恢复') + '"'
        : '';
      return '<tr>'
        + '<td style="text-align:left">' + esc(r.nickname || (r.uid || '').slice(0, 8)) + '</td>'
        + '<td style="text-align:left">' + esc(r.model) + ' ' + flags.join(' ') + '</td>'
        + '<td style="text-align:center;font-size:11px;color:var(--dim)">'
        + esc((r.window_iso || '').slice(5, 16)) + '</td>'
        + '<td style="text-align:right"' + usedTitle + '>' + fmtTok(r.used) + '</td>'
        + '<td style="text-align:right">' + remainCell + '</td>'
        + '<td>' + bar + '</td>'
        + '</tr>';
    }).join('');
  });
    applyTableSort('remainingUsageTableCn');
}

function loadUsageSeries(){
  getJSON('/usage/timeseries' + analyticsQuery(), POLL_READ)
    .then(data => { renderUsageSeries(data); renderCreditHistory(data); })
    .catch(() => {});
}

function renderUsageSeries(data){
  const canvas = document.getElementById('usageSeriesChart');
  if(!canvas) return;
  const series = (data && data.series) || [];
  const summary = document.getElementById('usageSeriesSummary');
  const totalTokens = series.reduce((sum, b) => sum + (b.total_tokens || 0), 0);
  const totalCredit = series.reduce((sum, b) => sum + (b.credit || 0), 0);
  if(summary) summary.textContent = '总 Token ' + fmt(totalTokens) + ' · 扣减积分 ' + fmt(totalCredit)
    + ' · 桶 ' + (data ? data.bucket_seconds : '-') + 's';
  const ctx = canvas.getContext('2d');
  const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
  const cAccent = cssVar('--accent') || '#b03024';
  const cTeal = cssVar('--accent2') || '#2f5d62';
  const cDim = cssVar('--dim') || '#6d6250';
  const cHair = cssVar('--line-hover') || '#bfab83';
  const ratio = window.devicePixelRatio || 1;
  const cssW = canvas.clientWidth || 800;
  const cssH = 220;
  canvas.width = cssW * ratio;
  canvas.height = cssH * ratio;
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, cssW, cssH);
  if(!series.length){
    ctx.fillStyle = cDim;
    ctx.font = '12px sans-serif';
    ctx.fillText('当前范围没有请求数据', 12, 24);
    return;
  }
  const pad = {l: 52, r: 16, t: 12, b: 26};
  const plotW = Math.max(10, cssW - pad.l - pad.r);
  const plotH = Math.max(10, cssH - pad.t - pad.b);
  const maxTokens = Math.max(1, ...series.map(b => b.total_tokens || 0));
  const maxReq = Math.max(1, ...series.map(b => b.requests || 0));
  const slot = plotW / series.length;
  const barW = Math.max(1, slot - 2);
  ctx.strokeStyle = cHair;
  ctx.beginPath();
  ctx.moveTo(pad.l, pad.t);
  ctx.lineTo(pad.l, pad.t + plotH);
  ctx.lineTo(pad.l + plotW, pad.t + plotH);
  ctx.stroke();
  ctx.fillStyle = cTeal;
  ctx.globalAlpha = .55;
  series.forEach((b, i) => {
    const h = plotH * (b.total_tokens || 0) / maxTokens;
    const x = pad.l + slot * i + 1;
    ctx.fillRect(x, pad.t + plotH - h, barW, h);
  });
  ctx.globalAlpha = 1;
  ctx.strokeStyle = cAccent;
  ctx.beginPath();
  series.forEach((b, i) => {
    const x = pad.l + slot * (i + 0.5);
    const y = pad.t + plotH - plotH * (b.requests || 0) / maxReq;
    if(i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.fillStyle = cDim;
  ctx.font = '10px monospace';
  ctx.fillText(fmt(maxTokens), 4, pad.t + 8);
  ctx.fillText('0', 4, pad.t + plotH);
  const tsLabel = t => new Date(t * 1000).toLocaleString();
  const firstLabel = tsLabel(series[0].at);
  const lastLabel = tsLabel(series[series.length - 1].at);
  ctx.fillText(firstLabel, pad.l, cssH - 6);
  ctx.fillText(lastLabel, Math.max(pad.l, cssW - pad.r - ctx.measureText(lastLabel).width), cssH - 6);
}

async function loadCreditHistory(btn){
  if(btn) btn.disabled = true;
  try{
    const data = await getJSON('/usage/timeseries' + analyticsQuery(), POLL_READ);
    renderUsageSeries(data);
    renderCreditHistory(data);
    if(btn) toast('积分扣减历史已刷新', 'ok');
  }catch(e){
    if(btn) toast('刷新失败: ' + e.message, 'bad');
  }finally{
    if(btn) btn.disabled = false;
  }
}

// 最近一次的积分扣减数据。账号昵称来自 /accounts（另一条并行请求），
// 它比 /usage/timeseries 晚到时就先用 uid 兜底，等账号到位后再补画一次。
let LAST_CREDIT_DATA = null;

// uid -> 昵称。取不到（账号已删除/尚未加载完）就回退 uid 前 8 位，不留空。
function creditAccountLabel(uid){
  const id = String(uid || '');
  if(!id) return '—';
  const acct = (window.ACCOUNTS || []).find(a => a.uid === id);
  return (acct && acct.nickname) || id.slice(0, 8);
}

function renderCreditHistory(data){
  if(data) LAST_CREDIT_DATA = data;
  const rows = ((LAST_CREDIT_DATA && LAST_CREDIT_DATA.credits) || []).slice(0, 50);
  const tbody = document.querySelector('#creditHistoryTable tbody');
  if(!tbody) return;
  tbody.innerHTML = rows.map(x => '<tr>'
    + '<td>' + esc(x.iso || '') + '</td>'
    + '<td>' + esc(x.model || '') + '</td>'
    + '<td title="' + esc(x.account || '') + '">' + esc(creditAccountLabel(x.account)) + '</td>'
    + '<td>' + fmt(x.credit) + '</td>'
    + '<td>' + fmt(x.total_tokens || 0) + '</td>'
    + '</tr>').join('') || '<tr><td colspan="5" style="color:var(--dim)">没有积分扣减记录</td></tr>';
  applyTableSort('creditHistoryTable');
}


/* 第一列的口径随范围切换，标签必须跟着走，否则「本周」的数字会被当成「今日」读。 */
const RANGE_LABELS = {today:'今日', week:'本周', month:'本月', custom:'自定义区间', all:'全部历史'};
function rangeLabel(){ return RANGE_LABELS[analyticsRange] || RANGE_LABELS.today; }

function renderAnalytics(data){
  if(!data || !data.summary) return;
  const sumWindow = data.summary.window || {};
  const sumAll = data.summary.all_time || {};
  const currentSum = sumWindow;

  // KPI 1: follows the range selector. It used to be hard-wired to the Today
  // bucket while the card next to it was hard-wired to All Time, so the range
  // buttons appeared to do nothing to the headline number.
  const elTodayTok = document.getElementById('kpiTodayTokens');
  const elTodayDetail = document.getElementById('kpiTodayTokensDetail');
  const elTodayTitle = document.getElementById('kpiRangeTokenTitle');
  if(elTodayTitle) elTodayTitle.textContent = rangeLabel() + '消耗 Token';
  if(elTodayTok) elTodayTok.textContent = fmtCompact(currentSum.total_tokens || 0);
  if(elTodayDetail) elTodayDetail.innerHTML =
    '<span style="color:var(--accent)">输入 ' + fmtCompact(currentSum.prompt_tokens || 0) + '</span>' +
    ' <span style="color:var(--dim-light)">/</span> ' + '<span style="color:var(--accent2)">输出 ' + fmtCompact(currentSum.completion_tokens || 0) + '</span>' +
    ' <span style="color:var(--dim-light)">/</span> ' + '<span style="color:var(--think)">思考 ' + fmtCompact(currentSum.reasoning_tokens || 0) + '</span>' +
    ' <span style="color:var(--dim-light)">/</span> ' + '<span style="color:var(--ok)">缓存 ' + fmtCompact(currentSum.cached_tokens || 0) + '</span>';

  // KPI 2: always the all-time figure, as the stable reference next to KPI 1.
  const elTotalTok = document.getElementById('kpiTotalTokens');
  const elTotalDetail = document.getElementById('kpiTotalTokensDetail');
  if(elTotalTok) elTotalTok.textContent = fmtCompact(sumAll.total_tokens || 0);
  if(elTotalDetail) elTotalDetail.innerHTML =
    '<span style="color:var(--accent)">输入 ' + fmtCompact(sumAll.prompt_tokens || 0) + '</span>' +
    ' <span style="color:var(--dim-light)">/</span> ' + '<span style="color:var(--accent2)">输出 ' + fmtCompact(sumAll.completion_tokens || 0) + '</span>' +
    ' <span style="color:var(--dim-light)">/</span> ' + '<span style="color:var(--think)">思考 ' + fmtCompact(sumAll.reasoning_tokens || 0) + '</span>' +
    ' <span style="color:var(--dim-light)">/</span> ' + '<span style="color:var(--ok)">缓存 ' + fmtCompact(sumAll.cached_tokens || 0) + '</span>' +
    // 只有「所选范围已经覆盖了日志里的全部请求」这一种情况需要说明：两张卡数字
    // 相同不是计数器坏了，而是没有更早的数据。
    ((analyticsRange !== 'all' && (sumAll.total_tokens || 0) === (sumWindow.total_tokens || 0) && (sumAll.total_tokens || 0) > 0)
      ? '<br><span style="color:var(--dim);font-size:11px">与' + rangeLabel() + '相同：所选范围已覆盖日志中的全部请求</span>'
      : '');

  // KPI 3: 网关平均生成速度（耗时作为副文案，速度与耗时是一对）
  const elAvgSpeed = document.getElementById('kpiAvgSpeed');
  const elAvgElapsed = document.getElementById('kpiAvgElapsed');
  if(elAvgSpeed) elAvgSpeed.innerHTML = (currentSum.speed_avg ? currentSum.speed_avg.toFixed(1) : '0.0') + ' <span style="font-size:12px;font-weight:400;color:var(--dim)">tok/s</span>';
  if(elAvgElapsed) elAvgElapsed.textContent = '平均耗时 ' + ms(currentSum.elapsed_ms_avg);

  // KPI 4: 平均首字延迟，单独一张卡
  const elAvgLatency = document.getElementById('kpiAvgLatency');
  if(elAvgLatency) elAvgLatency.textContent = ms(currentSum.ttft_ms_avg);

  // KPI 5: 缓存命中率
  const elCacheRate = document.getElementById('kpiCacheRate');
  if(elCacheRate) elCacheRate.textContent = (currentSum.cache_hit_pct != null ? currentSum.cache_hit_pct.toFixed(1) : '0.0') + '%';
  const elCacheDetail = document.getElementById('kpiCacheDetail');
  if(elCacheDetail) elCacheDetail.textContent = '缓存 ' + fmtCompact(currentSum.cached_tokens || 0) + ' tokens · 提示词前缀命中复用比';

  // KPI 6: 请求数（成功数）与 KPI 7: 成功率，拆成两张卡
  const elReqTitle = document.getElementById('kpiReqTitle');
  const elReqCount = document.getElementById('kpiReqCount');
  const elReqDetail = document.getElementById('kpiReqDetail');
  const elSuccessRate = document.getElementById('kpiSuccessRate');
  const elSuccessDetail = document.getElementById('kpiSuccessDetail');
  if(elReqTitle) elReqTitle.textContent = (analyticsRange === 'all' ? '累计' : rangeLabel()) + '请求数';
  const okReq = currentSum.requests || 0;
  const errReq = currentSum.errors || 0;
  const totalReq = okReq + errReq;
  const successPct = totalReq > 0 ? ((okReq / totalReq) * 100).toFixed(1) : '100.0';
  if(elReqCount) elReqCount.textContent = fmt(okReq) + ' 次';
  if(elReqDetail) elReqDetail.textContent = '含失败共 ' + fmt(totalReq) + ' 次';
  if(elSuccessRate) elSuccessRate.innerHTML = '<span style="color:' + (errReq ? 'var(--warn)' : 'var(--accent2)') + '">' + successPct + '%</span>';
  if(elSuccessDetail) elSuccessDetail.textContent = '失败 ' + fmt(errReq) + ' 次';

  // KPI 8「API 等价花费」已随价格估算体系一并移除（2026-10-22）。
  // 本网关只记积分，不再折算货币。

  // Table 1: 账号透视表
  const acctTbody = document.getElementById('analyticsAccountTbody');
  const acctCountEm = document.getElementById('analyticsAcctCount');
  let accts = (data.accounts || []).filter(a => {
    if(a.uid === '(unattributed)' && !((a.window || {}).requests || a.all_time.requests)) return false;
    return true;
  });
  if(acctCountEm) acctCountEm.textContent = accts.length ? '(' + accts.length + ' 个账号)' : '';

  if(acctTbody){
    if(!accts.length){
      acctTbody.innerHTML = '<tr><td colspan="6" class="empty">暂无账号用量数据</td></tr>';
    } else {
      acctTbody.innerHTML = accts.map(a => {
        // window 桶就是当前选中的范围，也就是这张表要展示的口径。
        const st = a.window || {};
        const modelsMap = a.window_models || {};
        const entries = Object.entries(modelsMap || {}).sort((x, y) => (y[1].tokens || 0) - (x[1].tokens || 0));
        
        let pills = '<span style="color:var(--dim)">无调用</span>';
        if(entries.length){
          pills = entries.map(([mid, ms]) => {
            return '<span class="model-pill">'
              + '<b style="color:var(--fg)">' + esc(mid) + '</b>: '
              + ms.requests + '次 · <b style="color:var(--accent)">' + fmtCompact(ms.tokens) + '</b> tok'
              + '</span>';
          }).join('');
        }

        let creditStr = '<span style="color:var(--dim)">—</span>';
        if(a.credits && a.credits.remain != null){
          if(a.credits.size){
            creditStr = '<b style="color:var(--accent2)">' + fmt(a.credits.remain) + '</b> <span style="color:var(--dim);font-size:11px">/ ' + fmt(a.credits.size) + ' 积分</span>';
          } else {
            creditStr = '<b style="color:var(--accent2)">' + fmt(a.credits.remain) + '</b> <span style="color:var(--dim);font-size:11px">积分</span>';
          }
        }

        return '<tr>'
          + '<td style="text-align:left">'
          +   '<b>' + esc(a.nickname || a.uid) + '</b>'
          +   '<div style="color:var(--dim);font-size:11px;font-family:monospace">' + esc((a.uid || '').slice(0, 10)) + '...</div>'
          + '</td>'
          + '<td>' + creditStr + '</td>'
          + '<td>' + fmt(st.requests || 0) + '</td>'
          + '<td><b style="color:var(--accent)">' + fmtCompact(st.total_tokens || 0) + '</b></td>'
          + '<td><b style="color:var(--accent2)">' + (st.credit != null ? Number(st.credit).toFixed(2) : '0.00') + '</b></td>'
          + '<td style="text-align:left;max-width:440px">' + pills + '</td>'
          + '</tr>';
      }).join('');
    }
    applyTableSort('analyticsAccountTable');
  }

  renderKeyTable(data);
}

/* 按 API Key 的归属表。口径与账号表完全一致（window 桶 = 当前选中范围），
   所以两张表的请求数应当相等；对不上是数据问题，不是渲染能修的，故这里
   不隐藏任何会兜差额的行——(未知 key) 正是用来兜住差额的。唯一能收起的是
   「(切换前)」：它是升级前的历史尾巴，只减不增，收起与否都不影响对账。 */

/* 「(切换前)」行开关的状态。表格每 5 秒重绘一次，所以状态不能存在渲染函数
   里，得放在外面；偏好与账号区折叠一样存服务端的 accounts/settings.json
   （key_before_hidden），不用 localStorage。 */
let keyBeforeHidden = false;
let lastKeyData = null;
/* 唯一的写入口：内存状态、复选框与表格一起改，三者不会不同步。 */
function applyKeyBeforeHidden(hidden){
  keyBeforeHidden = hidden === true;
  const box = document.getElementById('keyBeforeToggle');
  if(box) box.checked = keyBeforeHidden;
  if(lastKeyData) renderKeyTable(lastKeyData);
  return keyBeforeHidden;
}
// 显式选择走既有的 settings save 通道（一个键的 patch，不动别的设置）。

function keyModelPills(k){
  const pills = (k.models || []).map(m =>
    '<span class="model-pill">'
    + '<b style="color:var(--fg)">' + esc(m.model) + '</b>: '
    + m.requests + '次 · <b style="color:var(--accent)">' + fmtCompact(m.tokens) + '</b> tok'
    + '</span>');
  const rest = k.models_other;
  if(rest){
    pills.push('<span class="model-pill">'
      + '<b style="color:var(--dim)">' + esc(rest.model || '(其他)') + '</b> '
      + '<span style="color:var(--dim)">' + (rest.models || 0) + ' 个模型 · </span>'
      + rest.requests + '次 · ' + fmtCompact(rest.tokens) + ' tok</span>');
  }
  return pills.length ? pills.join('') : '<span style="color:var(--dim)">无调用</span>';
}

function renderKeyTable(data){
  const tbody = document.getElementById('analyticsKeyTbody');
  if(!tbody) return;
  const countEm = document.getElementById('analyticsKeyCount');
  const note = document.getElementById('analyticsKeyNote');
  const keys = data.keys || [];
  lastKeyData = data;
  const wrap = document.getElementById('keyBeforeSwitch');
  const box = document.getElementById('keyBeforeToggle');
  const hasBefore = keys.some(k => k.key === '__before_keys__');
  // 新装的环境没有这一行，就没得收，开关也不该出现。
  if(wrap) wrap.style.display = hasBefore ? '' : 'none';
  if(box) box.checked = keyBeforeHidden;
  const shown = keyBeforeHidden ? keys.filter(k => k.key !== '__before_keys__') : keys;
  if(countEm) countEm.textContent = shown.length ? '(' + shown.length + ' 把)' : '';

  if(note){
    const named = keys.filter(k => k.source !== 'bucket');
    const parts = [];
    if(!named.length) parts.push('设置里还没有任何 API Key，全部流量都落在下面的未归属行里。');
    // 收起那行时就不再解释那行，否则读者找不到话里指的东西。
    if(!keyBeforeHidden) parts.push('Key 维度只从本次升级之后开始记录：更早的请求没有这个字段，会一直留在「(切换前)」里且不会再增长。');
    note.innerHTML = parts.join(' ');
  }

  if(!shown.length){
    tbody.innerHTML = '<tr><td colspan="7" class="empty">暂无 API Key 用量数据</td></tr>';
    return;
  }

  tbody.innerHTML = shown.map(k => {
    const st = k.window || {};
    const sub = {panel:'面板 Key', launcher:'启动参数', bucket:'未归属', builtin:'内置'}[k.source] || '';
    let nameCell = '<td style="text-align:left" data-label="API Key">'
      + '<b>' + esc(k.name || k.key) + '</b>';
    if(sub || !k.enabled){
      nameCell += '<div style="font-size:11px">'
        + (sub ? '<span style="color:var(--dim)">' + esc(sub) + '</span>' : '')
        + (!k.enabled && k.source === 'panel' ? '<span class="badge off mini">已禁用</span>' : '')
        + '</div>';
    }
    nameCell += '</td>';

    const reqCell = '<td data-label="请求次数">' + fmt(st.requests || 0) + ' 次'
      + (st.errors ? '<span style="color:var(--bad);font-size:11px"> · 失败 ' + fmt(st.errors) + '</span>' : '')
      + '</td>';
    const tokCell = '<td data-label="消耗总 Token"><b style="color:var(--accent)">'
      + fmtCompact(st.total_tokens || 0) + '</b></td>';
    const splitCell = '<td data-label="输入 · 输出 · 思考" style="font-size:12px">'
      + '<span style="color:var(--accent)">' + fmtCompact(st.prompt_tokens || 0) + '</span>'
      + ' <span style="color:var(--dim-light)">/</span> '
      + '<span style="color:var(--accent2)">' + fmtCompact(st.completion_tokens || 0) + '</span>'
      + ' <span style="color:var(--dim-light)">/</span> '
      + '<span style="color:var(--think)">' + fmtCompact(st.reasoning_tokens || 0) + '</span>'
      + '</td>';
    const cacheCell = '<td data-label="缓存命中">'
      + (st.cache_hit_pct != null ? st.cache_hit_pct.toFixed(1) : '0.0') + '%</td>';
    const creditCell = '<td data-label="消耗积分"><b style="color:var(--accent2)">'
      + (st.credit != null ? Number(st.credit).toFixed(2) : '0.00') + '</b></td>';
    const modelCell = '<td style="text-align:left;max-width:440px" data-label="调用的模型分布">'
      + keyModelPills(k) + '</td>';

    return '<tr>'
      + nameCell
      + reqCell + tokCell + splitCell + cacheCell + creditCell + modelCell
      + '</tr>';
  }).join('');
  applyTableSort('analyticsKeyTable');
}
</script>
