<script>
let loginState = null, loginTimer = null;











/* ---------------- 码道 CodeArts（华为云）账号 ----------------
   与轮询式登录不同：码道是 PKCE + DPoP + 本地回跳。
   浏览器被华为云 307 回 http://127.0.0.1:{网关端口}/oauth/callback?code=…，
   网关当场换 token 落盘，前端只是轮询结果。所以这里没有「复制凭证」这一步。 */
let caLoginState = null, caLoginTimer = null;

function caSetStep(n, cls){
  const el = document.getElementById("caStep" + n);
  if(el) el.className = "step" + (cls ? " " + cls : "");
}

/* 时间戳格式化。注意：不能用数据看板那段的 fmtTime ——
   它整个包在 (function(){...})() 里，是那段脚本的私有函数，
   从账号区块调用会直接 ReferenceError（实测踩过，账号列表因此永远停在
   「正在读取…」）。这里放一份全局可用的。 */
function caStamp(epochSec){
  const d = new Date(Number(epochSec) * 1000);
  if(!isFinite(d.getTime())) return "时间未知";
  const p = n => String(n).padStart(2, "0");
  return (d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
}

function caLeft(seconds){
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  if(s < 60) return s + " 秒";
  const m = Math.floor(s / 60);
  if(m < 60) return m + " 分钟";
  const h = Math.floor(m / 60);
  if(h < 48) return h + " 小时" + (m % 60 ? String(m % 60).padStart(2, "0") + " 分" : "");
  return Math.floor(h / 24) + " 天" + (h % 24 ? (h % 24) + " 小时" : "");
}

function openCodeartsLogin(){
  const m = document.getElementById("codeartsLoginModal");
  if(m) m.classList.add("show");
  // 授权完成后的回跳地址固定是 http://127.0.0.1:{网关端口}/oauth/callback ——
  // 也就是说浏览器的 127.0.0.1 必须能连到网关。远程打开面板是常态：回跳会
  // 落到用户自己电脑上然后失败，这时走手动粘贴通道即可。要提前说清的是
  // 「该复制哪条 URL」和「只认本次发起的授权」——旧的回调链接会被拒。
  const host = location.hostname;
  const local = host === "127.0.0.1" || host === "localhost" || host === "[::1]";
  if(!local){
    toast("远程打开面板，浏览器回跳不到网关是正常的：完成授权后，把地址栏里 "
      + "http://127.0.0.1:端口/oauth/callback?code=… 那条完整 URL 复制到下方「提交回调」"
      + "（端口以下方授权链接里为准）。注意只认本次弹窗发出的授权链接——"
      + "旧标签页里的回调会被拒绝。", "warn");
  }
  loadCodeartsAccounts();
  startCodeartsLogin();
}

function closeCodeartsLogin(){
  const m = document.getElementById("codeartsLoginModal");
  if(m) m.classList.remove("show");
  if(caLoginTimer){ clearInterval(caLoginTimer); caLoginTimer = null; }
  if(caLoginState){ postJSON("/accounts/codearts/login/cancel", {state: caLoginState}).catch(()=>{}); caLoginState = null; }
}

function restartCodeartsLogin(){ startCodeartsLogin(); }

async function startCodeartsLogin(){
  if(caLoginTimer){ clearInterval(caLoginTimer); caLoginTimer = null; }
  if(caLoginState){ postJSON("/accounts/codearts/login/cancel", {state: caLoginState}).catch(()=>{}); caLoginState = null; }
  const box = document.getElementById("codeartsLinkBox");
  const status = document.getElementById("codeartsStatus");
  const t1 = document.getElementById("caStep1Text");
  if(box) box.innerHTML = "";
  if(status) status.textContent = "";
  caSetStep(1, "active"); caSetStep(2, ""); caSetStep(3, "");
  if(t1) t1.textContent = "正在生成授权链接…";
  try{
    const r = await postJSON("/accounts/codearts/login/start", {theme: 1});
    caLoginState = r.state;
    caSetStep(1, "done"); caSetStep(2, "active");
    if(t1) t1.textContent = "授权链接已生成";
    if(box) box.innerHTML =
      '<a class="login-link" id="codeartsLink" href="' + esc(r.authUrl) + '" target="_blank" rel="noopener">' + esc(r.authUrl) + '</a>'
      + '<button class="sec mini" onclick="copyCodeartsLink()">复制授权链接</button>'
      + '<div class="hint">① 打开授权链接，完成华为云登录；② 跳转页打不开时，复制浏览器地址栏的完整 URL；③ 粘贴到下面，点「提交回调」。</div>'
      + '<div id="codeartsManualRow" style="margin-top:6px;display:flex;gap:6px;align-items:center;">'
      + '<input id="codeartsManualCb" type="text" placeholder="手动提交：粘贴回调 URL（http://127.0.0.1:' + esc(String(r.port)) + '/oauth/callback?code=…）" style="flex:1;min-width:0;">'
      + '<button class="sec mini" onclick="submitCodeartsCallback()">提交回调</button>'
      + '</div>'
      + '<div id="codeartsManualNext"></div>';
    pollCodeartsLogin();
    caLoginTimer = setInterval(pollCodeartsLogin, 2000);
  }catch(e){
    caSetStep(1, "");
    if(status) status.textContent = "发起失败：" + e.message;
  }
}

async function copyCodeartsLink(){
  const link = document.getElementById("codeartsLink");
  if(!link) return;
  try{
    await writeClipboard(link.getAttribute("href"));
    toast("已复制授权链接", "ok");
  }catch(e){ toast("复制失败：" + e.message, "bad"); }
}

/* 浏览器够不到 127.0.0.1:<port> 时的逃生通道：把地址栏里的完整回调 URL
   粘贴进来，由面板代为提交（后端与 /oauth/callback 同一条 accept_callback）。 */
async function submitCodeartsCallback(){
  const input = document.getElementById("codeartsManualCb");
  const status = document.getElementById("codeartsStatus");
  const next = document.getElementById("codeartsManualNext");
  if(!input || !input.value.trim()){
    if(status) status.textContent = "先粘贴浏览器地址栏里的完整回调 URL（含 code 参数）";
    return;
  }
  try{
    const r = await postJSON("/accounts/codearts/login/callback", {url: input.value.trim()});
    if(r.status === "ok"){
      caSetStep(3, "done");
      if(status) status.textContent = "登录成功：账号已加入网关";
      if(caLoginTimer){ clearInterval(caLoginTimer); caLoginTimer = null; }
      caLoginState = null;
      input.value = "";
      if(next) next.innerHTML = "";
      toast("码道账号已添加", "ok");
      loadCodeartsAccounts();
    }else if(r.status === "redirect"){
      if(status) status.textContent = r.msg || "还需要一步";
      if(next) next.innerHTML =
        '<div style="margin-top:6px;">继续授权：<a class="login-link" href="' + esc(r.url) + '" target="_blank" rel="noopener">' + esc(r.url) + '</a>'
        + '<div class="hint">打开上面的链接完成后续步骤，然后把浏览器跳到的新回调 URL 再粘贴回来提交。</div></div>';
    }else{
      if(status) status.textContent = r.msg || "提交失败";
    }
  }catch(e){
    if(status) status.textContent = "回调提交失败：" + e.message;
  }
}

async function pollCodeartsLogin(){
  if(!caLoginState) return;
  let r;
  try{ r = await getJSON("/accounts/codearts/login/poll?state=" + encodeURIComponent(caLoginState)); }
  catch(e){ return; }
  const status = document.getElementById("codeartsStatus");
  if(status) status.textContent = r.message || r.status || "";
  if(r.status === "ok"){
    caSetStep(3, "done");
    if(status) status.textContent = "登录成功：" + ((r.summary && r.summary.account) || "账号") + " 已加入";
    if(caLoginTimer){ clearInterval(caLoginTimer); caLoginTimer = null; }
    caLoginState = null;
    toast("码道账号已添加", "ok");
    loadCodeartsAccounts();
  }else if(r.status === "pending"){
    caSetStep(3, "active");
  }else{
    if(caLoginTimer){ clearInterval(caLoginTimer); caLoginTimer = null; }
    caLoginState = null;
  }
}

/* 网关卡片上的汇总行：可用 / 总积分 · 账号数。
   多个账号时把各自的积分加起来 —— 每个账号是独立套餐，汇总只作总览。
   顺手把「账号累计已用积分」记到全局：顶部那张「积分消耗」卡改用它，
   因为账号的已用积分是上游 snap-manager 给的**累计实数**（和客户端显示的
   一致）；最近请求表里的 credit 是网关按计费档逐条估算的，拿它累加当总数
   会漏掉接入网关之前的消耗，也攒不下估算误差。 */
let caAccountCredit = null;

function caUpdateCardSummary(list){
  const remainEl = document.getElementById("caCardRemain");
  const totalEl = document.getElementById("caCardTotal");
  const usedEl = document.getElementById("caCardUsed");
  const acctEl = document.getElementById("caCardAccounts");
  if(!acctEl) return;
  if(!list){
    acctEl.textContent = "—";
    if(remainEl) remainEl.textContent = "—";
    if(totalEl) totalEl.textContent = "—";
    if(usedEl){ usedEl.textContent = "账号读取失败"; usedEl.style.color = "var(--warn)"; }
    return;
  }
  const rows = list;
  const alive = rows.filter(function(a){ return !a.sts_expired; }).length;
  acctEl.textContent = alive + "/" + rows.length;

  let remain = 0, total = 0, used = 0, got = false;
  rows.forEach(function(a){
    const c = a && a.credit;
    if(!c || c.total == null) return;
    got = true;
    total += Number(c.total) || 0;
    remain += Number(c.remaining) || 0;
    used += Number(c.used) || 0;
  });
  if(!got){
    caAccountCredit = null;
    if(remainEl) remainEl.textContent = "—";
    if(totalEl) totalEl.textContent = "—";
    if(usedEl) usedEl.textContent = "积分读取失败";
    return;
  }
  if(remainEl) remainEl.textContent = fmt(remain);
  if(totalEl) totalEl.textContent = fmt(total);
  const changed = (caAccountCredit !== used);
  caAccountCredit = used;
  // 账号比用量晚一步加载，卡片可能已经按 t.credit(0) 画完了 —— 拿到实数后补画一次，
  // 免得「积分消耗」先显示 0.00 再跳变。只在真的变了时才重画。
  if(changed && typeof refresh === "function"){ try{ refresh(); }catch(e){} }
  if(usedEl){
    const pct = total ? (used / total * 100) : 0;
    usedEl.textContent = "已用 " + fmt(used) + "（" + pct.toFixed(1) + "%）";
    usedEl.style.color = pct >= 90 ? "var(--warn)" : "var(--dim)";
  }
}

async function loadCodeartsAccounts(){
  // 账号列表要同时出现在「账号」页和账号弹窗里，所以按标记取全部容器，
  // 而不是只认弹窗里那个 —— 之前只渲染弹窗，页面上就看不到已添加的账号。
  const boxes = Array.from(document.querySelectorAll('[data-codearts-list]'));
  if(!boxes.length) return;
  const set = function(html){ boxes.forEach(function(b){ b.innerHTML = html; }); };
  let r;
  try{ r = await getJSON("/accounts/codearts"); }
  catch(e){ caUpdateCardSummary(null); set('<p class="hint">读取失败：' + esc(e.message) + '</p>'); return; }
  const list = (r && r.accounts) || [];
  caUpdateCardSummary(list);
  if(!list.length){
    set('<p class="hint">还没有码道账号。走完一次授权就能添加一个。</p>');
    return;
  }
  // 渲染放进 try：一旦某一项抛错，之前的表现是 set() 永远不执行、页面就一直
  // 停在「正在读取…」，看不出任何线索（fmtTime 那次就是这么被藏住的）。
  let html;
  try{
    html = list.map(function(a){
      let badge = '<span class="ca-badge ok">有效</span>';
      let when = a.expires_at ? ("STS 到期 " + caStamp(Date.parse(a.expires_at) / 1000)) : "STS 到期时间未知";
      if(a.sts_expired){
        badge = '<span class="ca-badge bad">STS 已过期</span>';
        if(a.sts_dead_external){
          badge = '<span class="ca-badge bad">被外部客户端占用</span>';
          when = "token 链被官方客户端等同账号端轮换，重新登录后恢复";
        }
      }else if(a.sts_remaining_seconds != null){
        when = "STS 剩 " + caLeft(a.sts_remaining_seconds);
        if(a.sts_remaining_seconds < 1800) badge = '<span class="ca-badge warn">即将过期</span>';
      }
      const renew = a.renewable ? "可续期" : "不可续期（需重新登录）";
      // refresh_token 的有效期：summarize 每轮都算好（refresh_expires_at，
      // JWT 的 exp），以前算了没人显示。STS 只有几小时、会自动续，真正会
      // 「静默死掉」的是这张 30 天的 refresh_token —— 到期前不吭声，用户只会在
      // 某天看到账号集体过期。剩不到 7 天时把话说重一点。
      let refreshText = "";
      if(a.refresh_expires_at != null){
        const exp = Number(a.refresh_expires_at) || 0;
        if(exp > 0){
          const days = (exp - Date.now() / 1000) / 86400;
          refreshText = " · refresh " + caStamp(exp) + " 到期";
          if(days < 7) refreshText += "（剩 " + Math.max(0, Math.ceil(days)) + " 天，到期需重新登录）";
        }
      }
      // 运行期：在跑几条 / 容量几格 + 账号级冷却。容量取自信号量的实时值
      // （面板改并发后下一个请求就变），不是启动时的配置快照。注意两个数
      // 不是一回事：「并发 n/m」是**网关**每号信号量（m = 面板/环境配置，
      // 上限 3）；「上游名额」是华为云给的会话数，是网关并发的天花板。
      // 2026-10-24 的疑问「截图怎么是 0/3」——那不是错填了上游槽位，
      // 是那台部署的面板并发真的配了 3；把两者分开写出来，省得再猜一遍。
      const rt = a.runtime || {};
      const cap = Number(rt.capacity || (r && r.concurrency_per_account) || 0);
      const flight = Number(rt.in_flight || 0);
      const slots = Number(r && r.upstream_slots) || 0;
      const runtimeText = " · 网关并发 " + flight + (cap ? "/" + cap : "")
        + (slots ? "（上游名额 " + slots + "）" : "")
        + (rt.cooling_s > 0 ? " · 冷却 " + Math.ceil(rt.cooling_s) + "s" : "");
      const id = esc(a.account_id || "");
      // 积分（snap-manager 统计插件）是客户端里真正在扣的额度。token 额度
      // 那一栏随福利渠道一起下线（opengw 已停服），不再展示。
      const quotaHtml = caCreditHtml(a.credit);
      // 每日签到是活动系统（/v1/ops）的积分体系，与已下线的福利渠道无关。
      const daily = a.welfare || null;
      const wStatus = daily ? String(daily.status || "").toUpperCase() : "";
      const canSign = !!daily && (daily.claimable || !wStatus || wStatus === "ELIGIBLE");
      return '<div class="ca-row"><div class="ca-main">'
        + '<span class="ca-name">' + esc(a.account || "(未命名)") + badge + '</span>'
        + '<span class="ca-sub">' + esc(when) + " · " + esc(renew) + esc(refreshText)
        + (a.domain_id ? " · 账号域 " + esc(String(a.domain_id).slice(0, 8)) + "…" : "")
        + esc(runtimeText)
        + '</span>'
        + quotaHtml
        + caWelfareHtml(daily, a.welfareError)
        + '</div><div class="ca-actions">'
        + (canSign
            ? '<button class="sec mini" data-ca-id="' + id + '" onclick="claimCodeartsWelfare(this)">积分签到</button>'
            : "")
        + (a.renewable ? '<button class="sec mini" data-ca-id="' + id + '" onclick="refreshCodeartsAccount(this)">续期</button>' : "")
        + '<button class="sec mini" data-ca-id="' + id + '" onclick="deleteCodeartsAccount(this)">删除</button>'
        + '</div></div>';
    }).join("");
  }catch(e){
    set('<p class="hint">账号列表渲染失败：' + esc(e && e.message ? e.message : e) + '</p>');
    return;
  }
  set(html);
}

/* 每日签到（活动页「每日签到领 1000 积分」）的状态行。它是 /v1/ops 的
   积分体系，既不是 token 额度，也不是上面那一栏积分总量。 */
function caWelfareHtml(w, err){
  if(err) return '<span class="ca-sub">积分签到不可用：' + esc(caWelfareErrText(err)) + '</span>';
  if(!w) return '';
  const amount = w.amount ? (' ' + fmt(w.amount) + ' 积分') : '';
  const st = String(w.status || '').toUpperCase();
  let text = '积分签到：可领' + amount;
  if(st === 'CLAIMED' || st === 'CONFIRMED' || st === 'CONSUMED') text = '积分签到：今日已领' + amount;
  else if(st && st !== 'ELIGIBLE') text = '积分签到：' + st;
  return '<span class="ca-sub">' + esc(text) + '</span>';
}

function caWelfareErrText(err){
  const s = String(err || "").replace(/^签到失败[:：]\s*/, "");
  if(/APIG\.0301|signature/i.test(s)) return "签名不被接受，该接口可能只认客户端令牌";
  if(/unauthorized|401|403/i.test(s)) return "凭证失效，需要重新授权";
  return s;
}

/* 体验版积分：客户端「总已用积分 4,817 / 11,500 · 6,683 剩余」那一栏，
   来自 snap-access 的 snap-manager 统计插件。它和已下线的 token 额度是两套
   体系（token 那套走 opengw benefit，2026-10 随福利渠道一起停了），
   积分才是客户端里真正在扣的那个数。 */
function caCreditHtml(c){
  if(!c) return '';
  const bits = ['积分 ' + fmt(c.used) + ' / ' + fmt(c.total)
    + ' · 剩余 ' + fmt(c.remaining)];
  if(c.percent != null) bits.push('已用 ' + c.percent + '%');
  if(c.package_name) bits.push(c.package_name);
  if(c.end_date) bits.push(String(c.end_date).slice(0, 10) + ' 到期');
  return '<span class="ca-sub">' + esc(bits.join(' · ')) + '</span>';
}

async function claimCodeartsWelfare(btn){
  const id = btn && btn.getAttribute("data-ca-id");
  if(!id) return;
  const old = btn.textContent;
  btn.disabled = true; btn.textContent = "签到中…";
  try{
    const r = await postJSON("/accounts/codearts/welfare/claim", {accountId: id});
    const res = (r && r.results && r.results[0]) || {};
    if(res.ok){
      const amount = res.amount ? (" +" + fmt(res.amount) + " 积分") : "";
      toast(res.already ? ("今日已签到" + amount) : ("签到成功" + amount), "ok");
    }else{
      toast("签到失败：" + caWelfareErrText(res.msg || "未知原因"), "bad");
    }
    await loadCodeartsAccounts();
  }catch(e){
    toast("签到失败：" + caWelfareErrText(e.message), "bad");
    btn.disabled = false; btn.textContent = old;
  }
}

/* 一键签到：后端 /welfare/claim 不带 accountId 时本来就循环全部账号，
   这里补一个入口并汇总结果（新增签到 / 已签过 / 失败各几户）。 */
async function claimCodeartsWelfareAll(btn){
  const old = btn.textContent;
  btn.disabled = true; btn.textContent = "签到中…";
  try{
    const r = await postJSON("/accounts/codearts/welfare/claim", {});
    const results = (r && r.results) || [];
    if(!results.length){ toast("没有可签到的账号", "bad"); return; }
    let fresh = 0, already = 0, failed = 0, gained = 0;
    const fails = [];
    results.forEach(function(res){
      if(res.ok){
        if(res.already){ already += 1; }
        else{ fresh += 1; gained += Number(res.amount || 0); }
      }else{
        failed += 1;
        fails.push((res.label || res.accountId || "账号") + "：" + caWelfareErrText(res.msg || "未知原因"));
      }
    });
    let msg = "签到完成：" + fresh + " 户新增";
    if(gained) msg += " +" + fmt(gained) + " 积分";
    if(already) msg += " · " + already + " 户已签过";
    if(failed) msg += " · " + failed + " 户失败";
    toast(msg, failed ? "warn" : "ok");
    if(fails.length && failed <= 3) console.warn("[claim-all]", fails.join("；"));
    await loadCodeartsAccounts();
  }catch(e){
    toast("一键签到失败：" + caWelfareErrText(e.message), "bad");
  }finally{
    btn.disabled = false; btn.textContent = old;
  }
}

async function refreshCodeartsAccount(btn){  const id = btn && btn.getAttribute("data-ca-id");
  if(!id) return;
  const old = btn.textContent;
  btn.disabled = true; btn.textContent = "续期中…";
  try{
    const r = await postJSON("/accounts/codearts/refresh", {accountId: id});
    if(r.ok){
      const s = r.summary || {};
      toast("续期成功，STS 剩 " + caLeft(s.sts_remaining_seconds || 0), "ok");
    }else{
      toast("续期失败：" + (r.msg || "未知原因"), "bad");
    }
  }catch(e){
    toast("续期失败：" + e.message, "bad");
  }finally{
    btn.disabled = false; btn.textContent = old;
    loadCodeartsAccounts();
  }
}

async function deleteCodeartsAccount(btn){
  const id = btn && btn.getAttribute("data-ca-id");
  if(!id) return;
  if(!confirm("删除这个码道账号的本地会话？重新登录才能恢复。")) return;
  try{
    await postJSON("/accounts/codearts/delete", {accountId: id});
    toast("已删除", "ok");
  }catch(e){
    toast("删除失败：" + e.message, "bad");
  }
  loadCodeartsAccounts();
}









// 出口只有一个（华为云码道）。realm 值跟着服务端走：历史行里的 cn / intl
// 会被 ca_proxy.normalize_realm 归一成 codearts，面板也用同一个名字取数。
window.ACTIVE_GATEWAY_REALM = "codearts";
window.VIEW_REALM = "codearts";
window.REALM_FILTER = "all";
window.MODELS_DATA = [];
window.ACCOUNTS = [];

function updateUI(){
  // 区块标题上的出口标签：这几个区块的内容都按当前视图区域取（账号、禁用汇总、
  // 最近请求、模型清单），标出来免得把数字看成全局的。用 <em> 承载：
  // 侧栏导航由 h2 生成时会剥掉 <em>，所以标签不会串进导航项。
  const sectionRealm = "（码道）";
  ["disabledRealmTag", "recentRealmTag", "modelsRealmTag"].forEach(function(id){
    const el = document.getElementById(id);
    if(el) el.textContent = sectionRealm;
  });

  const gwName = document.getElementById("activeGatewayName");
  if(gwName) {
    gwName.textContent = "华为云码道 (CodeArts)";
    gwName.style.color = "var(--accent)";
  }

  const cardGw = document.getElementById("cardGatewayCtrl");
  if(cardGw){
    cardGw.style.borderColor = "color-mix(in srgb,var(--accent) 45%,var(--line))";
    cardGw.style.background = "var(--accent-soft)";
  }

  // 计算当前生效的 Key 数量
  const keys = (typeof API_KEY_ROWS !== 'undefined' && API_KEY_ROWS.length) ? API_KEY_ROWS : (window.API_KEY_ROWS || []);
  const activeKeysTotal = keys.filter(k => k.enabled !== false).length;

  const elGwKeyBadge = document.getElementById("activeGatewayKeyCount");
  if(elGwKeyBadge) elGwKeyBadge.textContent = activeKeysTotal + ' 个 Key 生效';
};

async function refreshModelCatalog(btn){
  // 手动刷新模型清单：强制重取一次码道目录（服务端执行，绕过 300s 缓存），
  // 完成后立即重载表格。
  //
  // 这里原本打的是 /catalog/refresh —— 那是旧上游（copilot.tencent.com）的
  // 目录接口。本部署没有那种账号，点了必然失败，表现就是「按钮坏了」。
  const label = '码道';
  if(btn) btn.disabled = true;
  const prevText = btn ? btn.textContent : '';
  if(btn) btn.textContent = '刷新中...';
  try{
    const r = await postJSON('/accounts/codearts/refresh-catalog', {});
    if(r && r.ok){
      toast(label + '模型清单：' + (r.msg || '已更新'), 'ok');
      await loadModels();
    } else if(r && r.cooldown){
      // 冷却不是失败：清单还在、只是这次没到窗口，按提示语气说。
      toast(label + '模型清单：' + (r.msg || '刷新太频繁'), 'warn');
    } else {
      toast(label + '模型清单刷新失败：' + ((r && r.msg) || '未知原因'), 'warn');
    }
  }catch(e){
    toast(label + '模型清单刷新失败：' + e.message, 'bad');
  }finally{
    if(btn){ btn.disabled = false; btn.textContent = prevText; }
  }
}

async function loadModels(){
  try{
    const r = await getJSON('/v1/models?realm=' + encodeURIComponent(window.VIEW_REALM));
    MODELS_DATA = r.data || [];
    renderModelsSourceLine(r.catalog || null);
    renderAvailableModels();
  }catch(e){
    console.error('loadModels error:', e);
  }
}

// 清单来源横幅：把「通过 API 获取的最新数据」和「项目默认/缓存文件数据」在
// 视觉上分清楚——非 API 来源给黄色警示（模型、倍率数据可能不一致），API 来源
// 给绿色状态条并附刷新时间。数据由 /v1/models 响应的 catalog 字段驱动（见
// ca_proxy.catalog_meta）；旧版服务端没有该字段时如实提示。
const CATALOG_SOURCE_ORIGIN = {
  remote:   '上游 API · /v3/config',
  endpoint: '上游 API · /v1/models 端点',
  cache:    '本地配置文件（桌面客户端缓存）',
  legacy:   '本地配置文件（桌面客户端缓存）',
  bundled:  '内置快照'
};
const CATALOG_BANNER_BASE = 'font-size:12px;margin:0 0 12px;padding:7px 10px;border-radius:6px;'
  + 'display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;line-height:1.5;';

function fmtCatalogStamp(sec){
  const n = Number(sec);
  if(!n || n <= 0) return '';
  const d = new Date(n * 1000);
  if(isNaN(d.getTime())) return '';
  const p = v => String(v).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate())
    + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

function renderModelsSourceLine(meta){
  const el = document.getElementById('modelsSourceLine');
  if(!el) return;
  const tip = '清单构建顺序：先请求上游 API（/v3/config，用当前视图版本的账号）→ 失败则读取本机桌面客户端缓存文件 → 都拿不到才用内置快照。'
    + '清单在 5 分钟缓存期内复用，过期自动重取；网关后台每天也会兜底获取一次；点「刷新模型清单」可立即从上游更新。';
  if(!meta || !meta.source){
    el.style.cssText = CATALOG_BANNER_BASE + 'background:transparent;border:1px dashed var(--line);color:var(--dim)';
    el.title = tip;
    el.innerHTML = '数据来源：未知（当前网关进程版本较旧未提供来源信息，重启网关后可见）';
    return;
  }
  const isApi = (meta.source === 'remote' || meta.source === 'endpoint');
  const at = fmtCatalogStamp(meta.fetched_at);
  el.title = tip;
  if(isApi){
    el.style.cssText = CATALOG_BANNER_BASE
      + 'background:var(--accent2-soft);border:1px solid color-mix(in srgb,var(--accent2) 30%,transparent);color:var(--accent2)';
    el.innerHTML = '<b>✓ 当前为通过 API 获取的最新数据</b>'
      + '<span style="color:var(--dim)">刷新时间 ' + esc(at || '—')
      + ' · 来源 ' + esc(CATALOG_SOURCE_ORIGIN[meta.source] || meta.source) + '</span>';
    return;
  }
  // 非 API（缓存文件 / 内置快照）：警示横幅 + 真实出处做小字。
  let origin = CATALOG_SOURCE_ORIGIN[meta.source] || meta.source;
  if(meta.source === 'cache' || meta.source === 'legacy'){
    const fm = fmtCatalogStamp(meta.file_mtime);
    if(fm) origin += ' · 文件写入于 ' + fm;
    if(at) origin += ' · 网关读取于 ' + at;
  } else if(at){
    origin += ' · 生成于 ' + at;
  }
  el.style.cssText = CATALOG_BANNER_BASE
    + 'background:var(--warn-soft);border:1px solid color-mix(in srgb,var(--warn) 35%,transparent);color:var(--warn)';
  el.innerHTML = '<b>⚠ 当前为项目默认模型信息（未经 API 刷新）：模型、倍率数据可能不一致</b>'
    + '<span style="color:var(--dim)">数据出处：' + esc(origin)
    + ' · 建议点击「刷新模型清单」获取最新数据</span>';
}

function renderAvailableModels(){
  const tb = document.querySelector('#modelsTable tbody');
  if(!tb) return;
  const countEm = document.getElementById('availModelCount');
  if(countEm) countEm.textContent = '(共 ' + MODELS_DATA.length + ' 个)';
  if(!MODELS_DATA.length){
    tb.innerHTML = '<tr><td colspan="8" class="empty">暂无可用模型</td></tr>';
    return;
  }
  tb.innerHTML = MODELS_DATA.map(m => {
    // 1. 倍率与折扣 —— 一律以 /v1/models 取回的 credits 为准（活目录优先、
    //    内置快照兜底）。以前这里还按模型 id 写死了 hy3 / hy4-preview-f /
    //    几个模型标着"限时免费"，与 credits 值是 OR 关系，
    //    上游一旦调价面板会继续宣传免费；cn 的夜间注记在 credits 缺失时还会
    //    兜底显示写死的 0.79x。现在取不到就不显示数字。
    let credBadge = '-';
    const credText = (m.credits == null ? '' : String(m.credits)).trim();
    const c = credText.toLowerCase().replace('x', '');
    if(c === '0.00' || c === '0'){
      credBadge = '<span class="badge ok" style="background:var(--accent2-soft);color:var(--accent2)">限时免费 0.00x</span>';
    } else if(credText){
      // 统一成倍率写法：'x0.79' / '0.79' / 数字 0.5 都显示成 '0.79x' / '0.5x'。
      const raw = credText.replace(/^x/i, '') + 'x';
      const night = ((m.id === 'glm-5.2' || m.id === 'deepseek-v4-pro') && (window.VIEW_REALM === 'cn' || window.VIEW_REALM === 'codearts'))
        ? ' <span style="font-size:10px;color:var(--accent)">(夜间0.5x)</span>' : '';
      credBadge = '<span class="badge s">' + esc(raw) + night + '</span>';
    }

    // 1b. 计费规则（码道独有）：倍率只说明折扣，真正扣多少积分要按三个单价算。
    //     数据来自 /v1/models 的 credit_pricing，公式逆向自客户端
    //     calculateTurnCredits：credits = (input_price*(in-cache) + cache_price*cache
    //     + output_price*out) / 1e6 / ratio。所以「入 160 · 出 560 积分/M」就是
    //     花掉一百万个 token 要付的积分，比一个 0.7x 直观得多。
    const cp = m.credit_pricing;
    if(cp && cp.credits_per_mtok_output != null){
      const fmtC = v => { const n = Number(v) || 0; return n >= 100 ? Math.round(n) : (Math.round(n * 10) / 10); };
      const tip = '计费公式：' + (cp.formula || '')
        + '。单价：输入 ' + cp.input_price + ' 元/百万 · 缓存 ' + cp.cache_price
        + ' · 输出 ' + cp.output_price + '（人民币，每百万 token），再除以倍率 '
        + cp.ratio + '（' + (cp.ratio_display || '按站内标价') + '）。'
        + '换算结果：每百万输入 ' + fmtC(cp.credits_per_mtok_input) + ' 积分、'
        + '缓存 ' + fmtC(cp.credits_per_mtok_cache) + ' 积分、输出 '
        + fmtC(cp.credits_per_mtok_output) + ' 积分。';
      credBadge += '<div style="font-size:10px;color:var(--dim);margin-top:3px;cursor:help" title="' + esc(tip) + '">'
        + '入 ' + fmtC(cp.credits_per_mtok_input) + ' · 出 ' + fmtC(cp.credits_per_mtok_output) + ' 积分/M</div>';
    }
    // 1c. 错峰时段（码道 deepseek 独有）：上游同时给 default 与 off_peak 两档，
    //     只显示代表倍率会让用户以为夜里也按 0.18x 扣。把错峰的倍率单列一行，
    //     悬浮提示用上游自己的说明（含具体时段）。
    const offPeak = cp && cp.time_slots && cp.time_slots.off_peak;
    if(offPeak && offPeak.ratio_display){
      const offTip = offPeak.notice
        || ('错峰时段按 ' + offPeak.ratio_display + ' 计费'
            + (offPeak.schedule ? '（' + offPeak.schedule + '）' : ''));
      credBadge += '<div style="font-size:10px;color:var(--accent2);margin-top:2px;cursor:help" title="' + esc(offTip) + '">'
        + '错峰 ' + esc(offPeak.ratio_display) + '</div>';
    }

    // 2. 模型能力 (Vision, Tool calls)
    const caps = [];
    const hasVis = m.supports_vision || m.vision || m.multimodal || (m.input_modalities && m.input_modalities.includes('image'));
    if(hasVis){
      caps.push('<span class="badge ok" style="font-size:11px">视觉</span>');
    } else if(m.id === 'glm-5.3-flash' || m.vision_note){
      const tip = m.vision_note || '上游配置宣告支持多模态，但实际后端未接入视觉通道，已强制修正为纯文本';
      caps.push('<span class="badge warn" style="font-size:11px;background:var(--warn-soft);color:var(--warn);border-color:color-mix(in srgb,var(--warn) 35%,transparent)" title="' + esc(tip) + '">文本 (实测无视觉)</span>');
    } else {
      caps.push('<span class="badge" style="color:var(--dim);font-size:11px">文本</span>');
    }
    const hasTool = m.supports_tool_calls || (m.capabilities && m.capabilities.tool_calls);
    if(hasTool){
      caps.push('<span class="badge ok" style="font-size:11px">工具</span>');
    }
    const hasReasoning = m.supports_reasoning || m.reasoning_fixed_effort || (m.reasoning_efforts && m.reasoning_efforts.length);
    if(hasReasoning){
      caps.push('<span class="badge" style="background:var(--think-soft);color:var(--think);border-color:color-mix(in srgb,var(--think) 32%,transparent);font-size:11px;font-weight:600">推理</span>');
    }
    const capHtml = caps.join(' ');

    const fmtK = v => {
      if(!v) return '-';
      const k = Math.round(v / 1000);
      return k >= 1000 ? (k / 1000) + 'M' : k + 'K';
    };

    // 3. 上下文窗口
    //    context_source 说明这个数字的来源。'default' = 上游没给、实测表里也没有，
    //    按 1M 兜底 —— 它只是个占位估值，不能当规格看，所以在数字下面标注一下。
    let ctx = '-';
    if(m.context_length){
      ctx = '<b>' + fmtK(m.context_length) + '</b>';
      if(m.context_source === 'default'){
        ctx += '<div style="font-size:10px;color:var(--dim);margin-top:2px;cursor:help"'
          + ' title="上游既没返回上下文窗口，实测表里也没有这个模型；1M 是兜底估值，不是规格">估值</div>';
      }
    } else if(m.context_windows && m.context_windows.length){
      ctx = '<b>' + m.context_windows.map(fmtK).join(' / ') + '</b>';
    }

    // 4. 最大输出（有实测钳制时标注「钳制 N×」，数据来自 output_probes.json）
    let maxOut = m.max_output_tokens ? ('<b>' + fmtK(m.max_output_tokens) + '</b>') : '-';
    const clamp = Number(m.output_clamp || 0);
    if(clamp > 0){
      const claimed = Number(m.max_output_tokens || 0);
      const tip = '声称 ' + (claimed ? fmtK(claimed) : '?') + ' · 实测 ' + fmtK(clamp);
      if(!claimed){
        maxOut = '<b style="color:var(--warn)">' + fmtK(clamp) + ' ⚠</b>'
          + '<div style="font-size:11px;color:var(--warn);margin-top:2px" title="' + esc(tip) + '">实测上限</div>';
      }else if(clamp < claimed){
        const ratio = claimed / clamp;
        const xs = (ratio >= 10 ? Math.round(ratio) : Math.round(ratio * 10) / 10) + '×';
        maxOut = '<b style="color:var(--warn)">' + fmtK(clamp) + ' ⚠</b>'
          + '<div style="font-size:11px;color:var(--warn);margin-top:2px" title="' + esc(tip) + '">钳制 ' + xs + '</div>';
      }else{
        maxOut = '<b>' + fmtK(clamp) + '</b> <span style="color:var(--accent2)">✓</span>';
      }
    }

    // 5. 思考档位（档位徽章 + 默认档位 / 能否关闭思考两行注记）
    let effort = '<span style="color:var(--dim)">—</span>';
    const renderEffortBadge = e => {
      const lvl = String(e || '').toLowerCase();
      return '<span class="badge-effort">' + esc(lvl) + '</span>';
    };
    if(m.reasoning_fixed_effort){
      effort = renderEffortBadge(m.reasoning_fixed_effort);
    } else if(m.reasoning_efforts && m.reasoning_efforts.length === 1){
      effort = renderEffortBadge(m.reasoning_efforts[0]);
    } else if(m.reasoning_efforts && m.reasoning_efforts.length){
      effort = m.reasoning_efforts.map(renderEffortBadge).join(' ');
    } else if(m.supports_reasoning){
      effort = '<span class="badge-effort">原生</span>';
    }
    const effortNotes = [];
    if(m.reasoning_default_effort){
      effortNotes.push('默认 ' + esc(String(m.reasoning_default_effort)));
    }
    if(m.reasoning_can_disable === true){
      effortNotes.push('可关闭思考');
    } else if(m.reasoning_can_disable === false){
      effortNotes.push('不可关闭思考');
    }
    if(effortNotes.length){
      effort += '<div style="font-size:11px;color:var(--dim);margin-top:2px">' + effortNotes.join(' · ') + '</div>';
    }

    // 6. 名称（默认模型带星标；描述挂在名称的悬浮提示上）
    const nm = String(m.name || '').trim();
    const nmDesc = String(m.description || '').trim();
    const nameCell = '<td style="text-align:left" data-label="名称">'
      + (m.is_default ? '<span title="默认模型" style="color:var(--accent)">★</span> ' : '')
      + (nm
          ? '<span' + (nmDesc ? ' title="' + esc(nmDesc) + '"' : '') + '>' + esc(nm) + '</span>'
          : '<span style="color:var(--dim)">—</span>')
      + '</td>';

    // 7. 默认采样参数（上游对缺省请求生效的采样值；有的模型只给部分字段）
    const samples = [];
    if(m.temperature != null) samples.push('温度 ' + esc(String(m.temperature)));
    if(m.top_p != null) samples.push('top_p ' + esc(String(m.top_p)));
    const sampleCell = '<td style="text-align:left" data-label="默认采样参数">'
      + (samples.length
          ? '<span style="font-size:12px">' + samples.join(' · ') + '</span>'
          : '<span style="color:var(--dim)">—</span>')
      + '</td>';

    return '<tr>'
      + '<td style="text-align:left" class="mono" data-label="模型 ID"><b>' + esc(m.id) + '</b></td>'
      + nameCell
      + '<td style="text-align:center" data-label="消费倍率">' + credBadge + '</td>'
      + '<td style="text-align:center" data-label="能力">' + capHtml + '</td>'
      + '<td style="text-align:center" data-label="上下文">' + ctx + '</td>'
      + '<td style="text-align:center" data-label="最大输出">' + maxOut + '</td>'
      + '<td style="text-align:left" data-label="思考档位">' + effort + '</td>'
      + sampleCell
      + '</tr>';
  }).join('');
  applyTableSort('modelsTable');
}

const fmt = n => (n ?? 0).toLocaleString('en-US');
/* Token 数的紧凑显示：<1 万精确显示（千分位），≥1 万 K，≥100 万 M，≥10 亿 B；
   小数位随量级收缩（123K / 12.3K / 1.23K），尾零去掉。单位用大写 K/M/B，
   与表头排序解析器（cellSortValue 的 'K'/'M'/'G' 换算）同一口径，带单位的
   单元格照样按数值排序。 */
const fmtCompact = n => {
  const v = Number(n) || 0;
  const abs = Math.abs(v);
  const pick = (div, suffix) => {
    const x = v / div;
    const d = Math.abs(x) >= 100 ? 0 : Math.abs(x) >= 10 ? 1 : 2;
    return x.toFixed(d).replace(/(\.\d*?)0+$/, '$1').replace(/\.$/, '') + suffix;
  };
  if(abs >= 1e9) return pick(1e9, 'B');
  if(abs >= 1e6) return pick(1e6, 'M');
  if(abs >= 1e4) return pick(1e3, 'K');
  return fmt(v);
};
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const ms = v => v == null ? '—' : (v >= 1000 ? (v/1000).toFixed(2) + ' s' : Math.round(v) + ' ms');
const pct = v => v == null ? '—' : v.toFixed(1) + '%';

// ---- 表头点击排序 ---------------------------------------------------------
// 默认对所有数据表生效：任何带 id 的表都会自动接上，新加一张表不用改这里。例外
// 只有三处登记——SORT_DENY_TABLES（整表不排）、SORT_COL_KINDS（列类型 / 不可排）、
// SORT_PIN_ROWS（表体开头的汇总行）。
//
// 排的是渲染后的 DOM 行，不是回头排数据数组：单元格里已经是最终显示值，按数据重排
// 就得把那些格式化逻辑再抄一遍，两处不同步「看到的值」和「排出来的顺序」就会打架。
//
// 状态放在模块级变量里，所以 5 秒一次的整表重画不会把排序丢掉；没点过任何表头时
// SORT_STATE 里没有条目，各面板原本的默认顺序（多数是服务端顺序）原样保留。
//
// 手型、tooltip、箭头一律运行时挂到 DOM 上，源码标记一个字都不动——积分扣减历史表
// 的表头必须保持裸 <th>，最近请求表 / 按 Key 表 / 按账号表的行必须保持裸
// <tr>，这几条都有测试写死。

/* 整表不参与排序。默认任何带 id 的表都可排——新加一张表不必改这里。登记进来的
   一条，理由是：
     recent              最近请求严格按时间倒序，顺序本身就是要看的信息 */
const SORT_DENY_TABLES = new Set(['recent']);

/* 列类型的显式登记。默认按单元格内容推断（见 inferColKind），登记过的表按登记
   的来——「进度 4 / 10」「剩余 42 / 50 积分」「首字延迟 1.89 s (P50 1.90 s)」
   这类复合单元格只取其中一个数字是错的，得点名。

   下标 = 表头列序号。'num' 取单元格里的数字，'text' 按文本比，null = 该列不排
   （下拉框、按钮、拼给人看的标签串）。 */
const SORT_COL_KINDS = {
  modelsTable:      ['text', 'text', 'num', 'text', 'num', 'num', 'text', 'text'],
  // 时间列是 ISO 串，字典序就是时间序，不必另给排序值。
  creditHistoryTable: ['text', 'text', 'text', 'num', 'num'],
  analyticsAccountTable: ['text', 'num', 'num', 'num', 'num', null],
  analyticsKeyTable: ['text', 'num', 'num', 'num', 'num', 'num', null],
  perfMatrix:       ['text', 'text', 'num', 'num', 'num', 'num', 'num',
                     'num', 'num', 'num', 'num', 'num'],
};
/* 表体开头有几行是汇总行、不是数据行：矩阵面板的「全部模型合计」钉在表体第一行，
   它跟着表头走，不参与排序。 */
const SORT_PIN_ROWS = {perfMatrix: 1};
const SORT_STATE = {};
const SORT_HINT = '按此列排序（再点一次反向）';
/* 可排但当前没在排的列挂这个双向箭头——光靠手型和 tooltip 声明不了「这一列能排」，
   截图里看不见、触屏上也没有 hover。它是「能排」的常驻声明，▼ / ▲ 是「正在按这一列
   排」的状态，两者互斥。 */
const SORT_ARROW_IDLE = '⇅';
const SORT_KEY_PREFIX = 'ca-sort-';

/* 刷新后接着上次的选择排（键名照 ca-theme 的习惯）。读回来的列序号可能对不上
   表头——列增减、顺序调整都会让同一个序号指向别的字段，所以越界或那一列已经
   不可排就整条丢弃，退回该面板原本的默认顺序。

   遍历 localStorage 的键而不是 SORT_COL_KINDS：没登记过的表也存过选择，那些
   要一起恢复（列序号等 applyTableSort 推断出列类型时再校验）。 */
try {
  for(const key of Object.keys(localStorage)){
    if(key.indexOf(SORT_KEY_PREFIX) !== 0) continue;
    const id = key.slice(SORT_KEY_PREFIX.length);
    if(SORT_DENY_TABLES.has(id)) continue;
    const m = /^(\d+):(asc|desc)$/.exec(localStorage.getItem(key) || '');
    if(!m) continue;
    const col = Number(m[1]);
    const spec = SORT_COL_KINDS[id];
    if(spec && !spec[col]) continue;   // 登记过的表：越界或该列本就不排
    SORT_STATE[id] = {col: col, dir: m[2]};
  }
} catch(e) {}

/* 一个单元格的排序取值。返回 {text, forced}：forced 表示这个值是 data-sort 给的，
   不是显示出来的那个——那是给「显示的不是能排序的那个数」的列用的：剩余用量估算与
   积分获取历史的时间列显示 MM-DD HH:MM，跨年字典序就错，排序要的是 ISO 串。 */
function cellRaw(cell){
  const forced = cell.getAttribute ? cell.getAttribute('data-sort') : null;
  if(forced != null && forced !== '') return {text: String(forced), forced: true};
  return {text: String(cell.textContent == null ? '' : cell.textContent).trim(), forced: false};
}

/* 单元格取值。数字列忽略千分位、货币符号和百分号，并换算单位——否则「950 ms」和
   「4.01 s」会按 950 > 4.01 排反。量级单位只认大写 K/M/G：小写 m 在界面上是
   「分钟」（冷却列的 29m），当成百万去缩放会把冷却时间排得乱七八糟。取不到数的
   格（「—」「-」「未查询」）返回 null，恒沉底，不随升降序翻转。 */
function cellSortValue(cell, kind){
  if(!cell) return null;
  const raw = cellRaw(cell);
  const text = raw.text;
  if(kind === 'text') return text || null;
  // data-sort 给的已经是排序用的那个值，不再做千分位 / 单位解析。
  if(raw.forced){
    const n = Number(text);
    return isFinite(n) ? n : null;
  }
  const m = text.match(/(-?\d[\d,]*(?:\.\d+)?)\s*([A-Za-z%]*)/);
  if(!m) return null;
  const n = Number(m[1].replace(/,/g, ''));
  if(!isFinite(n)) return null;
  switch(m[2]){
    case 's': return n * 1000;   // 换算到毫秒，好跟同一列里的 ms 比
    case 'K': return n * 1e3;
    case 'M': return n * 1e6;
    case 'G': return n * 1e9;
    case 'B': return n * 1e9;   // fmtCompact 用 B 表示十亿，别让那一格按 1.5 排序
    default: return n;           // ms / % / 空 / 其它后缀（tok/s 之类）一律原值
  }
}

/* 整格就是一个「数字 + 可选单位」才算数字格。锚定整串而不是「搜到数字就算」：
   「glm-5.3」「10-09 16:19」里也有数字，但那两列该按文本排。 */
const SORT_NUM_CELL = /^[\s￥$]*(-?\d[\d,]*(?:\.\d+)?)\s*([A-Za-z%/]*)$/;
/* 取不到值的占位格，不参与整列的类型判断。 */
const SORT_BLANK_CELL = /^(—|-|–|未查询|无调用|无)$/;
/* 单元格里是交互控件的列不排：「出口」是下拉框、「操作」是按钮，拿它们的文字比
   大小没有意义。放在推断里而不是逐表登记，新表也能自动免掉这类列。 */
const SORT_WIDGET_SEL = 'select,button,input,textarea,a';

/* 整列的类型：'num' / 'text' / null（不可排）。只要有一个格按文本看，整列就按文本
   排——同一列里一半数字一半文本，混着比会乱。 */
function inferColKind(rows, col){
  let sawNum = false;
  for(const r of rows){
    const cell = r.children[col];
    if(!cell) continue;
    if(cell.querySelector && cell.querySelector(SORT_WIDGET_SEL)) return null;
    const text = cellRaw(cell).text;
    if(!text || SORT_BLANK_CELL.test(text)) continue;
    if(SORT_NUM_CELL.test(text)) sawNum = true;
    else return 'text';
  }
  return sawNum ? 'num' : null;
}

/* 一列的可排性与类型：登记过的表查表，没登记的按内容推断。 */
function colKind(id, i, rows, nCols){
  const spec = SORT_COL_KINDS[id];
  /* 登记表的列数与实际表头对不上时（上游加了一列或删了一列）不硬套登记——硬套
     会让每个序号都指向错的列，排出来的顺序看着对、其实全错。退回按内容推断：
     某一列可能排得不如登记时准，但不会错位。 */
  if(spec && spec.length === nCols) return spec[i] || null;
  return inferColKind(rows, i);
}

/* 按当前选中的列重排表体。 */
function applyTableSort(id){
  if(SORT_DENY_TABLES.has(id)) return;
  const root = document.getElementById(id);
  const table = !root ? null
    : (root.tagName === 'TABLE' ? root : root.querySelector('table'));
  if(!table) return;
  const thead = table.querySelector('thead');
  const tbody = table.querySelector('tbody');
  // 没有表头表体的不是数据表（KV 列表、纯布局表），不接。
  if(!thead || !tbody) return;
  // 把「表 → 登记项」接上，委托的点击监听才知道点的是哪张表。运行时挂，不进标记。
  table.setAttribute('data-sort-id', id);
  const rows = Array.from(tbody.children).filter(r => r.tagName === 'TR');
  const pinN = SORT_PIN_ROWS[id] || 0;
  const body = rows.slice(pinN);
  const ths = Array.from(thead.querySelectorAll('th'));
  const kinds = ths.map((th, i) => colKind(id, i, body, ths.length));
  const st = SORT_STATE[id] || null;
  ths.forEach((th, i) => {
    const kind = kinds[i];
    const active = !!(kind && st && st.col === i);
    if(!kind){
      /* 这一列不可排（登记成 null，或者推断出来整列没有可比内容）。把上一轮可能
         挂过的装饰摘干净——否则某一列的数据变空之后，表头还留着旧的手型和箭头，
         点上去没反应。 */
      th.classList.remove('sortable');
      th.removeAttribute('title');
      th.removeAttribute('tabindex');
      th.removeAttribute('aria-sort');
      const dead = th.querySelector('.sort-arrow');
      if(dead && dead.remove) dead.remove();
      return;
    }
    th.classList.add('sortable');
    /* tooltip 只补一次：i18n 会把它换成译文（title 在 ATTRS 里），每轮重写成中文
       会让它再翻一遍——英文 / 繁中界面下每 5 秒白跑一轮翻译。 */
    if(!th.title) th.title = SORT_HINT;
    // 可 Tab 聚焦，回车 / 空格触发（见下面那条 keydown 委托）。
    th.setAttribute('tabindex', '0');
    th.setAttribute('aria-sort', active ? (st.dir === 'asc' ? 'ascending' : 'descending') : 'none');
    /* 箭头只在真要变的时候动 DOM：这个函数每轮轮询都会跑一遍，白改一次就会多
       触发一轮 i18n 的 MutationObserver 重扫。 */
    const old = th.querySelector('.sort-arrow');
    const want = active ? (st.dir === 'asc' ? '▲' : '▼') : SORT_ARROW_IDLE;
    const cls = 'sort-arrow' + (active ? '' : ' idle');
    if(old){
      if(old.textContent !== want) old.textContent = want;
      if(old.className !== cls) old.className = cls;
    }else{
      // 前面不留空格：箭头是绝对定位的，不参与行内排版，留一个空格只会变成表头
      // 文本末尾的一个多余空白（读屏和复制表头时会带上）。
      th.insertAdjacentHTML('beforeend',
        '<span class="' + cls + '" aria-hidden="true">' + want + '</span>');
    }
  });
  if(!st || !kinds[st.col]) return;
  const kind = kinds[st.col];
  const dir = st.dir === 'asc' ? 1 : -1;
  const sorted = body
    .map((r, i) => [cellSortValue(r.children[st.col], kind), i, r])
    .sort((a, b) => {
      const av = a[0], bv = b[0];
      if(av == null || bv == null){
        if(av == null && bv == null) return a[1] - b[1];
        return av == null ? 1 : -1;   // 缺值的行沉底，两个方向都一样
      }
      const c = (typeof av === 'number' && typeof bv === 'number')
        ? av - bv : String(av).localeCompare(String(bv), 'zh-Hans-CN', {numeric: true});
      return c ? c * dir : a[1] - b[1];   // 同值保持原序，表不会自己抖
    })
    .map(t => t[2]);
  const ordered = rows.slice(0, pinN).concat(sorted);
  /* 顺序没变就别碰 DOM：每一轮轮询都会走这里，白挪一遍行没有任何收益，只会多触发
     一轮 i18n 的 MutationObserver 重扫。 */
  if(ordered.some((r, i) => rows[i] !== r)){
    // appendChild 对已在册的子节点是「移动」，所以这一遍就把顺序定下来了。
    ordered.forEach(r => tbody.appendChild(r));
  }
}

/* 扫一遍页面上所有数据表，把排序接上。挂在每 5 秒那条轮询上，新加一张表只要带
   id 就自动可排——不必在它的 render 函数里再写一行 applyTableSort。

   「带 id」这条把非数据表挡在外面：设置页的护栏表单、运行信息 / 其他客户端的 KV
   列表都没有 id（它们本来也不是能按列比大小的东西）。 */
function applyAllTableSorts(){
  if(!document.querySelectorAll) return;
  Array.from(document.querySelectorAll('table')).forEach(t => {
    const id = sortTableId(t);
    if(id) applyTableSort(id);
  });
}

/* 表的 id：自己带就用自己，否则找最近带 id 的祖先——最近请求、账号列表这些表是
   innerHTML 生成的，id 在包着它们的容器上。

   页面容器（.main-page）不算：那是「这一页」的 id，不是「这张表」的 id，拿它当
   表 id 会把设置页的护栏表单、账号页的表格一起误认成数据表。都没有就不接。 */
function sortTableId(table){
  let el = table;
  while(el && el !== document.body){
    if(el.id && !(el.classList && el.classList.contains('main-page'))) return el.id;
    el = el.parentElement || el.parentNode;
  }
  return '';
}

/* 同一列再点一次翻转方向；换一列一律从降序开始——「最大的排最上面」是这些表
   最常用的读法。 */
function toggleTableSort(id, col){
  if(SORT_DENY_TABLES.has(id)) return;
  const st = SORT_STATE[id];
  if(st && st.col === col) st.dir = st.dir === 'desc' ? 'asc' : 'desc';
  else SORT_STATE[id] = {col: col, dir: 'desc'};
  try { localStorage.setItem(SORT_KEY_PREFIX + id, col + ':' + SORT_STATE[id].dir); } catch(e) {}
  applyTableSort(id);
}

/* 点击与键盘两条委托都从这里问「点到 / 按到的是哪张表的哪一列」。表是每 5 秒整体
   重画的，逐个头挂监听就得跟着重挂，所以委托到 document。只认挂过 sortable 的表头
   ——不可排的列（下拉框、按钮、标签串）没挂，点了没反应。 */
function sortHeaderAt(e){
  const th = e.target && e.target.closest ? e.target.closest('th') : null;
  if(!th || !th.parentNode) return null;
  if(!th.classList || !th.classList.contains('sortable')) return null;
  const table = th.closest('table');
  const id = table && table.getAttribute ? table.getAttribute('data-sort-id') : null;
  if(!id) return null;
  const col = Array.from(th.parentNode.children).indexOf(th);
  return col < 0 ? null : {id: id, col: col};
}

document.addEventListener('click', e => {
  const hit = sortHeaderAt(e);
  if(hit) toggleTableSort(hit.id, hit.col);
});

/* 键盘走同一条路。空格在浏览器里默认是滚动页面，所以只在表头上吃掉它。 */
document.addEventListener('keydown', e => {
  if(e.key !== 'Enter' && e.key !== ' ' && e.key !== 'Spacebar') return;
  const hit = sortHeaderAt(e);
  if(!hit) return;
  e.preventDefault();
  toggleTableSort(hit.id, hit.col);
});



// 输入 / 输出 / 思考 三个数字，各自一色，斜杠分隔。思考为 0 也写出来，
// 列的形状因此固定，不会因某个模型不推理就缩短。
const tripleTokens = (inp, out, think) =>
  '<span style="color:var(--accent)">' + fmt(inp || 0) + '</span>' +
  ' <span style="color:var(--dim-light)">/</span> ' +
  '<span style="color:var(--accent2)">' + fmt(out || 0) + '</span>' +
  ' <span style="color:var(--dim-light)">/</span> ' +
  '<span style="color:var(--think)">' + fmt(think || 0) + '</span>';



function card(k, v, sub, cls){
  return '<div class="card ' + (cls||'') + '"><div class="k">' + k + '</div>'
    + '<div class="v">' + v + '</div>' + (sub ? '<div class="s">' + sub + '</div>' : '') + '</div>';
}

