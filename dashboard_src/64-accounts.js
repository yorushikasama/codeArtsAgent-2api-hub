/* ------------------------------- accounts ------------------------------- */
let USAGE_BY_ACCOUNT = {};

/* The API sends epoch seconds; display the recovery in the browser's local time. */
function fmtCoolAt(epoch){
  const seconds = Number(epoch);
  if(!Number.isFinite(seconds) || seconds <= 0) return '';
  const d = new Date(seconds * 1000);
  if(!Number.isFinite(d.getTime())) return '';
  const two = n => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + two(d.getMonth() + 1) + '-' + two(d.getDate())
    + ' ' + two(d.getHours()) + ':' + two(d.getMinutes());
}
// 徽章里放不下完整时间，折算成剩余量：45s / 29m / 2h05m。
function fmtLeft(seconds){
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  if(s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if(m < 60) return m + 'm';
  return Math.floor(m / 60) + 'h' + String(m % 60).padStart(2, '0') + 'm';
}
function coolPills(a){
  const list = a && Array.isArray(a.modelCooldowns) ? a.modelCooldowns : [];
  const pills = list.map(c => {
    const at = c && fmtCoolAt(c.expiresAt);
    if(!at) return '';
    // 撞过线（上游 code 6004）的模型带 cappedAt：把撞线时间一并画出来，
    // 两段时间配合就能看出这是窗口配额用满，而不是一次临时限流。
    const hit = c && fmtCoolAt(c.cappedAt);
    return hit
      ? '<span class="cool-pill" title="该账号仅此模型受限（上游判定额度用满）；撞线时间与恢复时间均为本地时间">'
        + esc(c.model) + ' · 撞线 ' + hit + ' · 恢复 ' + at + '</span>'
      : '<span class="cool-pill" title="该账号仅此模型受限；时间为本地时间">'
        + esc(c.model) + ' · ' + at + ' 恢复</span>';
  }).filter(Boolean);
  return pills.length ? '<div class="cool-list">' + pills.join('') + '</div>' : '';
}

// 按模型达日限额的模型清单（与冷却并列展示）：只影响列出的模型，其他模型照常。
function modelLimitPills(a){
  const limit = Number(a.modelDailyTokenLimit || 0);
  if(limit <= 0 || !a.modelDailyTokens) return '';
  const hit = Object.entries(a.modelDailyTokens)
    .filter(([mid, v]) => Number(v) >= limit);
  if(!hit.length) return '';
  return '<div class="cool-list">' + hit.map(([mid, v]) =>
    '<span class="cool-pill" title="该模型今日已达限额，仅此模型受限（本地 0 点恢复）">'
      + esc(mid) + ' · ' + fmt(v) + ' tok 达限</span>'
  ).join('') + '</div>';
}

// ---- 每日活动（国内签到 / 国际活跃）------------------------------------
// GET /activity/history 是唯一事实来源。账号行上的状态只由「今天已记录的事件」
// 推导：**没有记录不等于失败**，所以缺记录时给的是中性文案而不是红色。账号自带的
// lastActivityReport 只在「今天确实完成过、但这一版还没留下历史行」时补一个中性的
// 「今日已完成」，不据此伪造事件、时间或说明。
// 旧的每日签到（lastCheckin）已随码道领取上线而移除，此处不再回落。
// 关联键始终是 uid：切区域、刷新账号都只是重画同一份按 uid 建的表，另一个账号的
// 事件不会画到这一行上。
let ACTIVITY_TODAY = {byUid: {}, error: '', loaded: false};
const ACT_FILTER = {range: '7d', uid: '', task: '', result: ''};

const ACTIVITY_TASKS = {checkin: '国内签到'};
const ACTIVITY_TRIGGERS = {scheduler: '定时', manual: '手动',
                           account_add: '添加账号', account_import: '导入账号'};

function todayStamp(){
  const d = new Date();
  const pad = n => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
}

// 一个账号今天的活动状态。
// 国际版每日活跃已随该区域移除，这里只剩国内版一项：成长计划连登打卡
//（lastActivityReport）。旧的每日签到（lastCheckin）也已移除，签到改由码道
// 账号区的「领取每日 Token」承担 —— 那边读的是服务端余额而不是这里的历史流水，
// 所以两者不共用状态字段。
function activityStatusOf(a){
  const uid = String((a && a.uid) || '');

  // 国内版：成长计划连登打卡
  const streakDone = a && a.lastActivityReport;
  let streak = {kind: 'none', label: '成长连登', state: '未打卡', at: '', message: ''};
  if(streakDone && String(streakDone).startsWith(todayStamp())){
    streak = {kind: 'done', label: '成长连登', state: '已打卡', at: String(streakDone), message: '连登活跃已上报'};
  }

  return {isCn: true, streak: streak,
          kind: streak.kind === 'done' ? 'done' : 'none'};
}

function activityStatusChip(a){
  const status = activityStatusOf(a);
  const uidAttr = esc(String((a && a.uid) || '').replace(/[^\w.@-]/g, ''));
  const stkCls = (status.streak.kind === 'done') ? 'badge ok' : 'badge off';
  const stkTip = '成长计划连登活跃：' + status.streak.state
               + (status.streak.at ? ' · ' + status.streak.at : '');
  return '<span class="' + stkCls + '" style="cursor:pointer;white-space:nowrap" title="' + esc(stkTip) + '"'
    + ' onclick="openActivityHistory(&quot;' + uidAttr + '&quot;)">'
    + esc('成长计划 · ' + (status.streak.kind === 'done' ? '已签到' : '未签到')) + '</span>';
}

// 今天的事件，按 uid 建表。rows 是最新在前，所以第一次见到的就是最近一次。
// 读不到历史只是没有状态可显示：绝不能让它把账号区一起带坏。
async function loadActivityToday(){
  try{
    const payload = await getJSON('/activity/history?range=today&limit=200');
    const rows = (payload && Array.isArray(payload.rows)) ? payload.rows : [];
    const byUid = {};
    rows.forEach(row => {
      const uid = String((row && row.uid) || '');
      if(uid && !byUid[uid]) byUid[uid] = row;
    });
    ACTIVITY_TODAY = {byUid: byUid, error: '', loaded: true};
  }catch(e){
    ACTIVITY_TODAY = {byUid: {}, error: (e && e.message) || '读取失败', loaded: true};
  }
}



// 面板拼查询串，筛选在服务端做；写错的取值服务端会回 400，这里原样透出。
function activityFilterQuery(){
  const parts = ['range=' + encodeURIComponent(ACT_FILTER.range || '7d'), 'limit=200'];
  if(ACT_FILTER.uid) parts.push('uid=' + encodeURIComponent(ACT_FILTER.uid));
  if(ACT_FILTER.task) parts.push('task=' + encodeURIComponent(ACT_FILTER.task));
  if(ACT_FILTER.result) parts.push('result=' + encodeURIComponent(ACT_FILTER.result));
  return '/activity/history?' + parts.join('&');
}

function renderActivityFilters(){
  const uidSel = document.getElementById('actUid');
  if(uidSel){
    const accounts = Array.isArray(window.ACCOUNTS) ? window.ACCOUNTS : [];
    uidSel.innerHTML = '<option value="">全部账号</option>' + accounts.map(a =>
      '<option value="' + esc(String(a.uid || '')) + '">'
      + esc((a.nickname || a.uid || '') + ' · 国内版')
      + '</option>').join('');
  }
  const bind = (id, value) => {
    const el = document.getElementById(id);
    if(el) el.value = value;
  };
  bind('actRange', ACT_FILTER.range);
  bind('actUid', ACT_FILTER.uid);
  bind('actTask', ACT_FILTER.task);
  bind('actResult', ACT_FILTER.result);
}

function activityHistoryRow(row){
  const uid = String((row && row.uid) || '');
  const nick = String((row && row.nickname) || '') || (uid ? uid.slice(0, 8) : '未知账号');
  const task = ACTIVITY_TASKS[row && row.task] || '—';
  const trigger = ACTIVITY_TRIGGERS[row && row.trigger] || '';
  const message = String((row && row.message) || '');
  return '<tr>'
    + '<td class="mono" data-label="时间">'
    +   esc(String((row && row.ts) || '').replace('T', ' ').slice(0, 19)) + '</td>'
    + '<td data-label="账号">' + esc(nick)
    +   (uid ? '<div class="mono" style="color:var(--dim);font-size:11px">' + esc(uid.slice(0, 8)) + '</div>' : '')
    + '</td>'
    + '<td data-label="任务">' + esc(task)
    +   (trigger ? '<div style="color:var(--dim);font-size:11px">' + esc(trigger) + '</div>' : '')
    + '</td>'
    + '<td data-label="结果">'
    +   (row && row.ok ? '<span class="badge ok">成功</span>' : '<span class="badge bad">失败</span>')
    + '</td>'
    // 上游原文可能很长：在 span 上做行内截断（td 自身不吃 max-width），完整
    // 内容留在 title 里，模态框不会被撑宽。
    + '<td data-label="说明" style="text-align:left">'
    +   '<span style="display:inline-block;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom"'
    +   ' title="' + esc(message) + '">' + esc(message || '—') + '</span></td>'
    + '</tr>';
}

function renderActivityHistory(payload, error){
  const box = document.getElementById('activityHistoryRows');
  const meta = document.getElementById('activityHistoryMeta');
  if(!box) return;
  if(error){
    box.innerHTML = '<tr><td colspan="5" class="empty">活动记录读取失败：'
      + esc(error) + '</td></tr>';
    if(meta) meta.textContent = '';
    return;
  }
  const rows = (payload && Array.isArray(payload.rows)) ? payload.rows : [];
  const total = (payload && payload.total != null) ? payload.total : rows.length;
  if(meta) meta.textContent = rows.length ? ('显示 ' + rows.length + ' / ' + total + ' 条') : '';
  if(!rows.length){
    box.innerHTML = '<tr><td colspan="5" class="empty">这段时间没有活动记录</td></tr>';
    return;
  }
  box.innerHTML = rows.map(activityHistoryRow).join('');
}

function loadActivityHistory(){
  const box = document.getElementById('activityHistoryRows');
  if(box) box.innerHTML = '<tr><td colspan="5" class="empty">正在读取活动记录…</td></tr>';
  return getJSON(activityFilterQuery()).then(payload => {
    renderActivityHistory(payload, '');
  }).catch(e => {
    renderActivityHistory(null, (e && e.message) || '读取失败');
  });
}



// uid 为空表示「全部账号」；从账号行的状态徽章点进来时带上该账号，等于预筛选。
function openActivityHistory(uid){
  ACT_FILTER.uid = String(uid || '');
  const mask = document.getElementById('activityHistoryModal');
  if(mask) mask.style.display = 'flex';
  renderActivityFilters();
  return loadActivityHistory();
}



// 账号的手动调度权重提示：与 ca_accounts._pick_weighted_first 的行为一一对应。
const WEIGHT_TIP = '权重 >1 的账号优先接单，多个高权重账号按权重比分流量；它们都接不了单时其他账号照常顶上。已开始的会话保持粘性不换号，权重对新会话生效。1 = 不干预。';



// 悬停气泡（全局单例）。用自定义 DOM 而不是原生 title：原生 tooltip 由浏览器
// 自己绘制，既截不进图、也没法控制样式与换行。元素只要带 data-tip 就生效，
// 事件走委托，动态重渲染出来的节点不必重新绑定。
let _hoverTip = null;
function moveHoverTip(e){
  if(!_hoverTip) return;
  const pad = 14;
  const w = _hoverTip.offsetWidth, h = _hoverTip.offsetHeight;
  let x = e.clientX + pad, y = e.clientY + pad;
  if(x + w > window.innerWidth - 8) x = Math.max(8, e.clientX - w - pad);
  if(y + h > window.innerHeight - 8) y = Math.max(8, e.clientY - h - pad);
  _hoverTip.style.left = x + 'px';
  _hoverTip.style.top = y + 'px';
}
function ensureHoverTip(){
  if(_hoverTip) return _hoverTip;
  const el = document.createElement('div');
  el.id = 'hoverTip';
  el.style.cssText = 'position:fixed;z-index:9999;display:none;max-width:560px;'
    + 'padding:8px 10px;border-radius:8px;background:var(--panel);border:1px solid var(--line);'
    + 'box-shadow:var(--shadow-sm);font-size:12px;line-height:1.55;color:var(--fg);'
    + 'white-space:pre-wrap;word-break:break-word;pointer-events:none';
  document.body.appendChild(el);
  _hoverTip = el;
  document.addEventListener('mouseover', e => {
    const host = e.target && e.target.closest ? e.target.closest('[data-tip]') : null;
    if(!host) return;
    el.textContent = host.getAttribute('data-tip');
    el.style.display = 'block';
    moveHoverTip(e);
  });
  document.addEventListener('mousemove', e => {
    if(el.style.display === 'block') moveHoverTip(e);
  });
  document.addEventListener('mouseout', e => {
    const host = e.target && e.target.closest ? e.target.closest('[data-tip]') : null;
    if(host) el.style.display = 'none';
  });
  return el;
}

// 当前视图的账号：realm 为空的账号两侧都可见，与账号卡片一直以来的口径一致。
// 全页只留这一处 realm 过滤表达式 —— 账号卡片与「当前禁用账号与模型」都走它，
// 两处不会各写一份、然后各自漂移。视图的真源是 window.VIEW_REALM。
function accountsInView(){
  const view = window.VIEW_REALM || "codearts";
  return (window.ACCOUNTS || []).filter(a => !a.realm || a.realm === view);
}

// 当前禁用总览：把散落在账号卡片上的停用/限流状态汇总成一张表。
// 四类来源：①面板手动停用 ②上游账号级冷却 ③上游模型级冷却 ④本地日限额/积分护栏。
// 全部读 window.ACCOUNTS，不额外发请求；数据与账号卡片同源，不会互相矛盾。
// 只描述当前视图（accountsInView）：计数、分组与空状态都从这同一份过滤后的数据
// 算出来，否则会看到陈旧的停用状态（issue #31）。
function disabledRows(){
  const rows = [];
  const now = Math.floor(Date.now() / 1000);
  // 日限额与积分护栏按本地自然日恢复，这里取下一个零点。
  const nextMidnight = (() => {
    const d = new Date(); d.setHours(24, 0, 0, 0);
    return Math.floor(d.getTime() / 1000);
  })();
  accountsInView().forEach(a => {
    const who = (a.nickname || '?') + ' (' + String(a.uid || '').slice(0, 8) + ')';
    const realm = '国内版';
    const detail = a.lastErrorDetail || '';
    if(!a.enabled){
      rows.push({who, realm, scope: '账号', kind: '本地停用', manual: true,
                 reason: '面板手动停用，该账号不参与轮询', until: ''});
    }
    if(a.inCooldown){
      const secs = Number(a.cooldownFor || 0);
      const streak = Number(a.softStreak || 0);
      rows.push({who, realm, scope: '账号', kind: '上游限流', detail,
                 reason: (a.lastError || '上游 429')
                       + (streak > 1 ? '（连续软限流 ' + streak + ' 次，冷却按 2 倍递增）' : ''),
                 until: secs > 0 ? fmtCoolAt(now + secs) : ''});
    }
    if(a.breakerFor){
      const secs = Number(a.breakerFor || 0);
      rows.push({who, realm, scope: '账号', kind: '熔断', detail,
                 reason: '上游连续失败触发熔断，本窗口内不接单（账号与凭证本身没问题，恢复后可继续用）',
                 until: secs > 0 ? fmtCoolAt(now + secs) : ''});
    }
    if(a.degradeFor){
      const secs = Number(a.degradeFor || 0);
      rows.push({who, realm, scope: '账号', kind: '降权', detail,
                 reason: '连续未知失败进入降权窗口，优先级被压低',
                 until: secs > 0 ? fmtCoolAt(now + secs) : ''});
    }
    (Array.isArray(a.modelCooldowns) ? a.modelCooldowns : []).forEach(c => {
      if(!c || !c.model) return;
      // 带 cappedAt 的是 6004 撞线（恢复时间来自上游）：撞线时间单独一列。
      const hit = c.cappedAt ? fmtCoolAt(c.cappedAt) : '';
      // 起始时刻：6004 用上游给的撞线时刻；其余 429 用 hub 记下的限流时刻
      // （c.startedAt）。两者都取不到时才留空——不用假值填充表格。
      const started = hit || (c.startedAt ? fmtCoolAt(c.startedAt) : '');
      // 两类模型级限流的原因必须分开写：带 cappedAt 的是上游 6004 配额耗尽
      // （恢复时间以小时计），不带 cappedAt 的只是一次 429 临时限流（60s~10m
      // 的短窗口，到点自动恢复）。共用一句「配额耗尽」会把短时 parking 说成
      // 要等几小时，也让真正该关注的 6004 淹没在里面。
      rows.push({who, realm, scope: c.model, kind: '上游限流', detail, cappedAt: hit,
                 startedAt: started,
                 reason: hit
                   ? '该模型配额耗尽（code 6004），同账号其他模型不受影响'
                   : '该模型被上游临时限流（429），仅此模型受限，到点自动恢复',
                 until: fmtCoolAt(c.expiresAt)});
    });
    if(a.dailyLimitBlocked){
      rows.push({who, realm, scope: '账号', kind: '日限额',
                 reason: '今日 token ' + Number(a.dailyTokensToday || 0).toLocaleString()
                       + ' / 上限 ' + Number(a.dailyTokenLimit || 0).toLocaleString(),
                 until: fmtCoolAt(nextMidnight)});
    }
    if(a.creditLimitReached){
      rows.push({who, realm, scope: '账号', kind: '积分限额',
                 reason: '剩余积分低于保留线', until: fmtCoolAt(nextMidnight)});
    }
    const mcap = Number(a.modelDailyTokenLimit || 0);
    if(mcap > 0 && a.modelDailyTokens){
      Object.entries(a.modelDailyTokens).forEach(([mid, v]) => {
        if(Number(v) >= mcap){
          rows.push({who, realm, scope: mid, kind: '日限额',
                     reason: '今日 token ' + Number(v).toLocaleString() + ' / 上限 ' + mcap.toLocaleString(),
                     until: fmtCoolAt(nextMidnight)});
        }
      });
    }
  });
  return rows;
}

function renderDisabled(){
  const box = document.getElementById('disabledList');
  if(!box) return;
  ensureHoverTip();
  const count = document.getElementById('disabledCount');
  const rows = disabledRows();
  if(count) count.textContent = rows.length ? '(' + rows.length + ')' : '';
  if(!rows.length){
    box.innerHTML = '<div class="legend" style="margin:0"><span>当前没有禁用的账号或模型。</span></div>';
    return;
  }
  const badge = k => k === '上游限流' ? 'warn' : (k === '本地停用' || k === '熔断' ? 'bad' : 's');
  box.innerHTML = '<div class="table-wrap"><table class="data-cards"><thead><tr>'
    + '<th style="text-align:left">账号</th>'
    + '<th style="text-align:center;width:76px">版本</th>'
    + '<th style="text-align:left">范围</th>'
    + '<th style="text-align:center;width:100px">类型</th>'
    + '<th style="text-align:left">原因</th>'
    + '<th style="text-align:center;width:156px">开始时间</th>'
    + '<th style="text-align:center;width:156px">恢复时间</th>'
    + '</tr></thead><tbody>'
    + rows.map(r => '<tr>'
        + '<td style="text-align:left">' + esc(r.who) + '</td>'
        + '<td style="text-align:center">' + esc(r.realm) + '</td>'
        + '<td style="text-align:left" class="mono">' + esc(r.scope) + '</td>'
        + '<td style="text-align:center"><span class="badge ' + badge(r.kind) + '">' + esc(r.kind) + '</span></td>'
        + '<td style="text-align:left"' + (r.detail ? ' data-tip="' + esc(r.detail) + '"' : '') + '>'
          + esc(r.reason) + '</td>'
        // 开始时间：这一行是何时进入该状态的。模型级限流两类都有真实时刻——
        // 6004 是上游给的撞线时刻（cappedAt），临时 429 是 hub 记下的限流时刻
        // （startedAt）；其余行类没有起始时刻，留「—」。
        + '<td style="text-align:center">' + esc(r.startedAt || '—') + '</td>'
        + '<td style="text-align:center">' + (r.manual ? '—（需手动启用）' : (r.until || '—')) + '</td>'
        + '</tr>').join('')
    + '</tbody></table></div>';
  applyTableSort('disabledList');
}

