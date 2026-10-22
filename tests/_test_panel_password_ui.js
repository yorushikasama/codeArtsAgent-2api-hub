/* 设置页改密码的契约：输错当前密码必须看得见、且不能被踢回登录页。
 *
 * 线上表现（2026-10-22 15:27）：用户点「修改密码」后没有任何提示，页面直接
 * 回到登录闸门。服务端日志是一条 `POST /panel/password 401` —— 当前密码
 * 校验没过。旧前端把这条 401 当成会话失效：清令牌、开闸门，而错误文案又被
 * toast 的 'unauthorized' 过滤掉，于是两个问题同时出现。
 *
 * 这里钉住四件事：
 *   1. 两栏相同时不发请求，并给出明确提示；
 *   2. 两栏不同时按 {current, new} 提交；成功后清掉会话、回到登录页；
 *   3. 401（当前密码不对）原样、持久地显示在表单下面，不清会话 token；
 *   4. 改密码的 401 不打开登录闸门。
 *
 * Run with Node: node tests/_test_panel_password_ui.js
 */
'use strict';

const assert = require('assert');
const {dashboardScript, dashboardHtml} = require('./_dashboard_source.js');

const script = dashboardScript();
const html = dashboardHtml();

// 输入框必须分开标注，密码管理器才不会把同一个值填进两栏。
assert.ok(/id="setPwdCurrent"[^>]*autocomplete="current-password"/.test(html),
  '当前密码输入框应带 autocomplete="current-password"');
assert.ok(/id="setPwdNew"[^>]*autocomplete="new-password"/.test(html),
  '新密码输入框应带 autocomplete="new-password"');
assert.ok(/id="setPwdCurrent"[^>]*padding:8px 38px 8px 12px/.test(html),
  '当前密码框右侧要给睁眼按钮留位置');
assert.ok(/togglePwdVisibility\(this,'setPwdCurrent'\)/.test(html),
  '当前密码框应有睁眼/闭眼按钮');
assert.ok(/togglePwdVisibility\(this,'setPwdNew'\)/.test(html),
  '新密码框应有睁眼/闭眼按钮');
assert.ok(!/id="setPwdReveal"/.test(html), '不应再有独立的「显示密码」复选框');
assert.ok(/id="setPwdMsg"/.test(html), '应有表单内、不会自动消失的提示位');

// 确认函数真的在脚本里（防止 HTML 改了、脚本没跟上）
assert.ok(script.indexOf('async function savePanelPassword') >= 0,
  'dashboard 脚本里应存在 savePanelPassword');

const dom = require('./_dom_stub.js');
const {loadDashboard} = require('./_dashboard_sandbox.js');

const calls = [];
let reply = {status: 200, body: {ok: true, token: 'tok-new', synced_env: true}};

const page = loadDashboard({
  fetch: (url, options) => {
    calls.push({url: String(url), method: (options && options.method) || 'GET',
                body: options && options.body});
    const bodyText = JSON.stringify(reply.body);
    return Promise.resolve({
      status: reply.status,
      ok: reply.status >= 200 && reply.status < 300,
      text: () => Promise.resolve(bodyText),
      json: () => Promise.resolve(reply.body),
    });
  },
});

const toasts = [];
page.toast = (msg, kind) => toasts.push({msg: String(msg), kind: kind});

function reset() { calls.length = 0; toasts.length = 0; }

(async () => {
  const doc = page.document;
  const cur = doc.getElementById('setPwdCurrent');
  const nw = doc.getElementById('setPwdNew');
  const msg = doc.getElementById('setPwdMsg');
  const btn = doc.createElement('button');
  const gate = doc.getElementById('panelGate');
  const loginMsg = doc.getElementById('panelLoginMsg');

  // 0. 睁眼/闭眼：只切换输入框的 type，并把按钮文案换掉
  const eye = doc.createElement('button');
  cur.type = 'password';
  page.togglePwdVisibility(eye, 'setPwdCurrent');
  assert.strictEqual(cur.type, 'text', '点睁眼后应显示明文');
  assert.strictEqual(eye.getAttribute('aria-label'), '隐藏密码');
  page.togglePwdVisibility(eye, 'setPwdCurrent');
  assert.strictEqual(cur.type, 'password', '再点一次应恢复掩码');
  assert.strictEqual(eye.getAttribute('aria-label'), '显示密码');

  // 1. 两栏相同：不发请求，提示清楚
  reset();
  cur.value = 'admin';
  nw.value = 'admin';
  await page.savePanelPassword(btn);
  assert.strictEqual(calls.length, 0, '两栏相同时不应发请求');
  assert.ok(/相同/.test(msg.textContent), '应提示新密码与当前密码相同: ' + msg.textContent);

  // 2. 两栏不同：按 {current, new} 提交；成功后清掉会话、回到登录页
  reset();
  gate.style.display = 'none';
  loginMsg.textContent = '';
  page.sessionStorage.setItem('codearts-hub-panel-token', 'tok-old');
  reply = {status: 200, body: {ok: true, synced_env: true}};
  cur.value = 'old-pass';
  nw.value = 'new-pass';
  await page.savePanelPassword(btn);
  assert.strictEqual(calls.length, 1, '应恰好发一次请求');
  assert.strictEqual(calls[0].url, '/panel/password');
  assert.strictEqual(calls[0].method, 'POST');
  assert.deepStrictEqual(JSON.parse(calls[0].body), {current: 'old-pass', new: 'new-pass'});
  assert.strictEqual(page.sessionStorage.getItem('codearts-hub-panel-token'), null,
    '改完密码应清掉会话 token（服务端也不再下发新 token）');
  assert.strictEqual(gate.style.display, 'flex', '改完密码应回到登录页');
  assert.ok(/请用新密码重新登录/.test(loginMsg.textContent),
    '登录页应提示用新密码重新登录: ' + loginMsg.textContent);
  assert.strictEqual(cur.value, '', '成功后应清空当前密码');
  assert.strictEqual(nw.value, '', '成功后应清空新密码');

  // 3. 当前密码不对：文案原样显示在表单里，会话 token 不能被清
  reset();
  loginMsg.textContent = '';
  page.sessionStorage.setItem('codearts-hub-panel-token', 'tok-live');
  reply = {status: 401, body: {error: {message: '当前密码不正确，请重新输入；若忘了，可在服务端用 --panel-password-force 重置'}}};
  cur.value = 'wrong-pass';
  nw.value = 'another-pass';
  await page.savePanelPassword(btn);
  assert.ok(/当前密码不正确/.test(msg.textContent),
    '401 文案应持久显示在表单里: ' + msg.textContent);
  assert.strictEqual(page.sessionStorage.getItem('codearts-hub-panel-token'), 'tok-live',
    '401 不应清掉现有会话 token');

  // 4. 这条 401 不能走 panelSessionLost：它会把提示改成「会话已失效」并弹出
  //    登录闸门。闸门本身在这个沙箱里可能已被启动流程打开，所以用它专属的
  //    提示文本判断，而不是 display 值。
  assert.strictEqual(loginMsg.textContent, '',
    '当前密码填错不应触发「会话已失效」并弹登录页');

  // 5. 会话真失效（路由最前面的检查）才提示重新登录
  reset();
  reply = {status: 401, body: {error: {message: 'panel password required'}}};
  cur.value = 'whatever';
  nw.value = 'another-pass';
  await page.savePanelPassword(btn);
  assert.ok(/会话已失效/.test(msg.textContent),
    '会话失效应给出中文提示: ' + msg.textContent);

  console.log('panel password UI assertions passed (5 groups)');
})().catch(err => {
  console.error(err && err.stack || err);
  process.exit(1);
});
