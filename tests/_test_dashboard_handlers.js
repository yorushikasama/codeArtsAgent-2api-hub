/* Every inline event handler in the dashboard must have a function behind it.
 *
 * A handler name that no longer exists fails only in the browser, only when
 * that exact control is used, and only as a console error - no server-side
 * test can see it. The empty state's "登录新账号 (OAuth)" button shipped that
 * way for a month (issue #66): it still called startLogin(), which had been
 * replaced by openLoginModal() back in v1.1.0, so the first button a fresh
 * deployment puts in front of a new user did nothing at all.
 *
 * The sweep is textual on purpose: it reads the shipped dashboard.html, so it
 * covers every handler at once instead of the one that happened to be
 * reported, and it keeps working when the page is refactored.
 *
 * Run with Node: node tests/_test_dashboard_handlers.js
 */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'dashboard.html'), 'utf8');

// Inline attributes, e.g. onclick="setAnalyticsRange('today')".
const HANDLER_ATTR = /\son(?:click|change|input|submit|keydown|keyup|blur|focus)\s*=\s*"([^"]*)"/g;
// A plain call: `foo(` counts, `this.foo(` is a method and does not.
const CALL = /(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(/g;
// Keywords and browser builtins, which are not page functions.
const NOT_PAGE_FUNCTIONS = new Set([
  'if', 'for', 'while', 'switch', 'return', 'typeof', 'new', 'function',
  'alert', 'confirm', 'prompt', 'setTimeout', 'setInterval', 'clearTimeout',
  'parseInt', 'parseFloat', 'Number', 'String', 'Boolean', 'Date', 'Math',
  'JSON', 'encodeURIComponent', 'decodeURIComponent',
]);

const referenced = new Set();
for (const [, body] of html.matchAll(HANDLER_ATTR)) {
  for (const [, name] of body.matchAll(CALL)) {
    if (!NOT_PAGE_FUNCTIONS.has(name)) referenced.add(name);
  }
}

const defined = new Set();
for (const [, name] of html.matchAll(/function\s+([A-Za-z_$][\w$]*)\s*\(/g)) defined.add(name);
for (const [, name] of html.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\()/g)) {
  defined.add(name);
}
// `window.name = function(...)` is the other way this page defines a handler;
// the theme block's applyTheme / selectTheme / toggleThemeMenu all use it.
// Whether such a name is actually reachable from an inline attribute is a
// scope question this textual sweep cannot answer - _test_dashboard_theme.js
// executes the theme block and checks that.
for (const [, name] of html.matchAll(/window\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\()/g)) {
  defined.add(name);
}

const missing = [...referenced].filter(name => !defined.has(name)).sort();

// A regex that stopped matching would let this test pass silently, so insist
// it is still looking at a real page.
assert.ok(referenced.size >= 30,
  `the sweep found only ${referenced.size} handlers; the extraction broke, not the page`);

assert.deepStrictEqual(missing, [],
  `inline handlers with no function behind them: ${missing.join(', ')}`);

// 旧账号子系统（账号池 / OAuth 登录弹窗 / 空态「添加账号」按钮）已整体删除，
// 这两条钉子随之失效：openLoginModal 与 startLogin 都不该再被任何地方引用。
assert.ok(!/\bopenLoginModal\b/.test(html),
  'nothing may reference the removed openLoginModal()');
assert.ok(!/onclick="startLogin\(\)"/.test(html),
  'nothing may call the removed startLogin()');
// 现在的唯一账号入口是码道，钉住它，避免回归成又指向旧体系。
assert.ok(/onclick="openCodeartsLogin\(\)"/.test(html),
  'the account entry must call openCodeartsLogin()');

async function checkCheckinControls(){
  const page = html.match(/<section>\s*<div[^>]*>\s*<h2[^>]*>码道账号<\/h2>[\s\S]*?<\/section>/)[0];
  assert.match(page, /id="caClaimAllBtn" onclick="claimCodeartsWelfareAll\(this\)"/);
  assert.match(page, /onclick="openCodeartsLogin\(\)"/);
  assert.strictEqual((html.match(/id="caClaimAllBtn"/g) || []).length, 1);

  // The built dashboard joins several fragments into one script. Don't run
  // unrelated dashboard bootstrap when checking the account controls.
  const script = fs.readFileSync(path.join(__dirname, '..', 'dashboard_src', '60-codearts.js'), 'utf8')
    .replace(/^<script>\s*/, '');
  const boxes = [{id: 'codeartsPageList'}, {id: 'codeartsList'}];
  const calls = [], notices = [];
  let reads = 0;
  const ui = vm.createContext({
    window: {},
    document: {querySelectorAll: () => boxes, getElementById: () => null, addEventListener: () => {}},
    console,
    getJSON: async url => {
      assert.strictEqual(url, '/accounts/codearts');
      reads++;
      return {accounts: [{account_id: 'a', welfare: {claimable: true}}]};
    },
    postJSON: async (url, payload) => {
      calls.push([url, JSON.stringify(payload)]);
      return {results: payload.accountId
        ? [{ok: true, partial: true, amount: 100}]
        : [{ok: true, pending: true}, {ok: true, already: true}]};
    },
    toast: (message, kind) => notices.push([message, kind]),
  });
  vm.runInContext(script, ui);
  await ui.loadCodeartsAccounts();
  assert.match(boxes[0].innerHTML, /data-ca-id="a" onclick="claimCodeartsWelfare\(this\)"/);
  assert.doesNotMatch(boxes[1].innerHTML, /onclick="claimCodeartsWelfare/);
  const single = {textContent: '积分签到', getAttribute: () => 'a'};
  const all = {textContent: '一键签到全部账号'};
  await ui.claimCodeartsWelfare(single);
  await ui.claimCodeartsWelfareAll(all);
  const route = '/accounts/codearts/welfare/claim';
  assert.deepStrictEqual(calls, [[route, '{"accountId":"a"}'], [route, '{}']]);
  assert.strictEqual(reads, 3);
  assert.ok(!single.disabled && !all.disabled);
  assert.match(notices[0][0], /部分签到成功.*100/);
  assert.match(notices[1][0], /1 户暂无可领/);
  assert.ok(notices.every(([, kind]) => kind === 'warn'));
}

checkCheckinControls().then(() => {
  console.log(`dashboard handler assertions passed (${referenced.size} handlers checked, check-in controls verified)`);
}).catch(error => { console.error(error); process.exitCode = 1; });
