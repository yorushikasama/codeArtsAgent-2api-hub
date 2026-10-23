/* loadSettings 的完整性契约：一次 /settings 往返要把设置页每个区块都填上。
 *
 * loadSettings 是「一个 try 包住全部」的写法：中间任何一行抛异常都会被末尾的
 * catch 吞掉，只弹一条 toast，然后它后面的所有区块一起静默留空——价估算状态、
 * 总开关复选框、API Key 列表、版本号与目录。页面上只看得出「某块没内容」，
 * 看不出是异常；v1.6.14 合并 #130 时冲突处理掉了一行 `const pricingOn = ...`
 * （那一块后来随价格系统一起删除了，但「一次往返填满每一块」的契约仍然成立），
 * 正好造成这个后果：API Key 列表整个消失，而「(3 个生效)」的计数照常显示，
 * 于是最容易被当成显示问题而不是报错。
 *
 * 所以这里钉住两件事：不许吞异常，且每个区块都要真的被填上。
 * Run with Node.
 */
const assert = require('assert');
const {dashboardScript} = require('./_dashboard_source.js');

const script = dashboardScript();

// One shared fake DOM for every dashboard suite: tests/_dom_stub.js.
const dom = require('./_dom_stub.js');
dom.installDom();
const element = id => dom.byId(id);

/* 三把 Key：一把普通 Key、一把带模型白名单、一把禁用。 */
const SETTINGS = {
  panel_password_is_default: false,
  api_keys: [
    {id: 'k1', name: 'Cursor', models: [], enabled: true,
     masked: 'ca-aaaa****1111', created_at: '2026-09-01'},
    {id: 'k2', name: 'DSH', models: ['deepseek*'], enabled: true,
     masked: 'ca-bbbb****2222', created_at: '2026-09-02'},
    {id: 'k3', name: '本地测试', models: [], enabled: false,
     masked: 'ca-cccc****3333', created_at: '2026-09-03'},
  ],
  deleted_api_keys: [],
  limits: {
    daily_token_limit: {global: 1000},
    daily_credit_limit: {global: 0},
    model_daily_token_limit: {global: 0},
  },
  section_max_height: 640,
  daily_chat_web: false,
  daily_chat_web_timeout: 300,
  daily_chat_web_timeout_default: 120,
  daily_chat_web_attempts_default: 3,
  local_web_tools: true,
  version: 'v1.6.14',
  accounts_dir: '/data/accounts',
  usage_dir: '/data/usage',
  settings_file: '/data/settings.json',
};

global.fetch = (url) => {
  const payload = url === '/settings' ? SETTINGS
    : url === '/pricing' ? {models: 0, policies: 0, current: {}}
    : {current: 'intl', accounts: [], slots: [], data: [], results: [], byAccount: []};
  return Promise.resolve({status: 200, ok: true,
    json: () => Promise.resolve(payload),
    text: () => Promise.resolve(JSON.stringify(payload))});
};

const realLog = console.log;
console.log = () => {};
const toasts = [];
let api;
try {
  api = new Function(script + `
    toast = function(msg, kind){ global.__toasts.push([msg, kind]); };
    return { loadSettings: loadSettings, getRows: () => API_KEY_ROWS };`)();
} catch(e) {
  console.log = realLog;
  console.error('脚本求值失败:', e.message);
  process.exit(1);
}
global.__toasts = toasts;

(async () => {
  await api.loadSettings(true);
  await Promise.resolve();          // 让 loadPricingStatus 这类不 await 的尾巴跑完
  await new Promise(resolve => process.nextTick(resolve));

  console.log = realLog;

  // 1. 一次成功的读取不该报错——异常被 catch 吞掉正是这个 bug 的藏身处。
  const failed = toasts.filter(([msg]) => String(msg).indexOf('读取设置失败') === 0);
  assert.deepStrictEqual(failed, [],
    'loadSettings 抛异常了：' + (failed[0] ? failed[0][0] : ''));

  // 2. API Key 列表：三把 Key 各一张卡片，名字与出口徽章都要在**它自己那张卡上**。
  const rows = api.getRows();
  assert.equal(rows.length, 3, 'API_KEY_ROWS 应有 3 行');
  const list = element('keyList').innerHTML;
  // 每张卡片里正好一个 key-card-main；不能拿 class="key-card 去数，
  // 那个前缀会同时命中 key-card-main。
  assert.equal(list.split('class="key-card-main"').length - 1, 3, 'keyList 应有 3 张卡片');

  /* 卡片读取器：按 <div class="key-card…"> 把渲染结果切开，字段只在**单张卡片
     内部**找。整表 includes(...) 只能证明某段字符串在列表里出现过，证明不了它
     属于哪张卡 —— 徽章串到别的卡上时，那些断言照样全绿。
     边界用前瞻收口：`key-card` 后面必须是空白、引号或 `>`，否则会连
     `key-card-main` 一起切开。 */
  const cards = list.split(/<div class="key-card(?=[\s">])/).slice(1);
  const cardOf = name => cards.filter(c => c.includes('>' + name + '<'))[0] || '';
  const onCard = (name, text) => cardOf(name).includes(text);
  // 卡片自己的 class 里有没有 disabled（多一个属性、多一个 class 都不影响）。
  const cardIsDisabled = name =>
    /(^|["\s])disabled(["'\s]|$)/.test(cardOf(name).split('>')[0]);
  const cardsWith = text => cards.filter(c => c.includes(text)).length;

  for(const name of ['Cursor', 'DSH', '本地测试']){
    assert.ok(cardOf(name), '缺少 ' + name + ' 的卡片');
  }
  // Cursor：普通 Key，掩码在它自己那张卡上。
  assert.ok(onCard('Cursor', 'ca-aaaa****1111'), 'Cursor 卡上应显示掩码 Key');
  // DSH：带模型白名单。
  assert.ok(onCard('DSH', '限 deepseek*'), 'DSH 卡上应有「限 deepseek*」');
  // 本地测试：处于禁用状态。
  assert.ok(onCard('本地测试', '已禁用'), '本地测试 卡上应显示已禁用');
  assert.ok(cardIsDisabled('本地测试'), '本地测试 卡应带 disabled 状态');
  assert.equal(cardsWith('限 deepseek*'), 1, '模型白名单徽章只该出现在 DSH 卡上');
  // 出口绑定已随双出口删除：卡片上不该再有出口徽章。
  for(const gone of ['跟随面板切换', '固定国内版出口']){
    assert.equal(cardsWith(gone), 0, gone + ' 徽章应已从 Key 卡片删除');
  }

  assert.equal(element('setKeyState').textContent, '(2 个生效)',
    '计数只算启用中的 Key');

  // 3. 空列表时给的是提示语，不是一片空白。
  assert.ok(element('keyList').innerHTML.length > 0, 'keyList 被留空了');

  // 4. 价格估算的设置控件已随该功能删除：脚本不该再去找这些元素，也不该再读
  //    /settings 里的 pricing_* 字段。dom stub 只记录脚本真正碰过的 id，
  //    所以这里等于「谁把这些控件加回来，这条就红」。
  for(const gone of ['setPricingEnabled', 'setPricingEnabledState',
                     'setPricingMinutes', 'setPricingState', 'setPricingVariant',
                     'setPricingMeta', 'setPricingCurrent', 'setPricingGaps']){
    assert.equal(element(gone), null, gone + ' 应已从设置页删除');
  }
  for(const key of ['pricing_enabled', 'pricing_refresh_minutes',
                    'pricing_variant_inherit']){
    assert.ok(!script.includes(key), '脚本里不该再出现 ' + key);
  }

  // 5. 异常后面那些区块也得填上：漏填说明执行又提前断了。
  assert.equal(element('setVersion').textContent, 'v1.6.14');
  assert.equal(element('setAccountsDir').textContent, '/data/accounts');
  // 自动切换出站身份与剩余用量优先调度已随 WorkBuddy 专属面删除：
  // 控件、设置键与脚本引用都不该再出现。
  for(const gone of ['setAutoSwitch', 'setAutoSwitchState', 'setRemainingPriority',
                     'setRemainingPriorityState', 'setLimitsPerRealm', 'setLimitRealms']){
    assert.equal(element(gone), null, gone + ' 应已从设置页删除');
  }
  for(const key of ['auto_switch_product', 'remaining_priority_enabled',
                    'autoSwitchProduct', 'remainingPriority']){
    assert.ok(!script.includes(key), '脚本里不该再出现 ' + key);
  }
  // 国际版每日活跃（含它的网页通道与重试设置）已随该区域删除：
  // 这批控件不该再出现在设置页里。
  for(const gone of ['setDailyChatWeb', 'setDailyChatWebRetry',
                     'setDailyChatWebAttempts', 'setDailyChatWebTimeout']){
    assert.equal(element(gone), null, gone + ' 应已从设置页删除');
  }
  assert.equal(element('setLocalWebTools').checked, true);
  // 限额只剩三条全局护栏：值写回各自的输入框，区块状态跟着亮。
  assert.equal(element('limitGlobalDailyToken').value, '1000', '每日 Token 限额没写回');
  assert.equal(element('limitGlobalDailyCredit').value, '0', '每日积分限额没写回');
  assert.equal(element('limitGlobalModelDailyToken').value, '0', '按模型限额没写回');
  assert.equal(element('setLimitsState').textContent, '(已启用)');
  assert.equal(element('setWinMaxHeight').value, '640', '窗口限高输入框没写回');
  assert.equal(element('setWinMaxHeightState').textContent, '(当前 640px)',
    '窗口限高状态文案没写回');

  realLog('loadSettings 完整性断言通过（18 项）');
})().catch(e => {
  console.log = realLog;
  console.error(e && e.stack || e);
  process.exit(1);
});
