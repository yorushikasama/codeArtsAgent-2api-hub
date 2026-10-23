/* 限额表的前端契约：三条护栏，全局生效。
 *
 * 后端只存一个全局值（LIMIT_SCOPES = ("global",)），面板这张表必须一一对上：
 * 每条护栏一个输入框，id 由 LIMIT_FIELDS 的名字拼出来，保存时发
 * {key: {global: 数字}}，0 表示关闭。留空等同于 0，但乱填要拦下来——
 * 把 "1ooo" 悄悄当成 0 等于关掉护栏，页面上看不出来。
 *
 * 这类错名字只会静默失效：输入框填不上、或者发出去的键名对不上。所以这里把
 * 两侧的名字和语义都钉住。Run with Node.
 */
const assert = require('assert');
const {dashboardHtml, dashboardScript} = require('./_dashboard_source.js');

const html = dashboardHtml();
const script = dashboardScript();

// One shared fake DOM for every dashboard suite: tests/_dom_stub.js.
const dom = require('./_dom_stub.js');

let sent = null;
dom.installDom({
  fetch: (url, options) => {
    const body = options && options.body ? JSON.parse(options.body) : null;
    if(url === '/settings/save' && body) sent = body;
    const payload = {current: 'cn', accounts: [], slots: [], data: [],
                     results: [], byAccount: []};
    return Promise.resolve({status: 200, ok: true,
      json: () => Promise.resolve(payload),
      text: () => Promise.resolve(JSON.stringify(payload))});
  },
});

const realLog = console.log;
console.log = () => {};
const api = new Function(script + `
  return {
    LIMIT_FIELDS: LIMIT_FIELDS,
    limitEl: limitEl,
    applyLimits: applyLimits,
    saveLimits: saveLimits,
  };`)();

(async () => {
  // 1. 三条护栏，键名与服务端 LIMIT_KEYS 一致；每条恰好一个全局输入框。
  assert.deepStrictEqual(api.LIMIT_FIELDS.map(f => f.key), [
    'daily_token_limit', 'daily_credit_limit', 'model_daily_token_limit',
  ]);
  const expectedIds = api.LIMIT_FIELDS.map(f => 'limitGlobal' + f.id).sort();
  const htmlIds = [...html.matchAll(/id="(limitGlobal[A-Za-z]+)"/g)]
    .map(match => match[1]).sort();
  assert.deepStrictEqual(htmlIds, expectedIds,
                         '每条护栏只能有一个全局输入框，不能留下分版本列');
  for(const field of api.LIMIT_FIELDS){
    assert.ok(html.includes('id="limitGlobal' + field.id + '"'),
              '缺少输入框 limitGlobal' + field.id);
  }

  // 分版本时代的控件与键名都应消失，别再被谁重新加回来。
  for(const gone of ['LIMIT_SCOPES', 'toggleLimitRealms', 'setLimitsPerRealm',
                     'reserve_credits', 'expiring_window_days',
                     'toggleExpiringWindow', 'limitCn', 'limitIntl']){
    assert.ok(!html.includes(gone), '不应再出现 ' + gone);
  }

  // 2. 手机上这张表要跟着看板的「表 → 卡片」走：表要带 data-cards，限值格
  //    要有自己的 data-label 当行名，否则它会撑出 720px 的下限、把整个页面
  //    拉出横向滚动条。
  //
  //    这一段按「行」绑定，不数全页字符串：类名按集合看（顺序、多余类名都
  //    无所谓），data-label 必须落在承载该输入框的那一格上。
  const limitsTableTag = html.match(/<table\b[^>]*>/g)
    .find(tag => /\blimits-cards\b/.test(tag));
  assert.ok(limitsTableTag, '找不到限额表（带 limits-cards 的 <table>）');
  const tableClasses = new Set(
    (limitsTableTag.match(/class="([^"]*)"/) || ['', ''])[1].split(/\s+/).filter(Boolean));
  for(const cls of ['data-cards', 'limits-cards']){
    assert.ok(tableClasses.has(cls),
              '限额表要带 ' + cls + '（当前：' + [...tableClasses].join(' ') + '）');
  }

  // 输入框 id -> 它所在格的 data-label。只按 <tr>/<td> 切开，不做通用解析。
  const tableStart = html.indexOf(limitsTableTag);
  const tableHtml = html.slice(tableStart, html.indexOf('</table>', tableStart));
  const labelById = new Map();
  for(const row of tableHtml.split(/<tr\b/).slice(1)){
    for(const raw of row.split(/<td\b/).slice(1)){
      const close = raw.indexOf('</td>');
      const cell = close < 0 ? raw : raw.slice(0, close);
      const attrs = cell.slice(0, cell.indexOf('>'));
      const label = (attrs.match(/data-label="([^"]*)"/) || [])[1];
      for(const hit of cell.matchAll(/id="(limitGlobal[A-Za-z]+)"/g)) labelById.set(hit[1], label);
    }
  }
  assert.equal(labelById.size, api.LIMIT_FIELDS.length,
               '限额表里应有 3 条护栏的输入框');
  for(const field of api.LIMIT_FIELDS){
    assert.equal(labelById.get('limitGlobal' + field.id), '全局默认',
                 field.label + ' 的限值格必须自己带 data-label="全局默认"');
  }
  // 表头只有「护栏 / 全局默认」两列，不再有分版本列。
  assert.ok(!/国内版|国际版/.test(tableHtml), '限额表不应再有分版本列');

  // 护栏名与说明占整块那条规则：按选择器与声明的意义找，不比对一条写死的 CSS
  // 文本，所以空白、声明顺序、多余声明都不影响；而选择器不再指向限额表的
  // limit-name 格、或 display 不再是 block 时，就必须失败。
  const cssText = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)]
    .map(match => match[1]).join('\n').replace(/\/\*[\s\S]*?\*\//g, '');
  const cssRules = [...cssText.matchAll(/([^{}]+)\{([^{}]*)\}/g)]
    .map(match => ({selector: match[1].trim(), body: match[2]}));

  // 逗号分隔的每个 branch 各自判定：表限定与单元格限定必须落在同一个 branch 里。
  // 否则 `table.limits-cards td, td.limit-name` 这种把两个条件分居两个 branch 的
  // 写法会被读成「命中了限额表的 limit-name 格」，而它其实谁都没命中。
  function targetsLimitNameCell(rule){
    return rule.selector.split(',').some(branch =>
      /\.limits-cards\b/.test(branch) && /td\.limit-name\b/.test(branch));
  }
  const blockRule = cssRules.find(rule => targetsLimitNameCell(rule) &&
    /(?:^|;)\s*display\s*:\s*block\s*(?:!important)?\s*(?:;|$)/.test(rule.body));
  assert.ok(blockRule, '限额表手机卡片里 limit-name 格要有 display:block 的规则');

  // 判定本身也钉住，免得哪天又退回「两个条件各命中一个 branch 就算数」。
  assert.ok(targetsLimitNameCell({selector: 'table.limits-cards td.limit-name'}),
            '守卫：同一个 branch 同时点到表与 limit-name 格，应算命中');
  assert.ok(targetsLimitNameCell({selector: '.other, table.limits-cards td.limit-name'}),
            '守卫：多 branch 中只要有一个自己命中，就算命中');
  assert.ok(!targetsLimitNameCell({selector: '.limits-cards td, td.limit-name'}),
            '守卫：表限定与单元格限定分居两个 branch，不算命中');
  assert.ok(!targetsLimitNameCell({selector: 'td.limit-name'}),
            '守卫：只点到 limit-name 格、没限定在限额表里，不算命中');
  assert.ok(!targetsLimitNameCell({selector: '.limits-cards td'}),
            '守卫：只限定到限额表、没点到 limit-name 格，不算命中');

  // 3. 载入时：每条护栏的全局值填进输入框，状态跟着值走。
  api.applyLimits({limits: {
    daily_token_limit: {global: 1000},
    daily_credit_limit: {global: 0},
    model_daily_token_limit: {global: 5},
  }});
  assert.equal(api.limitEl('DailyToken').value, '1000');
  assert.equal(api.limitEl('DailyCredit').value, '0');
  assert.equal(api.limitEl('ModelDailyToken').value, '5');
  assert.equal(dom.byId('setDailyTokenState').textContent, '(1,000)');
  assert.equal(dom.byId('setDailyCreditState').textContent, '(已关闭)');
  assert.equal(dom.byId('setModelDailyTokenState').textContent, '(5)');
  assert.equal(dom.byId('setLimitsState').textContent, '(已启用)');

  // 缺条目或整块为空都读作 0（关闭），不会把旧值留在框里。
  api.applyLimits({limits: {}});
  assert.deepStrictEqual(
    api.LIMIT_FIELDS.map(f => api.limitEl(f.id).value), ['0', '0', '0']);
  assert.equal(dom.byId('setLimitsState').textContent, '(全部关闭)');

  // 4. 保存：三条护栏一起发，每条都是 {global: 数字}。
  api.limitEl('DailyToken').value = '20';
  api.limitEl('DailyCredit').value = '0';
  api.limitEl('ModelDailyToken').value = '5';
  sent = null;
  await api.saveLimits(null);
  assert.ok(sent && sent.limits, '保存必须发 limits');
  assert.deepStrictEqual(sent.limits, {
    daily_token_limit: {global: 20},
    daily_credit_limit: {global: 0},
    model_daily_token_limit: {global: 5},
  });

  // 留空 = 关闭，按 0 发出去。
  sent = null;
  api.limitEl('DailyToken').value = '';
  await api.saveLimits(null);
  assert.deepStrictEqual(sent.limits.daily_token_limit, {global: 0},
                         '留空应发 0（关闭）');

  // 5. 非法输入直接拦下，不发请求。
  sent = null;
  api.limitEl('DailyToken').value = 'abc';
  await api.saveLimits(null);
  assert.equal(sent, null, '乱填不能悄悄当成 0，应拦下不发请求');

  sent = null;
  api.limitEl('DailyToken').value = '10';
  api.limitEl('DailyCredit').value = '-1';
  await api.saveLimits(null);
  assert.equal(sent, null, '负数不应发请求');

  console.log = realLog;
  console.log('limit assertions passed');
})().catch(err => {
  console.log = realLog;
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
