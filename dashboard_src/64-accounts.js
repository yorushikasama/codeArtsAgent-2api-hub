/* ---------------- accounts ----------------
   旧账号池的行内部件（冷却/限额 pill、活动状态徽章、活动历史弹窗、
   手动权重提示）已随账号页重构整体移除；本文件只剩账号页与数据看板
   共用的悬停气泡。 */
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

