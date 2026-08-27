/* ============================================================
   pages/fusion.js — 融合策略（在线情报源判定结果汇总规则）
   2026-08-27 从 threatintel 页面独立为导航「策略管理 → 融合策略」
   ============================================================ */

async function loadFusion(){
  try{
    var cfg = (await api('GET', '/api/config')).data.items;
    var cur = (cfg.fusion_strategy && cfg.fusion_strategy.value) || 'any';
    document.querySelectorAll('#fusionCards .radio-inline-item').forEach(function(c){
      var sel = c.dataset.v === cur;
      c.classList.toggle('sel', sel);
      c.querySelector('input').checked = sel;
    });
  }catch(e){ toast(e.message, true); }
}

/* 融合策略切换（变更记入操作审计） */
document.querySelectorAll('#fusionCards .radio-inline-item').forEach(function(c){
  c.addEventListener('click', async function(){
    try{
      await api('PUT', '/api/threatintel/fusion-strategy', {strategy: c.dataset.v});
      document.querySelectorAll('#fusionCards .radio-inline-item').forEach(function(x){ x.classList.remove('sel'); });
      c.classList.add('sel');
      c.querySelector('input').checked = true;
      toast('融合策略已切换为 ' + c.dataset.v + '（已记入审计）');
    }catch(e){ toast(e.message, true); }
  });
});

PAGE_LOADERS.fusion = loadFusion;
