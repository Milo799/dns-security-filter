/* ============================================================
   pages/audit.js — 操作审计（敏感操作留痕）
   ============================================================ */
var auditPage = 1;
var AUDIT_LABELS = {
  list_create: '新增名单条目', list_update: '修改名单条目', list_delete: '删除名单条目',
  list_import: '批量导入名单', threatintel_create: '新增情报源', threatintel_update: '修改情报源',
  threatintel_delete: '删除情报源', threatlist_import: '导入离线情报源',
  threatlist_enable: '启停离线情报源', threatlist_delete: '清空离线情报源',
  fusion_strategy_change: '切换融合策略', detection_toggle: '切换检测开关', config_update: '修改系统配置'
};

async function loadAudit(page){
  if (page) auditPage = page;
  var q = new URLSearchParams({page: auditPage, size: 20});
  var op = document.getElementById('auOp').value.trim();
  var act = document.getElementById('auAction').value;
  if (op) q.set('operator', op);
  if (act) q.set('action', act);
  try{
    var d = (await api('GET', '/api/audit?' + q)).data;
    document.getElementById('auCount').textContent = '共 ' + d.total + ' 条';
    document.getElementById('auditRows').innerHTML = d.items.length ? d.items.map(function(a){
      var label = AUDIT_LABELS[a.action] || a.action;
      var main = esc(a.readable || a.detail || '');
      var raw = a.detail
        ? '<details class="audit-raw"><summary>原始数据</summary><code>' + esc(a.detail) + '</code></details>'
        : '';
      return '<tr><td class="mono">' + esc(a.timestamp) + '</td><td>' + esc(a.operator) + '</td>' +
        '<td><span class="tag tag-blue">' + esc(label) + '</span></td>' +
        '<td><div class="audit-readable">' + main + '</div>' + raw + '</td></tr>';
    }).join('') : '<tr><td colspan="4"><div class="empty-state"><span class="es-ico">📝</span>暂无审计记录</div></td></tr>';
    pager(document.getElementById('auPager'), d.total, auditPage, 20, 'loadAudit');
  }catch(e){ toast(e.message, true); }
}

PAGE_LOADERS.audit = loadAudit;
