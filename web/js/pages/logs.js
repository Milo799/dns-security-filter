/* ============================================================
   pages/logs.js — 过滤日志（查询 / 分页 / 导出 CSV）
   ============================================================ */
var logPage = 1;

function logFilterParams(){
  var q = new URLSearchParams();
  [['lgCip', 'client_ip'], ['lgDomain', 'domain'], ['lgAction', 'action'], ['lgReason', 'reason']]
    .forEach(function(p){
      var v = document.getElementById(p[0]).value.trim();
      if (v) q.set(p[1], v);
    });
  return q;
}

async function loadLogs(page){
  if (page) logPage = page;
  var q = logFilterParams();
  q.set('page', logPage); q.set('size', 20);
  try{
    var d = (await api('GET', '/api/logs?' + q)).data;
    document.getElementById('lgCount').textContent = '共 ' + d.total + ' 条';
    document.getElementById('logRows').innerHTML = d.items.length ? d.items.map(function(l){
      var reason = l.action === 'allow'
        ? '<span class="tag tag-neutral">allow</span>'
        : (l.filter_reason === 'local_blacklist'
          ? '<span class="tag tag-neutral">自定黑名单</span>'
          : (l.filter_reason === 'ip_filter'
            ? '<span class="tag tag-warning">IP过滤</span>'
            : '<span class="tag tag-error">' + esc(l.filter_reason) + '</span>'));
      var act = l.action === 'intercept'
        ? '<span class="tag tag-error">intercept</span>'
        : (l.action === 'remove_ip'
          ? '<span class="tag tag-warning">remove_ip</span>'
          : '<span class="tag tag-success">allow</span>');
      return '<tr><td class="mono">' + esc(l.timestamp) + '</td>' +
        '<td class="mono">' + (l.client_ip ? esc(l.client_ip) : '<span style="color:var(--text-dim)">未透传</span>') + '</td>' +
        '<td class="mono">' + esc(l.domain) + '</td><td>' + esc(l.query_type) + '</td>' +
        '<td>' + reason + '</td><td>' + act + '</td>' +
        '<td class="mono">' + esc(l.malicious_ips || '—') + '</td>' +
        '<td class="mono">' + esc(l.final_result) + '</td>' +
        '<td>' + esc(l.source_api || '—') + '</td></tr>';
    }).join('') : '<tr><td colspan="9"><div class="empty-state"><span class="es-ico">📭</span>暂无日志</div></td></tr>';
    pager(document.getElementById('lgPager'), d.total, logPage, 20, 'loadLogs');
  }catch(e){ toast(e.message, true); }
}

async function exportLogs(){
  var q = logFilterParams();
  try{
    var r = await api('GET', '/api/logs/export?' + q);
    downloadBlob(await r.blob(), 'filter_log.csv');
    toast('已导出');
  }catch(e){ toast(e.message, true); }
}

PAGE_LOADERS.logs = loadLogs;
