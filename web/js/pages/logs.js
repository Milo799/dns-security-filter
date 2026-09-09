/* ============================================================
   pages/logs.js — 过滤日志（查询 / 分页 / 导出 CSV）
   迭代 39：过滤原因筛选改下拉（固定四类 + 已启用在线源 +
   已启用离线源），值编码 "type:value" 区分筛选语义。
   ============================================================ */
var logPage = 1;

function logFilterParams(){
  var q = new URLSearchParams();
  [['lgCip', 'client_ip'], ['lgDomain', 'domain'], ['lgAction', 'action']]
    .forEach(function(p){
      var v = document.getElementById(p[0]).value.trim();
      if (v) q.set(p[1], v);
    });
  /* 原因下拉：值形如 "fixed:local_blacklist" / "online:spamhaus_dbl" /
     "offline:hagezi_ti"——按类型构造 reason 查询串：
     - fixed → 前缀匹配（threat_list 新旧格式都命中，
       local_blacklist/ip_filter/threatintel 同理覆盖其前缀族）
     - online:<name> → LIKE %name%（匹配 threatintel:strategy:srcs 段）
     - offline:<key> → threat_list:<key> 前缀匹配；迭代 39 前的旧数据
       reason 为裸 threat_list（无源信息），不命中按源筛选属预期 */
  var rv = document.getElementById('lgReason').value;
  if (rv){
    var sep = rv.indexOf(':'), type = rv.slice(0, sep), val = rv.slice(sep + 1);
    if (type === 'fixed') q.set('reason', val);
    else if (type === 'online') q.set('reason', val);
    else if (type === 'offline') q.set('reason', 'threat_list:' + val);
  }
  return q;
}

/* 加载过滤原因下拉选项（fixed/online/offline 三组 optgroup） */
async function loadReasonOptions(){
  var sel = document.getElementById('lgReason');
  if (!sel) return;
  try{
    var d = (await api('GET', '/api/logs/reasons')).data;
    var html = '<option value="">全部</option>';
    var groups = [
      ['fixed', '固定分类'], ['online', '在线情报源'], ['offline', '离线情报源']
    ];
    groups.forEach(function(g){
      var items = d[g[0]] || [];
      if (!items.length) return;
      html += '<optgroup label="' + esc(g[1]) + '">';
      items.forEach(function(it){
        html += '<option value="' + g[0] + ':' + esc(it.key) + '">' +
                esc(it.label) + '</option>';
      });
      html += '</optgroup>';
    });
    sel.innerHTML = html;
  }catch(e){ /* 下拉加载失败不阻塞日志主体，保留"全部" */ }
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
        : logReasonTag(l.filter_reason);
      var act = l.action === 'intercept'
        ? '<span class="tag tag-error">intercept</span>'
        : (l.action === 'remove_ip'
          ? '<span class="tag tag-warning">remove_ip</span>'
          : (l.action === 'observe'
            ? '<span class="tag tag-warning">observe</span>'
            : '<span class="tag tag-success">allow</span>'));
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

/* 过滤原因可读化（logs 页表格 + 事件流复用口径）：
   - local_blacklist → 人工黑名单
   - threat_list / threat_list:<source> → 离线情报源[:源名]
   - ip_filter → IP 过滤
   - nrd → 新注册域名（迭代 40，在线 RDAP 注册时间）
   - nrd_observe → 新注册域名·观察（在线层 observe 记录，未拦截）
   - nrd_offline → 新注册域名·离线名单（迭代 41，hagezi/nrd 拦截）
   - nrd_offline_observe → 新注册域名·离线名单·观察（未拦截）
   - threatintel:<strategy>:<srcs> → 在线情报[（源列表）]
   - degraded:failsafe → 降级放行（不应出现在拦截日志，兜底显示） */
function logReasonTag(reason){
  if (!reason) return '';
  if (reason === 'local_blacklist')
    return '<span class="tag tag-neutral">人工黑名单</span>';
  if (reason === 'ip_filter')
    return '<span class="tag tag-warning">IP过滤</span>';
  if (reason === 'nrd')
    return '<span class="tag tag-error">新注册域名</span>';
  if (reason === 'nrd_observe')
    return '<span class="tag tag-neutral">新注册域名·观察</span>';
  if (reason === 'nrd_offline')
    return '<span class="tag tag-error">新注册域名·离线名单</span>';
  if (reason === 'nrd_offline_observe')
    return '<span class="tag tag-neutral">新注册域名·离线名单·观察</span>';
  if (reason === 'threat_list')
    return '<span class="tag tag-warning">离线情报源</span>';
  if (reason.indexOf('threat_list:') === 0){
    var src = reason.slice(12);
    return '<span class="tag tag-warning">离线情报源</span>' +
           '<span class="tag tag-neutral" style="margin-left:4px">' + esc(src) + '</span>';
  }
  if (reason.indexOf('threatintel:') === 0){
    var segs = reason.split(':');
    var srcs = segs.slice(2).join(':');
    return '<span class="tag tag-error">在线情报</span>' +
           (srcs ? '<span class="tag tag-neutral" style="margin-left:4px" title="' + esc(srcs) + '">' +
             esc(srcs.split(',').length > 3 ? srcs.split(',').slice(0, 3).join(',') + '…' : srcs) + '</span>' : '');
  }
  return '<span class="tag tag-error">' + esc(reason) + '</span>';
}

async function exportLogs(){
  var q = logFilterParams();
  try{
    var r = await api('GET', '/api/logs/export?' + q);
    downloadBlob(await r.blob(), 'filter_log.csv');
    toast('已导出');
  }catch(e){ toast(e.message, true); }
}

PAGE_LOADERS.logs = function(){ loadReasonOptions(); loadLogs(); };
