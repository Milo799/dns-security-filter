/* ============================================================
   pages/aggdomains.js — 域名分析（迭代 37：过滤日志按域名聚合）
   按域名聚合拦截/剔除/放行计数与来源构成，支撑针对性排查：
   发现高频域名 → 看来源构成判断误拦/真恶意 → 跳明细/加白/加黑处置
   ============================================================ */
var aggPage = 1;

function aggFilterParams(){
  var q = new URLSearchParams();
  [['agStart','start'], ['agEnd','end'], ['agDomain','domain'], ['agAction','action']]
    .forEach(function(p){
      var v = document.getElementById(p[0]).value.trim();
      if (v) q.set(p[1], v);
    });
  return q;
}

/* 快捷时间窗：填入输入框后查询（custom=直接用输入框现值） */
function aggQuick(kind){
  var now = new Date();
  function fmt(d){
    function p(n){ return (n<10?'0':'')+n; }
    return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds());
  }
  if (kind !== 'custom'){
    var from = new Date(now.getTime());
    if (kind === '1h')  from.setHours(from.getHours()-1);
    if (kind === '24h') from.setDate(from.getDate()-1);
    if (kind === '7d')  from.setDate(from.getDate()-7);
    document.getElementById('agStart').value = fmt(from);
    document.getElementById('agEnd').value = fmt(now);
  }
  aggPage = 1;
  loadAggDomains();
}

/* 拦截原因 → 展示名（与过滤日志页口径一致） */
function aggReasonLabel(r){
  if (r === 'local_blacklist') return '人工黑名单';
  if (r === 'ip_filter') return 'IP过滤';
  if (r === 'threat_list') return '离线名单';
  if (r.indexOf('threatintel:') === 0) return '在线情报';
  return r;
}

/* 来源构成：Top3 原因徽标（计数+占比） */
function aggReasonBadges(row){
  if (!row.reason_top || !row.reason_top.length) return '—';
  var total = row.total || 1;
  return row.reason_top.map(function(r){
    var pct = Math.round(100 * r.count / total);
    return '<span class="tag tag-neutral" title="' + esc(r.reason) + ' × ' + r.count + '">'
      + esc(aggReasonLabel(r.reason)) + ' ' + pct + '%</span>';
  }).join(' ');
}

async function loadAggDomains(){
  var q = aggFilterParams();
  q.set('page', aggPage); q.set('size', 20);
  try{
    var d = (await api('GET', '/api/logs/agg/domains?' + q)).data;
    document.getElementById('agCount').textContent = '共 ' + d.total + ' 个域名';
    document.getElementById('aggRows').innerHTML = d.items.length ? d.items.map(function(r, i){
      var rank = (aggPage - 1) * 20 + i + 1;
      return '<tr>'
        + '<td class="mono">' + rank + '</td>'
        + '<td class="mono" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(r.domain) + '">' + esc(r.domain) + '</td>'
        + '<td class="mono"><b>' + r.total + '</b></td>'
        + '<td class="mono" style="color:var(--danger)">' + (r.intercepts || 0) + '</td>'
        + '<td class="mono" style="color:var(--warning)">' + (r.removes || 0) + '</td>'
        + '<td class="mono" style="color:var(--success)">' + (r.allows || 0) + '</td>'
        + '<td>' + aggReasonBadges(r) + '</td>'
        + '<td class="mono">' + esc(r.first_seen || '—') + '</td>'
        + '<td class="mono">' + esc(r.last_seen || '—') + '</td>'
        + '<td>'
        + '<button class="btn btn-normal btn-compact" onclick="aggToDetail(\'' + esc(r.domain) + '\')">明细</button> '
        + '<button class="btn btn-normal btn-compact" onclick="aggAddList(\'whitelist\',\'' + esc(r.domain) + '\')">加白</button> '
        + '<button class="btn btn-normal btn-compact" onclick="aggAddList(\'blacklist\',\'' + esc(r.domain) + '\')">加黑</button>'
        + '</td></tr>';
    }).join('') : '<tr><td colspan="10"><div class="empty-state"><span class="es-ico">📭</span>当前窗口无日志数据</div></td></tr>';
    pager(document.getElementById('aggPager'), d.total, aggPage, 20, 'loadAggDomains');
  }catch(e){ toast(e.message, true); }
}

/* 跳转过滤日志页并锁定该域名（复用现有筛选与查询） */
function aggToDetail(domain){
  go('logs');
  document.getElementById('lgDomain').value = domain;
  logPage = 1;
  loadLogs();
}

/* 快捷加白/加黑：复用人工情报源创建链路（后端校验层级/通配） */
async function aggAddList(listType, domain){
  if (!confirm('确认将 ' + domain + ' 加入' + (listType === 'whitelist' ? '白名单（后续放行）' : '黑名单（后续拦截）') + '？')) return;
  try{
    await api('POST', '/api/list', { list_type: listType, target: 'domain', value: domain, remark: '域名分析页快捷加入' });
    toast('已加入' + (listType === 'whitelist' ? '白名单' : '黑名单') + '：' + domain);
  }catch(e){ toast(e.message, true); }
}

PAGE_LOADERS.aggdomains = function(){ aggQuick('24h'); };
