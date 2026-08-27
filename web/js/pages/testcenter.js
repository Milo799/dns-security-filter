/* ============================================================
   pages/testcenter.js — 测试中心（域名 / IP 探测，只读）
   ============================================================ */
function ttDomainPlaceholder(){
  var el = document.getElementById('ttDomain');
  el.placeholder = document.getElementById('ttQtype').value === 'PTR'
    ? '如 8.8.8.8 或 8.8.8.8.in-addr.arpa'
    : '如 example.com';
}

function switchTestTab(tab){
  document.getElementById('tabDomain').classList.toggle('active', tab === 'domain');
  document.getElementById('tabIp').classList.toggle('active', tab === 'ip');
  document.getElementById('domainTestForm').style.display = tab === 'domain' ? '' : 'none';
  document.getElementById('ipTestForm').style.display = tab === 'ip' ? '' : 'none';
  document.getElementById('testResult').innerHTML = '';
}

function pBadge(p){
  if (p.status === 'hit') return '<span class="tag tag-error"><span class="dot"></span>命中（恶意）</span>';
  if (p.status === 'miss') return '<span class="tag tag-success"><span class="dot"></span>未命中</span>';
  if (p.status === 'error') return '<span class="tag tag-neutral"><span class="dot"></span>无结论</span>';
  return '<span class="tag tag-blue">不支持</span>';
}

function probeTable(probe){
  if (!probe || !probe.length) return '<div class="empty-state"><span class="es-ico">🔌</span>未启用支持该查询类型的情报源</div>';
  return '<table class="sap"><thead><tr><th>情报源</th><th>结果</th><th>详情</th></tr></thead><tbody>' +
    probe.map(function(p){
      return '<tr><td class="mono">' + esc(p.source) + '</td><td>' + pBadge(p) + '</td>' +
             '<td style="white-space:normal">' + esc(p.detail) + '</td></tr>';
    }).join('') + '</tbody></table>';
}

function verdictBanner(action, title, reason){
  var cls = action === 'intercept' ? 'verdict-intercept' : (action === 'allow' ? 'verdict-allow' : 'verdict-neutral');
  var icon = action === 'intercept' ? '🚫' : (action === 'allow' ? '✅' : '➡️');
  return '<div class="verdict-banner ' + cls + '"><span class="vb-icon">' + icon + '</span>' +
    '<div><div class="vb-title">' + title + '</div><div>' + esc(reason) + '</div></div></div>';
}

async function runDomainTest(){
  var domain = document.getElementById('ttDomain').value.trim();
  if (!domain){ toast('请输入域名', true); return; }
  var qtype = document.getElementById('ttQtype').value;
  var cip = document.getElementById('ttCip').value.trim();
  var el = document.getElementById('testResult');
  el.innerHTML = '<div class="card"><div class="loading">探测中…（情报源查询可能耗时数秒）</div></div>';
  try{
    var d = (await api('POST', '/api/test/domain', {domain: domain, query_type: qtype, client_ip: cip})).data;
    el.innerHTML = renderDomainResult(d);
  }catch(e){ el.innerHTML = ''; toast(e.message, true); }
}

function renderDomainResult(d){
  var fv = d.final_verdict;
  var isPtr = d.query_type === 'PTR';
  var html = verdictBanner(fv.action, fv.action === 'intercept' ? '判定：拦截' : '判定：放行/转发', fv.reason);
  if (!d.detection_enabled)
    html += '<div class="verdict-banner verdict-neutral" style="margin-top:-6px"><span class="vb-icon">⏸</span>' +
      '<div><div class="vb-title">检测总开关已关闭</div><div>当前平台不对任何域名执行过滤，真实流量将直接转发</div></div></div>';
  html += '<div class="card"><div class="card-head"><div class="card-title">' + (isPtr ? 'PTR 反向解析 · IP 维度' : '本地名单检查') + '</div>' +
    '<span class="tag tag-neutral">' + esc(isPtr ? (d.ptr_ip + ' → ' + d.domain) : (d.domain + ' · ' + d.query_type)) + '</span></div>' +
    '<div class="card-body" style="padding-top:0">' +
    '<div class="t-check"><div class="tk">🟢 白名单' + (isPtr ? ' IP' : '') + '</div><div>' +
      (d.whitelist.matched
        ? '<span class="tag tag-success"><span class="dot"></span>命中</span> <span class="rule-chip">' + esc(d.whitelist.rule) + '</span>'
        : '<span class="tag tag-neutral">未命中</span>') + '</div></div>' +
    '<div class="t-check"><div class="tk">🔴 本地' + (isPtr ? ' IP' : '') + '黑名单</div><div>' +
      (d.local_blacklist.matched
        ? '<span class="tag tag-error"><span class="dot"></span>命中</span> <span class="rule-chip">' + esc(d.local_blacklist.rule) + '</span>'
        : '<span class="tag tag-neutral">未命中</span>') + '</div></div>' +
    '<div class="t-check"><div class="tk">📋 离线大名单' + (isPtr ? ' IP' : '') + '</div><div>' +
      (d.threat_list.matched
        ? '<span class="tag tag-error"><span class="dot"></span>命中</span> <span class="rule-chip">' + esc(d.threat_list.entry) + '</span> <span class="form-hint" style="margin:0">来源 ' + esc(d.threat_list.source) + '</span>'
        : '<span class="tag tag-neutral">未命中</span>') + '</div></div>' +
    '</div></div>';
  html += '<div class="card"><div class="card-head"><div class="card-title">威胁情报 · ' + (isPtr ? 'IP 维度' : '域名维度') + '</div>' +
    '<span class="tag tag-blue">启用源逐源结果</span></div>' +
    '<div class="card-body table-wrap" style="padding-top:0">' + probeTable(d.threatintel_domain) + '</div></div>';
  if (d.resolution){
    html += '<div class="card"><div class="card-head"><div class="card-title">公网解析（' + esc(d.query_type) + '）</div></div>' +
      '<div class="card-body" style="padding-top:0">' +
      (d.resolution.ok
        ? '<div class="t-check"><div class="tk">解析结果</div><div class="tv">' + d.resolution.ips.map(esc).join('　') + '</div></div>'
        : '<div class="t-check"><div class="tk">解析结果</div><div class="t-error">解析失败（平台无法访问上游 DNS 或域名不存在）</div></div>') +
      '</div></div>';
    if (d.ip_checks && d.ip_checks.length){
      html += '<div class="card"><div class="card-head"><div class="card-title">IP 后置过滤</div><span class="tag tag-blue">逐 IP 校验</span></div>' +
        '<div class="card-body" style="padding-top:0">' +
        d.ip_checks.map(function(c){
          return '<div class="t-check" style="margin-top:6px"><div class="tk"><span class="mono">' + esc(c.ip) + '</span>' +
            (c.local_blacklist.matched ? '<span class="tag tag-error">本地黑名单</span>' : '') + '</div>' +
            '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">' +
            (c.verdict === 'intercept'
              ? '<span class="tag tag-error"><span class="dot"></span>剔除</span>'
              : '<span class="tag tag-success"><span class="dot"></span>放行</span>') +
            '<span class="form-hint" style="margin:0">' + esc(c.reason) + '</span></div></div>' +
            '<div class="card" style="margin:0 0 12px;box-shadow:none"><div class="card-body table-wrap" style="padding:0 0 6px">' + probeTable(c.threatintel_ip) + '</div></div>';
        }).join('') + '</div></div>';
    }
  }
  return html;
}

async function runIpTest(){
  var ip = document.getElementById('ttIp').value.trim();
  if (!ip){ toast('请输入 IP 地址', true); return; }
  var el = document.getElementById('testResult');
  el.innerHTML = '<div class="card"><div class="loading">探测中…</div></div>';
  try{
    var d = (await api('POST', '/api/test/ip', {ip: ip})).data;
    el.innerHTML = renderIpResult(d);
  }catch(e){ el.innerHTML = ''; toast(e.message, true); }
}

function renderIpResult(d){
  var inter = d.verdict === 'intercept';
  var html = verdictBanner(d.verdict, inter ? '判定：拦截' : '判定：放行', d.reason);
  html += '<div class="card"><div class="card-head"><div class="card-title">本地名单检查</div>' +
    '<span class="tag tag-neutral">' + esc(d.ip) + '</span></div>' +
    '<div class="card-body" style="padding-top:0">' +
    '<div class="t-check"><div class="tk">🔴 本地 IP 黑名单（含 CIDR）</div><div>' +
      (d.local_blacklist.matched
        ? '<span class="tag tag-error"><span class="dot"></span>命中</span> <span class="rule-chip">' + esc(d.local_blacklist.rule) + '</span>'
        : '<span class="tag tag-neutral">未命中</span>') + '</div></div>' +
    '<div class="t-check"><div class="tk">📋 离线大名单</div><div>' +
      (d.threat_list.matched
        ? '<span class="tag tag-error"><span class="dot"></span>命中</span> <span class="rule-chip">' + esc(d.threat_list.entry) + '</span> <span class="form-hint" style="margin:0">来源 ' + esc(d.threat_list.source) + '</span>'
        : '<span class="tag tag-neutral">未命中</span>') + '</div></div>' +
    '</div></div>';
  html += '<div class="card"><div class="card-head"><div class="card-title">威胁情报 · IP 维度</div>' +
    '<span class="tag tag-blue">启用源逐源结果</span></div>' +
    '<div class="card-body table-wrap" style="padding-top:0">' + probeTable(d.threatintel_ip) + '</div></div>';
  return html;
}

PAGE_LOADERS.testcenter = function(){};
