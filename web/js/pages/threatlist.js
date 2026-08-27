/* ============================================================
   pages/threatlist.js — 离线情报源（来源管理 / 调度可视化 /
   进度轮询 / 条目查看 / 命中查询）
   ============================================================ */
async function loadThreatlist(){
  try{
    var d = (await api('GET', '/api/threatlist/sources')).data.items;
    var cfg = (await api('GET', '/api/config')).data.items;
    var au = cfg.threatlist_auto_update, iv = cfg.threatlist_auto_interval_hours;
    document.getElementById('tlAutoUpdate').checked = au ? au.value === '1' : false;
    document.getElementById('tlAutoInterval').value = iv ? iv.value : 24;
    document.getElementById('tlRows').innerHTML = d.map(function(x){
      var has = x.total > 0;
      return '<tr><td style="white-space:nowrap"><b>' + esc(x.name) + '</b>' +
        '<div class="form-hint" style="margin-bottom:0">' + esc(x.key) + '</div></td>' +
        '<td style="white-space:normal;max-width:300px" title="' + esc(x.description) + '">' + esc(x.description) + '</td>' +
        '<td>' + (has ? x.total + ' 条' : '<span class="tag tag-neutral">未导入</span>') + '</td>' +
        '<td>' + (has
          ? (x.enabled_cnt > 0
            ? '<span class="tag tag-success"><span class="dot"></span>启用中</span>'
            : '<span class="tag tag-neutral">已停用</span>')
          : '-') + '</td>' +
        '<td class="mono">' + esc(x.updated_at || '-') + '</td>' +
        '<td>' + tlNextCell(x) + '</td>' +
        '<td><div class="td-ops">' +
        '<button class="btn btn-normal btn-compact" onclick="importThreatList(\'' + x.key + '\')">' + (has ? '↻ 更新' : '⬇ 导入') + '</button>' +
        (has
          ? '<button class="btn btn-subtle btn-compact" title="查看命中条目" onclick="openThreatListModal(\'' + x.key + '\',\'' + esc(x.name) + '\')">条目</button>' +
            '<button class="btn btn-subtle btn-compact" onclick="toggleThreatList(\'' + x.key + '\',' + (x.enabled_cnt > 0 ? 0 : 1) + ')">' + (x.enabled_cnt > 0 ? '停用' : '启用') + '</button>' +
            '<button class="btn btn-subtle btn-danger-subtle btn-compact" onclick="delThreatList(\'' + x.key + '\')">清空</button>'
          : '') +
        '</div>' +
        '<div id="tlp_' + x.key + '" style="margin-top:6px;max-width:320px"></div>' +
        '</td></tr>';
    }).join('');
    resumeTlProgress();
    if (!tlNextTimer){ tlNextTimer = setInterval(tickTlNext, 30000); }
  }catch(e){ toast(e.message, true); }
}

/* ---------- 下次更新调度可视化 ---------- */
var tlNextTimer = null;
function fmtTlInterval(s){
  if (!s) return '';
  if (s % 86400 === 0) return (s / 86400) + ' 天';
  if (s % 3600 === 0) return (s / 3600) + ' 小时';
  if (s >= 60) return Math.round(s / 60) + ' 分钟';
  return s + ' 秒';
}
function fmtTlRemaining(ms){
  if (ms <= 0) return '已到期';
  var s = Math.round(ms / 1000), d = Math.floor(s / 86400),
      h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60), p = [];
  if (d) p.push(d + ' 天');
  if (h) p.push(h + ' 小时');
  if (m) p.push(m + ' 分钟');
  if (!p.length) p.push(s + ' 秒');
  return p.slice(0, 2).join(' ') + '后';
}
function tlNextCell(x){
  if (!x.auto_update_on) return '<span class="tag tag-neutral" title="自动更新开关未开启，请在上方开启">未开启</span>';
  if (!x.total) return '<span class="tag tag-neutral">待导入</span>';
  var iv = fmtTlInterval(x.effective_interval_s);
  if (x.due) return '<span class="tag tag-warning">已到期 · 待调度</span>' +
    '<div class="form-hint" style="margin-bottom:0">周期 ' + esc(iv) + '，下轮调度自动更新</div>';
  var atms = Date.parse(String(x.next_update_at || '').replace(' ', 'T'));
  return '<div class="mono" style="font-size:12px">' + esc(x.next_update_at || '-') + '</div>' +
    '<div class="form-hint" style="margin-bottom:0">周期 ' + esc(iv) + ' · <span class="tl-rem" data-at="' + atms + '">' + fmtTlRemaining(atms - Date.now()) + '</span></div>';
}
function tickTlNext(){
  document.querySelectorAll('.tl-rem').forEach(function(el){
    var at = parseInt(el.getAttribute('data-at'), 10);
    if (at) el.textContent = fmtTlRemaining(at - Date.now());
  });
}

/* ---------- 导入 / 进度轮询 ---------- */
var tlTimer = null, tlPolling = {};
async function importThreatList(key){
  if (!confirm('确认导入/更新「' + key + '」？将整源替换该来源现有数据。视网络与体量需数分钟，期间可离开页面，进度会实时展示')) return;
  try{
    await api('POST', '/api/threatlist/import', {source: key, enabled: true});
    startTlProgress(key);
  }catch(e){ toast(e.message, true); }
}
function startTlProgress(key){
  tlPolling[key] = true;
  showTlProgress(key, {source: key, status: 'running', stage: 'download', downloaded: 0,
    total_bytes: 0, parsed: 0, inserted: 0, total: 0, message: '提交任务…'});
  ensureTlTimer();
}
function ensureTlTimer(){
  if (!tlTimer){
    tlTimer = setInterval(pollTlProgress, 1000);
    pollTlProgress();
  }
}
/* 页面加载后恢复仍在进行中的任务进度 */
async function resumeTlProgress(){
  try{
    var items = (await api('GET', '/api/threatlist/import/status')).data;
    var hit = false;
    (items || []).forEach(function(t){
      if (t.status === 'running' && t.source){
        tlPolling[t.source] = true;
        showTlProgress(t.source, t);
        hit = true;
      }
    });
    if (hit) ensureTlTimer();
  }catch(e){}
}
function tlPercent(d){
  if (d.stage === 'download' && d.total_bytes > 0) return Math.min(100, Math.round(d.downloaded / d.total_bytes * 100));
  if (d.stage === 'insert' && d.total > 0) return Math.min(100, Math.round(d.inserted / d.total * 100));
  return d.status === 'done' ? 100 : 0;
}
function tlStageText(d){
  if (d.stage === 'download') return d.total_bytes > 0 ? ('下载 ' + fmtBytes(d.downloaded) + ' / ' + fmtBytes(d.total_bytes)) : ('下载中 ' + fmtBytes(d.downloaded));
  if (d.stage === 'parse') return '解析中（已处理 ' + d.parsed.toLocaleString() + ' 行）';
  if (d.stage === 'insert') return '入库中 ' + d.inserted.toLocaleString() + ' / ' + d.total.toLocaleString();
  if (d.status === 'done') return d.message;
  return d.message || '处理中…';
}
function showTlProgress(key, d){
  var el = document.getElementById('tlp_' + key);
  if (!el) return;
  if (d.status === 'done'){
    el.innerHTML = '<div class="tl-progress done"><div class="tl-progress-bar" style="width:100%"></div><div class="tl-progress-text">✅ ' + esc(d.message) + '</div></div>';
    delete tlPolling[key];
    setTimeout(function(){ el.innerHTML = ''; loadThreatlist(); }, 2000);
    return;
  }
  if (d.status === 'error'){
    el.innerHTML = '<div class="tl-progress error"><div class="tl-progress-text">❌ ' + esc(d.error || '导入失败') + '</div></div>';
    delete tlPolling[key];
    setTimeout(function(){ el.innerHTML = ''; loadThreatlist(); }, 4000);
    return;
  }
  var p = tlPercent(d);
  el.innerHTML = '<div class="tl-progress"><div class="tl-progress-bar" style="width:' + p + '%"></div><div class="tl-progress-text">' + esc(tlStageText(d)) + '</div></div>';
}
async function pollTlProgress(){
  var keys = Object.keys(tlPolling);
  if (!keys.length){ clearInterval(tlTimer); tlTimer = null; return; }
  try{
    var items = (await api('GET', '/api/threatlist/import/status')).data;
    var seen = {};
    (items || []).forEach(function(t){ seen[t.source] = t; });
    keys.forEach(function(k){
      var d = seen[k];
      if (!d){ delete tlPolling[k]; return; }
      showTlProgress(k, d);
    });
  }catch(e){ clearInterval(tlTimer); tlTimer = null; }
}

/* ---------- 启停 / 清空 / 自动更新配置 ---------- */
async function toggleThreatList(key, to){
  try{
    await api('PUT', '/api/threatlist/source', {source: key, enabled: !!to});
    toast(to ? '已启用' : '已停用');
    loadThreatlist();
  }catch(e){ toast(e.message, true); }
}
async function delThreatList(key){
  if (!confirm('确认清空「' + key + '」全部条目？可随时重新导入恢复')) return;
  try{
    await api('DELETE', '/api/threatlist/source?source=' + encodeURIComponent(key));
    toast('已清空');
    loadThreatlist();
  }catch(e){ toast(e.message, true); }
}
async function saveThreatListAuto(){
  var on = document.getElementById('tlAutoUpdate').checked;
  var h = parseInt(document.getElementById('tlAutoInterval').value, 10) || 24;
  h = Math.max(1, Math.min(h, 720));
  document.getElementById('tlAutoInterval').value = h;
  try{
    await api('PUT', '/api/config', {threatlist_auto_update: on, threatlist_auto_interval_hours: h});
    toast(on ? '自动更新已开启（每 ' + h + ' 小时）' : '自动更新已关闭');
    loadThreatlist();
  }catch(e){ toast(e.message, true); }
}

/* ---------- 命中查询 ---------- */
async function runThreatListQuery(){
  var v = document.getElementById('tlQuery').value.trim();
  if (!v){ toast('请输入要查询的域名或 IP', true); return; }
  try{
    var d = (await api('GET', '/api/threatlist/query?value=' + encodeURIComponent(v))).data;
    var parts = [];
    if (d.threat_list.matched) parts.push('<span class="tag tag-error">离线情报命中</span> 来源 ' + esc(d.threat_list.source) + ' · 条目 ' + esc(d.threat_list.entry));
    else parts.push('<span class="tag tag-neutral">离线情报未命中</span>');
    if (d.manual_whitelist) parts.push('<span class="tag tag-success">手工白名单命中</span> ' + esc(d.manual_whitelist) + '（放行）');
    if (d.manual_blacklist) parts.push('<span class="tag tag-error">手工黑名单命中</span> ' + esc(d.manual_blacklist));
    document.getElementById('tlQueryResult').innerHTML =
      '<div class="tl-query-result">' + parts.join('') + '</div>';
  }catch(e){ toast(e.message, true); }
}

/* ---------- 条目查看弹窗 ---------- */
var tlModalSource = '', tlModalPage = 1, TL_SIZE = 50;
function openThreatListModal(key, name){
  tlModalSource = key;
  tlModalPage = 1;
  document.getElementById('tlModalTitle').textContent = '离线情报条目 · ' + name + '（' + key + '）';
  document.getElementById('tlKw').value = '';
  document.getElementById('tlEnabled').value = '';
  document.getElementById('tlModal').classList.add('show');
  loadThreatEntries(1);
}
async function loadThreatEntries(page){
  if (page) tlModalPage = page;
  var q = new URLSearchParams({source: tlModalSource, page: tlModalPage, size: TL_SIZE});
  var kw = document.getElementById('tlKw').value.trim();
  if (kw) q.set('keyword', kw);
  var en = document.getElementById('tlEnabled').value;
  if (en) q.set('enabled', en);
  try{
    var d = (await api('GET', '/api/threatlist/domains?' + q)).data;
    document.getElementById('tlEntryRows').innerHTML = d.items.length ? d.items.map(function(x, i){
      var n = (tlModalPage - 1) * TL_SIZE + i + 1;
      return '<tr><td class="mono" style="color:var(--text-dim)">' + n + '</td>' +
        '<td class="mono">' + esc(x.value) + '</td>' +
        '<td>' + (x.target === 'domain' ? '<span class="tag tag-blue">域名</span>' : '<span class="tag tag-neutral">IP</span>') + '</td>' +
        '<td>' + (x.enabled ? '<span class="tag tag-success"><span class="dot"></span>启用</span>' : '<span class="tag tag-neutral">停用</span>') + '</td>' +
        '<td class="mono">' + esc(x.updated_at || '—') + '</td></tr>';
    }).join('') : '<tr><td colspan="5"><div class="empty-state"><span class="es-ico">🔍</span>无匹配条目</div></td></tr>';
    pager(document.getElementById('tlEntryPager'), d.total, tlModalPage, TL_SIZE, 'loadThreatEntries');
  }catch(e){ toast(e.message, true); }
}

PAGE_LOADERS.threatlist = loadThreatlist;
