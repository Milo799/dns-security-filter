/* ============================================================
   pages/lists.js — 人工情报源（白/黑名单 Tab 切换 + CRUD + 导入导出）
   ============================================================ */

/* ---------- 白/黑 Tab 切换（防错：两个 Tab 各自独立工具栏与表格） ---------- */
var listTab = 'whitelist';
function switchListTab(type){
  listTab = type;
  document.getElementById('tabWl').classList.toggle('active', type === 'whitelist');
  document.getElementById('tabBl').classList.toggle('active', type === 'blacklist');
  document.getElementById('wlPanel').style.display = type === 'whitelist' ? '' : 'none';
  document.getElementById('blPanel').style.display = type === 'blacklist' ? '' : 'none';
  if (type === 'whitelist') loadWhitelist(); else loadBlacklist();
}
function refreshListTab(){
  if (listTab === 'whitelist') loadWhitelist(); else loadBlacklist();
}
function loadManualintel(){ switchListTab(listTab); }

function loadListData(page, listType, ids){
  if (page) ids.page = page;
  var q = new URLSearchParams({page: ids.page, size: 20, list_type: listType});
  var t = document.getElementById(ids.target).value;
  if (t) q.set('target', t);
  var kw = document.getElementById(ids.kw).value.trim();
  if (kw) q.set('keyword', kw);
  api('GET', '/api/list?' + q).then(function(d){
    document.getElementById(ids.count).textContent = '共 ' + d.data.total + ' 条';
    document.getElementById(ids.rows).innerHTML = d.data.items.length ? d.data.items.map(function(x){
      return '<tr><td class="mono">' + esc(x.value) + '</td>' +
        '<td>' + (x.target === 'domain'
          ? '<span class="tag tag-blue">域名</span>'
          : '<span class="tag tag-neutral">IP/CIDR</span>') + '</td>' +
        '<td>' + (x.enabled
          ? '<span class="tag tag-success"><span class="dot"></span>启用</span>'
          : '<span class="tag tag-neutral">停用</span>') + '</td>' +
        '<td style="white-space:normal">' + esc(x.remark || '') + '</td>' +
        '<td>' + esc(x.created_by) + '</td><td class="mono">' + esc(x.updated_at) + '</td>' +
        '<td><div class="row-actions">' +
        '<button class="icon-btn" title="' + (x.enabled ? '停用' : '启用') + '" onclick="toggleListItem(' + x.id + ',' + (!x.enabled ? 1 : 0) + ',\'' + listType + '\')">' + (x.enabled ? '⏸' : '▶') + '</button>' +
        '<button class="icon-btn" title="编辑备注" onclick="editListItem(' + x.id + ',\'' + listType + '\')">✎</button>' +
        '<button class="icon-btn danger" title="删除" onclick="delListItem(' + x.id + ',\'' + esc(x.value).replace(/'/g, '') + '\',\'' + listType + '\')">🗑</button>' +
        '</div></td></tr>';
    }).join('') : '<tr><td colspan="7"><div class="empty-state"><span class="es-ico">📭</span>暂无条目</div></td></tr>';
    pager(document.getElementById(ids.pager), d.data.total, ids.page, 20, ids.loader);
  }).catch(function(e){ toast(e.message, true); });
}

var wlPage = 1, blPage = 1;
var WL_IDS = {page: 1, target: 'wlTarget', kw: 'wlKw', count: 'wlCount', rows: 'wlRows', pager: 'wlPager', loader: 'loadWhitelist'};
var BL_IDS = {page: 1, target: 'blTarget', kw: 'blKw', count: 'blCount', rows: 'blRows', pager: 'blPager', loader: 'loadBlacklist'};
function loadWhitelist(page){ loadListData(page, 'whitelist', WL_IDS); }
function loadBlacklist(page){ loadListData(page, 'blacklist', BL_IDS); }

function openListDialog(listType){
  document.getElementById('mListType').value = listType;
  document.getElementById('mListTypeLabel').textContent = listType === 'whitelist' ? '🟢 白名单 · 放行豁免' : '🔴 黑名单 · 直接拦截';
  document.getElementById('listModal').classList.add('show');
}

async function saveListEntry(){
  var body = {
    list_type: document.getElementById('mListType').value,
    target: document.getElementById('mTarget').value,
    value: document.getElementById('mValue').value.trim(),
    remark: document.getElementById('mRemark').value.trim()
  };
  if (!body.value){ toast('请填写"值"', true); return; }
  try{
    await api('POST', '/api/list', body);
    closeModal('listModal');
    document.getElementById('mValue').value = '';
    document.getElementById('mRemark').value = '';
    toast('已创建（已记入审计）');
    (body.list_type === 'whitelist' ? loadWhitelist : loadBlacklist)(1);
  }catch(e){ toast(e.message, true); }
}

function toggleListItem(id, to, listType){
  api('PUT', '/api/list/' + id, {enabled: !!to}).then(function(){
    toast(to ? '已启用' : '已停用');
    (listType === 'whitelist' ? loadWhitelist : loadBlacklist)();
  }).catch(function(e){ toast(e.message, true); });
}

function editListItem(id, listType){
  var remark = prompt('修改备注：');
  if (remark === null) return;
  api('PUT', '/api/list/' + id, {remark: remark}).then(function(){
    toast('已更新');
    (listType === 'whitelist' ? loadWhitelist : loadBlacklist)();
  }).catch(function(e){ toast(e.message, true); });
}

function delListItem(id, value, listType){
  if (!confirm('确认删除条目 ' + value + ' ？')) return;
  api('DELETE', '/api/list/' + id).then(function(){
    toast('已删除（已记入审计）');
    (listType === 'whitelist' ? loadWhitelist : loadBlacklist)();
  }).catch(function(e){ toast(e.message, true); });
}

function importList(listType){
  document.getElementById('importResult').textContent = '';
  document.getElementById('mCsv').value = listType + ',domain,example.com,1,示例\n' + listType + ',ip,10.0.0.0/8,,整段';
  document.getElementById('importModal').classList.add('show');
}

async function doImportList(){
  var csv = document.getElementById('mCsv').value;
  if (!csv.trim()){ toast('请粘贴 CSV 内容', true); return; }
  try{
    var d = (await api('POST', '/api/list/import', csv, true)).data;
    document.getElementById('importResult').textContent =
      '导入 ' + d.imported + ' 条，跳过 ' + d.skipped + ' 条' +
      (d.errors && d.errors.length ? ('：' + d.errors.join('；')) : '');
    if (d.imported > 0){ refreshListTab(); }
  }catch(e){ toast(e.message, true); }
}

async function exportList(listType){
  try{
    var r = await api('GET', '/api/list/export?list_type=' + listType);
    downloadBlob(await r.blob(), listType + '.csv');
    toast('已导出');
  }catch(e){ toast(e.message, true); }
}

PAGE_LOADERS.manualintel = loadManualintel;
