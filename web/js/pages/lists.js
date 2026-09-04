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

/* ---------- 域名层级标签（Task #177：用户口径——顶级/二级/三级） ---------- */
var LEVEL_LABEL = {
  tld:         { text: '顶级', cls: 'tag tag-error' },
  registrable: { text: '二级', cls: 'tag tag-warning' },
  subdomain:   { text: '三级及以下', cls: 'tag tag-neutral' },
  ip:          { text: 'IP / 网段', cls: 'tag tag-neutral' }
};
var LEVEL_TIP = {
  tld: '公共后缀本身或其通配（*.com / *.cn / com）',
  registrable: '可注册的主域（baidu.com / qq.com / example.com.cn）',
  subdomain: '主域下的子域（www.baidu.com / mail.qq.com）'
};
function levelTag(x){
  if (x.target !== 'domain') {
    return '<span class="tag tag-neutral">IP / 网段</span>';
  }
  var lv = LEVEL_LABEL[x.level];
  var html = lv ? '<span class="' + lv.cls + '" title="' + (LEVEL_TIP[x.level] || '') + '">' + lv.text + '</span>' : '';
  if (x.wildcard){
    html += ' <span class="tag tag-blue">通配</span>';
  }
  /* 主域级通配警示：影响整站，黄点提示 */
  if (x.risk === 'warn'){
    html += ' <span class="tag tag-warning" title="' + esc(x.risk_note || '') + '">⚠ 影响整站</span>';
  }
  /* 顶层通配（手工刻意添加的整域管控，如 *.jp）：红标客观提示影响面 */
  if (x.risk === 'blocked'){
    html += ' <span class="tag tag-error" title="' + esc(x.risk_note || '') + '">⚠⚠ 顶层通配 · 影响整个后缀</span>';
  }
  return html;
}

function loadListData(page, listType, ids){
  if (page) ids.page = page;
  var q = new URLSearchParams({page: ids.page, size: 20, list_type: listType});
  var t = document.getElementById(ids.target).value;
  if (t) q.set('target', t);
  var lv = document.getElementById(ids.level).value;
  if (lv) q.set('domain_level', lv);
  var wc = document.getElementById(ids.wild).value;
  if (wc !== '') q.set('wildcard', wc === '1');
  var kw = document.getElementById(ids.kw).value.trim();
  if (kw) q.set('keyword', kw);
  api('GET', '/api/list?' + q).then(function(d){
    document.getElementById(ids.count).textContent = '共 ' + d.data.total + ' 条';
    document.getElementById(ids.rows).innerHTML = d.data.items.length ? d.data.items.map(function(x){
      return '<tr><td class="mono">' + esc(x.value) + '</td>' +
        '<td>' + (x.target === 'domain'
          ? '<span class="tag tag-blue">域名</span>'
          : '<span class="tag tag-neutral">IP/CIDR</span>') + '</td>' +
        '<td>' + levelTag(x) + '</td>' +
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
    }).join('') : ('<tr><td colspan="8"><div class="empty-state"><span class="es-ico">📭</span>' +
      (ids.level && document.getElementById(ids.level).value
        ? '当前筛选（' + LEVEL_LABEL[document.getElementById(ids.level).value].text +
          '）下没有条目。顶级域名（如 *.' + 'com）只能通过"新建"手工添加，批量导入会被拒绝'
        : '暂无条目') + '</div></td></tr>');
    pager(document.getElementById(ids.pager), d.data.total, ids.page, 20, ids.loader);
  }).catch(function(e){ toast(e.message, true); });
}

var wlPage = 1, blPage = 1;
var WL_IDS = {page: 1, target: 'wlTarget', level: 'wlLevel', wild: 'wlWild', kw: 'wlKw', count: 'wlCount', rows: 'wlRows', pager: 'wlPager', loader: 'loadWhitelist'};
var BL_IDS = {page: 1, target: 'blTarget', level: 'blLevel', wild: 'blWild', kw: 'blKw', count: 'blCount', rows: 'blRows', pager: 'blPager', loader: 'loadBlacklist'};
function loadWhitelist(page){ loadListData(page, 'whitelist', WL_IDS); }
function loadBlacklist(page){ loadListData(page, 'blacklist', BL_IDS); }

function openListDialog(listType){
  document.getElementById('mListType').value = listType;
  document.getElementById('mListTypeLabel').textContent = listType === 'whitelist' ? '🟢 白名单 · 放行豁免' : '🔴 黑名单 · 直接拦截';
  document.getElementById('listModal').classList.add('show');
}

/* ---------- 前端预校验（Task #177 口径：手工添加允许顶层通配） ----------
   - 无效语法（裸 * / *.）：拦截；
   - 顶层通配（*.com / *.jp 等）：不拦——手工添加属管理员明确意图
     （如 *.jp 入黑名单整域管控），红字强提示 + 保存时二次确认弹窗；
   - 主域级通配（*.example.com）：黄字提示影响范围。
   后端手工链路同样放行（仅 CSV 导入拒绝），前端预检与后端口径对齐。 */
var COMMON_TLD = ['com','net','org','cn','edu','gov','info','biz','io','co','xyz','top','app','dev','ai','me','tv','cc','uk','jp','hk','tw','mo','name','pro','mobi','asia','int','mil','arpa','site','online','shop','store','tech','cloud','live','ltd','group','team','work','wiki','fun','red','win','icu','link'];
var MULTI_TLD = ['com.cn','net.cn','org.cn','gov.cn','edu.cn','ac.cn','co.uk','org.uk','ac.uk','gov.uk','com.hk','com.tw','com.mo','com.sg','com.my','com.jp','co.jp','or.jp','co.kr','com.au','net.au','org.au','com.br','com.mx','com.ar','com.tr','com.ru','com.vn','com.ph','com.pk','com.in','co.in','com.co','com.sa','com.eg','co.nz','idv.tw','org.tw','net.au','edu.au','gov.au','gov.cn','mil.cn','bj.cn','sh.cn','tj.cn','cq.cn','zj.cn','js.cn','gd.cn','sc.cn'];
/* 顶层通配检测结果缓存：saveListEntry 二次确认时复用，避免重复计算 */
var _precheckState = { topWildcard: false, suffix: '' };

function precheckListValue(){
  var target = document.getElementById('mTarget').value;
  var v = document.getElementById('mValue').value.trim().toLowerCase();
  var hint = document.getElementById('mValueHint');
  if (!hint) return true;
  _precheckState.topWildcard = false;
  _precheckState.suffix = '';
  if (target === 'domain' && (v === '*' || v === '*.')){
    hint.textContent = '⛔ 裸通配符 * / *.（空后缀）是无效条目，禁止添加';
    hint.style.color = 'var(--danger)';
    return false;
  }
  if (target === 'domain' && v.indexOf('*.') === 0){
    var suffix = v.slice(2).replace(/\.$/, '');
    var parts = suffix.split('.');
    var onePart = parts.length === 1 && COMMON_TLD.indexOf(parts[0]) >= 0;
    var twoPart = parts.length === 2 && MULTI_TLD.indexOf(suffix) >= 0;
    if (onePart || twoPart){
      /* 顶层通配：不拦截（管理员明确意图），红字强提示 + 保存二次确认 */
      _precheckState.topWildcard = true;
      _precheckState.suffix = suffix;
      hint.textContent = '⚠⚠ *.' + suffix + ' 是顶层通配——影响整个互联网域段。确认是刻意的整域管控再保存（批量导入仍会被拒绝）';
      hint.style.color = 'var(--danger)';
      return true;
    }
    hint.textContent = '⚠ 父域级通配：' + suffix + ' 下全部子域都会命中此规则，请确认影响范围';
    hint.style.color = 'var(--warning)';
    return true;
  }
  hint.textContent = '';
  return true;
}

async function saveListEntry(){
  var body = {
    list_type: document.getElementById('mListType').value,
    target: document.getElementById('mTarget').value,
    value: document.getElementById('mValue').value.trim(),
    remark: document.getElementById('mRemark').value.trim()
  };
  if (!body.value){ toast('请填写"值"', true); return; }
  if (!precheckListValue()){ return; }
  /* 顶层通配二次确认：明确展示影响后果（Task #177） */
  if (_precheckState.topWildcard){
    var ltName = body.list_type === 'whitelist' ? '白名单（放行豁免）' : '黑名单（直接拦截）';
    var consequence = body.list_type === 'whitelist'
      ? '*.' + _precheckState.suffix + ' 将绕过全部检测放行该后缀下所有域名'
      : '*.' + _precheckState.suffix + ' 将拦截该后缀下所有域名，可能造成业务中断';
    if (!confirm('确认把 *.' + _precheckState.suffix + ' 加入' + ltName + '？\n\n' + consequence + '。\n\n此操作影响面极大，确定继续吗？')) return;
  }
  try{
    await api('POST', '/api/list', body);
    closeModal('listModal');
    document.getElementById('mValue').value = '';
    document.getElementById('mRemark').value = '';
    document.getElementById('mValueHint').textContent = '';
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
    var msg = '导入 ' + d.imported + ' 条，跳过 ' + d.skipped + ' 条';
    if (d.deduped > 0){
      msg += '，自动消重 ' + d.deduped + ' 条' +
             '（文件内重复 ' + (d.dup_in_file || 0) + ' / 名单中已存在 ' + (d.dup_in_db || 0) + '）';
    } else {
      msg += '，无重复条目';
    }
    if (d.errors && d.errors.length){ msg += '。错误：' + d.errors.join('；'); }
    var el = document.getElementById('importResult');
    el.textContent = msg;
    el.style.color = 'var(--text-sec)';
    if (d.duplicates && d.duplicates.length){
      el.textContent += '。重复条目：' + d.duplicates.join('、');
    }
    /* 跨名单冲突：导入条目已存在于另一份名单，安全提醒 */
    if (d.conflicts && d.conflicts.length){
      el.textContent += '。⚠ 跨名单冲突 ' + d.conflicts.length + ' 条（已导入，注意：白名单命中优先放行）：' +
                         d.conflicts.join('、');
      el.style.color = 'var(--warning)';
      toast('⚠ 有 ' + d.conflicts.length + ' 条与另一名单冲突，请查看明细', true);
    } else {
      toast('导入完成：新增 ' + d.imported + ' 条' + (d.deduped > 0 ? '，消重 ' + d.deduped + ' 条' : ''));
    }
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
