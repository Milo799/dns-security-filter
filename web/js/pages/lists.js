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

/* ---------- 域名层级标签（Task #176：层级筛选与过宽通配警示） ---------- */
var LEVEL_LABEL = {
  tld:         { text: '一级 · 公共后缀', cls: 'tag tag-error' },
  registrable: { text: '主域 · 可注册域', cls: 'tag tag-warning' },
  subdomain:   { text: '子域', cls: 'tag tag-neutral' },
  ip:          { text: 'IP / 网段', cls: 'tag tag-neutral' }
};
function levelTag(x){
  if (x.target !== 'domain') {
    return '<span class="tag tag-neutral">IP / 网段</span>';
  }
  var lv = LEVEL_LABEL[x.level];
  var html = lv ? '<span class="' + lv.cls + '">' + lv.text + '</span>' : '';
  if (x.wildcard){
    html += ' <span class="tag tag-blue">通配</span>';
  }
  /* 主域级通配警示：影响整站，黄点提示（入口已拒绝更危险的顶层通配） */
  if (x.risk === 'warn'){
    html += ' <span class="tag tag-warning" title="' + esc(x.risk_note || '') + '">⚠ 影响整站</span>';
  }
  /* 存量数据可能存在顶层通配（防护上线前入库的）：红标提示尽快删除 */
  if (x.risk === 'blocked'){
    html += ' <span class="tag tag-error" title="' + esc(x.risk_note || '') + '">⛔ 极高风险 · 建议立即删除</span>';
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
    }).join('') : '<tr><td colspan="8"><div class="empty-state"><span class="es-ico">📭</span>暂无条目</div></td></tr>';
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

/* ---------- 前端预校验：顶层通配提前拦截（后端 _validate 为准） ----------
   与后端口径对齐：两段式必须整串命中多级公共后缀（*.com.cn 拦，
   *.mysite.cn 是合法主域通配 → 放行并黄字警示）。前端表只是常见
   子集预检，最终以后端 classify_entry（PSL 感知）为准。 */
var COMMON_TLD = ['com','net','org','cn','edu','gov','info','biz','io','co','xyz','top','app','dev','ai','me','tv','cc','uk','jp','hk','tw','mo','name','pro','mobi','asia','int','mil','arpa','site','online','shop','store','tech','cloud','live','ltd','group','team','work','wiki','fun','red','win','icu','link'];
var MULTI_TLD = ['com.cn','net.cn','org.cn','gov.cn','edu.cn','ac.cn','co.uk','org.uk','ac.uk','gov.uk','com.hk','com.tw','com.mo','com.sg','com.my','com.jp','co.jp','or.jp','co.kr','com.au','net.au','org.au','com.br','com.mx','com.ar','com.tr','com.ru','com.vn','com.ph','com.pk','com.in','co.in','com.co','com.sa','com.eg','co.nz','idv.tw','org.tw','net.au','edu.au','gov.au','gov.cn','mil.cn','bj.cn','sh.cn','tj.cn','cq.cn','zj.cn','js.cn','gd.cn','sc.cn'];
function precheckListValue(){
  var target = document.getElementById('mTarget').value;
  var v = document.getElementById('mValue').value.trim().toLowerCase();
  var hint = document.getElementById('mValueHint');
  if (!hint) return true;
  if (target === 'domain' && (v === '*' || v === '*.')){
    hint.textContent = '⛔ 裸通配符 * 会命中所有域名，禁止添加';
    hint.style.color = 'var(--danger)';
    return false;
  }
  if (target === 'domain' && v.indexOf('*.') === 0){
    var suffix = v.slice(2).replace(/\.$/, '');
    var parts = suffix.split('.');
    /* 顶层通配：单段=公共后缀本身；两段=整串命中多级公共后缀 */
    var onePart = parts.length === 1 && COMMON_TLD.indexOf(parts[0]) >= 0;
    var twoPart = parts.length === 2 && MULTI_TLD.indexOf(suffix) >= 0;
    if (onePart || twoPart){
      hint.textContent = '⛔ *.' + suffix + ' 是顶层通配——白名单等于放行整个互联网、黑名单等于拦截整个互联网，禁止添加';
      hint.style.color = 'var(--danger)';
      return false;
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
