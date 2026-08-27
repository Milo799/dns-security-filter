/* ============================================================
   pages/threatintel.js — 在线情报源（在线源 CRUD）
   融合策略见 fusion.js，离线情报源见 threatlist.js
   ============================================================ */
var srcItems = [];

async function loadThreatintel(){
  try{
    var d = (await api('GET', '/api/threatintel')).data;
    document.getElementById('regAdapters').textContent = d.registered_adapters.join(' / ');
    srcItems = d.items;
    document.getElementById('srcRows').innerHTML = d.items.length ? d.items.map(function(x){
      var cfg = {};
      try{ cfg = JSON.parse(x.config || '{}'); }catch(e){}
      var zone = cfg.zone || '';
      var iface = (x.adapter_type === 'dnsbl'
        ? (zone ? 'DNS 查询 · <span class="mono">' + esc(zone) + '</span>' : 'DNS 查询')
        : esc(x.base_url || '（默认地址）'));
      return '<tr>' +
        '<td style="white-space:nowrap"><b>' + esc(x.name) + '</b>' +
        (x.is_builtin ? ' <span class="tag tag-blue">内置开源</span>' : '') +
        (x.adapter_registered ? '' : ' <span class="tag tag-error">未注册</span>') + '</td>' +
        '<td><span class="tag ' + (x.adapter_type === 'dnsbl' ? 'tag-neutral' : 'tag-blue') + '">' + (x.adapter_type === 'dnsbl' ? 'DNSBL' : 'HTTP') + '</span></td>' +
        '<td style="white-space:normal;word-break:break-all;max-width:250px">' + iface + '</td>' +
        '<td class="mono">' + (x.supports_domain ? '域名' : '') + (x.supports_domain && x.supports_ip ? '+' : '') + (x.supports_ip ? 'IP' : '') + '</td>' +
        '<td class="mono">' + x.timeout_ms + ' ms</td>' +
        '<td class="mono">' + (x.api_key_masked ? esc(x.api_key_masked) : '—') + '</td>' +
        '<td>' + (x.enabled
          ? '<span class="tag tag-success"><span class="dot"></span>已启用</span>'
          : '<span class="tag tag-neutral">已停用</span>') + '</td>' +
        '<td><div class="td-ops">' +
        '<button class="btn btn-normal btn-compact" title="编辑该源配置" onclick="editSrc(' + x.id + ')">编辑</button>' +
        '<button class="btn btn-normal btn-compact" title="测试连通性" onclick="testSrc(' + x.id + ')">测试</button>' +
        '<button class="btn btn-subtle btn-compact" title="' + (x.enabled ? '停用该源' : '启用该源') + '" onclick="toggleSrc(' + x.id + ',' + (!x.enabled ? 1 : 0) + ')">' + (x.enabled ? '停用' : '启用') + '</button>' +
        (x.is_builtin ? '' : '<button class="btn btn-subtle btn-danger-subtle btn-compact" title="删除该源" onclick="delSrc(' + x.id + ',\'' + esc(x.name) + '\')">删除</button>') +
        '</div></td></tr>';
    }).join('') : '<tr><td colspan="8"><div class="empty-state"><span class="es-ico">🌐</span>尚未接入情报源</div></td></tr>';
  }catch(e){ toast(e.message, true); }
}

/* ---------- 源弹窗（新增 / 编辑） ---------- */
var srcEditId = null;

function openSrcDialog(){
  srcEditId = null;
  document.getElementById('srcModalTitle').textContent = '接入在线情报源';
  document.getElementById('mSrcName').disabled = false;
  document.getElementById('mSrcUrl').value = '';
  document.getElementById('mSrcKey').value = '';
  document.getElementById('mSrcKey').placeholder = '存储于服务端';
  document.getElementById('mSrcTimeout').value = 2000;
  document.getElementById('mSrcDesc').value = '';
  document.getElementById('mSrcConfig').value = '';
  var sel = document.getElementById('mSrcName');
  api('GET', '/api/threatintel').then(function(d){
    var used = d.data.items.map(function(i){ return i.name; });
    var avail = d.data.registered_adapters.filter(function(n){ return used.indexOf(n) < 0; });
    sel.innerHTML = (avail.length ? avail : ['example']).map(function(n){ return '<option>' + n + '</option>'; }).join('');
    document.getElementById('srcModal').classList.add('show');
  });
}

function editSrc(id){
  var x = srcItems.find(function(i){ return i.id === id; });
  if (!x) return;
  srcEditId = id;
  document.getElementById('srcModalTitle').textContent = '编辑在线情报源';
  document.getElementById('mSrcName').innerHTML = '<option>' + esc(x.name) + '</option>';
  document.getElementById('mSrcName').disabled = true;
  document.getElementById('mSrcUrl').value = x.base_url || '';
  document.getElementById('mSrcKey').value = '';
  document.getElementById('mSrcKey').placeholder = x.api_key_masked ? ('留空保持不变（当前：' + x.api_key_masked + '）') : '留空保持不变';
  document.getElementById('mSrcTimeout').value = x.timeout_ms;
  document.getElementById('mSrcDesc').value = x.description || '';
  var cfg = '';
  try{ cfg = JSON.stringify(JSON.parse(x.config || '{}'), null, 2); }catch(e){ cfg = x.config || ''; }
  document.getElementById('mSrcConfig').value = (cfg === '{}') ? '' : cfg;
  document.getElementById('srcModal').classList.add('show');
}

async function saveSrcEntry(){
  var name = document.getElementById('mSrcName').value;
  var base_url = document.getElementById('mSrcUrl').value.trim();
  var api_key = document.getElementById('mSrcKey').value;
  var timeout_ms = parseInt(document.getElementById('mSrcTimeout').value) || 2000;
  var description = document.getElementById('mSrcDesc').value.trim();
  var config = document.getElementById('mSrcConfig').value.trim() || '';
  if (config){ try{ JSON.parse(config); }catch(e){ toast('扩展配置 JSON 格式错误：' + e.message, true); return; } }
  try{
    if (srcEditId === null){
      await api('POST', '/api/threatintel', {name: name, base_url: base_url, api_key: api_key,
        enabled: false, timeout_ms: timeout_ms, config: config, description: description});
      toast('已接入，可测试连通性后启用');
    } else {
      var x = srcItems.find(function(i){ return i.id === srcEditId; });
      await api('PUT', '/api/threatintel/' + srcEditId, {name: x.name, adapter_type: x.adapter_type,
        base_url: base_url, api_key: api_key, enabled: !!x.enabled, timeout_ms: timeout_ms,
        config: config, description: description});
      toast('已保存修改');
    }
    closeModal('srcModal');
    srcEditId = null;
    loadThreatintel();
  }catch(e){ toast(e.message, true); }
}

async function testSrc(id){
  toast('测试中…');
  try{
    var d = (await api('POST', '/api/threatintel/' + id + '/test')).data;
    toast((d.ok ? '连通正常 ' : '连通失败 ') + d.detail + '（' + d.latency_ms + 'ms）', !d.ok);
  }catch(e){ toast(e.message, true); }
}

async function toggleSrc(id, to){
  var x = srcItems.find(function(i){ return i.id === id; });
  try{
    await api('PUT', '/api/threatintel/' + id, {
      name: x.name, adapter_type: x.adapter_type, base_url: x.base_url, api_key: '',
      enabled: !!to, timeout_ms: x.timeout_ms,
      config: x.config || '', description: x.description || ''});
    toast(to ? '已启用' : '已停用');
    loadThreatintel();
  }catch(e){ toast(e.message, true); }
}

async function delSrc(id, name){
  if (!confirm('确认删除情报源 ' + name + ' ？')) return;
  try{
    await api('DELETE', '/api/threatintel/' + id);
    toast('已删除');
    loadThreatintel();
  }catch(e){ toast(e.message, true); }
}

PAGE_LOADERS.threatintel = loadThreatintel;
