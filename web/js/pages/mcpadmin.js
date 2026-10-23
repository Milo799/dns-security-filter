/* ============================================================
   pages/mcpadmin.js — MCP 服务管理（Web 端开关写能力 + 授权 Token）
   迭代 51（2026-10-23 用户需求）：不再需要 SSH 到 .191 改
   /etc/dnsfilter/mcp.env——在 Web 界面直接开关写能力、轮换 Token。
   ============================================================ */

var _mcpAdmin = null;   // 最近一次 /api/mcp/admin 的数据缓存

async function loadMcpAdmin(){
  try{
    var r = await api('GET', '/api/mcp/admin');
    if (r.code !== 0 || !r.data){ 
      document.getElementById('mcpRunning').textContent = r.message || '状态不可用';
      document.getElementById('mcpRunning').className = 'form-hint tag tag-danger';
      return;
    }
    var d = r.data;
    _mcpAdmin = d;

    // 服务状态
    var runEl = document.getElementById('mcpRunning');
    if (d.running === true){
      runEl.innerHTML = '<span class="tag tag-success">● 运行中</span>' +
        (d.since ? '　自 ' + esc(d.since) : '');
      runEl.className = 'form-hint';
    } else if (d.running === false){
      runEl.innerHTML = '<span class="tag tag-danger">● 未运行</span>（' + esc(d.state || 'unknown') + '）';
      runEl.className = 'form-hint';
    } else {
      runEl.textContent = '无法查询 systemd（非生产形态？）';
      runEl.className = 'form-hint';
    }

    document.getElementById('mcpEndpoint').textContent = d.endpoint || '-';
    document.getElementById('mcpApiBase').textContent = d.api_base || '-';
    document.getElementById('mcpAgent').textContent = d.agent_name || '-';
    document.getElementById('mcpEnvFile').textContent = d.env_file || '-';
    document.getElementById('mcpService').textContent = d.service || '-';

    // 写开关
    var tgl = document.getElementById('mcpWriteToggle');
    tgl.checked = !!d.allow_write;
    updateMcpWriteNote(d.allow_write);

    // Token
    document.getElementById('mcpTokenMasked').textContent =
      d.token_masked || '（未设置）';

    // 接入速查（端点动态填）
    var qc = document.getElementById('mcpQuickConfig');
    if (qc){
      qc.textContent =
        '{\n  "mcpServers": {\n    "dns-security-filter": {\n' +
        '      "type": "http",\n      "url": "' + (d.endpoint || '<端点>') + '",\n' +
        '      "headers": { "Authorization": "Bearer <轮换后获得>" }\n' +
        '    }\n  }\n}';
    }
  }catch(e){ toast(e.message, true); }
}

function updateMcpWriteNote(on){
  var el = document.getElementById('mcpWriteNote');
  if (!el) return;
  el.innerHTML = on
    ? '<span class="tag tag-warn">写能力：开</span>　AI 可在用户逐条确认后修改名单（仍受 confirm=true 二道闸门保护）'
    : '<span class="tag tag-success">写能力：只读</span>　所有写操作返回 write_disabled，查询类功能不受影响';
}

async function onMcpWriteToggle(cb){
  var on = cb.checked;
  // 先视觉回退，成功后再切换（避免开关与实际状态脱节）
  cb.checked = !on;
  var msg = on
    ? '确定开启写能力？\n\n开启后 AI 可在【你逐条确认】后修改黑白名单。\n每个写操作仍需 confirm=true 二道闸门。\n操作将重启 MCP 服务（约 3 秒）。'
    : '确定关闭写能力？\n\n关闭后所有 AI 写操作立即被拒（write_disabled）。\n查询类功能不受影响。\n操作将重启 MCP 服务（约 3 秒）。';
  if (!window.confirm(msg)) return;
  try{
    var r = await api('POST', '/api/mcp/admin/write',
                      {enabled: on, confirm: true});
    if (r.code !== 0){
      toast(r.message || '操作失败', true);
      loadMcpAdmin();
      return;
    }
    if (r.data && r.data.changed){
      toast(r.message + (r.data.hint ? '：' + r.data.hint : ''));
    } else {
      toast(r.message);
    }
    loadMcpAdmin();
  }catch(e){ toast(e.message, true); loadMcpAdmin(); }
}

async function rotateMcpToken(){
  if (!window.confirm('确定轮换 Token？\n\n· 旧 Token 立即失效，所有已接入的 AI 工具需更新配置\n· 新 Token 仅展示一次，请立即复制分发\n· 操作将重启 MCP 服务（约 3 秒）')) return;
  try{
    var r = await api('POST', '/api/mcp/admin/token', {confirm: true});
    if (r.code !== 0 || !r.data || !r.data.token){
      toast(r.message || '轮换失败', true);
      return;
    }
    var box = document.getElementById('mcpNewTokenBox');
    document.getElementById('mcpNewToken').textContent = r.data.token;
    box.style.display = 'block';
    toast('Token 已轮换，旧 Token 失效。请立即复制新 Token 分发。');
    loadMcpAdmin();
  }catch(e){ toast(e.message, true); }
}

function copyMcpNewToken(){
  var text = document.getElementById('mcpNewToken').textContent;
  if (navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(
      function(){ toast('已复制到剪贴板'); },
      function(){ toast('复制失败，请手动选择文本复制', true); });
  } else {
    // 旧浏览器兜底
    var ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta);
    ta.select();
    try{ document.execCommand('copy'); toast('已复制到剪贴板'); }
    catch(e){ toast('复制失败，请手动选择文本复制', true); }
    document.body.removeChild(ta);
  }
}

PAGE_LOADERS.mcpadmin = loadMcpAdmin;
