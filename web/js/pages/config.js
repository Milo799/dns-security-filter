/* ============================================================
   pages/config.js — 系统配置（运行时可改，保存立即生效）
   ============================================================ */
async function loadConfig(){
  try{
    var d = (await api('GET', '/api/config')).data.items;
    var v = function(k, def){ return d[k] ? d[k].value : def; };
    document.getElementById('cfgAlertIp').value = v('alert_ip', '127.0.0.1');
    document.getElementById('cfgAlertTtl').value = v('alert_ttl', '60');
    document.getElementById('cfgUpstream').value = v('upstream_dns', '8.8.8.8');
    document.getElementById('cfgRetention').value = v('log_retention_days', '90');
    document.getElementById('cfgDetection').checked = v('detection_enabled', '1') === '1';
    document.getElementById('cfgAllowLog').checked = v('allow_log_enabled', '0') === '1';
  }catch(e){ toast(e.message, true); }
}

async function saveConfig(){
  var body = {
    alert_ip: document.getElementById('cfgAlertIp').value.trim(),
    alert_ttl: parseInt(document.getElementById('cfgAlertTtl').value) || 60,
    upstream_dns: document.getElementById('cfgUpstream').value.trim(),
    log_retention_days: parseInt(document.getElementById('cfgRetention').value) || 90
  };
  if (!body.alert_ip || !body.upstream_dns){ toast('告警 IP 与上游 DNS 不能为空', true); return; }
  try{
    await api('PUT', '/api/config', body);
    var detection = document.getElementById('cfgDetection').checked;
    await api('POST', '/api/detection/toggle', {enabled: detection});
    await api('PUT', '/api/config', {allow_log_enabled: document.getElementById('cfgAllowLog').checked});
    toast('配置已保存，立即生效');
    loadDashboard();
  }catch(e){ toast(e.message, true); }
}

PAGE_LOADERS.config = loadConfig;
