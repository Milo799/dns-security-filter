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
    document.getElementById('cfgAllowSampleRate').value = v('allow_log_sample_rate', '100');
    document.getElementById('cfgLogAsync').checked = v('log_async_enabled', '1') === '1';
    document.getElementById('cfgLogFlushInterval').value = v('log_flush_interval_s', '2');
    document.getElementById('cfgLogBatchSize').value = v('log_batch_size', '500');
    document.getElementById('cfgCacheTtl').value = v('domain_cache_ttl_s', '300');
    document.getElementById('cfgCacheSize').value = v('domain_cache_size', '1000000');
    document.getElementById('cfgDegradeMode').checked = v('failsafe_mode', 'intercept') === 'degrade';
    document.getElementById('cfgCbThreshold').value = v('cb_failure_threshold', '5');
    document.getElementById('cfgCbTimeout').value = v('cb_open_timeout_s', '60');
    document.getElementById('cfgDegradeThreshold').value = v('degrade_threshold', '3');
    document.getElementById('cfgDegradeWindow').value = v('degrade_window_s', '300');
    document.getElementById('cfgHttpProxy').value = v('http_proxy', '');
    var ptEl = document.getElementById('cfgProxyTestResult');
    if (ptEl) ptEl.textContent = v('http_proxy', '') ? '已配置（未测试）' : '未配置（直连）';
    loadCacheStats();
    loadCbStats();
    loadLogWriterStats();
  }catch(e){ toast(e.message, true); }
}

async function loadLogWriterStats(){
  try{
    var s = (await api('GET', '/api/log-writer/stats')).data;
    var txt = (s.async_enabled ? '异步' : '同步') +
      '：入队 ' + (s.enqueued || 0).toLocaleString() +
      '，落库 ' + (s.flushed || 0).toLocaleString() +
      '，队列 ' + (s.queue_size || 0).toLocaleString();
    if (s.dropped > 0) txt += '，⚠️ 丢弃 ' + s.dropped.toLocaleString() + '（写入跟不上）';
    document.getElementById('cfgLogWriterStats').textContent = txt;
  }catch(e){
    document.getElementById('cfgLogWriterStats').textContent = '写入状态不可用';
  }
}

async function loadCbStats(){
  try{
    var d = (await api('GET', '/api/circuit-breaker/stats')).data;
    var srcs = Object.keys(d.sources || {});
    var srcTxt = srcs.length
      ? srcs.map(function(k){
          var s = d.sources[k];
          return k + '：' + (s.state === 'closed' ? '正常' : s.state === 'open' ? '已熔断' : '半开探测')
                 + (s.failures ? '（连续失败 ' + s.failures + '）' : '');
        }).join('；')
      : '暂无情报源活动记录';
    var dg = d.degrade || {};
    var dgTxt = dg.mode === 'degrade' ? '降级模式' : '拦截模式';
    if (dg.degraded) dgTxt += ' · 降级中（剩余 ' + dg.degrade_remaining_s + 's）';
    document.getElementById('cfgCbStats').textContent = dgTxt + '；' + srcTxt;
  }catch(e){
    document.getElementById('cfgCbStats').textContent = '状态不可用';
  }
}

async function loadCacheStats(){
  try{
    var s = (await api('GET', '/api/domain-cache/stats')).data;
    var rate = s.hit_rate === null || s.hit_rate === undefined ? '—'
             : (s.hit_rate * 100).toFixed(1) + '%';
    document.getElementById('cfgCacheStats').textContent =
      '当前 ' + s.size.toLocaleString() + ' / ' + s.max_size.toLocaleString() +
      ' 条，命中 ' + s.hits.toLocaleString() + ' 次，命中率 ' + rate +
      '（进程内累计，重启归零）';
  }catch(e){
    document.getElementById('cfgCacheStats').textContent = '缓存状态不可用';
  }
}

async function saveConfig(){
  var proxyAddr = document.getElementById('cfgHttpProxy').value.trim();
  if (proxyAddr && !/^https?:\/\//i.test(proxyAddr)){
    toast('代理地址须以 http:// 或 https:// 开头', true); return;
  }
  var body = {
    alert_ip: document.getElementById('cfgAlertIp').value.trim(),
    alert_ttl: parseInt(document.getElementById('cfgAlertTtl').value) || 60,
    upstream_dns: document.getElementById('cfgUpstream').value.trim(),
    log_retention_days: parseInt(document.getElementById('cfgRetention').value) || 90,
    domain_cache_ttl_s: parseInt(document.getElementById('cfgCacheTtl').value) || 300,
    domain_cache_size: parseInt(document.getElementById('cfgCacheSize').value) || 1000000,
    failsafe_mode: document.getElementById('cfgDegradeMode').checked ? 'degrade' : 'intercept',
    cb_failure_threshold: parseInt(document.getElementById('cfgCbThreshold').value),
    cb_open_timeout_s: parseInt(document.getElementById('cfgCbTimeout').value) || 60,
    degrade_threshold: parseInt(document.getElementById('cfgDegradeThreshold').value),
    degrade_window_s: parseInt(document.getElementById('cfgDegradeWindow').value) || 300,
    http_proxy: proxyAddr
  };
  if (!body.alert_ip || !body.upstream_dns){ toast('告警 IP 与上游 DNS 不能为空', true); return; }
  try{
    await api('PUT', '/api/config', body);
    var detection = document.getElementById('cfgDetection').checked;
    await api('POST', '/api/detection/toggle', {enabled: detection});
    await api('PUT', '/api/config', {allow_log_enabled: document.getElementById('cfgAllowLog').checked});
    await api('PUT', '/api/config', {
      allow_log_sample_rate: parseInt(document.getElementById('cfgAllowSampleRate').value) || 0,
      log_async_enabled: document.getElementById('cfgLogAsync').checked,
      log_flush_interval_s: parseInt(document.getElementById('cfgLogFlushInterval').value) || 2,
      log_batch_size: parseInt(document.getElementById('cfgLogBatchSize').value) || 500
    });
    toast('配置已保存，立即生效');
    loadDashboard();
    loadCacheStats();
    loadCbStats();
    loadLogWriterStats();
    var ptEl2 = document.getElementById('cfgProxyTestResult');
    if (ptEl2) ptEl2.textContent = proxyAddr ? '已配置（未测试）' : '未配置（直连）';
  }catch(e){ toast(e.message, true); }
}

async function testProxy(){
  var el = document.getElementById('cfgProxyTestResult');
  var addr = document.getElementById('cfgHttpProxy').value.trim();
  try{
    el.textContent = '测试中…';
    var d = (await api('POST', '/api/proxy/test', addr ? {proxy: addr} : {})).data;
    if (d.reachable){
      el.textContent = '✅ ' + d.detail + '（' + d.elapsed_ms + ' ms）';
      toast('代理连通：' + d.elapsed_ms + ' ms');
    }else{
      el.textContent = '❌ ' + d.detail + '（' + d.elapsed_ms + ' ms）';
      toast('代理测试失败：' + d.detail, true);
    }
  }catch(e){
    el.textContent = '❌ ' + e.message;
    toast('代理测试失败：' + e.message, true);
  }
}

PAGE_LOADERS.config = loadConfig;
