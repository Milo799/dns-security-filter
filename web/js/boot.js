/* ============================================================
   boot.js — 启动逻辑（登录 / 导航 / 主题切换 / Token 校验）
   必须在 app.js、charts.js、pages/*.js 之后加载
   ============================================================ */

/* ---------- 主题切换（深色 SOC 默认，浅色可选） ---------- */
(function(){
  if (localStorage.getItem('dnsf_theme') === 'light') document.body.classList.add('light');
})();
function toggleTheme(){
  document.body.classList.toggle('light');
  localStorage.setItem('dnsf_theme', document.body.classList.contains('light') ? 'light' : 'dark');
  var btn = document.getElementById('themeToggle');
  if (btn) btn.textContent = document.body.classList.contains('light') ? '☀' : '☾';
}

/* ---------- 登录 ---------- */
async function doLogin(){
  var u = document.getElementById('loginUser').value.trim();
  var p = document.getElementById('loginPass').value;
  document.getElementById('loginErr').textContent = '';
  try{
    var r = await api('POST', '/api/auth/login', {username: u, password: p});
    TOKEN = r.data.token;
    USERNAME = u;
    localStorage.setItem('dnsf_token', TOKEN);
    localStorage.setItem('dnsf_user', u);
    if (r.data.must_change_password){
      // 首次登录/初始密码：强制改密，未完成不进主界面
      openPwdModal(true);
    } else {
      enterApp();
    }
  }catch(e){ document.getElementById('loginErr').textContent = e.message; }
}

function doLogout(expired){
  TOKEN = '';
  localStorage.removeItem('dnsf_token');
  document.getElementById('app').style.display = 'none';
  document.getElementById('loginScreen').style.display = 'flex';
  if (expired) toast('登录已过期', true);
}

function enterApp(){
  document.getElementById('loginScreen').style.display = 'none';
  document.getElementById('app').style.display = 'flex';
  document.getElementById('avatar').textContent = (USERNAME || 'admin').slice(0, 2).toUpperCase();
  loadDashboard();
}

/* ---------- 修改密码（迭代 31：顶栏入口 + 首次登录强制闭环） ---------- */
var PWD_FORCED = false;   // true=强制模式（登录后未改密，弹窗不可关闭）

function openPwdModal(forced){
  PWD_FORCED = !!forced;
  document.getElementById('pwdOld').value = '';
  document.getElementById('pwdNew').value = '';
  document.getElementById('pwdNew2').value = '';
  document.getElementById('pwdErr').textContent = '';
  document.getElementById('pwdHint').textContent = '';
  document.getElementById('pwdForceTip').style.display = PWD_FORCED ? 'block' : 'none';
  document.getElementById('pwdModalTitle').textContent = PWD_FORCED ? '首次登录 · 必须修改密码' : '修改密码';
  // 强制模式：隐藏取消/关闭入口（完成改密才能进主界面）
  document.getElementById('pwdCancelBtn').style.display = PWD_FORCED ? 'none' : '';
  document.getElementById('pwdModalClose').style.display = PWD_FORCED ? 'none' : '';
  document.getElementById('pwdModal').classList.add('show');
}

function closePwdModal(){
  if (PWD_FORCED) return;   // 强制模式不可手动关闭
  document.getElementById('pwdModal').classList.remove('show');
}

/* 前端预校验（与后端 validate_password_strength 口径对齐） */
function pwdPrecheck(){
  var n = document.getElementById('pwdNew').value;
  var n2 = document.getElementById('pwdNew2').value;
  var hint = document.getElementById('pwdHint');
  if (!n){ hint.textContent = ''; return; }
  var problems = [];
  if (n.length < 8) problems.push('至少 8 位');
  if (!/[A-Za-z]/.test(n) || !/[0-9]/.test(n)) problems.push('须同时包含字母和数字');
  if (n2 && n !== n2) problems.push('两次输入不一致');
  hint.textContent = problems.length ? '⚠ ' + problems.join('；') : '✔ 新密码强度符合要求';
}

async function doChangePassword(){
  var oldP = document.getElementById('pwdOld').value;
  var newP = document.getElementById('pwdNew').value;
  var newP2 = document.getElementById('pwdNew2').value;
  var errEl = document.getElementById('pwdErr');
  errEl.textContent = '';
  if (!oldP || !newP || !newP2){ errEl.textContent = '请填写全部三项'; return; }
  if (newP !== newP2){ errEl.textContent = '两次输入的新密码不一致'; return; }
  if (newP.length < 8){ errEl.textContent = '新密码长度至少 8 位'; return; }
  if (!/[A-Za-z]/.test(newP) || !/[0-9]/.test(newP)){ errEl.textContent = '新密码须同时包含字母和数字'; return; }
  try{
    await api('POST', '/api/auth/change-password',
              {old_password: oldP, new_password: newP});
    document.getElementById('pwdModal').classList.remove('show');
    toast('密码修改成功，请用新密码重新登录');
    // 改密成功：强制清会话回登录页（旧 Token 服务端仍有效，但本地统一
    // 走重新登录流程，避免"改了密码却还挂在旧会话"的困惑）
    doLogout();
  }catch(e){ errEl.textContent = e.message; }
}

/* ---------- 事件绑定 ---------- */
document.getElementById('loginPass').addEventListener('keydown', function(e){
  if (e.key === 'Enter') doLogin();
});
document.querySelectorAll('.nav-item').forEach(function(el){
  el.addEventListener('click', function(){ go(el.dataset.page); });
});
document.getElementById('pwdNew2').addEventListener('keydown', function(e){
  if (e.key === 'Enter') doChangePassword();
});

/* ---------- 启动：已有 Token 则校验并进入 ---------- */
if (TOKEN){
  api('GET', '/api/status').then(enterApp).catch(function(){
    TOKEN = '';
    localStorage.removeItem('dnsf_token');
  });
}
