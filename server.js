'use strict';
/*
  خادم اختبار القدرات العقلية: تسجيل دخول + لوحة المعلم + حفظ النتائج (بدون قاعدة بيانات).
  البيانات تُحفظ في ملف واحد data.json. لا يغيّر ملف index.html: يقرؤه ويضيف إليه سكربتًا صغيرًا عند تقديمه للطالب.
  المتغيرات في Render:
    TEACHER_PASS  كلمة مرور المعلم (مطلوب)
    TEACHER_USER  اسم دخول المعلم (اختياري، الافتراضي teacher)
    DATA_DIR      مجلد حفظ البيانات (اختياري). اجعله /data إذا أضفت Disk في Render.
*/
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const TEACHER_USER = (process.env.TEACHER_USER || 'teacher').toLowerCase();
const TEACHER_PASS = process.env.TEACHER_PASS;
if (!TEACHER_PASS) {
  console.error('Missing environment variable: TEACHER_PASS is required.');
  process.exit(1);
}
const SECRET = process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update('mw|' + TEACHER_PASS).digest('hex');

/* ---------- تشفير وجلسات ---------- */
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function makeToken(obj, hours) {
  const body = Buffer.from(JSON.stringify(Object.assign({}, obj, { exp: Date.now() + hours * 3600e3 }))).toString('base64url');
  return body + '.' + sign(body);
}
function readToken(tok) {
  if (!tok || tok.indexOf('.') < 0) return null;
  const parts = tok.split('.');
  const a = Buffer.from(parts[1] || ''), b = Buffer.from(sign(parts[0]));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const o = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    return o.exp > Date.now() ? o : null;
  } catch (e) { return null; }
}
function parseCookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) { try { o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch (e) { /* ignore */ } }
  });
  return o;
}
function setSession(req, res, obj, hours) {
  res.cookie('mw', makeToken(obj, hours), { httpOnly: true, sameSite: 'lax', secure: !!req.secure, maxAge: hours * 3600e3, path: '/' });
}
const scrypt = (pw, salt) => new Promise((resolve, reject) =>
  crypto.scrypt(pw, salt, 32, { N: 4096, r: 8, p: 1 }, (e, k) => (e ? reject(e) : resolve(k))));
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + (await scrypt(pw, salt)).toString('hex');
}
async function checkPw(pw, stored) {
  const parts = String(stored).split(':');
  const k = await scrypt(pw, Buffer.from(parts[0], 'hex'));
  const h = Buffer.from(parts[1] || '', 'hex');
  return h.length === k.length && crypto.timingSafeEqual(h, k);
}
const safeEq = (a, b) => {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
};

/* ---------- حماية من تخمين كلمات المرور ---------- */
const fails = new Map();
function locked(key) {
  const f = fails.get(key);
  if (!f || f.n < 6) return false;
  if (Date.now() - f.t > 5 * 60e3) { fails.delete(key); return false; }
  return true;
}
function addFail(key) {
  const f = fails.get(key) || { n: 0, t: 0 };
  f.n++; f.t = Date.now(); fails.set(key, f);
}

/* ---------- التخزين في ملف ---------- */
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'data.json');
let D = { users: [], results: [], open: true, nextUserId: 1, nextResultId: 1 };
function loadData() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  try {
    const j = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    D = Object.assign(D, j);
  } catch (e) {
    if (e.code !== 'ENOENT') { console.error('Cannot read data file (not overwriting it):', e.message); process.exit(1); }
  }
}
let saving = Promise.resolve();
function save() {
  saving = saving.then(async () => {
    const tmp = DATA_FILE + '.tmp';
    await fs.promises.writeFile(tmp, JSON.stringify(D));
    await fs.promises.rename(tmp, DATA_FILE);
  }).catch(e => console.error('Save failed:', e.message));
  return saving;
}
const isOpen = () => D.open !== false;
const findUser = id => D.users.find(u => u.id === id);
async function auth(req) {
  const t = readToken(parseCookies(req).mw);
  if (!t) return null;
  if (t.r === 't') return { role: 't' };
  const u = findUser(t.id);
  return u ? { role: 's', id: u.id, username: u.username, name: u.name } : null;
}

/* ---------- كود المتصفح (يُدمج في الصفحات كنص) ---------- */
function clientHook() {
  var $ = function (id) { return document.getElementById(id); };
  var n = $('sname');
  if (n && window.MW_NAME) {
    n.value = window.MW_NAME; n.readOnly = true;
    setInterval(function () { if (!n.value) n.value = window.MW_NAME; }, 500);
  }
  var h = document.querySelector('header.top');
  if (h) {
    var a = document.createElement('a');
    a.href = '/logout'; a.className = 'chip'; a.style.textDecoration = 'none'; a.textContent = 'تسجيل الخروج';
    h.appendChild(a);
  }
  var tt;
  function toast(m, bad) {
    var t = $('mwToast');
    if (!t) {
      t = document.createElement('div'); t.id = 'mwToast';
      t.style.cssText = 'position:fixed;left:16px;right:16px;bottom:16px;max-width:420px;margin:auto;padding:10px 16px;border-radius:12px;text-align:center;z-index:99;font-weight:700;color:#fff';
      document.body.appendChild(t);
    }
    t.style.background = bad ? '#c43c3c' : '#1d8a55'; t.textContent = m; t.style.display = 'block';
    clearTimeout(tt); tt = setTimeout(function () { t.style.display = 'none'; }, 5000);
  }
  function txt(id) { var e = $(id); return e ? e.textContent.trim() : ''; }
  function post(body, sig, tries) {
    fetch('/api/result', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-MW': '1' }, body: JSON.stringify(body) })
      .then(function (r) {
        if (r.ok) {
          try { localStorage.setItem('__mwlast', sig); } catch (e) { /* ignore */ }
          toast('تم حفظ نتيجتك عند المعلم ✓');
        } else if (r.status >= 500 && tries > 0) {
          setTimeout(function () { post(body, sig, tries - 1); }, 3000);
        } else {
          r.json().then(function (j) { toast(j.error || 'تعذّر حفظ النتيجة', true); }, function () { toast('تعذّر حفظ النتيجة', true); });
        }
      })
      .catch(function () {
        if (tries > 0) setTimeout(function () { post(body, sig, tries - 1); }, 3000);
        else toast('تعذّر حفظ النتيجة، تأكد من الاتصال بالإنترنت', true);
      });
  }
  function send() {
    var rv = document.querySelectorAll('#rvList .rv'), total = rv.length, score = 0;
    rv.forEach(function (x) { if (!x.classList.contains('wrong') && !x.classList.contains('skip')) score++; });
    if (!total) {
      score = parseInt(txt('sc'), 10) || 0;
      total = parseInt((txt('scOf').match(/\d+/) || [0])[0], 10) || 0;
    }
    var secs = [];
    document.querySelectorAll('#secs .secrow').forEach(function (r) {
      var c = r.children;
      secs.push({ n: c[0] ? c[0].textContent.trim() : '', v: c.length ? c[c.length - 1].textContent.trim() : '' });
    });
    var body = { model: txt('whoModel'), score: score, total: total, grade: txt('grade'), meta: txt('rMeta'), sections: secs };
    var sig = [body.model, body.score, body.total, body.meta].join('|');
    try { if (localStorage.getItem('__mwlast') === sig) return; } catch (e) { /* ignore */ }
    post(body, sig, 3);
  }
  var res = $('result'), armed = false;
  if (res) {
    new MutationObserver(function () {
      if (!res.hidden && !armed) { armed = true; setTimeout(send, 1500); }
      else if (res.hidden) armed = false;
    }).observe(res, { attributes: true, attributeFilter: ['hidden'] });
  }
}

function loginClient() {
  var f = document.getElementById('f'), err = document.getElementById('err');
  f.addEventListener('submit', function (e) {
    e.preventDefault(); err.textContent = '';
    fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-MW': '1' }, body: JSON.stringify({ username: f.u.value, password: f.p.value }) })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (x) { if (x.ok) location.href = x.j.to; else err.textContent = x.j.error || 'تعذّر الدخول'; })
      .catch(function () { err.textContent = 'تعذّر الاتصال بالخادم'; });
  });
}

function teacherClient() {
  var $ = function (id) { return document.getElementById(id); };
  var S = { users: [], results: [], open: true }, tt;
  function api(method, url, body) {
    return fetch(url, { method: method, headers: { 'Content-Type': 'application/json', 'X-MW': '1' }, body: method === 'GET' ? undefined : JSON.stringify(body || {}) })
      .then(function (r) {
        if (r.status === 401) { location.href = '/login'; throw new Error('انتهت الجلسة'); }
        return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || 'حدث خطأ'); return j; });
      });
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function fmt(d) { return d ? new Date(d).toLocaleString('ar-u-ca-gregory-nu-latn', { dateStyle: 'short', timeStyle: 'short' }) : '—'; }
  function pct(r) { return r.total ? Math.round(r.score / r.total * 100) : 0; }
  function toast(m, bad) {
    var t = $('toast'); t.textContent = m; t.className = 'toast' + (bad ? ' bad' : ''); t.hidden = false;
    clearTimeout(tt); tt = setTimeout(function () { t.hidden = true; }, 3500);
  }
  function err(e) { toast(e.message || 'حدث خطأ', true); }

  function load() { return api('GET', '/api/t/data').then(function (d) { S = d; render(); }).catch(err); }

  function render() {
    $('stat').className = 'pill ' + (S.open ? 'on' : 'off');
    $('stat').textContent = S.open ? 'الموقع يعمل' : 'الموقع متوقف';
    $('toggle').textContent = S.open ? 'إيقاف الموقع' : 'تشغيل الموقع';
    $('toggle').className = 'btn ' + (S.open ? 'bad' : 'ok');
    var took = S.users.filter(function (u) { return u.attempts > 0; }).length;
    var avg = S.results.length ? Math.round(S.results.reduce(function (a, r) { return a + pct(r); }, 0) / S.results.length) : 0;
    $('nU').textContent = S.users.length; $('nT').textContent = took;
    $('nA').textContent = S.results.length; $('nAvg').textContent = avg + '%';
    renderUsers(); renderResults();
  }

  function renderUsers() {
    var s = $('qs').value.trim().toLowerCase(), only = $('notTaken').checked;
    var rows = S.users.filter(function (u) {
      return (!s || (u.name + ' ' + u.username).toLowerCase().indexOf(s) >= 0) && (!only || !u.attempts);
    });
    $('ub').innerHTML = rows.length ? rows.map(function (u) {
      return '<tr><td>' + esc(u.name) + '</td><td dir="ltr">' + esc(u.username) + '</td><td>' + u.attempts + '</td><td>' +
        (u.best == null ? '—' : u.best) + '</td><td>' + fmt(u.last_at) + '</td><td><div class="acts">' +
        '<button class="sm" data-a="pw" data-id="' + u.id + '">كلمة مرور جديدة</button>' +
        '<button class="sm bad" data-a="du" data-id="' + u.id + '">حذف</button></div></td></tr>';
    }).join('') : '<tr><td colspan="6" class="empty">لا يوجد طلاب بعد. أضف طلابك من الأعلى.</td></tr>';
  }

  function renderResults() {
    var s = $('qr').value.trim().toLowerCase();
    var rows = S.results.filter(function (r) { return !s || (r.name + ' ' + r.username + ' ' + r.model).toLowerCase().indexOf(s) >= 0; });
    $('rb').innerHTML = rows.length ? rows.map(function (r) {
      var secs = (r.sections || []).map(function (x) { return '<li><span>' + esc(x.n) + '</span><b dir="ltr">' + esc(x.v) + '</b></li>'; }).join('');
      return '<tr><td>' + esc(r.name) + '</td><td>' + esc(r.model) + '</td><td dir="ltr">' + r.score + ' / ' + r.total +
        '</td><td>' + pct(r) + '%</td><td>' + fmt(r.created_at) + '</td><td><div class="acts">' +
        '<button class="sm" data-a="det" data-id="' + r.id + '">التفاصيل</button>' +
        '<button class="sm bad" data-a="dr" data-id="' + r.id + '">حذف</button></div></td></tr>' +
        '<tr class="det" id="d' + r.id + '" hidden><td colspan="6"><div class="meta">' + esc(r.grade) + ' · ' + esc(r.meta) +
        '</div><ul class="secl">' + secs + '</ul></td></tr>';
    }).join('') : '<tr><td colspan="6" class="empty">لا توجد نتائج بعد.</td></tr>';
  }

  function showCreds(list) {
    window.__creds = list;
    $('credBox').hidden = false;
    $('credBody').innerHTML = list.map(function (c) {
      return '<tr><td>' + esc(c.name) + '</td><td dir="ltr">' + esc(c.username) + '</td><td dir="ltr">' + esc(c.password) + '</td></tr>';
    }).join('');
    $('credBox').scrollIntoView({ behavior: 'smooth' });
  }

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-a]'); if (!b) return;
    var a = b.dataset.a, id = b.dataset.id;
    if (a === 'det') { var t = $('d' + id); t.hidden = !t.hidden; }
    else if (a === 'dr') { if (confirm('حذف هذه النتيجة؟')) api('DELETE', '/api/t/results/' + id).then(load).catch(err); }
    else if (a === 'du') {
      var u = S.users.filter(function (x) { return String(x.id) === id; })[0];
      if (u && confirm('حذف الطالب «' + u.name + '» وجميع نتائجه؟')) api('DELETE', '/api/t/users/' + id).then(load).catch(err);
    } else if (a === 'pw') {
      var p = prompt('كلمة المرور الجديدة (اتركها فارغة لتوليد رقم عشوائي):');
      if (p === null) return;
      api('POST', '/api/t/users/' + id + '/password', { password: p }).then(function (j) { alert('كلمة المرور الجديدة: ' + j.password); }).catch(err);
    }
  });

  $('toggle').onclick = function () {
    var next = !S.open;
    if (!next && !confirm('إيقاف الموقع؟ لن يتمكن الطلاب من الاختبار حتى تعيد تشغيله.')) return;
    api('POST', '/api/t/site', { open: next }).then(load).catch(err);
  };
  $('refresh').onclick = load;
  $('bulk').onclick = function () {
    var names = $('names').value.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
    if (!names.length) return toast('اكتب اسمًا واحدًا على الأقل', true);
    api('POST', '/api/t/users/bulk', { names: names }).then(function (j) { $('names').value = ''; showCreds(j.created); load(); }).catch(err);
  };
  $('addOne').onclick = function () {
    var c = { name: $('n1').value.trim(), username: $('u1').value.trim().toLowerCase(), password: $('p1').value };
    api('POST', '/api/t/users', c).then(function () { showCreds([c]); $('n1').value = ''; $('u1').value = ''; $('p1').value = ''; load(); }).catch(err);
  };
  $('copyCreds').onclick = function () {
    var t = (window.__creds || []).map(function (c) { return c.name + '\t' + c.username + '\t' + c.password; }).join('\n');
    navigator.clipboard.writeText(t).then(function () { toast('تم النسخ'); }, function () { toast('تعذّر النسخ', true); });
  };
  $('printCreds').onclick = function () { window.print(); };
  $('hideCreds').onclick = function () { $('credBox').hidden = true; window.__creds = []; };
  $('delAll').onclick = function () {
    if (confirm('حذف جميع النتائج لكل الطلاب؟ لا يمكن التراجع.')) api('DELETE', '/api/t/results').then(load).catch(err);
  };
  $('restore').onclick = function () { $('restoreFile').click(); };
  $('restoreFile').onchange = function () {
    var inp = this, f = inp.files[0]; if (!f) return;
    if (!confirm('الاسترجاع يستبدل جميع الطلاب والنتائج الحالية بمحتوى الملف. متابعة؟')) { inp.value = ''; return; }
    f.text().then(function (t) {
      var data; try { data = JSON.parse(t); } catch (e) { throw new Error('الملف غير صالح'); }
      return api('POST', '/api/t/restore', data);
    }).then(function () { toast('تم استرجاع النسخة الاحتياطية'); load(); }).catch(err);
    inp.value = '';
  };
  $('qs').oninput = renderUsers; $('notTaken').onchange = renderUsers; $('qr').oninput = renderResults;
  load();
}

/* ---------- الصفحات ---------- */
const FONTS = '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=El+Messiri:wght@500;700&family=Tajawal:wght@400;500;700;800&display=swap">';
const CSS = '<style>' +
  '[hidden]{display:none!important}*{box-sizing:border-box}' +
  ':root{--bg:#f3f5fa;--surface:#fff;--ink:#18233d;--muted:#5d6886;--line:#dde2ee;--accent:#2e4fa8;--accent-soft:#e6ecfb;--gold:#c98a12;--gold-soft:#fbf1dc;--ok:#1d8a55;--ok-soft:#e2f4ea;--bad:#c43c3c;--bad-soft:#fbe7e7;--display:"El Messiri","Tajawal",system-ui,sans-serif;--body:"Tajawal",system-ui,"Segoe UI",Tahoma,sans-serif}' +
  '@media (prefers-color-scheme:dark){:root{--bg:#0f1524;--surface:#18203a;--ink:#e8ecf7;--muted:#9aa5c4;--line:#2a3455;--accent:#8aa6ff;--accent-soft:#233063;--gold:#f0b545;--gold-soft:#3a2f17;--ok:#4fcb8a;--ok-soft:#163a2a;--bad:#ff7a7a;--bad-soft:#432023;color-scheme:dark}}' +
  'body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--body);font-size:16px;line-height:1.7;padding:0 16px 40px}' +
  '.wrap{max-width:1000px;margin:0 auto}h1,h2{font-family:var(--display);margin:0}h2{font-size:1.25rem;margin-bottom:12px}' +
  '.card{background:var(--surface);border:1px solid var(--line);border-radius:18px;padding:20px;margin-bottom:16px}' +
  '.btn{font:inherit;font-weight:700;border:0;border-radius:12px;padding:10px 18px;cursor:pointer;background:var(--accent);color:var(--surface);text-decoration:none;display:inline-block}' +
  '.btn.ghost{background:transparent;color:var(--accent);border:1.5px solid var(--line)}.btn.ok{background:var(--ok);color:#fff}.btn.bad{background:var(--bad);color:#fff}' +
  '.btn:focus-visible,.sm:focus-visible,input:focus-visible,textarea:focus-visible{outline:3px solid var(--gold);outline-offset:2px}' +
  'input,textarea{width:100%;font:inherit;padding:10px 12px;border-radius:12px;border:1.5px solid var(--line);background:var(--bg);color:var(--ink)}' +
  'label{display:block;font-weight:700;margin-bottom:6px}.meta{color:var(--muted);font-size:.92rem}.err{color:var(--bad);min-height:1.5em;margin:8px 0 0}' +
  '</style>';
const HEAD = '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">';

const LOGIN_HTML = HEAD + '<title>تسجيل الدخول</title>' + FONTS + CSS +
  '<style>.box{max-width:400px;margin:12vh auto 0}.box h1{font-size:1.6rem;margin-bottom:4px}.fld{margin-top:14px}.box .btn{width:100%;margin-top:18px}</style></head><body><div class="wrap"><div class="box card">' +
  '<h1>اختبار القدرات العقلية</h1><p class="meta">مدرسة التويثير الابتدائية · سجّل دخولك للبدء</p>' +
  '<form id="f" autocomplete="off"><div class="fld"><label for="u">اسم المستخدم</label><input id="u" name="u" dir="ltr" autocapitalize="none" required></div>' +
  '<div class="fld"><label for="p">كلمة المرور</label><input id="p" name="p" type="password" dir="ltr" required></div>' +
  '<p class="err" id="err" role="alert"></p><button class="btn" type="submit">دخول</button></form></div></div>' +
  '<script>(' + loginClient.toString() + ')()</script></body></html>';

const CLOSED_HTML = HEAD + '<title>الاختبار متوقف</title>' + FONTS + CSS +
  '<style>.box{max-width:460px;margin:14vh auto 0;text-align:center}</style></head><body><div class="wrap"><div class="box card">' +
  '<h1>الاختبار متوقف حاليًا</h1><p class="meta">أوقف المعلم الاختبار مؤقتًا. حاول مرة أخرى حين يعيد تشغيله.</p>' +
  '<a class="btn ghost" href="/logout">تسجيل الخروج</a></div></div></body></html>';

const TEACHER_HTML = HEAD + '<title>لوحة المعلم</title>' + FONTS + CSS +
  '<style>' +
  'header.top{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:18px 0;border-bottom:1px solid var(--line);margin-bottom:20px}' +
  'header.top h1{font-size:1.5rem}.pill{font-size:.88rem;font-weight:700;padding:4px 14px;border-radius:999px}' +
  '.pill.on{background:var(--ok-soft);color:var(--ok)}.pill.off{background:var(--bad-soft);color:var(--bad)}' +