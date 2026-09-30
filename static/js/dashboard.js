const dashEl = document.getElementById('dash');
const CSRF = dashEl.dataset.csrf;
const ME_ID = Number(dashEl.dataset.uid);
const ME = dashEl.dataset.uname;
const OTHER = dashEl.dataset.otherUname;
const OTHER_ID = Number(dashEl.dataset.otherUid);

const $ = s => document.querySelector(s);
let txs = [], filt = 'all', ttl = 600, bal = 0, shown = 0;
let beneficiaries = [];

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const rs = p => 'Rs. ' + (p / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

function toast(m, c = '') {
  const d = document.createElement('div');
  d.className = 'toast ' + c;
  d.textContent = m;
  $('#toasts').append(d);
  setTimeout(() => d.remove(), 3500);
}

async function api(url, o = {}) {
  const h = {};
  if (o.json) h['Content-Type'] = 'application/json';
  if (o.method === 'POST' && o.csrf !== false) h['X-CSRF-Token'] = CSRF;
  const r = await fetch(url, {
    method: o.method || 'GET',
    headers: h,
    body: o.json ? JSON.stringify(o.json) : undefined,
    credentials: 'same-origin',
  });
  if (r.redirected && r.url.includes('/login')) { location = '/login'; return { status: 401, ok: false }; }
  let d = null;
  try { d = await r.clone().json(); } catch (e) {}
  if (r.ok) ttl = 600; // activity refreshes the session timeout
  return { status: r.status, ok: r.ok, data: d };
}

function countTo(v) {
  const s = shown, t0 = performance.now();
  bal = v;
  (function f(t) {
    const k = Math.min(1, (t - t0) / 600);
    shown = s + (v - s) * k;
    $('#bal').textContent = rs(Math.round(shown));
    if (k < 1) requestAnimationFrame(f);
  })(t0);
}


async function loadBeneficiaries() {
  const r = await api('/api/beneficiaries');
  if (!r.ok || !r.data) return;

  beneficiaries = r.data;
  renderBeneficiaries();
}

function renderBeneficiaries() {
  const container = $('#beneficiaryList');
  const select = $('#to');

  if (container) {
    if (!beneficiaries.length) {
      container.innerHTML = '<div class="mut">No beneficiaries added yet.</div>';
    } else {
      container.innerHTML = beneficiaries.map(b => `
        <div class="beneficiary-row" data-beneficiary-id="${Number(b.user_id)}">
          <div>
            <b>${esc(b.full_name || b.username)}</b>
            <div class="mut">@${esc(b.username)}</div>
          </div>
          <button type="button" class="ghost remove-beneficiary"
                  data-user-id="${Number(b.user_id)}">Remove</button>
        </div>
      `).join('');

      container.querySelectorAll('.remove-beneficiary').forEach(btn => {
        btn.addEventListener('click', () => removeBeneficiary(btn.dataset.userId));
      });
    }
  }

  // If the existing transfer recipient is a select element, populate it
  // from the saved beneficiaries. If it is an input, leave it unchanged.
  if (select && select.tagName === 'SELECT') {
    const current = select.value;
    select.innerHTML =
      '<option value="">-- Select Beneficiary --</option>' +
      beneficiaries.map(b =>
        `<option value="${esc(b.username)}">${esc(b.full_name || b.username)} (@${esc(b.username)})</option>`
      ).join('');
    if (beneficiaries.some(b => b.username === current)) select.value = current;
  }
}

async function addBeneficiary() {
  const input = $('#beneficiaryUsername');
  if (!input) return;

  const username = input.value.trim().toLowerCase();
  if (!username) {
    toast('Enter a beneficiary username.', 'err');
    return;
  }

  const body = new URLSearchParams();
  body.set('beneficiary_username', username);
  body.set('csrf_token', CSRF);

  const r = await fetch('/beneficiary/add', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-CSRF-Token': CSRF
    },
    body,
    credentials: 'same-origin'
  });

  if (r.redirected && r.url.includes('/login')) {
    location = '/login';
    return;
  }

  if (r.ok) {
    input.value = '';
    toast('Beneficiary request submitted.', 'ok');
    await loadBeneficiaries();
  } else {
    toast('Unable to add beneficiary.', 'err');
  }
}

async function removeBeneficiary(userId) {
  if (!confirm('Remove this beneficiary?')) return;

  const body = new URLSearchParams();
  body.set('beneficiary_id', userId);
  body.set('csrf_token', CSRF);

  const r = await fetch('/beneficiary/remove', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-CSRF-Token': CSRF
    },
    body,
    credentials: 'same-origin'
  });

  if (r.ok) {
    toast('Beneficiary removed.', 'ok');
    await loadBeneficiaries();
  } else {
    toast('Unable to remove beneficiary.', 'err');
  }
}

async function refresh() {
  const b = await api(`/api/wallet/${ME_ID}/balance`);
  if (b.ok) countTo(b.data.balance);
  const t = await api(`/api/wallet/${ME_ID}/transactions`);
  if (t.ok) { txs = t.data; render(); }
}

function setF(x, el) {
  filt = x;
  document.querySelectorAll('.f').forEach(b => b.classList.remove('on'));
  el.classList.add('on');
  render();
}

function tab(x) {
  $('#wal').hidden = x !== 'w';
  $('#lab').hidden = x !== 'l';
  $('#tw').className = x === 'w' ? 'on' : 'ghost';
  $('#tl').className = x === 'l' ? 'on' : 'ghost';
}

function render() {
  const q = $('#q').value.toLowerCase();
  const rows = txs.filter(t => {
    const out = t.sender_id === ME_ID;
    if (filt === 'sent' && !out) return false;
    if (filt === 'recv' && out) return false;
    if (filt === 'failed' && t.status !== 'FAILED') return false;
    return !q || ((t.sname || '') + ' ' + (t.rname || '')).toLowerCase().includes(q);
  });
  $('#rows').innerHTML = rows.map(t => {
    const out = t.sender_id === ME_ID;
    return `<tr><td>${t.id}</td><td>${esc(t.sname)}</td><td>${esc(t.rname)}</td>` +
      `<td class="${out ? 'neg' : 'pos'}">${out ? '−' : '+'}${rs(t.amount)}</td>` +
      `<td><span class="chip s-${esc(t.status)}">${esc(t.status)}</span></td>` +
      `<td class="mut">${esc(String(t.created_at).replace('T', ' ').slice(0, 19))}</td></tr>`;
  }).join('');
  $('#empty').textContent = rows.length ? '' : 'No transactions to show.';
}

function hint() {
  const v = $('#amt').value.trim(), h = $('#hint');
  if (!v) { h.textContent = ''; return; }
  const n = Number(v);
  let m = 'Looks good ✓', c = 'var(--ok)'; // UX only - the server re-validates everything
  if (!isFinite(n) || n <= 0) { m = 'Enter a positive amount'; c = 'var(--bad)'; }
  else if (!/^\d+(\.\d{1,2})?$/.test(v)) { m = 'Maximum 2 decimal places'; c = 'var(--bad)'; }
  else if (n > 100000) { m = 'Limit is Rs. 100,000 per transfer'; c = 'var(--bad)'; }
  else if (n * 100 > bal) { m = 'More than your balance'; c = 'var(--warn)'; }
  h.style.color = c;
  h.textContent = m;
}

async function send() {
  const to = $('#to').value.trim(), amount = $('#amt').value.trim();
  if (!to || !amount) { toast('Enter recipient and amount', 'err'); return; }
  if (!confirm(`Send Rs. ${amount} to ${to}?`)) return;
  $('#send').disabled = true;
  const r = await api('/api/transfer', { method: 'POST', json: { to, amount } });

  if (r.ok && r.data && r.data.step_up_required) {
    // C11: high-value transfer paused for a one-time code before it executes.
    // demo_code is shown here only because this class project has no real
    // SMS/email channel — a real system would never return it to the client.
    const hint = r.data.demo_code ? ` (demo code: ${r.data.demo_code})` : '';
    const entered = prompt(r.data.message + hint + '\n\nEnter the verification code:');
    $('#send').disabled = false;
    if (entered === null) { toast('Transfer cancelled.', 'err'); refresh(); return; }

    const confirmResult = await api('/api/transfer/confirm', { method: 'POST', json: { code: entered } });
    toast((confirmResult.data && confirmResult.data.message) || ('Request failed (HTTP ' + confirmResult.status + ')'), confirmResult.ok ? 'ok' : 'err');
    if (confirmResult.ok) { $('#to').value = ''; $('#amt').value = ''; hint(); }
    refresh();
    return;
  }

  $('#send').disabled = false;
  toast((r.data && r.data.message) || ('Request failed (HTTP ' + r.status + ')'), r.ok ? 'ok' : 'err');
  if (r.ok) { $('#to').value = ''; $('#amt').value = ''; hint(); }
  refresh();
}

// ---- Security Lab: real attack requests, verdict shown per attack ----
const ATK = [
  ['W3', "Read another user's balance (IDOR)", () => api(`/api/wallet/${OTHER_ID}/balance`)],
  ['W4', 'Send a NEGATIVE amount (reverse the money flow)', () => api('/api/transfer', { method: 'POST', json: { to: OTHER, amount: '-5000' } })],
  ['W4', 'Overdraft: send more than the balance', () => api('/api/transfer', { method: 'POST', json: { to: OTHER, amount: '99999' } })],
  ['W5', 'Forged transfer with NO CSRF token', () => api('/api/transfer', { method: 'POST', json: { to: OTHER, amount: '100' }, csrf: false })],
  ['W8', 'Open the admin audit log as a normal user', () => api('/admin/audit')],
  ['C11', 'Confirm a high-value transfer with a guessed code (no step-up was ever issued)', () => api('/api/transfer/confirm', { method: 'POST', json: { code: '000000' } })],
  ['W13', 'Bypass step-up: send 15,000 via the old /transfer route', async () => {
  const before = (await api(`/api/wallet/${ME_ID}/balance`)).data.balance;
  await fetch('/transfer', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({to: OTHER, amount: '15000', csrf_token: CSRF}),
    credentials: 'same-origin'
  });
  const after = (await api(`/api/wallet/${ME_ID}/balance`)).data.balance;
  const moved = after < before;
  return {status: 200, ok: moved,
          data: {message: moved ? 'Money moved without a code!' : 'Balance unchanged, step-up enforced'}};
}],
];

async function runAtk(i) {
  const r = await ATK[i][2]();
  const bad = r.ok;
  const el = $('#r' + i);
  let extra = r.data && r.data.message ? ' · ' + esc(r.data.message) : '';
  if (r.data && r.data.balance !== undefined) extra = ' · leaked ' + esc(r.data.username) + "'s balance: " + rs(r.data.balance);
  el.innerHTML = (bad ? '❌ SUCCEEDED' : '✅ BLOCKED') + ' — HTTP ' + r.status + extra;
  el.style.color = bad ? 'var(--bad)' : 'var(--ok)';
  refresh();
}

async function runAll() {
  for (let i = 0; i < ATK.length; i++) await runAtk(i);
}

function buildAttackList() {
  const container = $('#atk');
  container.innerHTML = '';
  ATK.forEach((a, i) => {
    const row = document.createElement('div');
    row.className = 'atk';
    const left = document.createElement('div');
    left.innerHTML = `<b>${esc(a[0])}</b> · ${esc(a[1])}<div class="mut" id="r${i}"></div>`;
    const btn = document.createElement('button');
    btn.className = 'ghost';
    btn.textContent = 'Run';
    btn.addEventListener('click', () => runAtk(i));
    row.append(left, btn);
    container.append(row);
  });
}

function wireEvents() {
  document.querySelectorAll('[data-tab]').forEach(btn => {
    btn.addEventListener('click', () => tab(btn.dataset.tab));
  });
  document.querySelectorAll('[data-filter]').forEach(btn => {
    btn.addEventListener('click', () => setF(btn.dataset.filter, btn));
  });
  $('#amt').addEventListener('input', hint);
  $('#q').addEventListener('input', render);
  $('#send').addEventListener('click', send);
  $('#runAllBtn').addEventListener('click', runAll);

  const addBtn = $('#addBeneficiaryBtn');
  if (addBtn) addBtn.addEventListener('click', addBeneficiary);

  const beneficiaryInput = $('#beneficiaryUsername');
  if (beneficiaryInput) {
    beneficiaryInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        addBeneficiary();
      }
    });
  }
}

$('#nm').textContent = ME;
buildAttackList();
wireEvents();
refresh();
setInterval(() => {
  ttl--;
  if (ttl <= 0) { location = '/login'; return; }
  const t = $('#timer');
  t.textContent = String(Math.floor(ttl / 60)).padStart(2, '0') + ':' + String(ttl % 60).padStart(2, '0');
  t.style.color = ttl < 60 ? 'var(--bad)' : '';
}, 1000);