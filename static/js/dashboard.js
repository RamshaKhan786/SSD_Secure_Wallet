const dashEl = document.getElementById('dash');
const CSRF = dashEl.dataset.csrf;
const ME_ID = Number(dashEl.dataset.uid);
const ME = dashEl.dataset.uname;
const OTHER = dashEl.dataset.otherUname;
const OTHER_ID = Number(dashEl.dataset.otherUid);
const SESSION_TIMEOUT = Number(dashEl.dataset.sessionTimeout) || 600;
const CNIC = dashEl.dataset.cnic || '';

const $ = selector => document.querySelector(selector);
let txs = [];
let filt = 'all';
let ttl = SESSION_TIMEOUT;
let bal = 0;
let shown = 0;
let beneficiaries = [];

const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
}[c]));

const rs = paisa => 'Rs. ' + (paisa / 100).toLocaleString('en-US', {
  minimumFractionDigits: 2,
  maximumFractionDigits: 2
});

function toast(message, type = '') {
  const element = document.createElement('div');
  element.className = `toast ${type}`;
  element.textContent = message;
  $('#toasts').append(element);
  setTimeout(() => element.remove(), 3500);
}

async function api(url, options = {}) {
  try {
    const method = options.method || 'GET';
    const headers = {};
    if (options.json) headers['Content-Type'] = 'application/json';
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && options.csrf !== false) {
      headers['X-CSRF-Token'] = CSRF;
    }

    const response = await fetch(url, {
      method,
      headers,
      body: options.json ? JSON.stringify(options.json) : undefined,
      credentials: 'same-origin',
    });

    if (response.redirected && response.url.includes('/login')) {
      location = '/login';
      return { status: 401, ok: false, data: null };
    }

    let data = null;
    try {
      data = await response.clone().json();
    } catch (_) {
      data = null;
    }

    if (response.ok) ttl = SESSION_TIMEOUT;
    return { status: response.status, ok: response.ok, data };
  } catch (error) {
    return { status: 0, ok: false, data: { message: 'Network error.' } };
  }
}

function countTo(value) {
  const start = shown;
  const startedAt = performance.now();
  bal = value;

  (function animate(timestamp) {
    const progress = Math.min(1, (timestamp - startedAt) / 600);
    shown = start + (value - start) * progress;
    $('#bal').textContent = rs(Math.round(shown));
    if (progress < 1) requestAnimationFrame(animate);
  })(startedAt);
}

async function refresh() {
  const [balanceResponse, historyResponse] = await Promise.all([
    api(`/api/wallet/${ME_ID}/balance`),
    api(`/api/wallet/${ME_ID}/transactions`),
  ]);

  if (balanceResponse.ok) countTo(balanceResponse.data.balance);
  if (historyResponse.ok) {
    txs = historyResponse.data;
    render();
  }
}

async function loadBeneficiaries() {
  const response = await api('/api/beneficiaries');
  if (!response.ok) return;

  beneficiaries = Array.isArray(response.data) ? response.data : [];
  renderBeneficiaries();
}


function renderBeneficiaries() {
  const list = $('#beneficiaryList');
  const quickList = $('#beneficiaryQuickList');

  list.innerHTML = beneficiaries.map(beneficiary => (
    `<div class="beneficiary-row">` +
      `<button type="button" class="beneficiary-select ghost" data-username="${esc(beneficiary.username)}">` +
        `<span><b>${esc(beneficiary.username)}</b> <span class="mut">${esc(beneficiary.full_name)}</span></span>` +
      `</button>` +
      `<button type="button" class="ghost beneficiary-remove" data-id="${beneficiary.id}" aria-label="Remove ${esc(beneficiary.username)}">Remove</button>` +
    `</div>`
  )).join('');

  quickList.innerHTML = beneficiaries.map(beneficiary => (
    `<button type="button" class="ghost quick-beneficiary" data-username="${esc(beneficiary.username)}">${esc(beneficiary.username)}</button>`
  )).join('');

  $('#beneficiaryEmpty').textContent = beneficiaries.length ? '' : 'No beneficiaries saved yet.';

  document.querySelectorAll('.beneficiary-select, .quick-beneficiary').forEach(button => {
    button.addEventListener('click', () => {
      $('#to').value = button.dataset.username;
      $('#to').focus();
      toast(`Recipient selected: ${button.dataset.username}`, 'ok');
    });
  });

  document.querySelectorAll('.beneficiary-remove').forEach(button => {
    button.addEventListener('click', () => removeBeneficiary(Number(button.dataset.id)));
  });
}


async function addBeneficiary() {
  const username = $('#beneficiaryUsername').value.trim();
  if (!username) {
    toast('Enter a beneficiary username.', 'err');
    return;
  }

  $('#addBeneficiary').disabled = true;
  const response = await api('/api/beneficiaries', {
    method: 'POST',
    json: { username },
  });
  $('#addBeneficiary').disabled = false;

  toast(
    (response.data && response.data.message) || `Request failed (HTTP ${response.status})`,
    response.ok ? 'ok' : 'err'
  );

  if (response.ok) {
    $('#beneficiaryUsername').value = '';
    await loadBeneficiaries();
  }
}


async function removeBeneficiary(id) {
  const beneficiary = beneficiaries.find(item => item.id === id);
  if (!beneficiary) return;

  if (!confirm(`Remove ${beneficiary.username} from your beneficiaries?`)) return;

  const response = await api(`/api/beneficiaries/${id}`, {
    method: 'DELETE',
  });

  toast(
    (response.data && response.data.message) || `Request failed (HTTP ${response.status})`,
    response.ok ? 'ok' : 'err'
  );

  if (response.ok) await loadBeneficiaries();
}


function setFilter(filter, element) {
  filt = filter;
  document.querySelectorAll('.f').forEach(button => button.classList.remove('on'));
  element.classList.add('on');
  render();
}

function tab(value) {
  $('#wal').hidden = value !== 'w';
  $('#lab').hidden = value !== 'l';
  $('#tw').className = value === 'w' ? 'on' : 'ghost';
  $('#tl').className = value === 'l' ? 'on' : 'ghost';
}

function render() {
  const query = $('#q').value.toLowerCase();
  const rows = txs.filter(transaction => {
    const outgoing = transaction.sender_id === ME_ID;
    if (filt === 'sent' && !outgoing) return false;
    if (filt === 'recv' && outgoing) return false;
    if (filt === 'failed' && transaction.status !== 'FAILED') return false;

    const people = `${transaction.sname || ''} ${transaction.rname || ''}`.toLowerCase();
    return !query || people.includes(query);
  });

  $('#rows').innerHTML = rows.map(transaction => {
    const outgoing = transaction.sender_id === ME_ID;
    const amountClass = outgoing ? 'neg' : 'pos';
    const sign = outgoing ? '-' : '+';
    const created = String(transaction.created_at).replace('T', ' ').slice(0, 19);

    return `<tr>` +
      `<td>${transaction.id}</td>` +
      `<td>${esc(transaction.sname)}</td>` +
      `<td>${esc(transaction.rname || '-')}</td>` +
      `<td class="${amountClass}">${sign}${rs(transaction.amount)}</td>` +
      `<td><span class="chip s-${esc(transaction.status)}">${esc(transaction.status)}</span></td>` +
      `<td class="mut">${esc(created)}</td>` +
      `</tr>`;
  }).join('');

  $('#empty').textContent = rows.length ? '' : 'No transactions to show.';
}

function hint() {
  const value = $('#amt').value.trim();
  const element = $('#hint');
  element.className = 'mut hint';

  if (!value) {
    element.textContent = '';
    return;
  }

  const number = Number(value);
  let message = 'Looks good.';
  let className = 'good-text';

  if (!Number.isFinite(number) || number <= 0) {
    message = 'Enter a positive amount.';
    className = 'bad-text';
  } else if (!/^\d+(\.\d{1,2})?$/.test(value)) {
    message = 'Use at most 2 decimal places.';
    className = 'bad-text';
  } else if (number > 100000) {
    message = 'Limit is Rs. 100,000 per transfer.';
    className = 'bad-text';
  } else if (number * 100 > bal) {
    message = 'Amount is greater than your balance.';
    className = 'warn-text';
  }

  element.classList.add(className);
  element.textContent = message;
}

async function send() {
  const to = $('#to').value.trim();
  const amount = $('#amt').value.trim();

  if (!to || !amount) {
    toast('Enter recipient and amount.', 'err');
    return;
  }

  if (!confirm(`Send Rs. ${amount} to ${to}?`)) return;

  $('#send').disabled = true;
  const response = await api('/api/transfer', {
    method: 'POST',
    json: { to, amount },
  });

  if (response.ok && response.data && response.data.step_up_required) {
    const demoCode = response.data.demo_code ? `\n\nDemo code: ${response.data.demo_code}` : '';
    const entered = prompt(`${response.data.message}${demoCode}\n\nEnter the verification code:`);

    if (entered === null) {
      $('#send').disabled = false;
      toast('Transfer cancelled.', 'err');
      return;
    }

    const confirmation = await api('/api/transfer/confirm', {
      method: 'POST',
      json: { code: entered },
    });

    toast(
      (confirmation.data && confirmation.data.message) || `Request failed (HTTP ${confirmation.status})`,
      confirmation.ok ? 'ok' : 'err'
    );

    if (confirmation.ok) {
      $('#to').value = '';
      $('#amt').value = '';
      hint();
    }

    $('#send').disabled = false;
    refresh();
    return;
  }

  $('#send').disabled = false;
  toast(
    (response.data && response.data.message) || `Request failed (HTTP ${response.status})`,
    response.ok ? 'ok' : 'err'
  );

  if (response.ok) {
    $('#to').value = '';
    $('#amt').value = '';
    hint();
  }
  refresh();
}

// Security Lab: real attack requests. They should fail in secure mode.
const ATTACKS = [
  ['W3', "Read another user's balance (IDOR)", () =>
    api(`/api/wallet/${OTHER_ID}/balance`)],

  ['W4', 'Send a NEGATIVE amount', () =>
    api('/api/transfer', { method: 'POST', json: { to: OTHER, amount: '-5000' } })],

  ['W4', 'Overdraft: send more than the balance', () =>
    api('/api/transfer', { method: 'POST', json: { to: OTHER, amount: '99999' } })],

  ['W5', 'Forged transfer with NO CSRF token', () =>
    api('/api/transfer', {
      method: 'POST',
      json: { to: OTHER, amount: '100' },
      csrf: false,
    })],

  ['W8', 'Open the admin audit log as a normal user', () =>
    api('/admin/audit')],

  ['C12', 'Confirm a high-value transfer with a guessed code', () =>
    api('/api/transfer/confirm', {
      method: 'POST',
      json: { code: '000000' },
    })],

  ['C12', 'Bypass step-up through the legacy /transfer route', async () => {
    const before = await api(`/api/wallet/${ME_ID}/balance`);
    if (!before.ok) return before;

    const beforeBalance = before.data.balance;
    await fetch('/transfer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        to: OTHER,
        amount: '15000',
        csrf_token: CSRF,
      }),
      credentials: 'same-origin',
    });

    const after = await api(`/api/wallet/${ME_ID}/balance`);
    const moved = after.ok && after.data.balance < beforeBalance;
    return {
      status: 200,
      ok: moved,
      data: { message: moved ? 'Money moved without a code.' : 'Balance unchanged; step-up enforced.' },
    };
  }],
];

async function runAttack(index) {
  const response = await ATTACKS[index][2]();
  const succeeded = response.ok;
  const resultElement = $(`#r${index}`);
  let extra = response.data && response.data.message ? ` - ${esc(response.data.message)}` : '';

  if (response.data && response.data.balance !== undefined) {
    extra = ` - leaked ${esc(response.data.username)}'s balance: ${rs(response.data.balance)}`;
  }

  resultElement.className = `mut attack-result ${succeeded ? 'attack-failed' : 'attack-blocked'}`;
  resultElement.textContent = `${succeeded ? 'ATTACK SUCCEEDED' : 'ATTACK BLOCKED'} - HTTP ${response.status}${extra}`;
  refresh();
}

async function runAll() {
  for (let index = 0; index < ATTACKS.length; index += 1) {
    await runAttack(index);
  }
}

function buildAttackList() {
  const container = $('#atk');
  container.innerHTML = '';

  ATTACKS.forEach((attack, index) => {
    const row = document.createElement('div');
    row.className = 'atk';

    const left = document.createElement('div');
    left.innerHTML = `<b>${esc(attack[0])}</b> - ${esc(attack[1])}<div class="mut attack-result" id="r${index}"></div>`;

    const button = document.createElement('button');
    button.className = 'ghost';
    button.type = 'button';
    button.textContent = 'Run';
    button.addEventListener('click', () => runAttack(index));

    row.append(left, button);
    container.append(row);
  });
}

function wireEvents() {
  document.querySelectorAll('[data-tab]').forEach(button => {
    button.addEventListener('click', () => tab(button.dataset.tab));
  });

  document.querySelectorAll('[data-filter]').forEach(button => {
    button.addEventListener('click', () => setFilter(button.dataset.filter, button));
  });

  $('#amt').addEventListener('input', hint);
  $('#q').addEventListener('input', render);
  $('#send').addEventListener('click', send);
  $('#addBeneficiary').addEventListener('click', addBeneficiary);
  $('#beneficiaryUsername').addEventListener('keydown', event => {
    if (event.key === 'Enter') addBeneficiary();
  });
  $('#runAllBtn').addEventListener('click', runAll);
}

$('#nm').textContent = ME;
$('#cnic').textContent = CNIC;
buildAttackList();
wireEvents();
refresh();
loadBeneficiaries();

setInterval(() => {
  ttl -= 1;
  if (ttl <= 0) {
    location = '/login';
    return;
  }

  const timer = $('#timer');
  timer.textContent = `${String(Math.floor(ttl / 60)).padStart(2, '0')}:${String(ttl % 60).padStart(2, '0')}`;
  timer.classList.toggle('timer-critical', ttl < 60);
}, 1000);
