const $ = id => document.getElementById(id);
let csrf = '', mode = 'create', quote = null, busy = false, lastState = null;
let seedTimer, idleTimer, lockRequested = false;
const atomic = value => {
  const amount = BigInt(value), whole = amount / 100000000000n;
  const fraction = (amount % 100000000000n).toString().padStart(11, '0').replace(/0+$/, '');
  return whole.toString() + (fraction ? '.' + fraction : '');
};
function notice(message, error = false) {
  $('notice').textContent = message;
  $('notice').classList.toggle('error', error);
}
async function api(action, data = {}) {
  const response = await fetch('/api/' + action, {method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: {'Content-Type': 'application/json', 'X-Meep-CSRF': csrf}, body: JSON.stringify(data)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Local wallet request failed.');
  return result;
}
function clearSecrets() {
  clearTimeout(seedTimer);
  $('password').value = ''; $('reveal-password').value = ''; $('seed-input').value = ''; $('seed-output').textContent = '';
  $('backup-check').checked = false; $('backup-confirm').disabled = true;
}
function showSeed(seed) {
  $('seed-output').textContent = seed; $('backup').hidden = false;
  clearTimeout(seedTimer);
  seedTimer = setTimeout(() => {
    clearSecrets(); $('backup').hidden = true;
    notice('Recovery words hidden after two minutes. Unlock and reveal them again if needed.');
  }, 120000);
}
function controls() {
  document.querySelectorAll('button').forEach(button => button.disabled = busy || !csrf);
  $('lock').disabled = busy || !lastState?.opened;
  $('backup-confirm').disabled = busy || !$('backup-check').checked;
  $('confirm-send').disabled = busy || !quote;
  $('send-form').querySelector('button').disabled = busy || !lastState?.opened ||
    Boolean(lastState.lastSend && !lastState.lastSend.observed);
}
function clearQuote() {
  quote = null; $('review').hidden = true; $('confirm-send').disabled = true;
}
function render(state) {
  lastState = state;
  clearTimeout(idleTimer);
  if (quote && state.pendingReviewId !== quote.id) clearQuote();
  $('closed').hidden = Boolean(state.opened); $('opened').hidden = !state.opened;
  $('lock').disabled = !state.opened;
  $('existing').textContent = state.wallets.length ? 'Existing wallets: ' + state.wallets.join(', ') : 'No local wallets yet.';
  $('network').textContent = `${state.network} · pinned genesis ${state.genesis}`;
  if (state.opened) {
    idleTimer = setTimeout(() => {
      clearSecrets(); $('backup').hidden = true; lockRequested = true;
      hideLock();
      if (!busy) operation(lock);
    }, Math.max(1, state.idleLockSeconds) * 1000);
    if (state.lastSend) {
      $('send-result').textContent = 'Last send: ' + state.lastSend.status + '. Transaction: ' + state.lastSend.txHash +
        (state.lastSend.observed ? '. Observed by the native wallet; check confirmations below.' : '. Refresh to resolve before sending again.');
    } else $('send-result').textContent = '';
    $('balance').textContent = atomic(state.balanceAtomic); $('unlocked').textContent = atomic(state.unlockedAtomic);
    $('address').textContent = state.address;
    $('transactions').replaceChildren();
    for (const t of state.transfers) {
      const row = document.createElement('tr');
      for (const value of [t.kind, atomic(t.amountAtomic), String(t.confirmations), t.txHash]) {
        const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
      }
      $('transactions').append(row);
    }
    if (!state.transfers.length) {
      const row = document.createElement('tr'), cell = document.createElement('td');
      cell.colSpan = 4; cell.textContent = 'No transactions observed yet.'; row.append(cell); $('transactions').append(row);
    }
  } else { $('backup').hidden = true; clearSecrets(); clearQuote(); $('send-result').textContent = ''; }
  controls();
}
async function operation(fn) {
  if (busy) return;
  busy = true;
  controls();
  try { await fn(); }
  catch (error) {
    try { render(await api('state')); }
    catch { clearSecrets(); clearQuote(); }
    notice(error.message, true);
  }
  finally {
    busy = false;
    controls();
    if (document.hidden) hideLock();
    else if (lockRequested) { lockRequested = false; operation(lock); }
  }
}
document.querySelectorAll('[data-mode]').forEach(button => button.addEventListener('click', () => {
  mode = button.dataset.mode; clearSecrets();
  document.querySelectorAll('[data-mode]').forEach(item => item.classList.toggle('selected', item === button));
  $('seed-label').hidden = mode !== 'restore'; $('seed-input').required = mode === 'restore';
  $('wallet-submit').textContent = {create: 'Create local wallet', open: 'Unlock wallet', restore: 'Recover into new wallet'}[mode];
  $('password').autocomplete = mode === 'open' ? 'current-password' : 'new-password';
}));
$('wallet-form').addEventListener('submit', event => {
  event.preventDefault();
  const request = {name: $('name').value, password: $('password').value, seed: $('seed-input').value.trim(), restoreHeight: 0};
  clearSecrets();
  operation(async () => {
    notice('Opening the native wallet…');
    const result = await api(mode, request);
    request.password = ''; request.seed = '';
    render(await api('state'));
    if (document.hidden) { result.seed = ''; await lock(); return; }
    if (mode === 'create') {
      showSeed(result.seed); result.seed = '';
      notice('Wallet created. Record the recovery words before mining or sending.');
    } else notice('Wallet unlocked. Balances came from the native wallet.');
  }).finally(() => { request.password = ''; request.seed = ''; });
});
$('reveal-form').addEventListener('submit', event => {
  event.preventDefault();
  const request = {password: $('reveal-password').value}; $('reveal-password').value = '';
  operation(async () => {
    const result = await api('backup', request); request.password = '';
    if (document.hidden) { result.seed = ''; await lock(); return; }
    render(await api('state'));
    showSeed(result.seed); result.seed = '';
    notice('Recovery words revealed locally. Record them privately and confirm to clear.');
  }).finally(() => request.password = '');
});
$('backup-check').addEventListener('change', () => $('backup-confirm').disabled = !$('backup-check').checked);
$('backup-confirm').addEventListener('click', () => operation(async () => {
  await api('backup-confirm', {confirmed: $('backup-check').checked}); clearSecrets(); $('backup').hidden = true;
  notice('Backup confirmed. Share only the public address to receive mining rewards.');
}));
async function lock() {
  lockRequested = false;
  clearSecrets(); clearQuote();
  await api('lock'); render(await api('state')); notice('Wallet locked. Spending keys are no longer loaded by the native wallet.');
}
$('lock').addEventListener('click', () => operation(lock));
$('refresh').addEventListener('click', () => operation(async () => { render(await api('refresh')); notice('Balances and transactions refreshed.'); }));
$('copy-address').addEventListener('click', () => operation(async () => {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText($('address').textContent); notice('Public address copied.');
  } else notice('Select and copy the public address above. This browser does not allow clipboard access here.');
}));
$('send-form').addEventListener('submit', event => {
  event.preventDefault();
  operation(async () => {
    clearQuote(); $('send-result').textContent = '';
    const prepared = await api('prepare', {address: $('destination').value.trim(), amount: $('amount').value.trim()});
    quote = prepared;
    $('review-address').textContent = prepared.address; $('review-amount').textContent = atomic(prepared.amountAtomic) + ' MEEP';
    $('review-fee').textContent = atomic(prepared.feeAtomic) + ' MEEP'; $('review-total').textContent = atomic(prepared.totalAtomic) + ' MEEP';
    $('review').hidden = false; notice('Review the exact native transaction. Nothing has been relayed.');
    setTimeout(() => { if (quote?.id === prepared.id) { clearQuote(); notice('Transfer review expired. Prepare a new review to send.'); } }, 120000);
  });
});
$('confirm-send').addEventListener('click', () => operation(async () => {
  const id = quote?.id, txHash = quote?.txHash; clearQuote();
  let result;
  try { result = await api('confirm', {id}); }
  catch (error) {
    $('send-result').textContent = 'Send outcome may be uncertain. Check this transaction before making another transfer: ' + txHash;
    throw error;
  }
  $('send-result').textContent = result.message + ' Transaction: ' + result.txHash;
  notice(result.message, result.status !== 'submitted');
  render(await api('state'));
}));
$('cancel-send').addEventListener('click', () => operation(async () => { await api('cancel'); clearQuote(); notice('Transfer cancelled before relay.'); }));
function hideLock() {
  clearSecrets(); clearQuote();
  if (csrf) fetch('/api/lock', {method: 'POST', credentials: 'same-origin', keepalive: true,
    headers: {'Content-Type': 'application/json', 'X-Meep-CSRF': csrf}, body: '{}'}).catch(() => {});
}
document.addEventListener('visibilitychange', () => {
  if (document.hidden) hideLock();
  else if (csrf) operation(async () => { render(await api('state')); notice('Check wallet lock state before continuing.'); });
});
window.addEventListener('pagehide', hideLock);
document.addEventListener('freeze', hideLock);
async function connect() {
  let token = new URLSearchParams(location.hash.slice(1)).get('connect') || '';
  history.replaceState(null, '', '/');
  try {
    const session = await api('session', {token}); token = ''; csrf = session.csrf;
    render(await api('state')); notice('Connected to your local wallet companion.');
  } catch (error) { token = ''; notice(error.message, true); controls(); }
}
connect();
