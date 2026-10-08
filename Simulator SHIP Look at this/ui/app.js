const $ = id => document.getElementById(id);
const apiKey = document.querySelector('meta[name="lab-key"]').content;
let state, busy = false, initialized = false, quitting = false;
const number = value => Number(value || 0).toLocaleString(undefined, { maximumFractionDigits: 2 });
const time = value => new Date(value).toLocaleTimeString();
function showError(message) { $('error-banner').textContent = message; $('error-banner').hidden = !message; }
async function command(action, payload) {
  const response = await fetch('/api/command', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Lab-Key': apiKey }, body: JSON.stringify({ action, payload }) });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request failed.');
  if (result.profile) { state = result; render(); }
  return result;
}
async function run(task) {
  if (busy) return;
  busy = true; showError(''); $('notice').hidden = true; render();
  try { await task(); }
  catch (error) { showError(error.message); }
  finally { busy = false; render(); }
}
function createOptions() {
  return { deviceName: $('device-name').value, name: $('room-name').value, difficulty: Number($('difficulty').value), lan: $('mode').value === 'host', address: $('adapter').value, resumeId: $('saved-room').value || undefined };
}
$('mine-button').onclick = () => run(async () => {
  if (state.miner.running) { await command('stop'); return; }
  if (!state.canMine) {
    if (state.room || state.role === 'joining' || $('mode').value === 'join') throw new Error('Join a room and wait for host approval first.');
    await command('create', createOptions());
  }
  await command('start');
});
$('create-button').onclick = () => run(() => command('create', createOptions()));
$('join-button').onclick = () => run(() => command('join', { deviceName: $('device-name').value, invite: $('join-invite').value }));
$('mode').onchange = () => render();
$('duty').onchange = () => { const duty = Number($('duty').value); void run(() => command('duty', { duty })); };
$('leave-button').onclick = () => run(() => command('leave'));
$('refresh-invite').onclick = () => run(() => command('invite'));
$('display-button').onclick = () => run(() => command('display', { mode: state.desktop?.mode === 'browser' ? 'app' : 'browser' }));
$('quit-button').onclick = () => run(async () => {
  await command('quit'); quitting = true; $('notice').textContent = 'Mining stopped. MeepCoin Local Lab is closed. You can close this tab.'; $('notice').hidden = false;
});
$('export-button').onclick = () => run(async () => {
  const result = await command('export'); $('notice').textContent = `Saved: ${result.path}`; $('notice').hidden = false;
});
$('copy-invite').onclick = async () => {
  try { await navigator.clipboard.writeText($('host-invite').value); $('notice').textContent = 'Invite copied.'; $('notice').hidden = false; }
  catch { $('host-invite').select(); showError('Select the invite and press Ctrl+C.'); }
};
function replaceOptions(element, items, initial) {
  const next = [...(initial ? [['', initial]] : []), ...items];
  if (JSON.stringify([...element.options].map(o => [o.value, o.textContent])) === JSON.stringify(next)) return;
  const value = element.value;
  element.replaceChildren(...next.map(([value, label]) => { const option = document.createElement('option'); option.value = value; option.textContent = label; return option; }));
  if ([...element.options].some(o => o.value === value)) element.value = value;
}
function row(text, detail) {
  const item = document.createElement('div'); item.className = 'list-row'; item.textContent = text;
  if (detail) { const small = document.createElement('small'); small.textContent = detail; item.append(small); }
  return item;
}
function render() {
  if (!state) return;
  const { room, miner, profile } = state, mode = $('mode').value;
  const connected = Boolean(room) || state.role === 'joining';
  if (!initialized) { $('device-name').value = profile.name; initialized = true; }
  $('hashrate').textContent = number(miner.hashrate >= 1000 ? miner.hashrate / 1000 : miner.hashrate);
  $('hashrate-unit').textContent = miner.hashrate >= 1000 ? 'kH/s' : 'H/s';
  $('balance').textContent = number(state.ownBalance); $('blocks').textContent = number(room?.height);
  $('mining-status').textContent = miner.running ? `Mining: ${miner.status}` : state.role === 'joining' ? 'Waiting for host approval.' : 'Not mining.';
  $('mine-button').textContent = miner.running ? 'Stop mining' : 'Start mining';
  for (const button of document.querySelectorAll('[data-command]')) button.disabled = busy;
  $('mine-button').disabled = busy || (!miner.running && !state.canMine && (connected || mode === 'join'));
  $('mode').disabled = busy; $('duty').disabled = busy;
  $('display-tools').hidden = !state.desktop;
  $('quit-tools').hidden = !state.desktop;
  $('display-button').textContent = state.desktop?.mode === 'browser' ? 'Open app window' : 'Open in browser';
  $('display-note').hidden = state.desktop?.mode !== 'browser';
  $('display-note').textContent = 'Closing this tab does not stop mining. Use Stop mining, More options > Quit, or the coin icon in the Windows tray.';
  $('difficulty-info').textContent = room ? `Room difficulty: ${room.difficulty} (fixed). More combined H/s means shorter average rounds.` : '';
  $('room-status').textContent = room
    ? `${room.name} - ${state.role === 'host' ? 'hosting' : state.connectionStatus || 'joined'} - ${room.devices.length} device(s)`
    : state.role === 'joining' ? state.connectionStatus : mode === 'join' ? 'Paste an invite below to join.'
    : mode === 'host' ? 'Start creates a LAN room and begins mining.' : 'Start to mine on this computer.';
  $('setup').hidden = connected;
  $('create-form').hidden = mode === 'join'; $('join-form').hidden = mode !== 'join';
  $('adapter-field').hidden = mode !== 'host'; $('lan-note').hidden = mode === 'solo';
  replaceOptions($('adapter'), state.adapters.map(a => [a.address, `${a.name} - ${a.address}`]));
  replaceOptions($('saved-room'), state.savedRooms.filter(r => !r.damaged).map(r => [r.id, `${r.name} - ${r.blocks} blocks`]), 'New room');
  $('create-button').disabled = busy || mode === 'host' && !state.adapters.length;
  if (!connected && mode === 'host' && !state.adapters.length) { $('mine-button').disabled = true; $('room-status').textContent = 'No private LAN adapter found. Use Just this computer instead.'; }
  $('duty').value = miner.duty;
  $('total-hashes').textContent = `${number(miner.hashes)} hashes computed this session`;
  $('connected-tools').hidden = !connected; $('export-button').hidden = state.role !== 'host';
  $('leave-button').textContent = state.role === 'host' ? 'Close room' : 'Leave room';
  $('invite-tools').hidden = !state.invite; $('host-invite').value = state.invite || '';
  $('approval-list').replaceChildren(...state.pending.map(p => {
    const item = document.createElement('div'); item.className = 'approval';
    const text = document.createElement('p'); text.textContent = `${p.name} wants to join. Is this your device?`;
    const buttons = document.createElement('div'); buttons.className = 'buttons';
    for (const [label, allow] of [['Approve', true], ['Decline', false]]) {
      const button = document.createElement('button'); button.textContent = label; button.disabled = busy;
      button.onclick = () => run(() => command('approve', { requestId: p.requestId, allow })); buttons.append(button);
    }
    item.append(text, buttons); return item;
  }));
  $('device-list').replaceChildren(...(room?.devices.length ? room.devices.map(d => row(
    `${d.name}${d.id === profile.id ? ' (you)' : ''} - ${number(d.id === profile.id ? miner.hashrate : d.rate)} H/s - ${number(room.balances[d.id])} demo MEEP`, d.active ? 'Mining' : 'Stopped',
  )) : [row('No room yet.')]));
  const blocks = [...(room?.blocks ?? [])].reverse();
  $('block-list').replaceChildren(...(blocks.length ? blocks.map(b => row(`Block ${b.height}: ${b.winnerName} +${b.reward} demo MEEP`, `${time(b.timestamp)} - ${b.hash}`)) : [row('No blocks yet.')]));
  $('activity').replaceChildren(...(state.events.length ? state.events.slice(0, 5).map(e => row(e.text, time(e.timestamp))) : [row('No activity yet.')]));
  $('data-path').textContent = state.dataDirectory;
  if (room?.fatal) showError(room.fatal);
  if (quitting) { $('mining-status').textContent = 'Not mining. App closed.'; for (const button of document.querySelectorAll('button')) button.disabled = true; }
}
async function poll() {
  if (quitting) return;
  try {
    const response = await fetch('/api/state', { headers: { 'X-Lab-Key': apiKey } });
    if (!response.ok) throw new Error('Dashboard session ended.');
    state = await response.json(); render();
  } catch (error) { if (!quitting) showError(`${error.message} Reopen the app if it was closed. Mining does not restart automatically.`); }
  setTimeout(poll, 1000);
}
poll();
