const { app, BrowserWindow, Tray, Menu, shell, session, powerMonitor } = require('electron');
const { DesktopMode } = require('./desktop-mode.cjs');
const path = require('node:path');
const fs = require('node:fs/promises');
// Smoke runs must not forward to, or contend for Chromium cache with, the user's app.
if (process.env.MEEP_LAB_SMOKE === '1' && process.env.MEEP_LAB_DATA_DIR) {
  const profile = path.join(process.env.MEEP_LAB_DATA_DIR, 'electron-profile');
  require('node:fs').mkdirSync(profile, { recursive: true }); app.setPath('userData', profile);
}
let controller, web, display, closing = false;
if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('display-error', error => { controller?.note(`Could not switch display: ${error.message}`, 'error'); require('electron').dialog.showErrorBox('Could not switch display', error.message); });
  app.on('second-instance', (_event, argv) => { if (display) void display.setMode(argv.includes('--browser') ? 'browser' : 'app').catch(e => display.report(e)); });
  app.whenReady().then(async () => {
    const { Application } = await import('./application.mjs');
    const { dashboard } = await import('./dashboard.mjs');
    const data = process.env.MEEP_LAB_DATA_DIR || path.join(app.getPath('userData'), 'lab-data');
    controller = await Application.create(data);
    display = new DesktopMode({ app, BrowserWindow, Tray, Menu, shell, stopMining: () => controller.stopMining() });
    web = await dashboard(controller, { desktop: display }); display.url = web.url;
    session.defaultSession.setPermissionRequestHandler((_contents, permission, callback) => callback(permission === 'clipboard-sanitized-write'));
    powerMonitor.on('suspend', () => { controller.stopMining(); controller.note('Computer suspended: mining stopped. Resume manually when ready.', 'warning'); });
    await display.setMode(process.env.MEEP_LAB_SMOKE !== '1' && process.argv.includes('--browser') ? 'browser' : 'app');
    // Optional developer smoke mode uses the SAME dashboard API and never leaves mining running.
    if (process.env.MEEP_LAB_SMOKE === '1') {
      const window = display.window;
      const output = process.env.MEEP_LAB_SMOKE_OUTPUT;
      const events = [];
      window.webContents.on('console-message', (_e, details) => events.push(details.message));
      await new Promise(resolve => setTimeout(resolve, 800));
      const before = await window.webContents.executeJavaScript(`(() => {const button=document.getElementById('display-button'),rect=button.getBoundingClientRect();return {title:document.title,heading:document.querySelector('h1')?.textContent,buttons:[...document.querySelectorAll('button')].filter(x=>x.getClientRects().length&&!x.closest('details:not([open])')).map(x=>x.textContent.trim()),plain:!document.querySelector('aside,canvas,img'),optionsClosed:!document.getElementById('more-options').open,displayVisible:!button.closest('details')&&!button.disabled&&rect.width>0&&rect.top>=0&&rect.bottom<=innerHeight,displayNoteHidden:document.getElementById('display-note').hidden};})()`);
      if (output) { await fs.mkdir(output, { recursive: true }); const image = await window.webContents.capturePage(); await fs.writeFile(path.join(output, 'dashboard.png'), image.toPNG()); }
      const modeChecks = await window.webContents.executeJavaScript(`(() => {const options=document.getElementById('more-options');options.open=true;const mode=document.getElementById('mode');mode.value='join';mode.dispatchEvent(new Event('change'));const join=!document.getElementById('join-form').hidden&&document.getElementById('mine-button').disabled;mode.value='host';mode.dispatchEvent(new Event('change'));const host=!document.getElementById('adapter-field').hidden;mode.value='solo';mode.dispatchEvent(new Event('change'));options.open=false;return {join,host};})()`);
      await window.webContents.executeJavaScript(`document.getElementById('difficulty').value='8';document.getElementById('room-name').value='Desktop smoke test';document.getElementById('mine-button').click()`);
      const createdDeadline = Date.now() + 10_000;
      while (!controller.room && Date.now() < createdDeadline) await new Promise(resolve => setTimeout(resolve, 100));
      if (!controller.room) throw new Error('Start UI did not create a room.');
      const deadline = Date.now() + 90_000;
      while (controller.room.blocks.length < 1 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 300));
      const mined = await controller.snapshot();
      await window.webContents.executeJavaScript(`document.getElementById('mine-button').click()`);
      const stopDeadline = Date.now() + 10_000;
      while (controller.miner.running && Date.now() < stopDeadline) await new Promise(resolve => setTimeout(resolve, 100));
      await new Promise(resolve => setTimeout(resolve, 1000));
      const after = await controller.snapshot();
      const afterUI = await window.webContents.executeJavaScript(`({balance:document.getElementById('balance').textContent,blocks:document.getElementById('blocks').textContent,button:document.getElementById('mine-button').textContent,error:document.getElementById('error-banner').hidden?null:document.getElementById('error-banner').textContent})`);
      if (output) {
        const image = await window.webContents.capturePage(); await fs.writeFile(path.join(output, 'mined.png'), image.toPNG());
        await fs.writeFile(path.join(output, 'desktop-smoke.json'), JSON.stringify({ before, modeChecks, mined, after, afterUI, events, passed: before.plain && before.optionsClosed && before.buttons.join('|') === 'Start mining|Open in browser' && before.displayVisible && before.displayNoteHidden && modeChecks.join && modeChecks.host && mined.room.height >= 1 && after.miner.running === false && after.miner.hashrate === 0 && afterUI.balance === String(after.ownBalance) && afterUI.button === 'Start mining' && !afterUI.error }, null, 2));
      }
      app.quit();
    }
  }).catch(async error => { console.error(error.stack || error.message); if (process.env.MEEP_LAB_SMOKE !== '1') require('electron').dialog.showErrorBox('MeepCoin Local Lab could not start', error.stack || error.message); app.quit(); });
}
app.on('window-all-closed', () => { if (display?.mode !== 'browser') app.quit(); });
app.on('before-quit', event => {
  if (closing || !controller) return;
  event.preventDefault(); closing = true; display?.dispose();
  Promise.all([controller.close(), web?.close()]).finally(() => app.quit());
});
