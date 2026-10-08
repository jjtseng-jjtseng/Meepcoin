import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { DesktopMode } from '../src/desktop-mode.cjs';

function fixture() {
  const calls = { opened: [], windows: [], trays: [], stopped: 0, quit: 0 };
  const app = new EventEmitter(); app.quit = () => calls.quit++;
  class Window extends EventEmitter {
    constructor(options) { super(); this.options = options; this.dead = false; calls.windows.push(this); this.webContents = new EventEmitter(); this.webContents.setWindowOpenHandler = fn => { this.popup = fn; }; }
    async loadURL(url) { this.loaded = url; }
    isDestroyed() { return this.dead; }
    isMinimized() { return false; }
    show() { this.shown = true; }
    focus() { this.focused = true; }
    close() { this.dead = true; this.emit('closed'); app.emit('window-all-closed'); }
    destroy() { this.close(); }
  }
  class Tray extends EventEmitter {
    constructor(icon) { super(); this.icon = icon; calls.trays.push(this); }
    setToolTip(text) { this.tooltip = text; }
    setContextMenu(items) { this.menu = items; }
    destroy() { this.dead = true; }
  }
  const shell = { openExternal: async url => { calls.opened.push(url); } };
  const display = new DesktopMode({ app, BrowserWindow: Window, Tray, Menu: { buildFromTemplate: items => items }, shell, stopMining: () => calls.stopped++ });
  display.url = 'http://127.0.0.1:12345';
  app.on('window-all-closed', () => { if (display.mode !== 'browser') app.quit(); });
  return { display, calls, shell, app };
}

test('browser startup has no app window; switching views keeps one engine and never mines', async () => {
  const { display, calls } = fixture();
  await display.setMode('browser');
  assert.equal(display.mode, 'browser'); assert.equal(calls.windows.length, 0);
  assert.deepEqual(calls.opened, ['http://127.0.0.1:12345/']); assert.ok(display.tray);
  await display.setMode('app');
  const window = display.window;
  assert.equal(display.mode, 'app'); assert.ok(window.shown); assert.equal(display.tray, null);
  assert.deepEqual(window.options.webPreferences, { nodeIntegration: false, contextIsolation: true, sandbox: true, webSecurity: true });
  assert.equal(window.popup().action, 'deny');
  let blocked = false;
  window.webContents.emit('will-navigate', { preventDefault: () => { blocked = true; } }, 'https://example.com');
  assert.equal(blocked, true);
  await display.setMode('browser');
  assert.equal(window.dead, true); assert.equal(display.window, null); assert.equal(calls.quit, 0);
  const menu = display.tray.menu;
  menu.find(x => x.label === 'Stop mining').click(); assert.equal(calls.stopped, 1);
  menu.find(x => x.label === 'Quit MeepCoin Local Lab').click(); assert.equal(calls.quit, 1);
  display.dispose(); assert.equal(display.tray, null);
  await assert.rejects(display.setMode('app'), /closing/);
});

test('browser-open failure retains the app and invalid destinations cannot open externally', async () => {
  const { display, calls, shell } = fixture();
  await display.setMode('app'); const window = display.window;
  shell.openExternal = async () => { throw new Error('No browser available'); };
  await assert.rejects(display.setMode('browser'), /No browser/);
  assert.equal(display.mode, 'app'); assert.equal(display.window, window); assert.equal(window.dead, false);
  assert.equal(display.tray, null); assert.equal(calls.quit, 0); assert.equal(calls.stopped, 0);
  await assert.rejects(display.setMode('remote'), /app or browser/);
  for (const url of ['https://example.com', 'http://192.168.1.5:1234', 'http://127.0.0.1:1234/?secret=1', 'file:///C:/test']) {
    display.url = url; await assert.rejects(display.setMode('browser'), /Invalid local dashboard/);
  }
  window.close(); assert.equal(calls.quit, 1);
});
