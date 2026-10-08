const path = require('node:path');

// Presentation only: switching views never creates a room or starts a miner.
// Browser mode keeps one local engine alive with a visible tray exit control.
class DesktopMode {
  constructor({ app, BrowserWindow, Tray, Menu, shell, stopMining }) {
    Object.assign(this, { app, BrowserWindow, Tray, Menu, shell, stopMining });
    this.mode = 'app'; this.window = null; this.tray = null; this.url = null;
    this.pending = Promise.resolve(); this.disposed = false;
    this.icon = path.join(__dirname, '../assets/icon.png');
  }
  setMode(mode) {
    if (!['app', 'browser'].includes(mode)) return Promise.reject(new Error('Choose app or browser mode.'));
    const task = this.pending.then(() => this.switchMode(mode));
    this.pending = task.catch(() => {});
    return task;
  }
  report(error) { if (!this.disposed) this.app.emit('display-error', error); }
  ensureTray() {
    if (this.tray) return;
    const tray = new this.Tray(this.icon);
    try {
      tray.setToolTip('MeepCoin Local Lab - browser mode');
      tray.setContextMenu(this.Menu.buildFromTemplate([
        { label: 'Open browser', click: () => { void this.setMode('browser').catch(e => this.report(e)); } },
        { label: 'Open app', click: () => { void this.setMode('app').catch(e => this.report(e)); } },
        { type: 'separator' },
        { label: 'Stop mining', click: () => this.stopMining() },
        { label: 'Quit MeepCoin Local Lab', click: () => this.quit() },
      ]));
      tray.on('double-click', () => { void this.setMode('browser').catch(e => this.report(e)); });
      this.tray = tray;
    } catch (error) { tray.destroy(); throw error; }
  }
  async switchMode(mode) {
    if (this.disposed) throw new Error('App is closing.');
    const url = new URL(this.url);
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.pathname !== '/' || url.search || url.hash || url.username || url.password) throw new Error('Invalid local dashboard address.');
    if (mode === 'browser') {
      const hadTray = Boolean(this.tray);
      this.ensureTray();
      try { await this.shell.openExternal(url.href); }
      catch (error) { if (!hadTray) { this.tray.destroy(); this.tray = null; } throw error; }
      if (this.disposed) return;
      this.mode = 'browser';
      this.window?.close(); // window-all-closed must not quit the browser engine.
      return;
    }
    if (!this.window || this.window.isDestroyed()) {
      const window = new this.BrowserWindow({ width: 680, height: 630, minWidth: 420, minHeight: 500,
        title: 'MeepCoin Local Lab', backgroundColor: '#ffffff', icon: this.icon, autoHideMenuBar: true,
        webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true, webSecurity: true } });
      this.window = window;
      window.on('closed', () => { if (this.window === window) this.window = null; });
      window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
      window.webContents.on('will-navigate', (event, next) => { if (next !== url.href) event.preventDefault(); });
      try { await window.loadURL(url.href); }
      catch (error) { window.destroy(); throw error; }
    }
    if (this.disposed) return;
    this.mode = 'app';
    if (this.window.isMinimized()) this.window.restore();
    this.window.show(); this.window.focus();
    this.tray?.destroy(); this.tray = null;
  }
  quit() { this.app.quit(); }
  dispose() { this.disposed = true; this.tray?.destroy(); this.tray = null; }
}
module.exports = { DesktopMode };
