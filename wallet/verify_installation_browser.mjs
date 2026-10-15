// Finite participant installation UI check. Disposable wallets only; secrets stay
// in this device's browser process memory and are never written to evidence.
import {readFile, writeFile, readdir} from 'node:fs/promises';
import {resolve, join} from 'node:path';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const argument = name => { const i = process.argv.indexOf('--' + name); return i < 0 ? undefined : process.argv[i + 1]; };
const prefix = argument('wallet-prefix') || 'installation';
const original = prefix + '-original', recovered = prefix + '-recovered';
const root = resolve(argument('data-dir'));
const output = resolve(argument('output-dir'));
const {chromium} = await import(pathToFileURL(resolve(argument('playwright-module'))));
let browser, context, seed = '';
const password = 'disposable-installation-' + crypto.randomUUID();
const errors = [];
const deadline = setTimeout(() => process.exit(124), 240000);
try {
  const link = await readFile(join(root, 'wallets/OPEN_WALLET.html'), 'utf8');
  const url = link.match(/href="([^"]+)"/)[1];
  browser = await chromium.launch({executablePath: resolve(argument('browser')), headless: true,
    args: ['--no-first-run', '--disable-background-networking', '--disable-component-update', '--disable-sync'],
    chromiumSandbox: true});
  context = await browser.newContext({viewport: {width: 1200, height: 900}});
  let page = await context.newPage();
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(url, {waitUntil: 'networkidle'});
  assert((await page.locator('#notice').textContent()).includes('Connected'));
  assert(new URL(page.url()).hash === '');
  await page.getByRole('button', {name: 'Create', exact: true}).click();
  await page.getByLabel('Wallet name', {exact: true}).fill(original);
  await page.getByLabel('Wallet password', {exact: true}).fill(password);
  await page.getByRole('button', {name: 'Create local wallet', exact: true}).click();
  await page.locator('#backup').waitFor({state: 'visible', timeout: 45000});
  seed = await page.locator('#seed-output').textContent();
  assert(seed.trim().split(/\s+/).length >= 24);
  const address = await page.locator('#address').textContent();
  await page.getByLabel('I recorded the words in order and can recover this wallet.').check();
  await page.getByRole('button', {name: 'I have backed up my wallet', exact: true}).click();
  await page.locator('#backup').waitFor({state: 'hidden'});
  assert(await page.locator('#seed-output').textContent() === '');
  const cookie = (await context.cookies()).find(c => c.name.startsWith('meep_local_'));
  assert(cookie && cookie.httpOnly && cookie.sameSite === 'Strict');
  assert(cookie.domain === new URL(page.url()).hostname);
  if (cookie.domain !== '127.0.0.1') {
    assert((await context.cookies('http://127.0.0.1:' + new URL(page.url()).port)).length === 0);
  }
  async function lock() {
    await page.getByRole('button', {name: 'Lock wallet', exact: true}).click();
    await page.locator('#closed').waitFor({state: 'visible'});
  }
  async function unlock(name, pass = password) {
    await page.getByRole('button', {name: 'Unlock', exact: true}).click();
    await page.getByLabel('Wallet name', {exact: true}).fill(name);
    await page.getByLabel('Wallet password', {exact: true}).fill(pass);
    await page.getByRole('button', {name: 'Unlock wallet', exact: true}).click();
  }
  await lock();
  await unlock(original, 'wrong-password');
  await page.waitForFunction(() => document.getElementById('notice').classList.contains('error'));
  assert(await page.locator('#closed').isVisible());
  await unlock(original);
  await page.locator('#opened').waitFor({state: 'visible', timeout: 45000});
  assert(await page.locator('#address').textContent() === address);
  await lock();
  await page.getByRole('button', {name: 'Recover', exact: true}).click();
  await page.getByLabel('Wallet name', {exact: true}).fill(recovered);
  await page.getByLabel('Wallet password', {exact: true}).fill(password);
  await page.getByLabel('Recovery words', {exact: true}).fill(seed);
  await page.getByRole('button', {name: 'Recover into new wallet', exact: true}).click();
  await page.locator('#opened').waitFor({state: 'visible', timeout: 60000});
  assert(await page.locator('#address').textContent() === address);
  assert(await page.locator('#seed-input').inputValue() === '');
  assert(await page.locator('#seed-output').textContent() === '');
  await page.screenshot({path: join(output, 'wallet-recovered.png'), fullPage: true});
  await page.reload({waitUntil: 'networkidle'});
  await page.locator('#closed').waitFor({state: 'visible'});
  await page.getByRole('button', {name: 'Create', exact: true}).click();
  await page.getByLabel('Wallet name', {exact: true}).fill(original);
  await page.getByLabel('Wallet password', {exact: true}).fill(password);
  await page.getByRole('button', {name: 'Create local wallet', exact: true}).click();
  await page.waitForFunction(() => document.getElementById('notice').classList.contains('error'));
  assert(await page.locator('#closed').isVisible());
  await unlock(original);
  await page.locator('#opened').waitFor({state: 'visible', timeout: 45000});
  assert(await page.locator('#address').textContent() === address);
  await lock();
  let upgradeContinuity = false;
  if (process.argv.includes('--wait-upgrade')) {
    await writeFile(join(output, 'UPGRADE_WALLET_READY.json'), JSON.stringify({status: 'WALLET_LOCKED_FOR_UPGRADE', secretsExported: false}) + '\n', {flag: 'wx', mode: 0o600});
    const until = Date.now() + 150000;
    while (true) {
      try { await readFile(join(output, 'UPGRADE_WALLET_CONTINUE.json')); break; }
      catch (error) { if (error.code !== 'ENOENT' || Date.now() >= until) throw error; }
      await new Promise(ok => setTimeout(ok, 200));
    }
    await context.close();
    context = await browser.newContext({viewport: {width: 1200, height: 900}});
    page = await context.newPage();
    const freshLink = await readFile(join(root, 'wallets/OPEN_WALLET.html'), 'utf8');
    await page.goto(freshLink.match(/href="([^"]+)"/)[1], {waitUntil: 'networkidle'});
    assert((await page.locator('#notice').textContent()).includes('Connected'));
    await unlock(original);
    await page.locator('#opened').waitFor({state: 'visible', timeout: 45000});
    assert(await page.locator('#address').textContent() === address);
    await page.screenshot({path: join(output, 'wallet-after-upgrade.png'), fullPage: true});
    await lock();
    upgradeContinuity = true;
  }
  async function checkLogs(directory) {
    for (const entry of await readdir(directory, {withFileTypes: true})) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await checkLogs(path);
      else if (entry.name.endsWith('.log')) {
        const raw = await readFile(path, 'utf8');
        assert(!raw.includes(password) && !raw.includes(seed), 'Secret appeared in a native/session log');
      }
    }
  }
  await checkLogs(root);
  assert.deepEqual(errors, []);
  await writeFile(join(output, 'BROWSER_INSTALLATION.json'), JSON.stringify({
    status: 'REAL_PARTICIPANT_WALLET_UI_PASS', platform: process.platform, browser: browser.version(),
    mode: 'headless isolated profile; browser sandbox enabled', encryptedNativeWalletCreated: true,
    backupConfirmedAndCleared: true, wrongPasswordRefused: true, lockAndUnlock: true,
    recoveryToSeparateWalletSameAddress: true, originalRemainsUsable: true, reloadLocksWallet: true,
    creatingOverExistingWalletRefused: true,
    oldWalletUnlockedAfterCompatibleUpgrade: upgradeContinuity,
    hostOnlyCookieIsolatedFromAdjacentLoopback: true, nativeAndSessionLogsNoSeedOrPassword: true,
    secretsExported: false, miningOrTransfersTested: false, pageErrors: errors
  }, null, 2) + '\n', {flag: 'wx', mode: 0o600});
  console.log('REAL_PARTICIPANT_WALLET_UI_PASS');
} finally {
  clearTimeout(deadline);
  seed = '';
  await context?.close();
  await browser?.close();
}
