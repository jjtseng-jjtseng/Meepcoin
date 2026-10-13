// Real Chromium UI half of the finite native participant rehearsal.
// Uses an explicitly provided installed Playwright module and browser. Installs nothing.
// No direct wallet API calls or fabricated browser visibility/mining results.
import {readFile, writeFile, readdir} from 'node:fs/promises';
import {resolve, join} from 'node:path';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const argument = name => process.argv[process.argv.indexOf('--' + name) + 1];
const root = resolve(argument('run-dir'));
const {chromium} = await import(pathToFileURL(resolve(argument('playwright-module'))));
const pause = ms => new Promise(ok => setTimeout(ok, ms));
async function waitFile(name, seconds = 120) {
  const end = Date.now() + seconds * 1000;
  while (Date.now() < end) {
    try { return JSON.parse(await readFile(join(root, name), 'utf8')); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    await pause(200);
  }
  throw Error('Finite browser checkpoint expired: ' + name);
}
const save = (name, data) => writeFile(join(root, name), JSON.stringify(data, null, 2) + '\n', {flag: 'wx', mode: 0o600});
const amount = value => {
  const n = BigInt(value), fraction = (n % 100000000000n).toString().padStart(11, '0').replace(/0+$/, '');
  return (n / 100000000000n).toString() + (fraction ? '.' + fraction : '');
};
const toAtomic = text => {
  const [whole, fraction = ''] = text.trim().replace(/ MEEP$/, '').split('.');
  assert(/^[0-9]+$/.test(whole) && /^[0-9]{0,11}$/.test(fraction));
  return (BigInt(whole) * 100000000000n + BigInt(fraction.padEnd(11, '0'))).toString();
};
let server, browser, context, stopping = false;
const failures = [];
let seedAlice = '', seedBob = '';
const password = 'fresh-participant-disposable-password';
async function cleanup() {
  if (stopping) return;
  stopping = true;
  await context?.close().catch(() => {});
  await browser?.close().catch(() => {});
  await server?.close().catch(() => {});
  seedAlice = ''; seedBob = '';
}
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, async () => { await cleanup(); process.exit(130); });
const deadline = setTimeout(async () => { await cleanup(); process.exit(124); }, 1000000);
try {
  const ready = await waitFile('READY.json');
  const privateLink = await readFile(ready.privateLinkFile, 'utf8');
  const url = privateLink.match(/href="([^"]+)"/)[1];
  server = await chromium.launchServer({executablePath: resolve(argument('browser')), headless: !process.argv.includes('--headed'),
    args: ['--no-first-run', '--disable-background-networking', '--disable-component-update', '--disable-sync'],
    chromiumSandbox: true});
  const pid = server.process().pid;
  if (process.platform === 'linux') {
    const stat = await readFile('/proc/' + pid + '/stat', 'utf8');
    await save('BROWSER_PROCESS.json', {pid, processGroup: Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[2])});
  }
  browser = await chromium.connect(server.wsEndpoint());
  context = await browser.newContext({viewport: {width: 1280, height: 900}});
  const page = await context.newPage();
  page.on('pageerror', error => failures.push(error.message));
  await page.goto(url, {waitUntil: 'networkidle'});
  assert((await page.locator('#notice').textContent()).includes('Connected'));
  assert(new URL(page.url()).hash === '');
  async function create(name) {
    await page.getByRole('button', {name: 'Create', exact: true}).click();
    await page.getByLabel('Wallet name', {exact: true}).fill(name);
    await page.getByLabel('Wallet password', {exact: true}).fill(password);
    await page.getByRole('button', {name: 'Create local wallet', exact: true}).click();
    await page.locator('#backup').waitFor({state: 'visible', timeout: 45000});
    const seed = await page.locator('#seed-output').textContent();
    assert(seed.trim().split(/\s+/).length >= 24);
    const address = await page.locator('#address').textContent();
    await page.getByLabel('I recorded the words in order and can recover this wallet.').check();
    await page.getByRole('button', {name: 'I have backed up my wallet', exact: true}).click();
    await page.locator('#backup').waitFor({state: 'hidden'});
    assert((await page.locator('#seed-output').textContent()) === '');
    return {seed, address};
  }
  async function lock() {
    await page.getByRole('button', {name: 'Lock wallet', exact: true}).click();
    await page.locator('#closed').waitFor({state: 'visible'});
  }
  async function unlock(name) {
    await page.getByRole('button', {name: 'Unlock', exact: true}).click();
    await page.getByLabel('Wallet name', {exact: true}).fill(name);
    await page.getByLabel('Wallet password', {exact: true}).fill(password);
    await page.getByRole('button', {name: 'Unlock wallet', exact: true}).click();
    await page.locator('#opened').waitFor({state: 'visible', timeout: 45000});
  }
  async function refresh(expected) {
    await page.getByRole('button', {name: 'Refresh from node', exact: true}).click();
    await page.waitForFunction(value => document.getElementById('balance').textContent === value &&
                               !document.getElementById('refresh').disabled &&
                               document.getElementById('notice').textContent === 'Balances and transactions refreshed.',
                               amount(expected), {timeout: 45000});
  }
  const alice = await create('alice'); seedAlice = alice.seed; alice.seed = '';
  await lock();
  const bob = await create('bob'); seedBob = bob.seed; bob.seed = '';
  await lock();
  await unlock('alice');
  await save('CREATED.json', {alice: alice.address, bob: bob.address, walletNames: ['alice', 'bob']});
  const funded = await waitFile('FUNDED.json');
  await refresh(funded.aliceBalanceAtomic);
  const privateMiner = await waitFile('MINER_PRIVATE.json');
  const miner = await context.newPage();
  miner.on('pageerror', error => failures.push(error.message));
  await miner.goto(privateMiner.url, {waitUntil: 'networkidle'});
  await miner.bringToFront();
  assert(await miner.evaluate(() => document.visibilityState) === 'visible');
  assert(await miner.locator('#address').textContent() === alice.address);
  await miner.getByRole('button', {name: 'Start mining', exact: true}).click();
  await miner.waitForFunction(() => document.getElementById('state').textContent === 'Block observed', null, {timeout: 120000});
  assert(await miner.evaluate(() => window.meepPrivate.workerCount) === 0);
  await miner.screenshot({path: join(root, 'BROWSER_MINED.png'), fullPage: true});
  const reward = await waitFile('REWARD.json');
  await page.bringToFront();
  // Hiding the wallet may already have requested its lock. Explicitly lock
  // through the UI if this headless browser keeps both documents visible.
  if (await page.locator('#opened').isVisible()) await lock();
  await unlock('alice');
  await refresh(reward.aliceBalanceAtomic);
  await page.screenshot({path: join(root, 'BROWSER_REWARD.png'), fullPage: true});
  await page.getByLabel('Recipient’s public testnet address', {exact: true}).fill(bob.address);
  await page.getByLabel('Amount in MEEP', {exact: true}).fill('1.00000000000');
  await page.getByRole('button', {name: 'Review transfer', exact: true}).click();
  await page.locator('#review').waitFor({state: 'visible'});
  assert(await page.locator('#review-address').textContent() === bob.address);
  await page.getByRole('button', {name: 'Cancel', exact: true}).click();
  await page.locator('#review').waitFor({state: 'hidden'});
  await save('CANCELLED.json', {reviewCancelled: true});
  await waitFile('CANCELLED_OK.json');
  await page.getByRole('button', {name: 'Review transfer', exact: true}).click();
  await page.locator('#review').waitFor({state: 'visible'});
  const fee = toAtomic(await page.locator('#review-fee').textContent());
  assert(toAtomic(await page.locator('#review-amount').textContent()) === '100000000000');
  assert(toAtomic(await page.locator('#review-total').textContent()) === (100000000000n + BigInt(fee)).toString());
  await page.getByRole('button', {name: 'Confirm and send', exact: true}).click();
  await page.waitForFunction(() => /Submitted.*[0-9a-f]{64}/.test(document.getElementById('send-result').textContent));
  const txHash = (await page.locator('#send-result').textContent()).match(/[0-9a-f]{64}/)[0];
  await save('SENT.json', {txHash, amountAtomic: '100000000000', feeAtomic: fee});
  const confirmed = await waitFile('CONFIRMED.json');
  await refresh(confirmed.aliceBalanceAtomic);
  const outgoing = page.locator('#transactions tr').filter({hasText: txHash});
  assert(await outgoing.count() === 1);
  assert(await outgoing.locator('td').nth(0).textContent() === 'out');
  assert(await outgoing.locator('td').nth(2).textContent() === '12');
  await lock(); await unlock('bob');
  assert(await page.locator('#destination').inputValue() === '');
  assert(await page.locator('#amount').inputValue() === '');
  await refresh(confirmed.bobBalanceAtomic);
  assert(await page.locator('#address').textContent() === bob.address);
  const incoming = page.locator('#transactions tr').filter({hasText: txHash});
  assert(await incoming.count() === 1);
  assert(await incoming.locator('td').nth(0).textContent() === 'in');
  assert(await incoming.locator('td').nth(2).textContent() === '12');
  await page.screenshot({path: join(root, 'BROWSER_RECEIVED.png'), fullPage: true});
  await lock();
  await page.getByRole('button', {name: 'Recover', exact: true}).click();
  await page.getByLabel('Wallet name', {exact: true}).fill('bob-recovered');
  await page.getByLabel('Wallet password', {exact: true}).fill(password);
  await page.getByLabel('Recovery words', {exact: true}).fill(seedBob);
  await page.getByRole('button', {name: 'Recover into new wallet', exact: true}).click();
  await page.locator('#opened').waitFor({state: 'visible', timeout: 60000});
  assert(await page.locator('#address').textContent() === bob.address);
  assert(await page.locator('#balance').textContent() === amount(confirmed.bobBalanceAtomic));
  assert(await page.locator('#seed-input').inputValue() === '');
  await page.reload({waitUntil: 'networkidle'});
  await page.locator('#closed').waitFor({state: 'visible'});
  await page.getByRole('button', {name: 'Unlock', exact: true}).click();
  await page.getByLabel('Wallet name', {exact: true}).fill('bob-recovered');
  await page.getByLabel('Wallet password', {exact: true}).fill('deliberately-wrong-password');
  await page.getByRole('button', {name: 'Unlock wallet', exact: true}).click();
  await page.waitForFunction(() => document.getElementById('notice').classList.contains('error'));
  assert(await page.locator('#closed').isVisible());
  assert(await page.locator('#opened').isHidden());
  async function checkLogs(directory) {
    for (const entry of await readdir(directory, {withFileTypes: true})) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await checkLogs(path);
      else if (entry.name.endsWith('.log')) {
        const raw = await readFile(path, 'utf8');
        assert(![password, seedAlice, seedBob].some(secret => secret && raw.includes(secret)), 'Secret detected in log');
      }
    }
  }
  await checkLogs(root);
  assert.deepEqual(failures, []);
  await save('BROWSER_RESULT.json', {browser: browser.version(), mode: process.argv.includes('--headed') ? 'headed' : 'headless',
    browserCreateAndBackup: true, backupWordsCleared: true, visibleBrowserMining: true,
    exactBrowserReward: true, reviewCancelNoRelay: true, confirmedSend: true,
    exactSenderBalance: true, exactRecipientBalance: true, seedRecoverySameAddressAndBalance: true,
    reloadLocksWallet: true, wrongPasswordLeavesLocked: true, nativeLogsNoSeedOrPassword: true,
    switchingWalletClearsPaymentDraft: true,
    txHash, amountAtomic: '100000000000', feeAtomic: fee,
    aliceBalanceAtomic: confirmed.aliceBalanceAtomic, bobBalanceAtomic: confirmed.bobBalanceAtomic,
    browserPageErrors: failures, permissionsBypassed: false, browserExtensions: 'fresh isolated profile'});
  console.log('REAL_BROWSER_PARTICIPANT_UI_PASS');
} finally {
  clearTimeout(deadline);
  await cleanup();
}
