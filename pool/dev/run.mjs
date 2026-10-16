// Command-line entry point for the local MeepCoin development pool.
//
//   node pool/dev/run.mjs [--host 127.0.0.1] [--port 8171] [--nonce-range 16]
//   node pool/dev/run.mjs --mode real-local-daemon --artifact-dir <WSL artifact dir, optional /out>
//        --image <meepcoin-build:tag> --rpc-port <n> --p2p-port <n>
//   Add --peer-rpc-port and --peer-p2p-port (and a pinned --expected-image-id) to run the
//   existing private two-daemon path. Optional --sequence-blocks / --refresh-windows disclose a
//   finite, bounded search plan to the page before its one Start. The paired path can also opt into
//   lower-difficulty server-verified shares with --share-difficulty 1..500.
//
// Then open the printed http://127.0.0.1:<port> address and press Start. In the default synthetic
// mode, starting this process loads NO Wasm and computes NO hash: it checks the pinned artifact
// identity, reads the synthetic target out of the committed vectors, and listens. Real-daemon mode
// additionally starts its owned converter and one offline daemon (or an explicit private pair),
// then fetches and personalizes one fresh template before listening. The converter parses a block;
// it does not allocate a PoW dataset or hash a nonce.
// In every mode the verifier appears only when a human presses Start, and lives until Ctrl-C.

import { randomBytes } from 'node:crypto';

import { startDevPool, NonLoopbackBindError } from './server.mjs';
import { WasmIdentityError, IDENTITY } from './identity.mjs';
import { createShutdownController } from './cli_shutdown.mjs';
import { parseRealPoolCli, RealPoolCliError, REAL_POOL_USAGE } from './run_config.mjs';
import { REAL_DAEMON_MODE } from '../../web-miner/lib/shared/protocol.js';

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}

// RECORDED-TEMPLATE SIMULATION: opt-in, off by default, chosen here and nowhere else.
//
//   node pool/dev/run.mjs --mode recorded-template-simulation
//   node pool/dev/run.mjs --simulation
//
// It replays ONE committed historical devnet block (height 2113) so a browser can do one real
// contextual hash against a known answer. It contacts no daemon and no chain, submits nothing and
// creates nothing. A server process may complete it once.
const explicitMode = arg('mode', null);
if (process.argv.includes('--simulation') && explicitMode !== null) {
  console.error('--simulation cannot be combined with an explicit --mode');
  process.exit(2);
}
const mode = process.argv.includes('--simulation')
  ? 'recorded-template-simulation'
  : (explicitMode ?? 'synthetic');
if (mode !== 'synthetic' && mode !== 'recorded-template-simulation' && mode !== REAL_DAEMON_MODE) {
  console.error(`unknown --mode ${mode}; expected "synthetic", "recorded-template-simulation" or "${REAL_DAEMON_MODE}"`);
  process.exit(2);
}

let realCli = null;
if (mode === REAL_DAEMON_MODE) {
  try {
    realCli = parseRealPoolCli(process.argv.slice(2), { runId: randomBytes(8).toString('hex') });
  } catch (err) {
    if (!(err instanceof RealPoolCliError)) throw err;
    console.error(`\n${err.message}\n\nUsage:\n  ${REAL_POOL_USAGE}\n`);
    process.exit(2);
  }
}
const host = realCli?.host ?? arg('host', '127.0.0.1');
const port = realCli?.port ?? Number(arg('port', '8171'));
const nonceRange = Number(arg('nonce-range', '16'));

let pool;
try {
  pool = await startDevPool({
    host,
    port,
    nonceRange,
    mode,
    ...(realCli === null ? {} : { realDaemon: realCli.realDaemon }),
    ...(realCli?.twoSlotAssignments === true ? { twoSlotAssignments: true } : {}),
  });
} catch (err) {
  if (err instanceof NonLoopbackBindError || err instanceof WasmIdentityError) {
    console.error(`\n${err.message}\n`);
    process.exit(2);
  }
  throw err;
}

if (pool.mode === REAL_DAEMON_MODE) {
  if (realCli.twoSlotAssignments) {
    console.log('MeepCoin local browser pool  --  PRIVATE TWO-BROWSER DEV MODE, LOOPBACK ONLY');
    console.log('ONE PRIVATE OFFLINE DAEMON / UP TO TWO STARTS / ONE CANONICAL BLOCK SUBMISSION');
    console.log('NO WALLET IS OPENED. NO PUBLIC NETWORK OR PEER IS CONTACTED.');
    console.log('');
    console.log(`  page                 ${pool.url}`);
    console.log(`  websocket            ${pool.wsUrl}`);
    console.log('  browser assignments  at most two; each personalized job is issued only after Start');
    console.log(`  private daemon RPC   127.0.0.1:${realCli.realDaemon.daemon.rpcPort}`);
    console.log(`  private daemon P2P   127.0.0.1:${realCli.realDaemon.daemon.p2pPort} (offline; no peers)`);
    console.log(`  daemon build         ${realCli.realDaemon.daemon.image}`);
    console.log(`  private chain data   ${realCli.realDaemon.daemon.runDir}`);
    console.log('                       retained after shutdown; remove manually when no longer needed');
    console.log('');
    console.log('Open two separate browser sessions and read the disclosed limits before pressing Start.');
    console.log('The first canonical submission claim stops the sibling. There is no automatic retry.');
    console.log('Ctrl-C closes the listener, both assignments and the owned private daemon.');
    console.log('');
  } else if (realCli.realDaemon.peer) {
    const blocks = realCli.realDaemon.sequenceBlocks ?? 1;
    const windows = realCli.realDaemon.refreshWindows ?? 1;
    const a = realCli.realDaemon.daemon;
    const b = realCli.realDaemon.peer.daemon;
    console.log('MeepCoin local browser pool  --  PRIVATE PAIRED DEVELOPMENT MODE, LOOPBACK ONLY');
    console.log(`ONE EXPLICIT START / AT MOST ${blocks} HEIGHT(S) AND ${windows} WINDOW(S) PER HEIGHT`);
    console.log(realCli.realDaemon.daemon.profile === 'private-exclusive-peer-natural'
      ? 'DAEMON-SELECTED DIFFICULTY; NO FIXED TEST TARGET; NO WALLET OR PUBLIC PEER.'
      : 'FIXED DEVELOPMENT DIFFICULTY 500; NO WALLET OPENED OR PUBLIC PEER CONTACTED.');
    if (realCli.realDaemon.daemon.profile === 'private-exclusive-peer-natural') {
      const genesisTimestamp = pool.simulation.peer.genesis.timestamp;
      const ageSeconds = Math.floor(Date.now() / 1000) - genesisTimestamp;
      console.log(`GENESIS TIMESTAMP ${genesisTimestamp} (daemon-read); age at pool launch ${ageSeconds} s.`);
      console.log(`PINNED GENESIS TIMESTAMP ${realCli.realDaemon.expectedGenesisTimestamp} (matched before work).`);
      console.log(`PINNED GENESIS HASH ${realCli.realDaemon.expectedGenesisHash} (matched before work).`);
      if (realCli.realDaemon.maxGenesisAgeSeconds !== undefined) {
        console.log(`MAX GENESIS AGE ${realCli.realDaemon.maxGenesisAgeSeconds} s (enforced before work).`);
      }
      console.log('A new data directory does not make an old compiled genesis a fresh launch.');
    }
    if (realCli.realDaemon.shareDifficulty !== undefined) {
      console.log(`SHARE DIFFICULTY ${realCli.realDaemon.shareDifficulty}; AT MOST 8 VERIFIED RESULTS PER JOB.`);
      console.log('Non-block shares are checked locally and are not submitted to a daemon.');
    }
    console.log('');
    console.log(`  page                 ${pool.url}`);
    console.log(`  websocket            ${pool.wsUrl}`);
    console.log(`  daemon A RPC/P2P     127.0.0.1:${a.rpcPort} / 127.0.0.1:${a.p2pPort}`);
    console.log(`  daemon B RPC/P2P     127.0.0.1:${b.rpcPort} / 127.0.0.1:${b.p2pPort}`);
    console.log('  private peers        A and B only, numeric loopback');
    console.log(`  daemon build         ${a.image}`);
    console.log(`  private chain A      ${a.runDir}`);
    console.log(`  private chain B      ${b.runDir}`);
    console.log('                       retained after shutdown; remove manually when no longer needed');
    console.log('');
    console.log('Read the page disclosure before pressing Start. One Start may search up to the printed');
    console.log('finite block/window plan, one context at a time; Stop or hiding the tab ends the session.');
    console.log('The pool never clicks Start, auto-retries, opens a wallet, or connects to a public peer.');
    console.log('Ctrl-C closes the listener and both owned private daemons.');
    console.log('');
  } else {
    const sim = pool.simulation;
    console.log('MeepCoin local browser pool  --  PRIVATE OFFLINE REAL DAEMON, LOOPBACK ONLY');
    console.log('ONE FRESH TEMPLATE / ONE EXPLICIT START / ONE ATTEMPT / NO AUTOMATIC RETRY');
    console.log('NO WALLET IS OPENED. NO PUBLIC NETWORK OR PEER IS CONTACTED.');
    console.log('');
    console.log(`  page                 ${pool.url}`);
    console.log(`  websocket            ${pool.wsUrl}`);
    console.log(`  fresh block height   ${sim.job.height}`);
    console.log(`  nonce window         [${sim.job.nonceStart}, ${sim.job.nonceStart + sim.job.nonceRange})`);
    console.log(`  private daemon RPC   127.0.0.1:${realCli.realDaemon.daemon.rpcPort}`);
    console.log(`  private daemon P2P   127.0.0.1:${realCli.realDaemon.daemon.p2pPort} (offline; no peers)`);
    console.log(`  daemon build         ${realCli.realDaemon.daemon.image}`);
    console.log(`  private chain data   ${realCli.realDaemon.daemon.runDir}`);
    console.log('                       retained after shutdown; remove manually when no longer needed');
    console.log('');
    console.log('Open the page yourself and read its disclosed limits. No browser Worker, server verifier,');
    console.log('native HASHING helper or MeepHash-W hash exists until the page sends Start. The owned');
    console.log('native block converter has only parsed the server-side personalized template. This');
    console.log('server permits exactly one bounded attempt; it never clicks Start and never retries.');
    console.log('Press Ctrl-C here to close the listener and its one owned private daemon. The private');
    console.log('chain directory printed above is retained for inspection; shutdown does not delete it.');
    console.log('');
  }
} else if (pool.mode === 'recorded-template-simulation') {
  const sim = pool.simulation;
  console.log('MeepCoin local pool  --  RECORDED-TEMPLATE SIMULATION, LOCALHOST ONLY');
  console.log('LIVE LOCAL NATIVE HELPER / MOCK DAEMON / NO DAEMON OR BLOCKCHAIN CONTACTED');
  console.log('NO BLOCK MINED, SUBMITTED, OR ACCEPTED. Nothing is created.');
  console.log('');
  console.log(`  page                 ${pool.url}`);
  console.log(`  websocket            ${pool.wsUrl}`);
  console.log(`  recorded height      ${sim.job.height}  (seed height ${sim.job.seedHeight})`);
  console.log(`  the one nonce        ${sim.job.nonceStart}  (window size ${sim.job.nonceRange})`);
  console.log(`  expected hash        ${sim.expectedHashHexLE}`);
  console.log(`  issuance             ${sim.job.issuanceId}`);
  for (const a of pool.identity.checked) {
    console.log(`  wasm identity OK     ${a.relative}  ${a.sha256.slice(0, 16)}...`);
  }
  console.log('');
  console.log('Nothing is hashed and no native helper is started until you press the button on the');
  console.log('page. The native check is the live local helper; the "daemon" is an in-memory model:');
  console.log('no RPC socket is opened and no chain is touched. One simulation attempt per server');
  console.log('process; restart to run it again. Ctrl-C to stop.');
  console.log('');
} else {
console.log('MeepCoin local development pool  --  SYNTHETIC, LOCALHOST ONLY, NO COINS OR REWARDS');
console.log('This slice includes, connects to and runs no MeepCoin or Monero daemon.\n');
console.log(`  page                 ${pool.url}`);
console.log(`  websocket            ${pool.wsUrl}`);
console.log(`  algorithm            ${pool.jobs.active().algorithm}`);
console.log(`  nonce window         [${pool.fixture.nonceStart}, ${pool.fixture.nonceStart + pool.fixture.nonceRange})`);
console.log(`  target (LE hex)      ${pool.fixture.targetHexLE}`);
console.log(`  qualifying nonce     ${pool.fixture.qualifyingNonce} (target == its hash, so it passes by equality)`);
console.log(`  target source        committed ${IDENTITY.syntheticFixture.vectorFile} -- read, not computed`);
for (const a of pool.identity.checked) {
  console.log(`  wasm identity OK     ${a.relative}  ${a.sha256.slice(0, 16)}...`);
}
console.log(`  server verifier      ${pool.verifierState}  (not imported/compiled/instantiated, no dataset, ${pool.serverHashCalls} hashes)`);
console.log('\nNothing is hashed on EITHER side until a client declares start intent (the official');
console.log('page sends that only from its Start button). Before then the pool has read and hashed');
console.log('59,524 bytes (~58.1 KiB) of build output so it can serve exactly what it verified, but');
console.log('has NOT imported, compiled or instantiated the module, allocated a dataset, or hashed.');
console.log('It loads its own verifier (~46 MiB) only on Start, and keeps it until you stop this');
console.log('process.');
console.log('One run ends after one accepted share; press Start again for another. Ctrl-C to stop.\n');
}

// Shutdown is single-flight, reports a failed close instead of crashing on it, retries a bounded
// number of times, and REFUSES TO EXIT while a resource is unconfirmed -- exiting would orphan the
// native child and print success over it. See pool/dev/cli_shutdown.mjs.
const shutdown = createShutdownController({ pool });
process.on('SIGINT', () => { shutdown.requestShutdown('SIGINT'); });
process.on('SIGTERM', () => { shutdown.requestShutdown('SIGTERM'); });
