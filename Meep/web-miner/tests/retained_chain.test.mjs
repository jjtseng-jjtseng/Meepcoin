// --keep-chain retention must fail closed, on the EXACT inventory. Pure decision functions only:
// NO WSL, DOCKER, DAEMON, BROWSER, LISTENER, WALLET OR CHAIN is touched by this file.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  DEFAULT_OWNER,
  EXPECTED_LMDB_FILES,
  collectRetainedChain,
  LMDB_SUBDIR,
  evaluateRetainedChain,
  expectedLmdbPaths,
  pathSpellingProblem,
  retentionSatisfied,
} from '../tools/retained_chain.mjs';
import { evaluateRelease } from '../tools/release_decision.mjs';

const RUN = '/home/tseng/meepcoin-private-run-52a9042d5eabd7e5';
const DIR = `${RUN}/data`;
const LMDB = `${DIR}/${LMDB_SUBDIR}`;
const H = (c) => c.repeat(64);
const OK_CHMOD = { status: 0 };
const sums = (...lines) => ({ status: 0, stdout: `${lines.join('\n')}\n` });
const okSums = () => sums(`${H('2')}  ${LMDB}/data.mdb`, `${H('0')}  ${LMDB}/lock.mdb`);
const okStat = () => ({
  status: 0,
  stdout: `700 1000 1000 ${RUN}\n700 1000 1000 ${DIR}\n600 1000 1000 ${LMDB}/data.mdb\n600 1000 1000 ${LMDB}/lock.mdb\n`,
});
const evalWith = (o) => evaluateRetainedChain({
  path: DIR,
  runDir: RUN,
  identityMatched: true,
  evidenceRequested: true,
  chmod: OK_CHMOD,
  find: okSums(),
  stat: okStat(),
  owner: DEFAULT_OWNER,
  ...o,
});
const problemText = (r) => r.problems.join(' | ');

// ---------------------------------------------------------------- the one accepted shape
test('the exact testnet inventory is confirmed and its hashes recorded', () => {
  const r = evalWith({});
  assert.equal(r.ok, true);
  assert.deepEqual(r.problems, []);
  assert.equal(r.identityMatched, true);
  assert.equal(r.sums.length, 2);
  assert.deepEqual(r.expected, [`${LMDB}/data.mdb`, `${LMDB}/lock.mdb`]);
  assert.deepEqual(expectedLmdbPaths(DIR), r.expected);
  assert.deepEqual(r.files.map((f) => f.path).sort(), [...r.expected].sort());
  assert.equal(r.files.find((f) => f.path.endsWith('data.mdb')).sha256, H('2'));
  assert.equal(r.files.find((f) => f.path.endsWith('lock.mdb')).sha256, H('0'));
  assert.equal(r.permissions.length, 4);
  assert.deepEqual(r.expectedOwner, { uid: 1000, gid: 1000 });
  assert.deepEqual([...EXPECTED_LMDB_FILES], ['data.mdb', 'lock.mdb']);
});

// ---------------------------------------------------------------- basename-only bugs of 2a64554
test('data/junk/{data,lock}.mdb is rejected: basenames are not the inventory', () => {
  const r = evalWith({ find: sums(`${H('2')}  ${DIR}/junk/data.mdb`, `${H('0')}  ${DIR}/junk/lock.mdb`) });
  assert.equal(r.ok, false);
  assert.match(problemText(r), /unexpected extra \.mdb file under the data root: .*junk\/data\.mdb/);
  assert.match(problemText(r), /unexpected extra \.mdb file under the data root: .*junk\/lock\.mdb/);
  assert.match(problemText(r), /expected LMDB file missing: .*testnet\/lmdb\/data\.mdb/);
  assert.match(problemText(r), /expected LMDB file missing: .*testnet\/lmdb\/lock\.mdb/);
  assert.equal(r.sums.length, 0);
});

test('paths outside the supplied data root are rejected', () => {
  const r = evalWith({ find: sums(`${H('2')}  /home/tseng/elsewhere/data.mdb`, `${H('0')}  ${LMDB}/lock.mdb`) });
  assert.equal(r.ok, false);
  assert.match(problemText(r), /retained path outside the data root: \/home\/tseng\/elsewhere\/data\.mdb/);
  assert.match(problemText(r), /expected LMDB file missing: .*data\.mdb/);
});

test('a sibling directory sharing the root as a string prefix is still outside the root', () => {
  const r = evalWith({ find: sums(`${H('2')}  ${DIR}-evil/${LMDB_SUBDIR}/data.mdb`, `${H('0')}  ${LMDB}/lock.mdb`) });
  assert.equal(r.ok, false);
  assert.match(problemText(r), /retained path outside the data root: .*-evil/);
});

test('the wrong network is rejected', () => {
  const r = evalWith({ find: sums(`${H('2')}  ${DIR}/mainnet/lmdb/data.mdb`, `${H('0')}  ${DIR}/mainnet/lmdb/lock.mdb`) });
  assert.equal(r.ok, false);
  assert.match(problemText(r), /unexpected extra \.mdb file .*mainnet\/lmdb\/data\.mdb/);
  assert.equal(r.problems.filter((p) => /expected LMDB file missing/.test(p)).length, 2);
});

test('the right network but the wrong subdirectory is rejected', () => {
  const r = evalWith({ find: sums(`${H('2')}  ${DIR}/testnet/data.mdb`, `${H('0')}  ${DIR}/testnet/lmdb2/lock.mdb`) });
  assert.equal(r.ok, false);
  assert.equal(r.problems.filter((p) => /unexpected extra \.mdb file/.test(p)).length, 2);
  assert.equal(r.problems.filter((p) => /expected LMDB file missing/.test(p)).length, 2);
});

test('duplicate data.mdb is rejected even when both copies are the expected path', () => {
  const r = evalWith({ find: sums(`${H('2')}  ${LMDB}/data.mdb`, `${H('2')}  ${LMDB}/data.mdb`, `${H('0')}  ${LMDB}/lock.mdb`) });
  assert.equal(r.ok, false);
  assert.match(problemText(r), /duplicate retained entry \(2x\): .*data\.mdb/);
});

test('a second data.mdb at another path is rejected, not counted as the required name', () => {
  const r = evalWith({ find: sums(`${H('2')}  ${LMDB}/data.mdb`, `${H('3')}  ${DIR}/old/data.mdb`, `${H('0')}  ${LMDB}/lock.mdb`) });
  assert.equal(r.ok, false);
  assert.match(problemText(r), /unexpected extra \.mdb file .*old\/data\.mdb/);
});

test('the expected pair plus an unexpected extra .mdb is rejected', () => {
  const r = evalWith({ find: sums(`${H('2')}  ${LMDB}/data.mdb`, `${H('0')}  ${LMDB}/lock.mdb`, `${H('7')}  ${LMDB}/stray.mdb`) });
  assert.equal(r.ok, false);
  assert.match(problemText(r), /unexpected extra \.mdb file .*stray\.mdb/);
  assert.equal(r.problems.filter((p) => /missing/.test(p)).length, 0);
});

test('an unexpected non-.mdb file under the root is rejected too', () => {
  const r = evalWith({ find: sums(`${H('2')}  ${LMDB}/data.mdb`, `${H('0')}  ${LMDB}/lock.mdb`, `${H('7')}  ${LMDB}/notes.txt`) });
  assert.equal(r.ok, false);
  assert.match(problemText(r), /unexpected file under the data root: .*notes\.txt/);
});

// ---------------------------------------------------------------- spelling ambiguity
test('dot, dot-dot, doubled-slash and trailing-slash spellings are rejected, not normalized', () => {
  for (const p of [
    `${DIR}/testnet/./lmdb/data.mdb`,
    `${DIR}/testnet/../testnet/lmdb/data.mdb`,
    `${DIR}//testnet/lmdb/data.mdb`,
    `${LMDB}/data.mdb/`,
    `${DIR}\\testnet\\lmdb\\data.mdb`,
    `testnet/lmdb/data.mdb`,
  ]) {
    const r = evalWith({ find: sums(`${H('2')}  ${p}`, `${H('0')}  ${LMDB}/lock.mdb`) });
    assert.equal(r.ok, false, p);
    assert.match(problemText(r), /non-normalized or ambiguous retained path|outside the data root/, p);
    assert.match(problemText(r), /expected LMDB file missing: .*data\.mdb/, p);
  }
});

test('pathSpellingProblem names each ambiguity and accepts the normal spelling', () => {
  assert.equal(pathSpellingProblem(`${LMDB}/data.mdb`), null);
  assert.match(pathSpellingProblem(`${DIR}/./x`), /dot or dot-dot/);
  assert.match(pathSpellingProblem(`${DIR}/../x`), /dot or dot-dot/);
  assert.match(pathSpellingProblem(`${DIR}//x`), /empty path segment/);
  assert.match(pathSpellingProblem(`${DIR}/x/`), /trailing slash/);
  assert.match(pathSpellingProblem('relative/x'), /not an absolute path/);
  assert.match(pathSpellingProblem(''), /empty path/);
  assert.match(pathSpellingProblem(null), /empty path/);
});

test('an unusable data root fails closed instead of building nonsense expectations', () => {
  const r = evalWith({ path: `${DIR}/..`, runDir: RUN });
  assert.equal(r.ok, false);
  assert.match(problemText(r), /retained data root is unusable \(dot or dot-dot segment\)/);
  assert.deepEqual(r.expected, []);
  assert.deepEqual(r.sums, []);
});

// ---------------------------------------------------------------- malformed output
test('malformed hashes are rejected, not dropped', () => {
  for (const line of [
    `${'a'.repeat(63)}  ${LMDB}/data.mdb`,
    `${'A'.repeat(64)}  ${LMDB}/data.mdb`,
    `${H('2')} ${LMDB}/data.mdb`,
    `${H('2')}\t${LMDB}/data.mdb`,
    `sha256sum: ${LMDB}/data.mdb: Permission denied`,
  ]) {
    const r = evalWith({ find: sums(line, `${H('0')}  ${LMDB}/lock.mdb`) });
    assert.equal(r.ok, false, line);
    assert.match(problemText(r), /unparsable hash output: 1 line\(s\)/, line);
  }
});

test('an empty or failed discovery fails closed -- the original mis-globbed bug', () => {
  const empty = evalWith({ find: { status: 0, stdout: '\n' } });
  assert.equal(empty.ok, false);
  assert.match(problemText(empty), /no retained chain files were hashed/);
  const failed = evalWith({ find: { status: 2, stdout: '' } });
  assert.equal(failed.ok, false);
  assert.match(problemText(failed), /chain file discovery\/hash failed/);
});

test('a missing required file fails closed', () => {
  const noData = evalWith({ find: sums(`${H('0')}  ${LMDB}/lock.mdb`) });
  assert.equal(noData.ok, false);
  assert.match(problemText(noData), /expected LMDB file missing: .*data\.mdb/);
  const noLock = evalWith({ find: sums(`${H('2')}  ${LMDB}/data.mdb`) });
  assert.equal(noLock.ok, false);
  assert.match(problemText(noLock), /expected LMDB file missing: .*lock\.mdb/);
  const similar = evalWith({ find: sums(`${H('2')}  ${LMDB}/data.mdb.bak`, `${H('0')}  ${LMDB}/lock.mdb`) });
  assert.equal(similar.ok, false);
  assert.match(problemText(similar), /expected LMDB file missing: .*data\.mdb/);
});

// ---------------------------------------------------------------- identity, chmod, read-back
test('identity mismatch and chmod failure fail closed', () => {
  const idm = evalWith({ identityMatched: false, chmod: null });
  assert.equal(idm.ok, false);
  assert.match(problemText(idm), /identity did not match/);
  assert.match(problemText(idm), /permission tightening failed/);
  const bad = evalWith({ chmod: { status: 1 } });
  assert.equal(bad.ok, false);
  assert.match(problemText(bad), /permission tightening failed/);
});

test('a chmod that exited 0 but left group or other bits is caught by the read-back', () => {
  const group = evalWith({
    stat: { status: 0, stdout: `700 1000 1000 ${RUN}\n750 1000 1000 ${DIR}\n600 1000 1000 ${LMDB}/data.mdb\n600 1000 1000 ${LMDB}/lock.mdb\n` },
  });
  assert.equal(group.ok, false);
  assert.match(problemText(group), /group\/other permission bits remain \(750\) on: .*\/data$/m);
  const other = evalWith({
    stat: { status: 0, stdout: `700 1000 1000 ${RUN}\n700 1000 1000 ${DIR}\n604 1000 1000 ${LMDB}/data.mdb\n600 1000 1000 ${LMDB}/lock.mdb\n` },
  });
  assert.equal(other.ok, false);
  assert.match(problemText(other), /group\/other permission bits remain \(604\) on: .*data\.mdb/);
});

test('an unexpected owner is caught by the read-back', () => {
  const r = evalWith({
    stat: { status: 0, stdout: `700 1000 1000 ${RUN}\n700 1000 1000 ${DIR}\n600 0 0 ${LMDB}/data.mdb\n600 1000 1000 ${LMDB}/lock.mdb\n` },
  });
  assert.equal(r.ok, false);
  assert.match(problemText(r), /unexpected owner 0:0 \(want 1000:1000\) on: .*data\.mdb/);
});

test('a missing, failed, malformed or padded read-back fails closed', () => {
  const none = evalWith({ stat: null });
  assert.equal(none.ok, false);
  assert.match(problemText(none), /permission read-back failed/);
  const failed = evalWith({ stat: { status: 1, stdout: '' } });
  assert.equal(failed.ok, false);
  assert.match(problemText(failed), /permission read-back failed/);
  const short = evalWith({ stat: { status: 0, stdout: `700 1000 1000 ${RUN}\n700 1000 1000 ${DIR}\n600 1000 1000 ${LMDB}/data.mdb\n` } });
  assert.equal(short.ok, false);
  assert.match(problemText(short), /no permission read-back for: .*lock\.mdb/);
  const garbage = evalWith({ stat: { status: 0, stdout: `${okStat().stdout}stat: cannot stat 'x': No such file\n` } });
  assert.equal(garbage.ok, false);
  assert.match(problemText(garbage), /unparsable permission read-back: 1 line\(s\)/);
  const extra = evalWith({ stat: { status: 0, stdout: `${okStat().stdout}600 1000 1000 /etc/shadow\n` } });
  assert.equal(extra.ok, false);
  assert.match(problemText(extra), /unexpected permission read-back entry: \/etc\/shadow/);
  const dup = evalWith({ stat: { status: 0, stdout: `${okStat().stdout}600 1000 1000 ${LMDB}/lock.mdb\n` } });
  assert.equal(dup.ok, false);
  assert.match(problemText(dup), /duplicate permission read-back entry: .*lock\.mdb/);
});

// ---------------------------------------------------------------- evidence requirement
test('--keep-chain without --evidence is not a retained chain', () => {
  const r = evalWith({ evidenceRequested: false });
  assert.equal(r.ok, false);
  assert.equal(r.evidenceRequested, false);
  assert.match(problemText(r), /without --evidence: retained hashes would not be persisted/);
});

test('the runner refuses --keep-chain without --evidence at argument time', async () => {
  const src = await (await import('node:fs/promises')).readFile(new URL('../tools/local_daemon_block.mjs', import.meta.url), 'utf8');
  assert.match(src, /if \(keepChain && evidencePath === null\)/);
  assert.match(src, /EXIT_CODES\.USAGE/);
});

test('an omitted result object fails closed rather than throwing', () => {
  const r = evaluateRetainedChain({});
  assert.equal(r.ok, false);
  assert.equal(r.identityMatched, false);
  assert.ok(r.problems.length >= 4);
});

// ---------------------------------------------------------------- release-decision wiring
test('an unconfirmed retained chain makes the terminal release predicate false', () => {
  const clean = {
    browserExited: true,
    daemonContainerGone: true,
    daemonPidGone: true,
    helperPidGone: true,
    daemonPortsFree: true,
    profileRemoved: true,
    containersMountingRunDir: [],
  };
  // Everything else released, keep-chain requested, retention failing on the exact inventory only.
  const failing = evalWith({ find: sums(`${H('2')}  ${DIR}/junk/data.mdb`, `${H('0')}  ${DIR}/junk/lock.mdb`) });
  assert.equal(failing.ok, false);
  const blocked = evaluateRelease({ cleanup: { ...clean, daemonDataKept: failing }, keepChain: true });
  assert.equal(blocked.released, false);
  assert.deepEqual(blocked.blockers, ['retained chain not confirmed']);
  // An absent record with --keep-chain is a failure, not a pass.
  assert.equal(evaluateRelease({ cleanup: clean, keepChain: true }).released, false);
  // The same record confirmed releases; without --keep-chain retention is not part of the decision.
  const passing = evalWith({});
  assert.equal(evaluateRelease({ cleanup: { ...clean, daemonDataKept: passing }, keepChain: true }).released, true);
  assert.equal(evaluateRelease({ cleanup: clean, keepChain: false }).released, true);
  // The rest of the predicate is unchanged.
  assert.equal(evaluateRelease({ cleanup: { ...clean, daemonPortsFree: false } }).released, false);
  assert.equal(evaluateRelease({ cleanup: { ...clean, containersMountingRunDir: ['c1'] } }).released, false);
  assert.equal(evaluateRelease({ cleanup: { ...clean, containersMountingRunDir: null } }).released, false);
  assert.equal(evaluateRelease({}).released, false);
  assert.equal(retentionSatisfied({ keepChain: true, record: null }), false);
  assert.equal(retentionSatisfied({ keepChain: false, record: null }), true);
});

// ---------------------------------------------------------------------------------------------
// PRODUCTION WIRING. The two defects below were invisible to every test above, because those tests
// hand the evaluator synthetic results and the evaluator was never the broken part. These drive
// collectRetainedChain with an injected runner and assert on the ACTUAL COMMANDS issued.

/** A fake `wsl` that records argv and answers from a table keyed by the command name. */
function fakeRunner(answers = {}) {
  const calls = [];
  const run = (argv) => {
    calls.push(argv);
    const key = argv[0];
    const a = answers[key];
    if (typeof a === 'function') return a(argv);
    return a ?? { status: 0, stdout: '' };
  };
  return { run, calls, names: () => calls.map((a) => a[0]) };
}

const prodFind = (...lines) => ({ status: 0, stdout: `${lines.join('\n')}\n` });
const prodAnswers = (over = {}) => ({
  chmod: { status: 0, stdout: '' },
  find: prodFind(`${H('2')}  ${LMDB}/data.mdb`, `${H('0')}  ${LMDB}/lock.mdb`),
  stat: okStat(),
  ...over,
});
const collect = (answers, over = {}) => {
  const f = fakeRunner(answers);
  const out = collectRetainedChain({
    run: f.run, runDir: RUN, dataRoot: DIR, identityMatched: true, evidenceRequested: true,
    owner: DEFAULT_OWNER, ...over,
  });
  return { ...out, fake: f };
};

test('production: discovery enumerates EVERY regular file, not just *.mdb', () => {
  const { fake } = collect(prodAnswers());
  const find = fake.calls.find((a) => a[0] === 'find');
  assert.ok(find, 'a find command must be issued');
  // The defect was this filter. Its presence hid every non-.mdb file from the inventory check.
  assert.equal(find.includes('-name'), false, `find must not filter by name: ${find.join(' ')}`);
  assert.equal(find.includes('*.mdb'), false);
  assert.deepEqual(find, ['find', DIR, '-type', 'f', '-exec', 'sha256sum', '{}', '+']);
});

/**
 * A `find` that actually OBEYS its argv over a virtual set of files, including `-name`. With this,
 * reintroducing the `-name '*.mdb'` filter makes the stray-file test fail, because the filter really
 * would hide the file -- which is precisely what went wrong in production.
 */
const findingRunner = (files) => fakeRunner({
  chmod: { status: 0, stdout: '' },
  stat: okStat(),
  find: (argv) => {
    const nameIdx = argv.indexOf('-name');
    const pattern = nameIdx === -1 ? null : argv[nameIdx + 1];
    const matches = files.filter(({ path }) => {
      if (pattern === null) return true;
      const suffix = pattern.replace(/^\*/, '');
      return path.endsWith(suffix);
    });
    return { status: 0, stdout: matches.map(({ sha, path }) => `${sha}  ${path}`).join('\n') + '\n' };
  },
});

test('production: an unexpected non-.mdb file under the data root is surfaced and REJECTED', () => {
  // Exactly the Regression testing case: a stray notes.txt beside the chain. The runner below honours -name, so
  // this fails if discovery ever filters again.
  const f = findingRunner([
    { sha: H('2'), path: `${LMDB}/data.mdb` },
    { sha: H('0'), path: `${LMDB}/lock.mdb` },
    { sha: H('e'), path: `${LMDB}/notes.txt` },
  ]);
  const { record } = collectRetainedChain({
    run: f.run, runDir: RUN, dataRoot: DIR, identityMatched: true, evidenceRequested: true,
    owner: DEFAULT_OWNER,
  });
  assert.equal(record.ok, false);
  assert.match(record.problems.join('|'), /unexpected file under the data root: .*notes\.txt/);
});

test('production: the canonical two-file chain still succeeds and records its hashes', () => {
  const { record, fake } = collect(prodAnswers());
  assert.deepEqual(record.problems, []);
  assert.equal(record.ok, true);
  assert.deepEqual(record.sums, [`${H('2')}  ${LMDB}/data.mdb`, `${H('0')}  ${LMDB}/lock.mdb`]);
  // chmod before the read-back, and the read-back really happens.
  assert.deepEqual(fake.names(), ['chmod', 'find', 'stat']);
});

test('production: identity mismatch runs NO chmod, find, sha256sum or stat against that path', () => {
  const f = fakeRunner(prodAnswers());
  const { record, commands } = collectRetainedChain({
    run: f.run, runDir: RUN, dataRoot: DIR, identityMatched: false, evidenceRequested: true,
    owner: DEFAULT_OWNER,
  });
  // The whole point: nothing was aimed at a directory we cannot vouch for.
  assert.deepEqual(f.calls, []);
  assert.deepEqual(commands, []);
  for (const forbidden of ['chmod', 'find', 'stat', 'sha256sum']) {
    assert.equal(f.names().includes(forbidden), false, `${forbidden} must not run on mismatch`);
  }
  // And it still fails closed, which is what drives exit code 3.
  assert.equal(record.ok, false);
  assert.equal(record.identityMatched, false);
  assert.match(record.problems.join('|'), /run-directory identity did not match/);
  assert.equal(evaluateRelease({
    cleanup: {
      browserExited: true, daemonContainerGone: true, daemonPidGone: true, helperPidGone: true,
      daemonPortsFree: true, profileRemoved: true, containersMountingRunDir: [], daemonDataKept: record,
    },
    keepChain: true,
  }).released, false);
});

test('production: a failing chmod or find still fails closed through the collector', () => {
  assert.equal(collect(prodAnswers({ chmod: { status: 1, stdout: '' } })).record.ok, false);
  assert.equal(collect(prodAnswers({ find: { status: 2, stdout: '' } })).record.ok, false);
  assert.equal(collect(prodAnswers({ find: prodFind('') })).record.ok, false);
  assert.equal(collect(prodAnswers({ stat: { status: 1, stdout: '' } })).record.ok, false);
  // --keep-chain without --evidence cannot persist the hashes it just took.
  assert.equal(collect(prodAnswers(), { evidenceRequested: false }).record.ok, false);
});
