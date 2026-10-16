// Fail-closed evaluation of a chain retained by `--keep-chain`.
//
// Retention is only safe to call a success if the directory we tightened and hashed is provably the
// same directory the daemon used, the tightening actually happened AND was read back, the
// discovery/hash command actually ran, and what it found is EXACTLY the chain we expect -- no more,
// no less, at the exact paths the fixed testnet local-daemon runner writes.
//
// History of this file, so the weakening is not repeated:
//   1. the first version recorded whatever the command printed -- including nothing -- and still let
//      the tool exit 0;
//   2. the second version (2a64554) required data.mdb and lock.mdb but compared only BASENAMES, so
//      `data/junk/data.mdb`, a file outside the retained data root, a duplicated data.mdb, or the
//      real pair plus an unexpected extra `.mdb` all still evaluated ok:true;
//   3. this version requires the exact inventory
//        <data root>/testnet/lmdb/data.mdb
//        <data root>/testnet/lmdb/lock.mdb
//      and nothing else, each exactly once, spelled normally, inside the supplied root, with a
//      well-formed hash, and with the permissions and ownership READ BACK after chmod.
//
//   4. the third version was still wrong in the PRODUCTION WIRING, which this file's pure evaluator
//      could not see, so the tests all passed anyway:
//        (a) collection ran `find <root> -type f -name '*.mdb'`, so a non-.mdb regular file such as
//            `<root>/testnet/lmdb/notes.txt` was INVISIBLE to the evaluator and the "exact
//            inventory, nothing else" guarantee was false wherever it actually mattered;
//        (b) on run-directory identity MISMATCH the runner skipped only the chmod, and still ran
//            sha256sum, find/hash and stat AGAINST THE MISMATCHED PATH -- reading and hashing a
//            directory that is by then provably not the one the daemon used.
//      collectRetainedChain below is the fix, and it is the seam the tests drive.
//
// evaluateRetainedChain is pure: it takes already-collected command results and decides. It runs no
// command, touches no daemon, no wallet, no chain and no network. collectRetainedChain issues
// commands ONLY through an injected runner, so the production sequence itself is testable.

/** The fixed network of the local-daemon runner. Any other subdirectory is an unexpected file. */
export const RETAINED_NETWORK = 'testnet';
/** Where that runner's LMDB lives, relative to the retained data root. */
export const LMDB_SUBDIR = `${RETAINED_NETWORK}/lmdb`;
/** The database files a retained MeepCoin LMDB chain must contain -- all of them, and only them. */
export const EXPECTED_LMDB_FILES = Object.freeze(['data.mdb', 'lock.mdb']);
/** The run directory and its contents are created by the container as this uid:gid. */
export const DEFAULT_OWNER = Object.freeze({ uid: 1000, gid: 1000 });

/** The exact absolute paths the retained chain must consist of. */
export function expectedLmdbPaths(dataRoot) {
  return EXPECTED_LMDB_FILES.map((name) => `${dataRoot}/${LMDB_SUBDIR}/${name}`);
}

/**
 * Why a path may not be used as-is. A retained path has to be absolute, normalized and unambiguous:
 * `a//b`, `a/./b`, `a/../b` and `a/b/` all denote things we did not verify the spelling of, so they
 * are rejected rather than normalized on the tool's behalf.
 * @returns {string|null} the problem, or null when the spelling is exact
 */
export function pathSpellingProblem(p) {
  if (typeof p !== 'string' || p === '') return 'empty path';
  if (p.includes('\0')) return 'NUL byte in path';
  if (p.includes('\\')) return 'backslash in path';
  if (!p.startsWith('/')) return 'not an absolute path';
  if (p.length > 1 && p.endsWith('/')) return 'trailing slash';
  for (const seg of p.slice(1).split('/')) {
    if (seg === '') return 'empty path segment';
    if (seg === '.' || seg === '..') return 'dot or dot-dot segment';
  }
  return null;
}

/**
 * Parse `sha256sum` output into entries. Lines are `<64 lowercase hex><2 spaces|space+*><path>`;
 * anything else -- a short hash, an uppercase hash, a `find:` error, a truncated line -- is rejected
 * rather than silently dropped, because an unparsable line means we do not know what we retained.
 */
function parseSums(stdout) {
  const entries = [];
  const bad = [];
  for (const raw of String(stdout ?? '').split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (line === '') continue;
    const m = /^([0-9a-f]{64})(?: {2}| \*)(\S.*)$/.exec(line);
    if (m === null) { bad.push(line.slice(0, 120)); continue; }
    entries.push({ sha256: m[1], path: m[2] });
  }
  return { entries, bad };
}

/**
 * Parse `stat -c '%a %u %g %n'` output. Mode is octal (3 or 4 digits), uid/gid decimal.
 */
function parseStat(stdout) {
  const rows = [];
  const bad = [];
  for (const raw of String(stdout ?? '').split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (line === '') continue;
    const m = /^([0-7]{3,4}) (\d{1,10}) (\d{1,10}) (\S.*)$/.exec(line);
    if (m === null) { bad.push(line.slice(0, 120)); continue; }
    rows.push({ mode: parseInt(m[1], 8), modeText: m[1], uid: Number(m[2]), gid: Number(m[3]), path: m[4] });
  }
  return { rows, bad };
}

/**
 * Confirm the exact retained inventory.
 * @returns {{problems:string[], files:object[]}}
 */
function checkInventory({ dataRoot, expected, entries }) {
  const problems = [];
  const expectedSet = new Set(expected);
  const counts = new Map();
  const kept = [];
  for (const e of entries) {
    const spelling = pathSpellingProblem(e.path);
    if (spelling !== null) { problems.push(`non-normalized or ambiguous retained path (${spelling}): ${e.path}`); continue; }
    if (!e.path.startsWith(`${dataRoot}/`)) { problems.push(`retained path outside the data root: ${e.path}`); continue; }
    if (!expectedSet.has(e.path)) {
      problems.push(`unexpected ${e.path.endsWith('.mdb') ? 'extra .mdb file' : 'file'} under the data root: ${e.path}`);
      continue;
    }
    counts.set(e.path, (counts.get(e.path) ?? 0) + 1);
    if (counts.get(e.path) === 1) kept.push(e);
  }
  for (const [p, n] of counts) if (n > 1) problems.push(`duplicate retained entry (${n}x): ${p}`);
  for (const want of expected) if (!counts.has(want)) problems.push(`expected LMDB file missing: ${want}`);
  return { problems, files: kept };
}

/**
 * Confirm the permissions and ownership we asked for are actually on disk now, read back after the
 * chmod, rather than trusting the chmod's exit status. Every target must be reported exactly once,
 * carry no group or other permission bit at all, and be owned by the expected uid:gid.
 */
function checkPermissions({ targets, stat, owner }) {
  const problems = [];
  const observed = [];
  if (stat === null || stat === undefined || stat.status !== 0) {
    problems.push('permission read-back failed');
    return { problems, observed };
  }
  const { rows, bad } = parseStat(stat.stdout);
  if (bad.length > 0) problems.push(`unparsable permission read-back: ${bad.length} line(s)`);
  const byPath = new Map();
  for (const r of rows) {
    if (!targets.includes(r.path)) { problems.push(`unexpected permission read-back entry: ${r.path}`); continue; }
    if (byPath.has(r.path)) { problems.push(`duplicate permission read-back entry: ${r.path}`); continue; }
    byPath.set(r.path, r);
  }
  for (const t of targets) {
    const r = byPath.get(t);
    if (r === undefined) { problems.push(`no permission read-back for: ${t}`); continue; }
    if ((r.mode & 0o077) !== 0) problems.push(`group/other permission bits remain (${r.modeText}) on: ${t}`);
    if (r.uid !== owner.uid || r.gid !== owner.gid) {
      problems.push(`unexpected owner ${r.uid}:${r.gid} (want ${owner.uid}:${owner.gid}) on: ${t}`);
    }
    observed.push({ path: t, mode: r.modeText, uid: r.uid, gid: r.gid });
  }
  return { problems, observed };
}

/**
 * @param {object} o
 * @param {string} o.path                  the data root we asked to retain (e.g. `<runDir>/data`)
 * @param {string|null} [o.runDir]         the retained run directory itself, also permission-checked
 * @param {boolean} o.identityMatched      dev:inode:uid of the run dir still equals the daemon's
 * @param {boolean} o.evidenceRequested    --keep-chain without --evidence cannot persist the hashes
 * @param {{status:number}|null} [o.chmod] result of the permission-tightening command
 * @param {{status:number,stdout:string}|null} [o.find] result of the discovery/hash command
 * @param {{status:number,stdout:string}|null} [o.stat] read-back of mode/uid/gid after the chmod
 * @param {{uid:number,gid:number}} [o.owner]           the uid:gid the retained tree must have
 */
export function evaluateRetainedChain({
  path: dataRoot,
  runDir = null,
  identityMatched,
  evidenceRequested = true,
  chmod = null,
  find = null,
  stat = null,
  owner = DEFAULT_OWNER,
} = {}) {
  const problems = [];

  const rootProblem = pathSpellingProblem(dataRoot);
  if (rootProblem !== null) problems.push(`retained data root is unusable (${rootProblem})`);
  const runDirProblem = runDir === null ? null : pathSpellingProblem(runDir);
  if (runDirProblem !== null) problems.push(`retained run directory is unusable (${runDirProblem})`);

  if (identityMatched !== true) problems.push('run-directory identity did not match');
  if (evidenceRequested !== true) problems.push('--keep-chain without --evidence: retained hashes would not be persisted');
  if (chmod === null || chmod.status !== 0) problems.push('permission tightening failed');
  if (find === null || find.status !== 0) problems.push('chain file discovery/hash failed');

  const expected = rootProblem === null ? expectedLmdbPaths(dataRoot) : [];
  const { entries, bad } = parseSums(find?.status === 0 ? find.stdout : '');
  if (bad.length > 0) problems.push(`unparsable hash output: ${bad.length} line(s)`);
  if (find?.status === 0 && entries.length === 0) problems.push('no retained chain files were hashed');

  let files = [];
  if (rootProblem === null) {
    const inv = checkInventory({ dataRoot, expected, entries });
    problems.push(...inv.problems);
    files = inv.files;
  }

  const permissionTargets = rootProblem === null
    ? [...(runDir !== null && runDirProblem === null ? [runDir] : []), dataRoot, ...expected]
    : [];
  const perm = rootProblem === null
    ? checkPermissions({ targets: permissionTargets, stat, owner })
    : { problems: ['permissions not checked: unusable data root'], observed: [] };
  problems.push(...perm.problems);

  return {
    path: dataRoot ?? null,
    runDir,
    identityMatched: identityMatched === true,
    evidenceRequested: evidenceRequested === true,
    sums: files.map((e) => `${e.sha256}  ${e.path}`),
    files,
    expected,
    permissions: perm.observed,
    expectedOwner: { uid: owner?.uid ?? null, gid: owner?.gid ?? null },
    problems,
    ok: problems.length === 0,
  };
}

/**
 * Collect and evaluate the retained chain, in the exact order production must use.
 *
 * IDENTITY MISMATCH SHORT-CIRCUITS. If the run directory is not provably the same directory the
 * daemon used, this runs NOTHING against that path -- no chmod, no find, no sha256sum, no stat --
 * and returns a failing record. Inspecting a replaced directory is exactly what we must not do.
 *
 * Discovery enumerates EVERY REGULAR FILE under the data root, not just `*.mdb`, because the claim
 * being made is "these two files and nothing else".
 *
 * @param {object} o
 * @param {(argv:string[]) => {status:number,stdout:string}} o.run  injected command runner
 * @returns {{record:object, commands:string[][]}}
 */
export function collectRetainedChain({
  run,
  runDir,
  dataRoot,
  identityMatched,
  evidenceRequested = true,
  owner = DEFAULT_OWNER,
}) {
  const commands = [];
  const exec = (argv) => { commands.push(argv); return run(argv); };

  const base = { path: dataRoot, runDir, identityMatched, evidenceRequested, owner };

  // Fail closed WITHOUT touching the path. evaluateRetainedChain turns the null results into
  // problems, so the record is failing and no command was aimed at a directory we do not trust.
  if (identityMatched !== true) {
    return { record: evaluateRetainedChain({ ...base, chmod: null, find: null, stat: null }), commands };
  }

  const chmod = exec(['chmod', '-R', 'go-rwx', '--', runDir]);
  // Every regular file under the data root. NOT filtered to *.mdb: an unexpected non-.mdb file is a
  // finding, and a filter that hides it makes the inventory check a lie.
  const find = exec(['find', dataRoot, '-type', 'f', '-exec', 'sha256sum', '{}', '+']);
  const stat = exec(['stat', '-c', '%a %u %g %n', '--', runDir, dataRoot, ...expectedLmdbPaths(dataRoot)]);

  return { record: evaluateRetainedChain({ ...base, chmod, find, stat }), commands };
}

/**
 * The retention gate of the terminal release predicate. Without --keep-chain retention is not part
 * of the decision; with it, an absent or unconfirmed record is a FAILURE, never a pass.
 */
export function retentionSatisfied({ keepChain, record }) {
  if (keepChain !== true) return true;
  return record !== null && typeof record === 'object' && record.ok === true;
}
