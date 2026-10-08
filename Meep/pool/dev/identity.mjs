// Fail-closed identity check for the MeepHash-W Wasm build, and the synthetic fixture.
//
// TWO JOBS, BOTH DELIBERATELY CHEAP:
//
//   1. Hash the two Wasm build outputs and compare them against pool/dev/wasm_identity.json
//      BEFORE anything imports, instantiates or serves them. A SHA-256 of two small files is
//      ordinary file integrity -- it is not MeepHash-W and it is not mining.
//
//   2. Read the synthetic job's target out of the COMMITTED vector file
//      meepow/vectors/vectors_v2.txt instead of computing it. The pool therefore performs ZERO
//      MeepHash-W computations before a client declares start intent.
//
// Why the vector file is the right source: meep_v2_setup() in meepow/wasm/meepow_wasm.cpp builds
// exactly the context those vectors were generated from (32 MiB dataset, nparents = 4, the same
// fixed epoch key, seed hash and 8-byte template), so nonce N of that file IS meep_v2_run1(N).
// pool/dev/tests/identity.test.mjs proves that equality against the real Wasm.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { meetsTargetLE, bytesToHex, hexToBytes } from '../../web-miner/lib/shared/target.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = resolve(__dirname, '../..');
export const IDENTITY_PATH = resolve(__dirname, 'wasm_identity.json');

export const IDENTITY = JSON.parse(readFileSync(IDENTITY_PATH, 'utf8'));

export const WASM_MJS_PATH = resolve(REPO_ROOT, 'meepow/wasm/meepow.mjs');
export const WASM_BINARY_PATH = resolve(REPO_ROOT, 'meepow/wasm/meepow.wasm');

export class WasmIdentityError extends Error {
  constructor(message, detail) {
    super(message);
    this.name = 'WasmIdentityError';
    this.detail = detail;
  }
}

const BUILD_HINT =
  'meepow/wasm/meepow.mjs and meepow/wasm/meepow.wasm are gitignored BUILD OUTPUTS, not committed\n'
  + 'files. Build them with scripts/build-wasm.ps1 (or scripts/build-wasm.sh) and check them with:\n'
  + '  node meepow/wasm/v2_regress.mjs      (frozen v2 native/Wasm equivalence, 20 vectors)';

export function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/**
 * Verify both artifacts exist and match the pinned hashes. Throws WasmIdentityError otherwise.
 *
 * `overrides` lets a test point the check at a deliberately corrupted COPY; it never mutates or
 * even opens the real build outputs for writing.
 */
export function verifyWasmIdentity({ mjsPath = WASM_MJS_PATH, wasmPath = WASM_BINARY_PATH } = {}) {
  const expected = IDENTITY.artifacts;
  const checked = [];
  // `bytes` holds the EXACT Buffer that was hashed. A caller that serves an artifact must send
  // THIS Buffer rather than re-reading the file: hashing one read and shipping another leaves a
  // window in which the file can change between the two, which is the gap this closes.
  const bytes = new Map();
  for (const [relative, path] of [['meepow/wasm/meepow.mjs', mjsPath], ['meepow/wasm/meepow.wasm', wasmPath]]) {
    if (!existsSync(path)) {
      throw new WasmIdentityError(`MeepHash-W Wasm build not found: ${path}\n${BUILD_HINT}`, { path, reason: 'missing' });
    }
    const content = readFileSync(path);
    const actual = createHash('sha256').update(content).digest('hex');
    const want = expected[relative];
    if (actual !== want) {
      throw new WasmIdentityError(
        `MeepHash-W Wasm identity mismatch for ${relative}\n`
        + `  expected ${want}\n  actual   ${actual}\n`
        + `pinned by ${IDENTITY_PATH}\n`
        + 'Refusing to import, instantiate or serve it. This is fail-closed on purpose: do not\n'
        + `edit the manifest to make it pass.\n${BUILD_HINT}`,
        { path, relative, expected: want, actual, reason: 'mismatch' },
      );
    }
    checked.push({ relative, path, sha256: actual });
    bytes.set(relative, content);
  }
  return { algorithm: IDENTITY.algorithm, checked, bytes };
}

/**
 * The verified Buffers, keyed by the URL path the static server exposes them on.
 *
 * These snapshots are what the HTTP response sends. Once taken, mutating the file on disk cannot
 * change the bytes a client receives, because no later read of it ever happens.
 */
export function verifiedArtifactSnapshots(paths) {
  const { bytes } = verifyWasmIdentity(paths);
  return new Map([
    ['/wasm/meepow.mjs', bytes.get('meepow/wasm/meepow.mjs')],
    ['/wasm/meepow.wasm', bytes.get('meepow/wasm/meepow.wasm')],
  ]);
}

/**
 * Load the fixed synthetic job from the committed v2 vectors. NO MeepHash-W computation.
 *
 * CONSTRUCTION, STATED PLAINLY: over the nonce window, the target is set to the EXACT value of
 * the lowest hash in the committed vector table. Exactly one nonce qualifies, and it qualifies by
 * equality -- the documented `hash <= target` boundary in meepow/src/target.hpp. This is a test
 * fixture chosen so a browser finds a share in a second or two. It is NOT a difficulty, it
 * corresponds to no network's work requirement, and it says nothing about how hard real mining
 * would be.
 */
export function loadSyntheticFixture({
  vectorPath = resolve(REPO_ROOT, IDENTITY.syntheticFixture.vectorFile),
  nonceStart = IDENTITY.syntheticFixture.nonceStart,
  nonceRange = IDENTITY.syntheticFixture.nonceRange,
} = {}) {
  const spec = IDENTITY.syntheticFixture;
  if (!existsSync(vectorPath)) {
    throw new WasmIdentityError(`committed v2 vector file not found: ${vectorPath}`, { reason: 'missing_vectors' });
  }
  if (!Number.isInteger(nonceRange) || nonceRange < 2) {
    throw new RangeError('nonceRange must be at least 2 so a non-qualifying nonce also exists');
  }

  const byNonce = new Map();
  for (const line of readFileSync(vectorPath, 'utf8').split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length !== 4 || parts[0] !== 'v2') continue;
    if (Number(parts[1]) !== spec.nparents) continue;
    if (!/^[0-9a-f]{64}$/.test(parts[3])) continue;
    byNonce.set(Number(parts[2]), parts[3]);
  }

  let best = null;
  let worst = null;
  for (let i = 0; i < nonceRange; i++) {
    const nonce = nonceStart + i;
    const hex = byNonce.get(nonce);
    if (hex === undefined) {
      throw new WasmIdentityError(
        `committed vectors do not cover nonce ${nonce} at nparents=${spec.nparents}`,
        { reason: 'window_not_covered', nonce },
      );
    }
    const hash = hexToBytes(hex);
    if (best === null || meetsTargetLE(hash, best.hash)) best = { nonce, hash };
    if (worst === null || meetsTargetLE(worst.hash, hash)) worst = { nonce, hash };
  }
  if (best.nonce === worst.nonce) {
    throw new WasmIdentityError('every vector in the window is identical', { reason: 'degenerate_window' });
  }

  const fixture = {
    targetBytes: best.hash,
    targetHexLE: bytesToHex(best.hash),
    qualifyingNonce: best.nonce,
    qualifyingHashHexLE: bytesToHex(best.hash),
    nonQualifyingNonce: worst.nonce,
    nonQualifyingHashHexLE: bytesToHex(worst.hash),
    nonceStart,
    nonceRange,
    source: vectorPath,
  };

  // The manifest records what the default window must produce, so a swapped or edited vector file
  // is caught here rather than quietly changing the demonstration.
  if (nonceStart === spec.nonceStart && nonceRange === spec.nonceRange) {
    if (fixture.targetHexLE !== spec.expectedTargetHexLE
      || fixture.qualifyingNonce !== spec.expectedQualifyingNonce
      || fixture.nonQualifyingNonce !== spec.expectedNonQualifyingNonce) {
      throw new WasmIdentityError(
        'synthetic fixture does not match the pinned expectation\n'
        + `  expected target ${spec.expectedTargetHexLE} at nonce ${spec.expectedQualifyingNonce}\n`
        + `  actual   target ${fixture.targetHexLE} at nonce ${fixture.qualifyingNonce}`,
        { reason: 'fixture_mismatch' },
      );
    }
  }
  return fixture;
}


/**
 * THE FIXED SYNTHETIC CONTEXT, owned by the server.
 *
 * These are exactly the values meep_v2_setup() hardcodes in meepow/wasm/meepow_wasm.cpp, which is
 * the context the committed vectors in meepow/vectors/vectors_v2.txt were generated from. The
 * native helper is initialised from the SAME values, which is why the two builds can be compared
 * hash-for-hash and against the vectors.
 *
 * Nothing here comes from a client, and no target is ever sent to the native helper: it returns a
 * hash and the server owns the target comparison.
 *
 * This is a synthetic development context. It is not a daemon block template and carries no
 * consensus meaning.
 */
function buildSyntheticContext() {
  const epochKey = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 1) & 0xff);
  const seedHash = Uint8Array.from({ length: 32 }, (_, i) => (i * 3 + 9) & 0xff);
  const template = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);

  // nonce -> committed vector hash, for the startup self-test.
  const vectors = new Map();
  try {
    const spec = IDENTITY.syntheticFixture;
    const path = resolve(REPO_ROOT, spec.vectorFile);
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length !== 4 || parts[0] !== 'v2') continue;
      if (Number(parts[1]) !== spec.nparents) continue;
      if (!/^[0-9a-f]{64}$/.test(parts[3])) continue;
      vectors.set(Number(parts[2]), parts[3]);
    }
  } catch {
    // The fixture loader reports a missing or malformed vector file with a precise error; this map is a
    // best-effort cross-check input and its absence must not break module load.
  }

  return {
    epochKeyHex: bytesToHex(epochKey),
    seedHashHex: bytesToHex(seedHash),
    height: 4096,
    templateHex: bytesToHex(template),
    nparents: 4,
    // A target of all-zero can never be met, so a self-test hash cannot be mistaken for a share.
    zeroTarget: new Uint8Array(32),
    // The nonce both builds must agree on before this pool will mine at all.
    selfTestNonce: IDENTITY.syntheticFixture.expectedQualifyingNonce,
    vectorFor: (nonce) => vectors.get(nonce) ?? null,
  };
}

export const SYNTHETIC_CONTEXT = buildSyntheticContext();
