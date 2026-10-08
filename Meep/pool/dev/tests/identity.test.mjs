// Wasm identity pinning and the vector-derived fixture.
//
// The two build outputs are gitignored, so the manifest is how a reviewer knows which build ran.
// A mismatch must be refused BEFORE the module is imported, before the pool listens, and before
// any dataset or hash exists -- so the corrupted copy tests below use disposable COPIES and never
// touch the real artifacts.

import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, rmSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createHash } from 'node:crypto';

import {
  IDENTITY, IDENTITY_PATH, WASM_MJS_PATH, WASM_BINARY_PATH,
  verifyWasmIdentity, verifiedArtifactSnapshots, sha256File, loadSyntheticFixture, WasmIdentityError,
} from '../identity.mjs';
import { createStaticHandler } from '../static.mjs';
import { createServer } from 'node:http';
import { startDevPool } from '../server.mjs';
import { availablePort } from './available_port.mjs';
import { createShareVerifier, deriveSyntheticTargetByHashing } from '../verifier.mjs';

let scratch;
const originalHashes = {};

before(() => {
  scratch = mkdtempSync(join(tmpdir(), 'meep-identity-'));
  originalHashes.mjs = sha256File(WASM_MJS_PATH);
  originalHashes.wasm = sha256File(WASM_BINARY_PATH);
});

after(() => {
  // The real artifacts must be exactly as they were: these tests only ever wrote to copies.
  assert.equal(sha256File(WASM_MJS_PATH), originalHashes.mjs, 'the real .mjs was not modified');
  assert.equal(sha256File(WASM_BINARY_PATH), originalHashes.wasm, 'the real .wasm was not modified');
  if (scratch) rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

// ---------------------------------------------------------------- the manifest

test('the manifest pins both artifacts and names frozen v2', () => {
  assert.equal(IDENTITY.algorithm, 'meephash-w-v2-frozen');
  assert.deepEqual(Object.keys(IDENTITY.artifacts).sort(), ['meepow/wasm/meepow.mjs', 'meepow/wasm/meepow.wasm']);
  for (const hash of Object.values(IDENTITY.artifacts)) assert.match(hash, /^[0-9a-f]{64}$/);
});

test('the local artifacts match the pinned identity', () => {
  const result = verifyWasmIdentity();
  assert.equal(result.algorithm, 'meephash-w-v2-frozen');
  assert.equal(result.checked.length, 2);
  assert.equal(result.checked[0].sha256, IDENTITY.artifacts['meepow/wasm/meepow.mjs']);
  assert.equal(result.checked[1].sha256, IDENTITY.artifacts['meepow/wasm/meepow.wasm']);
  // An INDEPENDENT pin of the current build, so editing wasm_identity.json alone cannot make a
  // mismatch go away -- this literal has to be changed too, deliberately.
  //
  // These deliberately DIFFER from the hashes in docs/BROWSER_V2.md. That document is a historical
  // measurement report and still pins the artifact it actually measured. The artifact was rebuilt
  // when meepow/wasm/meepow_wasm.cpp gained the arbitrary-context entry points; meepow/src/** is
  // byte-identical and all 20 committed v2 known-answer vectors still pass
  // (pool/dev/tests/wasm_context.test.mjs), which is the evidence that only the adapter moved.
  assert.equal(result.checked[0].sha256, '5a61038d0d40aaaf4f33d779dfa9e0b4ee7e68817eabdf8de57465711ef49e31');
  assert.equal(result.checked[1].sha256, 'a039b57ed7d874792eced9044054764c6c3d10c316581efe64721ff52b3988a7');
});

test('the manifest is tracked, so a reviewer can see what was pinned', () => {
  assert.ok(statSync(IDENTITY_PATH).size > 0);
  assert.doesNotThrow(() => JSON.parse(readFileSync(IDENTITY_PATH, 'utf8')));
});

// ---------------------------------------------------------------- mismatch fails closed

/** A disposable copy of both artifacts, with one byte of one file flipped. */
function corruptedCopy(which) {
  const dir = mkdtempSync(join(scratch, 'copy-'));
  const mjs = join(dir, 'meepow.mjs');
  const wasm = join(dir, 'meepow.wasm');
  copyFileSync(WASM_MJS_PATH, mjs);
  copyFileSync(WASM_BINARY_PATH, wasm);
  const victim = which === 'mjs' ? mjs : wasm;
  const bytes = readFileSync(victim);
  bytes[bytes.length - 1] ^= 0x01; // exactly one bit
  writeFileSync(victim, bytes);
  return { mjsPath: mjs, wasmPath: wasm };
}

test('a one-byte change in either artifact is refused', () => {
  for (const which of ['mjs', 'wasm']) {
    const paths = corruptedCopy(which);
    assert.throws(() => verifyWasmIdentity(paths), WasmIdentityError, `${which} must be refused`);
    try {
      verifyWasmIdentity(paths);
    } catch (err) {
      assert.equal(err.detail.reason, 'mismatch');
      assert.match(err.message, /identity mismatch/);
      assert.match(err.message, /Refusing to import, instantiate or serve it/);
      assert.match(err.message, /do not\s*\n?\s*edit the manifest to make it pass/);
    }
  }
});

test('a missing artifact is refused with build instructions', () => {
  const dir = mkdtempSync(join(scratch, 'empty-'));
  assert.throws(
    () => verifyWasmIdentity({ mjsPath: join(dir, 'nope.mjs'), wasmPath: WASM_BINARY_PATH }),
    (err) => err instanceof WasmIdentityError && err.detail.reason === 'missing' && /build-wasm/.test(err.message),
  );
});

test('a mismatched artifact is never imported, instantiated or hashed', async () => {
  const paths = corruptedCopy('wasm');
  // createShareVerifier must fail on identity, before the dynamic import.
  await assert.rejects(() => createShareVerifier(paths), WasmIdentityError);
});

test('startDevPool refuses to listen at all on a mismatched artifact', async () => {
  const paths = corruptedCopy('mjs');
  await assert.rejects(() => startDevPool({ port: 0, wasmPaths: paths }), WasmIdentityError);

  // And nothing was left listening: a fresh pool on that same OS-selected port binds afterwards.
  const port = await availablePort();
  await assert.rejects(() => startDevPool({ port, wasmPaths: paths }), WasmIdentityError);
  const ok = await startDevPool({ port });
  try {
    assert.equal(ok.port, port);
    assert.equal(ok.verifier, null, 'and still no verifier, because nobody pressed Start');
  } finally {
    await ok.close();
  }
});

// ---------------------------------------------------------------- the fixture

test('the fixture is read from the committed vectors, not computed', () => {
  const fixture = loadSyntheticFixture();
  assert.match(fixture.source.replace(/\\/g, '/'), /meepow\/vectors\/vectors_v2\.txt$/);
  assert.equal(fixture.targetHexLE, IDENTITY.syntheticFixture.expectedTargetHexLE);
  assert.equal(fixture.qualifyingNonce, IDENTITY.syntheticFixture.expectedQualifyingNonce);
  assert.equal(fixture.nonQualifyingNonce, IDENTITY.syntheticFixture.expectedNonQualifyingNonce);
  assert.equal(fixture.nonceRange, 16);
});

test('the fixture the pool uses is EXACTLY what the Wasm computes', async () => {
  // The cross-check that lets the production path skip hashing entirely: derive the same fixture
  // the expensive way and require byte equality.
  const verifier = await createShareVerifier();
  try {
    const byHashing = deriveSyntheticTargetByHashing(verifier, { nonceStart: 0, nonceRange: 16 });
    const fromVectors = loadSyntheticFixture({ nonceStart: 0, nonceRange: 16 });
    assert.equal(fromVectors.targetHexLE, byHashing.targetHexLE);
    assert.equal(fromVectors.qualifyingNonce, byHashing.qualifyingNonce);
    assert.equal(fromVectors.nonQualifyingNonce, byHashing.nonQualifyingNonce);
    assert.equal(fromVectors.qualifyingHashHexLE, byHashing.qualifyingHashHexLE);
    assert.equal(verifier.hashCalls, 16, 'the expensive derivation costs 16 hashes; the production path costs 0');
  } finally {
    await verifier.close();
  }
}, { timeout: 60_000 });

test('a vector file that does not cover the window is refused', () => {
  assert.throws(
    () => loadSyntheticFixture({ nonceStart: 0, nonceRange: 64 }),
    (err) => err instanceof WasmIdentityError && err.detail.reason === 'window_not_covered',
  );
});

test('a missing vector file is refused', () => {
  assert.throws(
    () => loadSyntheticFixture({ vectorPath: join(scratch, 'no-such-vectors.txt') }),
    (err) => err instanceof WasmIdentityError && err.detail.reason === 'missing_vectors',
  );
});

test('a tampered vector file is caught by the pinned expectation', () => {
  const fake = join(scratch, 'tampered_vectors.txt');
  const lines = readFileSync(IDENTITY.syntheticFixture.vectorFile.replace(/^/, `${process.cwd()}/`).replace(/\\/g, '/'), 'utf8')
    .trim().split('\n');
  // Replace the winning vector with an all-zero hash: still well-formed, but not what was pinned.
  const doctored = lines.map((l) => {
    const p = l.split(' ');
    return Number(p[2]) === IDENTITY.syntheticFixture.expectedQualifyingNonce ? `${p[0]} ${p[1]} ${p[2]} ${'0'.repeat(64)}` : l;
  }).join('\n');
  writeFileSync(fake, doctored);
  assert.throws(
    () => loadSyntheticFixture({ vectorPath: fake }),
    (err) => err instanceof WasmIdentityError && err.detail.reason === 'fixture_mismatch',
  );
});

test('a degenerate window is refused rather than producing a meaningless target', () => {
  const fake = join(scratch, 'degenerate_vectors.txt');
  writeFileSync(fake, ['v2 4 0 ' + 'ab'.repeat(32), 'v2 4 1 ' + 'ab'.repeat(32)].join('\n'));
  assert.throws(
    () => loadSyntheticFixture({ vectorPath: fake, nonceStart: 0, nonceRange: 2 }),
    (err) => err instanceof WasmIdentityError && err.detail.reason === 'degenerate_window',
  );
});


// ---------------------------------------------------------------- bytes actually served

const sha = (b) => createHash('sha256').update(b).digest('hex');

/** A throwaway HTTP server using the production static handler. */
async function serveWith(artifacts) {
  const handler = createStaticHandler({ wsOrigin: 'ws://127.0.0.1:1', artifacts });
  const server = createServer((req, res) => { handler(req, res).catch(() => res.destroy()); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((r) => server.close(r)),
  };
}

test('the bytes served on the real Wasm routes hash to the manifest values', async () => {
  const snapshots = verifiedArtifactSnapshots();
  const s = await serveWith(snapshots);
  try {
    for (const [route, relative] of [
      ['/wasm/meepow.mjs', 'meepow/wasm/meepow.mjs'],
      ['/wasm/meepow.wasm', 'meepow/wasm/meepow.wasm'],
    ]) {
      const res = await fetch(s.url + route);
      assert.equal(res.status, 200);
      const body = Buffer.from(await res.arrayBuffer());
      assert.equal(sha(body), IDENTITY.artifacts[relative], `${route} response bytes must match the manifest`);
      assert.equal(Number(res.headers.get('content-length')), body.length, 'Content-Length matches the verified body');
    }
    // HEAD keeps the verified length and sends no body.
    const head = await fetch(s.url + '/wasm/meepow.wasm', { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(Number(head.headers.get('content-length')),
      verifiedArtifactSnapshots().get('/wasm/meepow.wasm').length, 'HEAD reports the verified length');
    assert.equal((await head.arrayBuffer()).byteLength, 0, 'HEAD sends no body');
  } finally {
    await s.close();
  }
});

test('mutating an artifact AFTER the check cannot change the bytes a client receives', async () => {
  // Disposable copies only: the real build outputs are never written to.
  const dir = mkdtempSync(join(scratch, 'served-'));
  const mjs = join(dir, 'meepow.mjs');
  const wasm = join(dir, 'meepow.wasm');
  copyFileSync(WASM_MJS_PATH, mjs);
  copyFileSync(WASM_BINARY_PATH, wasm);

  // 1. verify and snapshot while the copies are still correct
  const snapshots = verifiedArtifactSnapshots({ mjsPath: mjs, wasmPath: wasm });
  assert.equal(sha(snapshots.get('/wasm/meepow.wasm')), IDENTITY.artifacts['meepow/wasm/meepow.wasm']);

  // 2. mutate the file on disk afterwards
  const tampered = readFileSync(wasm);
  tampered[tampered.length - 1] ^= 0x01;
  writeFileSync(wasm, tampered);
  assert.notEqual(sha(readFileSync(wasm)), IDENTITY.artifacts['meepow/wasm/meepow.wasm'], 'the file really did change');

  // 3. the response must still be the verified bytes -- no later read of the file happens
  const s = await serveWith(snapshots);
  try {
    const body = Buffer.from(await (await fetch(s.url + '/wasm/meepow.wasm')).arrayBuffer());
    assert.equal(sha(body), IDENTITY.artifacts['meepow/wasm/meepow.wasm'],
      'post-check mutation must not reach the client');
    assert.notEqual(sha(body), sha(tampered), 'the mutated bytes were not sent');
  } finally {
    await s.close();
  }
});

test('a Wasm route with no verified snapshot is refused, without artifact bytes', async () => {
  const s = await serveWith(null);
  try {
    for (const route of ['/wasm/meepow.mjs', '/wasm/meepow.wasm']) {
      const res = await fetch(s.url + route);
      assert.equal(res.status, 503, `${route} must fail closed`);
      const text = await res.text();
      assert.match(text, /identity-verified/);
      assert.ok(text.length < 200, 'the failure body carries no artifact bytes');
    }
    // Ordinary page routes are unaffected.
    assert.equal((await fetch(s.url + '/')).status, 200);
  } finally {
    await s.close();
  }
});

test('verifyWasmIdentity hashes and returns the SAME buffer, so no second read can differ', () => {
  const { checked, bytes } = verifyWasmIdentity();
  for (const entry of checked) {
    assert.equal(sha(bytes.get(entry.relative)), entry.sha256,
      'the returned buffer is exactly the one that was hashed');
  }
});

test('startDevPool takes ONE read of each artifact, not a second snapshot set', async () => {
  // Hooking fs is not usable here: identity.mjs binds `readFileSync` as an ESM named import at
  // load time, so a later monkey-patch is invisible to it. The clean equivalents are structural
  // plus behavioural, and together they pin the property that matters.
  //
  // Structural: the server must build its HTTP snapshots from the buffers verifyWasmIdentity()
  // already returned, and must NOT call the convenience helper that verifies-and-reads again.
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../server.mjs', import.meta.url), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
  assert.doesNotMatch(src, /verifiedArtifactSnapshots/,
    'startDevPool must not take a second, separately-read artifact set');
  assert.match(src, /identity\.bytes\.get\(/,
    'it must serve the very buffers verifyWasmIdentity() hashed');

  // Behavioural: what the running server actually sends still hashes to the manifest.
  const pool = await startDevPool({ port: 0 });
  try {
    for (const [route, relative] of [
      ['/wasm/meepow.mjs', 'meepow/wasm/meepow.mjs'],
      ['/wasm/meepow.wasm', 'meepow/wasm/meepow.wasm'],
    ]) {
      const body = Buffer.from(await (await fetch(pool.url + route)).arrayBuffer());
      assert.equal(sha(body), IDENTITY.artifacts[relative], `${route} serves verified bytes`);
    }
    // And the identity record the pool exposes carries those same buffers.
    assert.equal(sha(pool.identity.bytes.get('meepow/wasm/meepow.wasm')),
      IDENTITY.artifacts['meepow/wasm/meepow.wasm']);
  } finally {
    await pool.close();
  }
});
