// Static fail-closed checks for the canonical daemon build's package-source boundary.
// No Docker, network, WSL, daemon, browser, listener, wallet or hash is started here.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const dockerfile = readFileSync(new URL('../../../node/Dockerfile', import.meta.url), 'utf8');
const offlineDockerfile = readFileSync(new URL('../../../node/Dockerfile.offline-variant', import.meta.url), 'utf8');
const dockerignore = readFileSync(new URL('../../../.dockerignore', import.meta.url), 'utf8');
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const lockDir = resolve(repoRoot, 'node/daemon-source');

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

test('the Ubuntu 24 moving Deb822 source is removed before the first apt update', () => {
  const removeAt = dockerfile.indexOf('rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources');
  const updateAt = dockerfile.indexOf('apt-get -o APT::Update::Error-Mode=any update');
  assert.ok(removeAt >= 0, 'both legacy and Deb822 source files must be removed');
  assert.ok(updateAt > removeAt, 'source removal must precede apt update');
  assert.doesNotMatch(dockerfile, /archive\.ubuntu\.com|security\.ubuntu\.com/);
});

test('the CA bootstrap has three exact snapshot URLs and three enforced SHA-256 digests', () => {
  const adds = [...dockerfile.matchAll(/^ADD --checksum=sha256:([0-9a-f]{64}) \\\r?\n\s+https:\/\/snapshot\.ubuntu\.com\/ubuntu\/20250601T000000Z\/([^\s]+) \\\r?\n\s+\/tmp\/ca-bootstrap\/([^\s]+)$/gm)];
  assert.equal(adds.length, 3);
  assert.deepEqual(adds.map((m) => m[3]).sort(), [
    'ca-certificates.deb',
    'libssl3t64.deb',
    'openssl.deb',
  ]);
  assert.equal(new Set(adds.map((m) => m[1])).size, 3, 'each package must have its own digest');
});

test('ordinary apt traffic is TLS-verified, snapshot-only and warning-fatal', () => {
  assert.match(dockerfile, /https:\/\/snapshot\.ubuntu\.com\/ubuntu\/%s noble main universe/);
  assert.match(dockerfile, /https:\/\/snapshot\.ubuntu\.com\/ubuntu\/%s noble-updates main universe/);
  assert.match(dockerfile, /test -z "\$\(find \/etc\/apt\/sources\.list\.d -type f -print -quit\)"/);
  assert.match(dockerfile, /apt-get -o APT::Update::Error-Mode=any update/);
  assert.doesNotMatch(dockerfile, /Acquire::https::Verify-Peer=false|--allow-unauthenticated|trusted=yes/);
});

test('the MeepHash manifest locks Git-canonical bytes, not checkout line endings', () => {
  const manifest = JSON.parse(readFileSync(resolve(lockDir, 'MEEPOW_BUILD_INPUTS.json'), 'utf8'));
  const lines = [];

  for (const entry of manifest.files) {
    // `hash-object --path` runs the path's clean filter, so CRLF in a Windows worktree is
    // canonicalized exactly as `git add` would canonicalize it. Reading that temporary object
    // back checks the bytes that a fresh LF checkout/build context must contain.
    const oid = execFileSync('git', [
      'hash-object', '-w', `--path=${entry.path}`, entry.path,
    ], { cwd: repoRoot, encoding: 'utf8' }).trim();
    const canonical = execFileSync('git', ['cat-file', 'blob', oid], {
      cwd: repoRoot,
      encoding: 'buffer',
      maxBuffer: 2 * 1024 * 1024,
    });
    assert.equal(canonical.byteLength, entry.bytes, `${entry.path} canonical byte count`);
    assert.equal(sha256(canonical), entry.sha256, `${entry.path} canonical SHA-256`);
    lines.push(`${entry.sha256}  ${entry.path}\n`);
  }

  const aggregate = sha256(Buffer.from(lines.sort().join(''), 'utf8'));
  assert.equal(aggregate, manifest.aggregate_identity);
  const headMeepowTree = execFileSync('git', ['rev-parse', 'HEAD:meepow'], {
    cwd: repoRoot,
    encoding: 'utf8',
  }).trim();
  assert.equal(manifest.head_meepow_tree, headMeepowTree);
  const sourceLock = JSON.parse(readFileSync(resolve(lockDir, 'SOURCE_LOCK.json'), 'utf8'));
  assert.equal(sourceLock.meephash_build_inputs.file_count, manifest.file_count);
  assert.equal(sourceLock.meephash_build_inputs.aggregate_identity, aggregate);
});

test('offline builder refreshes every compile input over one immutable local parent', () => {
  assert.match(offlineDockerfile,
    /^ARG BASE_IMAGE=sha256:7eff53d041d9e1cfac1c22badcd92694d2756cb2bb088d66d35ddee1a50f19b2$/m);
  assert.match(offlineDockerfile, /^FROM \$\{BASE_IMAGE\}$/m);
  assert.match(offlineDockerfile, /^COPY node\/daemon-source \/src\/daemon-source$/m);
  assert.match(offlineDockerfile, /^COPY meepow \/src\/meephash\/meepow$/m);
  assert.match(offlineDockerfile, /^COPY node\/docker-build\.sh \/usr\/local\/bin\/meepcoin-build$/m);
  assert.match(offlineDockerfile, /verify_lock\.py meepow \/src\/daemon-source \/src\/meephash/);
  assert.match(offlineDockerfile, /verify_lock\.py contract \/src\/daemon-source/);
  assert.match(dockerignore, /^!node\/Dockerfile\.offline-variant$/m);
  assert.match(dockerignore, /^!node\/daemon-source\/\*\*$/m);
  assert.match(dockerignore, /^!meepow\/src\/v2_api\.cpp$/m);
  assert.doesNotMatch(offlineDockerfile, /^(?:ADD|RUN .*?(?:curl|wget|apt-get|git clone))\b/m);
});
