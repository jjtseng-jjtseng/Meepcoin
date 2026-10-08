// Pure server-side template personalization tests.  No process, daemon, browser, socket or native
// helper is started.  The converter is injected; these checks prove the orchestration boundary, not
// the native converter implementation that will occupy it.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { fullBlockBlobOf, toClientJobMessage } from '../real_template.mjs';
import {
  TemplatePersonalizationError, personalizeRealTemplate,
} from '../template_personalizer.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const row = JSON.parse(readFileSync(
  resolve(here, '../../../meepow/vectors/block_vectors_v16_devnet.json'), 'utf8',
)).vectors[1];

function fixture(patch = {}) {
  const fullBytes = row.full_block_blob.length / 2;
  return {
    height: row.height,
    seedHeight: row.seed_height,
    seedHashHex: row.delayed_seed_input,
    wideDifficulty: `0x${BigInt(row.difficulty).toString(16)}`,
    blockhashingBlobHex: row.block_hashing_blob,
    blocktemplateBlobHex: row.full_block_blob,
    reservedOffset: fullBytes - 8,
    reservedSize: 8,
    ...patch,
  };
}

const issuance = '12'.repeat(16);

test('writes exactly the reserved bytes, converts once, and binds the personalized full block', async () => {
  const template = fixture();
  const before = structuredClone(template);
  const seen = [];
  const extraNonceHex = '0102030405060708';
  const result = await personalizeRealTemplate(template, {
    extraNonceHex,
    convertFullBlock: async (fullHex) => { seen.push(fullHex); return row.block_hashing_blob; },
    now: () => 1234,
    mintIssuanceId: () => issuance,
  });

  assert.deepEqual(template, before, 'the daemon response was mutated');
  assert.equal(seen.length, 1, 'the canonical converter was not called exactly once');
  const start = template.reservedOffset * 2;
  assert.equal(seen[0].slice(start, start + template.reservedSize * 2), extraNonceHex);
  assert.equal(seen[0].slice(0, start), row.full_block_blob.slice(0, start));
  assert.equal(seen[0].slice(start + template.reservedSize * 2),
    row.full_block_blob.slice(start + template.reservedSize * 2));
  assert.equal(Buffer.from(fullBlockBlobOf(result.job)).toString('hex'), seen[0]);
  assert.equal(result.reservedOffset, template.reservedOffset);
  assert.equal(result.reservedSize, 8);
  assert.match(result.extraNonceDigest, /^[0-9a-f]{64}$/);
});

test('the browser projection exposes neither the full block nor reserved-region allocation facts', async () => {
  const result = await personalizeRealTemplate(fixture(), {
    extraNonceHex: '11'.repeat(8),
    convertFullBlock: () => row.block_hashing_blob,
    mintIssuanceId: () => issuance,
  });
  const msg = toClientJobMessage(result.job);
  const encoded = JSON.stringify(msg);
  for (const forbidden of ['reservedOffset', 'reservedSize', 'extraNonce', 'fullBlockBlob', 'blocktemplate']) {
    assert.equal(encoded.includes(forbidden), false, forbidden);
  }
});

test('different pool extra nonces produce different immutable content identities', async () => {
  // The scripted converter returns two distinct, header-compatible hashing blobs by changing one
  // byte after the parsed header.  A real converter derives this from the changed miner transaction.
  const convert = (fullHex) => {
    const marker = fullHex.slice(-2);
    return row.block_hashing_blob.slice(0, -2) + marker;
  };
  const a = await personalizeRealTemplate(fixture(), {
    extraNonceHex: '00'.repeat(7) + '01', convertFullBlock: convert, mintIssuanceId: () => issuance,
  });
  const b = await personalizeRealTemplate(fixture(), {
    extraNonceHex: '00'.repeat(7) + '02', convertFullBlock: convert, mintIssuanceId: () => issuance,
  });
  assert.notEqual(a.job.contentDigest, b.job.contentDigest);
  assert.notEqual(a.job.jobId, b.job.jobId);
  assert.notEqual(a.extraNonceDigest, b.extraNonceDigest);
});

test('malformed reserve contracts and extra nonces fail before conversion', async () => {
  const cases = [
    ['zero reserve', fixture({ reservedSize: 0 }), '00'],
    ['negative offset', fixture({ reservedOffset: -1 }), '00'.repeat(8)],
    ['huge safe offset', fixture({ reservedOffset: Number.MAX_SAFE_INTEGER }), '00'.repeat(8)],
    ['region past end', fixture({ reservedOffset: row.full_block_blob.length / 2 - 7 }), '00'.repeat(8)],
    ['short extra nonce', fixture(), '00'.repeat(7)],
    ['uppercase extra nonce', fixture(), 'AA'.repeat(8)],
  ];
  for (const [name, template, extraNonceHex] of cases) {
    let calls = 0;
    await assert.rejects(
      () => personalizeRealTemplate(template, {
        extraNonceHex, convertFullBlock: () => { calls += 1; return row.block_hashing_blob; },
      }),
      (err) => err instanceof TemplatePersonalizationError && err.code === 'bad_input',
      name,
    );
    assert.equal(calls, 0, `${name}: converter was reached`);
  }
});

test('converter failures and malformed output cannot mint a job', async () => {
  const boom = new Error('native parser stopped');
  await assert.rejects(
    () => personalizeRealTemplate(fixture(), {
      extraNonceHex: '22'.repeat(8), convertFullBlock: async () => { throw boom; },
    }),
    (err) => err.code === 'conversion_failed' && err.cause === boom,
  );
  for (const converted of ['', 'abc', 'AABB', 42, null]) {
    await assert.rejects(
      () => personalizeRealTemplate(fixture(), {
        extraNonceHex: '22'.repeat(8), convertFullBlock: () => converted,
      }),
      (err) => err.code === 'bad_input',
    );
  }
});

test('the options object is closed and the converter dependency is mandatory', async () => {
  await assert.rejects(
    () => personalizeRealTemplate(fixture(), { extraNonceHex: '33'.repeat(8) }),
    (err) => err.code === 'bad_input',
  );
  await assert.rejects(
    () => personalizeRealTemplate(fixture(), {
      extraNonceHex: '33'.repeat(8), convertFullBlock: () => row.block_hashing_blob, clientOffset: 4,
    }),
    (err) => err.code === 'bad_input',
  );
});
