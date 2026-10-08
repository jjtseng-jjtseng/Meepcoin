// The native helper's build-source identity, computed from the working tree.
//
// The helper reports a MEEPOW_HELPER_SOURCE_ID compiled into it by
// scripts/build-native-helper.sh. This module recomputes the same value here, so the pool can
// refuse a helper that was built from different bytes than the ones on disk right now.
//
// WHAT THIS ESTABLISHES. That the native side of the cross-check was compiled from the source
// tree the pool is looking at. It catches the ordinary and dangerous case: the algorithm or the
// helper was edited and the binary was not rebuilt, so "native" is a stale build.
//
// WHAT IT DOES NOT ESTABLISH. Nothing about which compiler, flags, standard library or machine
// produced the executable, and nothing about the executable's own bytes. Two different toolchains
// over the same sources produce the same source id -- which is exactly what a build/runtime
// cross-check wants, and exactly why this must never be described as an attestation of the binary. The
// BUILD RECIPE (meepow/CMakeLists.txt, scripts/build-native-helper.sh) is deliberately outside the
// id as well: see the header of scripts/helper-source-inventory.txt.
//
// THE INVENTORY IS A CONSERVATIVE COVERED SET, not "the exact compile inputs". It may name more
// than the compiler reads; pool/dev/tests/source_identity.test.mjs proves it never names less, by
// walking the real include closure from the real helper target.
//
// BASH AND NODE MUST AGREE. scripts/build-native-helper.sh computes this same value with sha256sum
// and sort. Anything that could make the two readers canonicalise a path differently -- a
// duplicate, an absolute path, '..', a backslash, a leading './', a trailing space, a directory,
// or two entries differing only by case on a case-insensitive filesystem -- is REFUSED here rather
// than resolved, because "refused" is the only outcome both readers agree on.
//
// THE FINAL-NEWLINE RULE, chosen and enforced identically on both sides: THE INVENTORY MUST END
// WITH LF. Bash's `while IFS= read -r line` DROPS a final line with no terminator, while
// JavaScript's `split('\n')` KEEPS it -- so an inventory whose last line lacked LF made the two
// "identical" readers disagree about how many files there even were (Bash 1, Node 2 on a two-entry
// file). Rejecting is the rule rather than "both accept it" because rejection is trivially
// identical in both languages and fails closed: an unterminated manifest is an editing accident,
// and the fix is one keystroke.
//
// The algorithm is deliberately trivial to reproduce by hand:
//
//   for each inventory path, in the file's listed order:  sha256(file bytes)
//   sort the "<sha256>  <path>\n" lines by path, byte-wise
//   sourceId = sha256(the concatenated sorted listing)

import { createHash } from 'node:crypto';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';

import { REPO_ROOT } from './native_helper.mjs';

export const INVENTORY_PATH = resolve(REPO_ROOT, 'scripts/helper-source-inventory.txt');

export class SourceIdentityError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SourceIdentityError';
  }
}

/**
 * A repository-relative path the Bash and Node readers are guaranteed to canonicalise identically.
 *
 * Forward slashes, no leading slash, no drive letter, no '.' or '..' segment, no empty segment, no
 * backslash, no trailing dot or space, and printable ASCII only.
 */
// A segment is printable ASCII EXCLUDING '/' -- 0x21..0x2e and 0x30..0x7e. Leaving '/' inside the
// class would have let the whole of "/etc/passwd" match as a single segment, which is exactly the
// absolute path this is supposed to refuse.
const CANONICAL_REL_PATH = /^[\x21-\x2e\x30-\x7e]+(?:\/[\x21-\x2e\x30-\x7e]+)*$/; // eslint-disable-line no-control-regex

function rejectNonCanonicalPath(rel, lineNo) {
  const where = `helper source inventory line ${lineNo}`;
  if (!CANONICAL_REL_PATH.test(rel)) {
    throw new SourceIdentityError(`${where}: not a canonical repository-relative path: ${JSON.stringify(rel)}`);
  }
  if (rel.includes('\\')) throw new SourceIdentityError(`${where}: backslashes are not portable: ${rel}`);
  if (/^[A-Za-z]:/.test(rel)) throw new SourceIdentityError(`${where}: absolute (drive-qualified) path: ${rel}`);
  for (const seg of rel.split('/')) {
    if (seg === '.' || seg === '..') {
      throw new SourceIdentityError(`${where}: '${seg}' traversal is not allowed: ${rel}`);
    }
  }
}

/**
 * The inventory, in file order. Comments and blank lines removed, every entry canonical, no
 * duplicates and no two entries that collide when compared case-insensitively.
 *
 * A case collision matters even though the listing is hashed case-sensitively: on a
 * case-insensitive filesystem two such entries name ONE file, so the listing would contain two
 * different spellings of the same bytes and the id would depend on which spellings were written.
 */
export function readInventory(inventoryPath = INVENTORY_PATH) {
  if (!existsSync(inventoryPath)) {
    throw new SourceIdentityError(`helper source inventory is missing: ${inventoryPath}`);
  }
  const text = readFileSync(inventoryPath, 'utf8');
  // See THE FINAL-NEWLINE RULE above. scripts/build-native-helper.sh applies exactly this check.
  if (text.length > 0 && !text.endsWith('\n')) {
    throw new SourceIdentityError(
      'helper source inventory does not end with a newline. Bash drops a final unterminated line '
      + 'and Node keeps it, so the build script and this verifier would compute different '
      + `identities from the same file. Add a trailing newline to ${inventoryPath}`,
    );
  }
  // The build script strips a trailing CR the same way, so a CRLF checkout hashes identically.
  const lines = text.split('\n');
  const paths = [];
  const seen = new Set();
  const seenLower = new Map();
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].replace(/\r$/, '');
    // EXACTLY the build script's rule: `case "${line}" in ''|'#'*) continue ;; esac`. An indented
    // '#' is NOT a comment to either reader -- Bash would treat it as a path and fail to find it,
    // so this treats it as a path and refuses it too. Selection must not diverge before
    // canonicalisation, or the two readers disagree about what the listing even contains.
    if (raw.length === 0 || raw.startsWith('#')) continue;
    // NOT trimmed: a leading or trailing space is a difference between the two readers, not
    // whitespace to be tidied away.
    const rel = raw;
    rejectNonCanonicalPath(rel, i + 1);
    if (seen.has(rel)) {
      throw new SourceIdentityError(`helper source inventory lists ${rel} more than once`);
    }
    const lower = rel.toLowerCase();
    if (seenLower.has(lower) && seenLower.get(lower) !== rel) {
      throw new SourceIdentityError(
        `helper source inventory lists ${seenLower.get(lower)} and ${rel}, which differ only by case`,
      );
    }
    seen.add(rel);
    seenLower.set(lower, rel);
    paths.push(rel);
  }
  if (paths.length === 0) throw new SourceIdentityError('helper source inventory lists no files');
  return paths;
}

/**
 * Compute the source identity from the working tree.
 *
 * A listed file that does not exist is an ERROR, never a skipped entry: silently hashing a shorter
 * inventory would produce a stable-looking id that means something different.
 */
export function computeSourceId({ inventoryPath = INVENTORY_PATH, repoRoot = REPO_ROOT } = {}) {
  const paths = readInventory(inventoryPath);
  const lines = [];
  for (const rel of paths) {
    const abs = resolve(repoRoot, rel);
    if (!existsSync(abs)) {
      throw new SourceIdentityError(`helper source inventory lists a file that does not exist: ${rel}`);
    }
    // A directory would make `sha256sum` fail in the build script and readFileSync throw here.
    // Refuse it with the same message on both sides rather than at two different layers.
    if (!statSync(abs).isFile()) {
      throw new SourceIdentityError(`helper source inventory lists something that is not a regular file: ${rel}`);
    }
    lines.push(`${createHash('sha256').update(readFileSync(abs)).digest('hex')}  ${rel}\n`);
  }
  lines.sort();
  return {
    sourceId: createHash('sha256').update(lines.join(''), 'utf8').digest('hex'),
    fileCount: paths.length,
    listing: lines,
  };
}

/**
 * Compare what the helper reported against what the tree says.
 *
 * `-` and `unknown` are the helper's explicit "I was built without an identity" values. They are
 * refused rather than accepted, because a helper that cannot say what it was built from is exactly
 * the one whose agreement means the least.
 */
export function checkReportedSourceId(reported, options = {}) {
  const { sourceId, fileCount } = computeSourceId(options);
  if (typeof reported !== 'string' || reported === '-' || reported === 'unknown') {
    throw new SourceIdentityError(
      'the native helper reports no build-source identity. It was built without '
      + 'MEEPOW_HELPER_SOURCE_ID, which means nothing here can tell which sources it computes. '
      + 'Rebuild it with: npm run build:native-helper',
    );
  }
  if (reported !== sourceId) {
    throw new SourceIdentityError(
      `the native helper was built from different sources than this working tree.\n`
      + `  helper reports : ${reported}\n`
      + `  working tree   : ${sourceId} (${fileCount} files in scripts/helper-source-inventory.txt)\n`
      + 'This is a STALE BINARY, not a hash disagreement: rebuild with npm run build:native-helper.',
    );
  }
  return { sourceId, fileCount };
}
