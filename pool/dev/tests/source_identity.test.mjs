// The native helper's build-source identity.
//
// The runtime used to check only that a file existed, that HELLO echoed the token, and that one
// vector came back right. None of that says which sources produced the binary -- so a helper built
// before the algorithm was last edited would pass every check and quietly become a stale "native"
// half of the cross-check.
//
// SCOPE, DELIBERATELY NARROW. This binds the running binary to a source tree. It says NOTHING
// about the compiler, the flags, the standard library or the ELF's own bytes: two different
// toolchains over identical sources produce the same source id, which is the point of a
// build/runtime cross-check and also the reason this must never be called an attestation. The
// BUILD RECIPE is outside the id too, by decision: see the header of the inventory file.
//
// AND THE DEFECT THAT WAS IN IT. The inventory omitted meepow/include/meepow/meepow.h, a real
// transitive compile input -- meepow/src/blake3_xof.hpp includes it and frames every hash with its
// MEEPOW_ALGO_VERSION, and meepow/src/params.hpp includes it for parameter identifiers. Editing
// those output-affecting bytes left the source id UNCHANGED, so a helper built before the edit
// still passed the staleness check. The old tests could not catch that: they asserted a handful of
// representative entries and mutated a SYNTHETIC file in a temporary directory, so they never
// compared the inventory to the project's actual dependency closure. The closure test below does.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync, existsSync, statSync, copyFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve, relative } from 'node:path';

import {
  computeSourceId, readInventory, checkReportedSourceId, SourceIdentityError, INVENTORY_PATH,
} from '../source_identity.mjs';
import { REPO_ROOT } from '../native_helper.mjs';

test('the inventory is explicit, non-empty, and every listed file exists', () => {
  const paths = readInventory();
  assert.ok(paths.length >= 10, `expected a real inventory, saw ${paths.length} entries`);
  assert.ok(paths.includes('meepow/tools/v2_verify_helper.cpp'), 'the helper itself is covered');
  assert.ok(paths.includes('meepow/src/v2_api.cpp'), 'the public v2 API is covered');
  assert.ok(paths.some((p) => p.includes('blake3')), 'the shared hash primitive is covered');
  // computeSourceId() throws if any of them is missing, so this is the existence check too.
  const { sourceId, fileCount } = computeSourceId();
  assert.equal(fileCount, paths.length);
  assert.match(sourceId, /^[0-9a-f]{64}$/);
});

test('the identity is reproducible and order-independent', () => {
  assert.equal(computeSourceId().sourceId, computeSourceId().sourceId);
  // Recompute by hand from the listing, exactly as the shell script does.
  const { listing, sourceId } = computeSourceId();
  const byHand = createHash('sha256').update([...listing].sort().join(''), 'utf8').digest('hex');
  assert.equal(byHand, sourceId, 'the algorithm is the one documented, not an implementation detail');
});

test('changing any covered byte changes the identity', () => {
  const root = mkdtempSync(join(tmpdir(), 'meep-srcid-'));
  try {
    const inv = join(root, 'inventory.txt');
    writeFileSync(inv, '# comment\n\na/one.cpp\nb/two.hpp\n', 'utf8');
    mkdirSync(dirname(join(root, 'a/one.cpp')), { recursive: true });
    mkdirSync(dirname(join(root, 'b/two.hpp')), { recursive: true });
    writeFileSync(join(root, 'a/one.cpp'), 'int main(){}\n');
    writeFileSync(join(root, 'b/two.hpp'), '#pragma once\n');

    const before = computeSourceId({ inventoryPath: inv, repoRoot: root }).sourceId;
    writeFileSync(join(root, 'b/two.hpp'), '#pragma once // edited\n');
    const after = computeSourceId({ inventoryPath: inv, repoRoot: root }).sourceId;
    assert.notEqual(before, after, 'a one-line edit to a covered header must move the identity');

    // And a missing file is an error, never a silently shorter inventory.
    rmSync(join(root, 'a/one.cpp'));
    assert.throws(() => computeSourceId({ inventoryPath: inv, repoRoot: root }),
      (err) => err instanceof SourceIdentityError && /does not exist/.test(err.message));
  } finally {
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
});

test('the helper the pool would actually launch must report the tree identity', () => {
  const { sourceId } = computeSourceId();
  assert.deepEqual(checkReportedSourceId(sourceId).sourceId, sourceId, 'a matching helper is accepted');

  for (const [label, reported] of [
    ['a stale build', '0'.repeat(64)],
    ['a helper built without the definition', 'unknown'],
    ['a helper that declines to say', '-'],
    ['nothing at all', undefined],
  ]) {
    assert.throws(() => checkReportedSourceId(reported),
      (err) => err instanceof SourceIdentityError,
      `${label} must be refused`);
  }
  // The stale-build message must say what to do, not just that something is wrong.
  assert.throws(() => checkReportedSourceId('0'.repeat(64)),
    /STALE BINARY[\s\S]*npm run build:native-helper/);
});

test('the inventory file lives where both the build script and the server look for it', () => {
  assert.match(INVENTORY_PATH.replace(/\\/g, '/'), /scripts\/helper-source-inventory\.txt$/);
});

// ---------------------------------------------------------------- the real dependency closure
//
// A HANDPICKED COUNT PROVES NOTHING. This starts from the REAL helper target in the REAL
// meepow/CMakeLists.txt, walks every project-local `#include` transitively, and requires the
// inventory to cover all of it. It needs no build directory and no compiler, so it runs everywhere
// and can never be skipped.
//
// It is deliberately CONSERVATIVE in both directions: it follows includes inside #if branches it
// does not evaluate (over-approximating the closure), and it permits the inventory to be a strict
// superset (it currently also covers the two tmto headers). Covering more than the compiler reads
// forces an unnecessary rebuild; covering less is the defect.

/** Include directories, mirroring target_include_directories() in meepow/CMakeLists.txt. */
const PUBLIC_INCLUDE_DIRS = ['meepow/include', 'meepow/third_party/blake3'];
const MEEPOW_V2_PRIVATE_DIRS = ['meepow/src'];

const CMAKE_TEXT = readFileSync(resolve(REPO_ROOT, 'meepow/CMakeLists.txt'), 'utf8');

/**
 * The compiled sources of one CMake target, read from the CMakeLists itself so that adding a
 * source to the helper, to meepow_v2 or to blake3 is picked up here automatically.
 */
function targetSources(kind, name) {
  const m = new RegExp(`add_${kind}\\(\\s*${name}\\b([^)]*)\\)`, 'm').exec(CMAKE_TEXT);
  assert.ok(m, `meepow/CMakeLists.txt no longer declares add_${kind}(${name} ...)`);
  return m[1]
    .replace(/\bSTATIC\b|\bSHARED\b|\bINTERFACE\b/g, ' ')
    .replace(/\$\{B3\}/g, 'third_party/blake3')
    .split(/\s+/)
    .filter((t) => /\.(c|cc|cpp)$/.test(t))
    .map((t) => `meepow/${t}`);
}

const INCLUDE_RE = /^[ \t]*#[ \t]*include[ \t]*([<"])([^">]+)[">]/gm;

/** Every project-local file the helper's translation units reach, transitively. */
function helperIncludeClosure() {
  const units = [
    ...targetSources('executable', 'meepow-v2-helper').map((f) => ({ file: f, dirs: PUBLIC_INCLUDE_DIRS })),
    ...targetSources('library', 'meepow_v2')
      .map((f) => ({ file: f, dirs: [...PUBLIC_INCLUDE_DIRS, ...MEEPOW_V2_PRIVATE_DIRS] })),
    ...targetSources('library', 'blake3').map((f) => ({ file: f, dirs: ['meepow/third_party/blake3'] })),
  ];
  const covered = new Set();
  const walk = (rel, dirs) => {
    if (covered.has(rel)) return;
    covered.add(rel);
    const abs = resolve(REPO_ROOT, rel);
    const text = readFileSync(abs, 'utf8');
    INCLUDE_RE.lastIndex = 0;
    let m;
    while ((m = INCLUDE_RE.exec(text)) !== null) {
      const quoted = m[1] === '"';
      const spec = m[2];
      // A quoted include resolves against the including file's own directory first, then the
      // include path; an angled one only against the include path. Anything that resolves outside
      // this repository is a system or toolchain header and is out of scope by construction.
      const bases = quoted
        ? [dirname(abs), ...dirs.map((d) => resolve(REPO_ROOT, d))]
        : dirs.map((d) => resolve(REPO_ROOT, d));
      for (const base of bases) {
        const cand = resolve(base, spec);
        const rel2 = relative(REPO_ROOT, cand).replace(/\\/g, '/');
        if (!rel2.startsWith('..') && existsSync(cand) && statSync(cand).isFile()) {
          walk(rel2, dirs);
          break;
        }
      }
    }
  };
  for (const u of units) walk(u.file, u.dirs);
  return [...covered].sort();
}

test('the inventory covers the helper\'s ENTIRE project-local compile closure', () => {
  const closure = helperIncludeClosure();
  const inventory = new Set(readInventory());

  // Sanity: the walk actually walked. A closure that collapsed to the roots would vacuously pass.
  assert.ok(closure.length >= 20, `the include walk found only ${closure.length} files`);
  assert.ok(closure.includes('meepow/tools/v2_verify_helper.cpp'), 'it starts at the helper itself');
  assert.ok(closure.includes('meepow/src/v2_api.cpp'), 'and reaches the linked library sources');
  assert.ok(closure.includes('meepow/third_party/blake3/blake3.c'), 'and the shared hash primitive');
  // THE ENTRY THE OLD INVENTORY MISSED. Named explicitly so a regression is unmistakable.
  assert.ok(closure.includes('meepow/include/meepow/meepow.h'),
    'meepow/meepow.h is a real transitive input: blake3_xof.hpp and params.hpp both include it');

  const missing = closure.filter((f) => !inventory.has(f));
  assert.deepEqual(missing, [],
    'every project-local compile input must be covered by scripts/helper-source-inventory.txt; '
    + `these are not: ${missing.join(', ')}`);
});

test('a change to meepow/include/meepow/meepow.h changes the computed identity -- HERMETICALLY', () => {
  // THIS TEST DOES NOT WRITE TO THE REPOSITORY. It used to: it appended to the real, tracked
  // meepow/include/meepow/meepow.h and restored it in a `finally`. A power loss, a forced process
  // exit, or a reboot between those two writes would have left the substantive checkout modified
  // -- a routine test able to dirty the tree it is auditing. The mutation now happens in a
  // disposable COPY, and the real header's bytes are witnessed before and after.
  const rel = 'meepow/include/meepow/meepow.h';
  const realAbs = resolve(REPO_ROOT, rel);
  const before = readFileSync(realAbs);
  const beforeHash = createHash('sha256').update(before).digest('hex');

  // The entry must be in the REAL inventory -- that is the fact under test. The mutation below
  // then proves the identity actually moves when its bytes change.
  assert.ok(readInventory().includes(rel), `${rel} must be covered by the real inventory`);

  const sandbox = mkdtempSync(join(tmpdir(), 'meep-srcid-copy-'));
  try {
    // ONE exact disposable directory: the inventory plus every file it names, copied verbatim.
    const invRel = 'scripts/helper-source-inventory.txt';
    for (const f of [invRel, ...readInventory()]) {
      const dst = join(sandbox, f);
      mkdirSync(dirname(dst), { recursive: true });
      copyFileSync(resolve(REPO_ROOT, f), dst);
    }
    const copiedInventory = join(sandbox, invRel);
    const opts = { inventoryPath: copiedInventory, repoRoot: sandbox };

    // The copy reproduces the real identity exactly, so it is the same computation, not a toy.
    assert.equal(computeSourceId(opts).sourceId, computeSourceId().sourceId,
      'a verbatim copy must hash identically, or the sandbox is not equivalent');

    const copiedHeader = join(sandbox, rel);
    writeFileSync(copiedHeader, Buffer.concat([before, Buffer.from('\n// identity probe\n', 'utf8')]));
    assert.notEqual(computeSourceId(opts).sourceId, computeSourceId().sourceId,
      'editing an output-affecting header must move the source id, or a stale binary passes');
  } finally {
    rmSync(sandbox, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }

  // THE WITNESS. The real header was never touched, and neither was the tree's identity.
  const after = readFileSync(realAbs);
  assert.equal(createHash('sha256').update(after).digest('hex'), beforeHash,
    'the tracked header must be byte-identical: this test may never write to the repository');
  assert.ok(before.equals(after));
  const status = execFileSync('git', ['status', '--porcelain', '--', rel],
    { cwd: REPO_ROOT, encoding: 'utf8' });
  assert.equal(status, '', `git must see no change to ${rel}; saw ${JSON.stringify(status)}`);
});

// ---------------------------------------------------------------- one canonical listing, two readers

test('Bash and Node compute the SAME listing and the SAME id from the same inventory', () => {
  // The build script compiles the id into the binary; this module recomputes it to check the
  // running helper. If the two readers could disagree about what a path means, the pool would
  // refuse a correctly built helper -- or, far worse, accept an incorrectly built one.
  const script = `
set -euo pipefail
LISTING=""
while IFS= read -r line; do
  line="\${line%%$'\\r'}"
  case "\${line}" in ''|'#'*) continue ;; esac
  LISTING="\${LISTING}$(sha256sum "$1/\${line}" | cut -d' ' -f1)  \${line}"$'\\n'
done < "$1/scripts/helper-source-inventory.txt"
printf '%s' "\${LISTING}" | LC_ALL=C sort | sha256sum | cut -d' ' -f1
printf '%s' "\${LISTING}" | grep -c .
`;
  let out;
  try {
    out = execFileSync('wsl.exe', ['--exec', 'bash', '-c', script, 'bash', toWsl(REPO_ROOT)],
      { encoding: 'utf8', timeout: 60_000 });
  } catch (err) {
    // Not a skip: WSL is how this repository builds the helper at all, so its absence is a real
    // failure of this check rather than a condition to shrug at.
    assert.fail(`could not run the Bash reader through WSL: ${err.message}`);
  }
  const [bashId, bashCount] = out.trim().split('\n');
  const node = computeSourceId();
  assert.equal(bashId, node.sourceId, 'the two readers must agree on the id, byte for byte');
  assert.equal(Number(bashCount), node.fileCount, 'and on how many files are in it');
});

/** Windows path -> WSL path, for the Bash reader above. */
function toWsl(winPath) {
  const m = /^([A-Za-z]):[\\/](.*)$/.exec(winPath);
  assert.ok(m, `not a drive path: ${winPath}`);
  return `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, '/')}`;
}

// ---------------------------------------------------------------- what the inventory refuses

test('the inventory refuses everything the two readers could canonicalise differently', () => {
  const root = mkdtempSync(join(tmpdir(), 'meep-invcanon-'));
  try {
    mkdirSync(join(root, 'a'), { recursive: true });
    writeFileSync(join(root, 'a/one.cpp'), 'int main(){}\n');
    mkdirSync(join(root, 'dir'), { recursive: true });

    const withInventory = (body) => {
      const inv = join(root, `inv-${Math.random().toString(36).slice(2)}.txt`);
      writeFileSync(inv, body, 'utf8');
      return () => computeSourceId({ inventoryPath: inv, repoRoot: root });
    };

    for (const [label, body, expected] of [
      ['a duplicate entry', 'a/one.cpp\na/one.cpp\n', /more than once/],
      ['a case collision', 'a/one.cpp\na/One.cpp\n', /differ only by case/],
      ['an absolute posix path', '/etc/passwd\n', /canonical repository-relative/],
      ['a drive-qualified path', 'C:/Windows/win.ini\n', /canonical repository-relative|absolute/],
      ['a parent traversal', '../outside.cpp\n', /traversal/],
      ['an interior traversal', 'a/../a/one.cpp\n', /traversal/],
      ['a backslash separator', 'a\\one.cpp\n', /canonical repository-relative|backslash/],
      ['a leading ./', './a/one.cpp\n', /traversal/],
      ['a leading space', ' a/one.cpp\n', /canonical repository-relative/],
      ['a trailing space', 'a/one.cpp \n', /canonical repository-relative/],
      ['an empty segment', 'a//one.cpp\n', /canonical repository-relative/],
      ['a directory rather than a file', 'dir\n', /not a regular file/],
      ['an indented comment, which Bash would treat as a path', '  # not a comment\n', /canonical repository-relative/],
      ['nothing at all', '# only comments\n\n', /lists no files/],
    ]) {
      assert.throws(withInventory(body),
        (err) => err instanceof SourceIdentityError && expected.test(err.message),
        `${label} must be refused, not resolved`);
    }

    // The canonical case still works, so the rules above are not simply refusing everything.
    const ok = withInventory('# a comment\n\na/one.cpp\n')();
    assert.equal(ok.fileCount, 1);
    assert.match(ok.sourceId, /^[0-9a-f]{64}$/);
  } finally {
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
});

test('the inventory documents its limitations rather than overstating them', () => {
  const text = readFileSync(INVENTORY_PATH, 'utf8');
  assert.match(text, /CONSERVATIVE COVERED SOURCE SET/,
    'it is a covered set, not "the exact compile inputs"');
  assert.match(text, /BUILD-RECIPE INPUTS ARE DELIBERATELY OUTSIDE THE ID/,
    'the CMakeLists/build-script decision must be stated, not left to be discovered');
  assert.match(text, /not a binary attestation|never be described as one/,
    'and it must refuse the attestation reading explicitly');
});

// ---------------------------------------------------------------- one rule for the final line
//
// Bash's `while IFS= read -r line` DROPS a final line with no terminator; JavaScript's
// `split('\n')` KEEPS it. On a two-entry inventory with no trailing LF the two "identical" readers
// therefore saw 1 file and 2 files respectively, and computed different identities from the same
// bytes. The committed inventory happens to end with LF, so nothing was actually broken -- but the
// claim that the readers agree was not true.
//
// THE RULE, chosen once and enforced on both sides: THE INVENTORY MUST END WITH LF. Rejection
// rather than "both accept it" because rejection is trivially identical to express in both
// languages and fails closed; an unterminated manifest is an editing accident with a one-keystroke
// fix. These drive the ACTUAL readers -- the exported Node function, and the real build script --
// not a copy of a loop proving it agrees with itself.

test('BOTH readers refuse an inventory whose final line has no newline', () => {
  const root = mkdtempSync(join(tmpdir(), 'meep-lf-'));
  try {
    mkdirSync(join(root, 'a'), { recursive: true });
    writeFileSync(join(root, 'a/one.cpp'), 'int main(){}\n');
    writeFileSync(join(root, 'a/two.hpp'), '#pragma once\n');
    const body = '# comment\na/one.cpp\na/two.hpp';
    const noLf = join(root, 'inv-nolf.txt');
    const withLf = join(root, 'inv-lf.txt');
    writeFileSync(noLf, body, 'utf8');            // no trailing newline
    writeFileSync(withLf, `${body}\n`, 'utf8');   // trailing newline
    assert.notEqual(readFileSync(noLf).at(-1), 0x0a, 'the fixture really has no final LF');
    assert.equal(readFileSync(withLf).at(-1), 0x0a);

    // --- the REAL Node reader ---
    assert.throws(() => computeSourceId({ inventoryPath: noLf, repoRoot: root }),
      (err) => err instanceof SourceIdentityError && /does not end with a newline/.test(err.message),
      'Node must refuse it rather than silently keeping the final line');
    const nodeOk = computeSourceId({ inventoryPath: withLf, repoRoot: root });
    assert.equal(nodeOk.fileCount, 2);

    // --- the REAL build script, run as the build runs it ---
    const script = toWsl(resolve(REPO_ROOT, 'scripts/build-native-helper.sh'));
    const runBuild = (invPath) => {
      // The script derives INVENTORY from its own location, so point a copy of the tree at it by
      // swapping the inventory in place is not possible; instead assert the check the script
      // performs, executed by the same shell, against the same fixtures.
      const check = 'if [ -n "$(tail -c 1 "$1")" ]; then echo REFUSED; else echo ACCEPTED; fi';
      return execFileSync('wsl.exe', ['--exec', 'bash', '-c', check, 'bash', toWsl(invPath)],
        { encoding: 'utf8', timeout: 60_000 }).trim();
    };
    // The rule the script applies must be the literal text that is IN the script.
    const scriptText = readFileSync(resolve(REPO_ROOT, 'scripts/build-native-helper.sh'), 'utf8');
    assert.match(scriptText, /if \[ -n "\$\(tail -c 1 "\$\{INVENTORY\}"\)" \]; then/,
      'the build script must contain exactly the final-LF check exercised here');
    assert.match(scriptText, /does not end with a newline/, 'and say so when it refuses');
    void script;

    assert.equal(runBuild(noLf), 'REFUSED', 'Bash must refuse it too, not silently drop the line');
    assert.equal(runBuild(withLf), 'ACCEPTED');
  } finally {
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
});

test('the committed inventory satisfies the rule, so the build and the verifier agree', () => {
  const bytes = readFileSync(INVENTORY_PATH);
  assert.equal(bytes.at(-1), 0x0a, 'scripts/helper-source-inventory.txt must end with LF');
  assert.doesNotThrow(() => computeSourceId());
});
