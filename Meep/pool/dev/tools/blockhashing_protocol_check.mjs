#!/usr/bin/env node

// Bounded executable-level check for the daemon-source meepcoin-blockhashing protocol.
//
// This is deliberately a standalone diagnostic rather than part of the ordinary JS test suite:
// it requires a freshly compiled daemon-source binary. It starts no daemon, opens no socket, and
// creates no file. On Windows it can launch the Linux binary through one explicitly named WSL
// distribution; on Linux it launches the binary directly.

import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { readFile, readFileSync } from 'node:fs';
import { platform } from 'node:process';

const TOKEN = '0123456789abcdef0123456789abcdef';
const TIMEOUT_MS = 10_000;
const MAX_CAPTURE_BYTES = 4 * 1024 * 1024;

function usage() {
  return [
    'usage: node blockhashing_protocol_check.mjs --binary <linux-path> --vectors <json-path>',
    '       [--wsl-distro <space-free-name>]',
    '',
    'The vector path is read by Node on the host. The binary path is interpreted inside the',
    'selected WSL distribution when --wsl-distro is present.',
  ].join('\n');
}

function parseArgs(argv) {
  const out = { binary: null, vectors: null, wslDistro: null };
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (value === undefined) throw new Error(`missing value for ${key ?? '<argument>'}`);
    if (key === '--binary') out.binary = value;
    else if (key === '--vectors') out.vectors = value;
    else if (key === '--wsl-distro') out.wslDistro = value;
    else throw new Error(`unknown argument: ${key}`);
  }
  if (!out.binary || !out.vectors) throw new Error('both --binary and --vectors are required');
  if (out.wslDistro !== null && !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/.test(out.wslDistro)) {
    throw new Error(`invalid WSL distribution name: ${JSON.stringify(out.wslDistro)}`);
  }
  if (platform === 'win32' && out.wslDistro === null) {
    throw new Error('--wsl-distro is required on Windows');
  }
  return out;
}

function commandFor(config, args) {
  if (config.wslDistro === null) return { file: config.binary, args };
  return {
    file: 'wsl.exe',
    args: ['-d', config.wslDistro, '--exec', config.binary, ...args],
  };
}

function withTimeout(promise, label, ms = TIMEOUT_MS) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms} ms`)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

function appendBounded(current, chunk, label) {
  const next = Buffer.concat([current, chunk]);
  if (next.length > MAX_CAPTURE_BYTES) throw new Error(`${label} exceeded ${MAX_CAPTURE_BYTES} bytes`);
  return next;
}

function execBounded(config, args, { timeoutMs = TIMEOUT_MS } = {}) {
  const command = commandFor(config, args);
  return new Promise((resolve, reject) => {
    execFile(command.file, command.args, {
      encoding: 'buffer',
      maxBuffer: MAX_CAPTURE_BYTES,
      timeout: timeoutMs,
      windowsHide: true,
      shell: false,
    }, (error, stdout, stderr) => {
      const code = error ? error.code : 0;
      if (error && (error.killed || error.signal)) {
        reject(new Error(`command timed out or was killed: ${error.message}`));
        return;
      }
      resolve({
        code: typeof code === 'number' ? code : 1,
        stdout: Buffer.from(stdout ?? []),
        stderr: Buffer.from(stderr ?? []),
      });
    });
  });
}

class ServerProcess {
  constructor(config, token = TOKEN) {
    const command = commandFor(config, ['--server', token]);
    this.child = spawn(command.file, command.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
      shell: false,
    });
    this.stdout = Buffer.alloc(0);
    this.stderr = Buffer.alloc(0);
    this.lines = [];
    this.waiters = [];
    this.fragment = Buffer.alloc(0);
    this.spawnError = null;
    this.exit = new Promise((resolve) => {
      this.child.once('error', (error) => {
        this.spawnError = error;
      });
      this.child.once('close', (code, signal) => resolve({ code, signal }));
    });
    this.child.stdout.on('data', (chunk) => this.#takeStdout(Buffer.from(chunk)));
    this.child.stderr.on('data', (chunk) => {
      this.stderr = appendBounded(this.stderr, Buffer.from(chunk), 'stderr');
    });
    // The oversized-input case may make the child close stdin while the parent still has buffered
    // bytes. The verdict comes from the child's FAULT line and exit status; an expected EPIPE on
    // this stream must not become an unhandled Node error.
    this.child.stdin.on('error', () => {});
  }

  #takeStdout(chunk) {
    this.stdout = appendBounded(this.stdout, chunk, 'stdout');
    this.fragment = appendBounded(this.fragment, chunk, 'stdout line');
    for (;;) {
      const newline = this.fragment.indexOf(0x0a);
      if (newline < 0) break;
      const raw = this.fragment.subarray(0, newline);
      this.fragment = this.fragment.subarray(newline + 1);
      const line = raw.toString('ascii');
      const waiter = this.waiters.shift();
      if (waiter) waiter.resolve(line);
      else this.lines.push(line);
    }
  }

  nextLine(label) {
    if (this.lines.length > 0) return Promise.resolve(this.lines.shift());
    return withTimeout(new Promise((resolve, reject) => {
      this.waiters.push({ resolve, reject });
    }), label);
  }

  send(data) {
    // A deliberately oversized test can race the child's fail-closed exit. EPIPE in the callback
    // is therefore expected and not itself the verdict; stdout and the actual exit are.
    this.child.stdin.write(data, () => {});
  }

  end() {
    this.child.stdin.end();
  }

  async waitForExit(label) {
    const result = await withTimeout(this.exit, label);
    if (this.spawnError) throw this.spawnError;
    return result;
  }

  async releaseAfterFailure() {
    if (this.child.exitCode !== null || this.child.signalCode !== null) return;
    this.end();
    try {
      await withTimeout(this.exit, 'failed-check EOF cleanup', 2_000);
    } catch {
      // Signal only the exact wrapper child this object spawned. Closing its stdin normally makes
      // the converter exit on EOF; this is the bounded fallback if even that ownership path fails.
      this.child.kill();
      await withTimeout(this.exit, 'failed-check signal cleanup', 2_000);
    }
  }
}

function parseHello(line, token = TOKEN) {
  const match = /^HELLO 1 ([0-9a-f]{32}) ([1-9][0-9]*)$/.exec(line);
  assert(match, `malformed HELLO: ${JSON.stringify(line)}`);
  assert.equal(match[1], token, 'HELLO token mismatch');
  const pid = Number(match[2]);
  assert(Number.isSafeInteger(pid) && pid > 0, 'HELLO pid is not a canonical positive integer');
  return pid;
}

function assertNoSecretEcho(proc, secrets) {
  const transcript = Buffer.concat([proc.stdout, proc.stderr]).toString('ascii');
  for (const secret of secrets) {
    assert(!transcript.includes(secret), 'child echoed a submit-ready full block');
  }
}

async function readLinuxCmdline(config, pid) {
  if (config.wslDistro === null) {
    return await new Promise((resolve, reject) => {
      readFile(`/proc/${pid}/cmdline`, (error, data) => error ? reject(error) : resolve(data));
    });
  }
  const command = {
    file: 'wsl.exe',
    args: ['-d', config.wslDistro, '--exec', 'cat', `/proc/${pid}/cmdline`],
  };
  return await new Promise((resolve, reject) => {
    execFile(command.file, command.args, {
      encoding: 'buffer', maxBuffer: 64 * 1024, timeout: TIMEOUT_MS, windowsHide: true, shell: false,
    }, (error, stdout) => error ? reject(error) : resolve(Buffer.from(stdout)));
  });
}

async function startServer(config) {
  const proc = new ServerProcess(config);
  try {
    const pid = parseHello(await proc.nextLine('HELLO'));
    return { proc, pid };
  } catch (error) {
    await proc.releaseAfterFailure();
    throw error;
  }
}

async function checkLegacy(config, vectors) {
  for (const vector of vectors.slice(0, 2)) {
    const run = await execBounded(config, [vector.full_block_blob]);
    assert.equal(run.code, 0, `legacy conversion exited ${run.code}: ${run.stderr.toString('utf8')}`);
    assert.equal(run.stderr.length, 0, 'legacy conversion wrote stderr');
    assert.equal(run.stdout.toString('ascii'), `${vector.block_hashing_blob}\n`);
  }
  const badHex = await execBounded(config, ['0G']);
  assert.equal(badHex.code, 2);
  assert.equal(badHex.stdout.length, 0);
  assert.equal(badHex.stderr.toString('ascii'), 'bad hex\n');
  const badBlock = await execBounded(config, ['00']);
  assert.equal(badBlock.code, 1);
  assert.equal(badBlock.stdout.length, 0);
  assert.equal(badBlock.stderr.toString('ascii'), 'could not parse block\n');
}

async function checkHappySession(config, vectors) {
  const { proc, pid } = await startServer(config);
  let complete = false;
  try {
    const cmdline = await readLinuxCmdline(config, pid);
    const argv = cmdline.toString('utf8').split('\0').filter(Boolean);
    assert.deepEqual(argv, [config.binary, '--server', TOKEN], 'Linux process argv was not exact');
    for (const vector of vectors.slice(0, 2)) {
      assert(!argv.includes(vector.full_block_blob), 'submit-ready block leaked into process argv');
    }

    for (let index = 0; index < 2; index += 1) {
      const id = index + 1;
      const vector = vectors[index];
      proc.send(`CONVERT ${id} ${vector.full_block_blob}\n`);
      assert.equal(
        await proc.nextLine(`RESULT ${id}`),
        `RESULT ${id} ${vector.block_hashing_blob}`,
      );
    }
    proc.send('QUIT\n');
    assert.equal(await proc.nextLine('BYE'), 'BYE');
    const exit = await proc.waitForExit('clean server exit');
    assert.deepEqual(exit, { code: 0, signal: null });
    assert.equal(proc.stderr.length, 0, 'clean session wrote stderr');
    assert.equal(proc.lines.length, 0, 'clean session wrote a stray line after BYE');
    assert.equal(proc.fragment.length, 0, 'clean session left a partial stdout line');
    assertNoSecretEcho(proc, vectors.slice(0, 2).map((v) => v.full_block_blob));
    complete = true;
  } finally {
    if (!complete) await proc.releaseAfterFailure();
  }
}

async function checkFault(config, vector, request, expectedFault, label) {
  const { proc } = await startServer(config);
  let complete = false;
  try {
    proc.send(request);
    assert.equal(await proc.nextLine(`${label} fault`), `FAULT ${expectedFault}`);
    const exit = await proc.waitForExit(`${label} exit`);
    assert.equal(exit.code, 1, `${label} did not exit 1`);
    assert.equal(exit.signal, null, `${label} died by signal`);
    assert.equal(proc.stderr.length, 0, `${label} wrote stderr`);
    assert.equal(proc.lines.length, 0, `${label} wrote a stray line after its fault`);
    assert.equal(proc.fragment.length, 0, `${label} left a partial stdout line`);
    assertNoSecretEcho(proc, [vector.full_block_blob]);
    complete = true;
  } finally {
    if (!complete) await proc.releaseAfterFailure();
  }
}

async function checkFailures(config, vector) {
  const blob = vector.full_block_blob;
  const cases = [
    [`CONVERT 01 ${blob}\n`, 'bad_request', 'leading-zero id'],
    [`CONVERT +1 ${blob}\n`, 'bad_request', 'signed id'],
    [`CONVERT 1e0 ${blob}\n`, 'bad_request', 'exponent id'],
    [`CONVERT 4294967296 ${blob}\n`, 'bad_request', 'overflow id'],
    [`CONVERT 1 ${blob.toUpperCase()}\n`, 'bad_request', 'uppercase hex'],
    [`CONVERT 1 ${blob.slice(0, -1)}\n`, 'bad_request', 'odd hex'],
    [`CONVERT 1 ${blob}\r\n`, 'malformed_line', 'carriage return'],
    ['CONVERT 1 00\n', 'invalid_block', 'unparsable block'],
  ];
  for (const [request, fault, label] of cases) {
    await checkFault(config, vector, request, fault, label);
  }

  const tooLarge = `CONVERT 1 ${'00'.repeat((1 << 20) + 17)}\n`;
  await checkFault(config, vector, tooLarge, 'line_too_long', 'oversized line');

  const { proc } = await startServer(config);
  proc.end();
  const exit = await proc.waitForExit('unexpected EOF exit');
  assert.equal(exit.code, 1);
  assert.equal(exit.signal, null);
  assert.equal(proc.lines.length, 0, 'unexpected EOF produced an extra line');
  assert.equal(proc.stderr.length, 0, 'unexpected EOF wrote stderr');
  assert.equal(proc.fragment.length, 0, 'unexpected EOF left a partial stdout line');

  const invalidToken = await execBounded(config, ['--server', TOKEN.toUpperCase()]);
  assert.equal(invalidToken.code, 2);
  assert.equal(invalidToken.stdout.length, 0);
  assert.equal(invalidToken.stderr.length, 0);
}

async function main() {
  let config;
  try {
    config = parseArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n${usage()}\n`);
    process.exitCode = 2;
    return;
  }
  const document = JSON.parse(readFileSync(config.vectors, 'utf8'));
  assert.equal(document.network, 'meepcoin-devnet');
  assert(Array.isArray(document.vectors) && document.vectors.length >= 2, 'need at least two vectors');
  for (const vector of document.vectors.slice(0, 2)) {
    assert.match(vector.full_block_blob, /^[0-9a-f]+$/);
    assert.equal(vector.full_block_blob.length % 2, 0);
    assert.match(vector.block_hashing_blob, /^[0-9a-f]+$/);
  }

  await checkLegacy(config, document.vectors);
  await checkHappySession(config, document.vectors);
  await checkFailures(config, document.vectors[0]);
  process.stdout.write('PASS meepcoin-blockhashing legacy + owned protocol (19 bounded scenarios)\n');
}

main().catch((error) => {
  process.stderr.write(`FAIL ${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
