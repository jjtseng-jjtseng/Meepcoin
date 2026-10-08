// Strict parent-side protocol for an ALREADY-OWNED meepcoin-blockhashing child.
//
// This module never spawns, signals or claims physical release of a process. That separation is
// intentional: on Windows, the ChildProcess is wsl.exe, and observing that wrapper is not proof the
// Linux converter died. A later owner must launch the child, corroborate its HELLO pid against the
// exact Linux argv, and provide bounded reaping. This layer does only the protocol job well:
// validate HELLO, serialize one secret-bearing conversion at a time, accept only the matching
// RESULT, redact all block material from errors, and grade QUIT/BYE plus wrapper exit exactly.

const LOWER_HEX = /^[0-9a-f]+$/;
const CANONICAL_U32 = /^(?:0|[1-9][0-9]*)$/;
const FAULT_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const UINT32_MAX = 0xffff_ffff;

export const BLOCK_CONVERTER_PROTOCOL = Object.freeze({
  version: 1,
  maxBlockBytes: 1 << 20,
  helloTimeoutMs: 10_000,
  requestTimeoutMs: 30_000,
  quitTimeoutMs: 5_000,
  maxStderrBytes: 8_192,
});

export class BlockConverterProtocolError extends Error {
  constructor(code, message, { cancelled = false } = {}) {
    super(message);
    this.name = 'BlockConverterProtocolError';
    this.code = code;
    this.cancelled = cancelled;
  }
}

function closedError(code, message) {
  return new BlockConverterProtocolError(code, message);
}

function cancelledError(message) {
  return new BlockConverterProtocolError('cancelled', message, { cancelled: true });
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  // Deferreds are sometimes rejected as part of synchronous shutdown before the caller reaches
  // its await. Marking the promise observed here prevents a process-level unhandled rejection;
  // the original promise still rejects normally for its actual consumer.
  promise.catch(() => {});
  return { promise, resolve, reject, settled: false };
}

function boundedInteger(value, fallback, name, { min, max }) {
  const actual = value ?? fallback;
  if (!Number.isSafeInteger(actual) || actual < min || actual > max) {
    throw closedError('bad_config', `${name} must be an integer in [${min}, ${max}]`);
  }
  return actual;
}

function validateChild(child) {
  if (child === null || typeof child !== 'object'
      || typeof child.on !== 'function'
      || child.stdin === null || typeof child.stdin?.write !== 'function'
      || child.stdout === null || typeof child.stdout?.on !== 'function'
      || child.stderr === null || typeof child.stderr?.on !== 'function') {
    throw closedError('bad_config', 'child must be a spawned process with piped stdin/stdout/stderr');
  }
}

function validateFullBlock(fullHex, maxBytes) {
  if (typeof fullHex !== 'string' || fullHex.length === 0 || fullHex.length % 2 !== 0
      || fullHex.length > maxBytes * 2 || !LOWER_HEX.test(fullHex)) {
    throw closedError('bad_block', 'full block must be bounded, non-empty, even-length lowercase hex');
  }
}

/**
 * Attach the strict protocol layer to a child the caller already owns.
 *
 * The returned object exists immediately, including when HELLO later fails, so the physical owner
 * never loses the only handle it needs to clean up. Await `ready` before trusting `linuxPid`.
 */
export function createBlockConverterProtocol({
  child,
  token,
  limits = {},
  onFault = () => {},
} = {}) {
  validateChild(child);
  if (typeof token !== 'string' || !/^[0-9a-f]{32}$/.test(token)) {
    throw closedError('bad_config', 'token must be exactly 32 lowercase hexadecimal characters');
  }
  if (limits === null || typeof limits !== 'object' || Array.isArray(limits)) {
    throw closedError('bad_config', 'limits must be an object');
  }
  const allowedLimits = new Set([
    'maxBlockBytes', 'helloTimeoutMs', 'requestTimeoutMs', 'quitTimeoutMs', 'maxStderrBytes',
  ]);
  for (const key of Object.keys(limits)) {
    if (!allowedLimits.has(key)) throw closedError('bad_config', `unknown protocol limit ${key.slice(0, 40)}`);
  }
  if (typeof onFault !== 'function') throw closedError('bad_config', 'onFault must be a function');
  const cfg = Object.freeze({
    maxBlockBytes: boundedInteger(limits.maxBlockBytes, BLOCK_CONVERTER_PROTOCOL.maxBlockBytes,
      'maxBlockBytes', { min: 1, max: BLOCK_CONVERTER_PROTOCOL.maxBlockBytes }),
    helloTimeoutMs: boundedInteger(limits.helloTimeoutMs, BLOCK_CONVERTER_PROTOCOL.helloTimeoutMs,
      'helloTimeoutMs', { min: 1, max: 60_000 }),
    requestTimeoutMs: boundedInteger(limits.requestTimeoutMs, BLOCK_CONVERTER_PROTOCOL.requestTimeoutMs,
      'requestTimeoutMs', { min: 1, max: 120_000 }),
    quitTimeoutMs: boundedInteger(limits.quitTimeoutMs, BLOCK_CONVERTER_PROTOCOL.quitTimeoutMs,
      'quitTimeoutMs', { min: 1, max: 30_000 }),
    maxStderrBytes: boundedInteger(limits.maxStderrBytes, BLOCK_CONVERTER_PROTOCOL.maxStderrBytes,
      'maxStderrBytes', { min: 256, max: 64 * 1024 }),
  });

  const hello = deferred();
  const goodbye = deferred();
  const exited = deferred();
  let helloTimer = null;
  let requestTimer = null;
  let quitTimer = null;
  let stdout = Buffer.alloc(0);
  let stderrBytesRetained = 0;
  let ready = false;
  let linuxPid = null;
  let pending = null;
  let nextId = 1;
  let closing = false;
  let quitWritten = false;
  let byeCount = 0;
  let exitInfo = null;
  let fault = null;
  let faultReported = false;
  let api = null;

  const cancelTimer = (name) => {
    if (name === 'hello' && helloTimer !== null) { clearTimeout(helloTimer); helloTimer = null; }
    if (name === 'request' && requestTimer !== null) { clearTimeout(requestTimer); requestTimer = null; }
    if (name === 'quit' && quitTimer !== null) { clearTimeout(quitTimer); quitTimer = null; }
  };

  const reportFault = (err) => {
    if (faultReported || err.cancelled) return;
    faultReported = true;
    try { onFault(err); } catch { /* a diagnostic callback never defeats protocol state */ }
  };

  const settlePending = (err) => {
    cancelTimer('request');
    if (pending !== null) {
      const current = pending;
      pending = null;
      current.reject(err);
    }
  };

  const latch = (code, message) => {
    if (fault !== null) return fault;
    fault = closedError(code, message);
    cancelTimer('hello');
    if (!hello.settled) { hello.settled = true; hello.reject(fault); }
    settlePending(fault);
    if (!goodbye.settled) { goodbye.settled = true; goodbye.reject(fault); }
    reportFault(fault);
    return fault;
  };

  const writeLine = (line) => {
    if (fault) throw fault;
    if (!child.stdin.writable) throw latch('stdin_closed', 'converter stdin is not writable');
    try {
      child.stdin.write(`${line}\n`, (error) => {
        if (error) latch('write_failed', 'converter request could not be written');
      });
    } catch {
      throw latch('write_failed', 'converter request could not be written');
    }
  };

  const parseId = (text) => {
    if (!CANONICAL_U32.test(text) || text.length > 10) return null;
    const value = Number(text);
    return Number.isSafeInteger(value) && value >= 0 && value <= UINT32_MAX ? value : null;
  };

  const handleLine = (line) => {
    if (!ready) {
      const match = /^HELLO 1 ([0-9a-f]{32}) ([1-9][0-9]*)$/.exec(line);
      if (!match || match[1] !== token) {
        latch('bad_hello', 'converter HELLO was malformed or did not echo the startup token');
        return;
      }
      const pid = Number(match[2]);
      if (!Number.isSafeInteger(pid) || pid < 1) {
        latch('bad_hello', 'converter HELLO pid was not a canonical positive safe integer');
        return;
      }
      ready = true;
      linuxPid = pid;
      cancelTimer('hello');
      hello.settled = true;
      hello.resolve(api);
      return;
    }

    if (line === 'BYE') {
      byeCount += 1;
      if (!closing || !quitWritten || byeCount !== 1) {
        latch('unexpected_bye', 'converter sent an unsolicited or duplicate BYE');
        return;
      }
      goodbye.settled = true;
      goodbye.resolve();
      return;
    }

    const faultMatch = /^FAULT ([a-z][a-z0-9_]{0,63})$/.exec(line);
    if (faultMatch) {
      latch('converter_fault', `converter refused the request (${faultMatch[1]})`);
      return;
    }

    const result = /^RESULT ([^ ]+) ([^ ]+)$/.exec(line);
    if (!result) {
      latch('bad_output', 'converter sent an unrecognised protocol line');
      return;
    }
    const id = parseId(result[1]);
    if (pending === null || id === null || id !== pending.id) {
      latch('wrong_result', 'converter RESULT did not match the one outstanding request');
      return;
    }
    const hashingHex = result[2];
    if (hashingHex.length === 0 || hashingHex.length % 2 !== 0
        || hashingHex.length > cfg.maxBlockBytes * 2 || !LOWER_HEX.test(hashingHex)) {
      latch('bad_result', 'converter RESULT was not bounded even-length lowercase hex');
      return;
    }
    const current = pending;
    pending = null;
    cancelTimer('request');
    current.resolve(hashingHex);
  };

  const takeStdout = (chunk) => {
    if (fault) return;
    stdout = Buffer.concat([stdout, Buffer.from(chunk)]);
    // Before HELLO, no legitimate line is large. Afterwards RESULT is bounded by the maximum full
    // block size plus its short framing. Count bytes, not UTF-16 code units.
    const limit = ready ? cfg.maxBlockBytes * 2 + 64 : 256;
    if (stdout.length > limit) {
      latch('oversized_output', 'converter stdout line exceeded its protocol bound');
      return;
    }
    for (;;) {
      const nl = stdout.indexOf(0x0a);
      if (nl < 0) break;
      const raw = stdout.subarray(0, nl);
      stdout = stdout.subarray(nl + 1);
      for (const byte of raw) {
        if (byte < 0x20 || byte > 0x7e) {
          latch('bad_output', 'converter output contained a non-printable byte');
          return;
        }
      }
      handleLine(raw.toString('ascii'));
      if (fault) return;
    }
  };

  child.stdout.on('data', takeStdout);
  child.stderr.on('data', (chunk) => {
    // The converter must never echo the submitted block, but do not make that assumption part of
    // the parent's secret boundary: retain only a capped byte count, never child stderr content.
    stderrBytesRetained = Math.min(cfg.maxStderrBytes,
      stderrBytesRetained + Buffer.byteLength(chunk));
  });
  child.on('error', () => latch('child_error', 'converter process reported a launch or I/O error'));
  child.on('close', (code, signal) => {
    exitInfo = { code, signal };
    exited.settled = true;
    exited.resolve(exitInfo);
    if (!closing || !goodbye.settled) {
      latch('unexpected_exit', 'converter exited before completing its canonical goodbye');
    }
  });

  helloTimer = setTimeout(() => latch('hello_timeout', 'converter did not complete HELLO in time'),
    cfg.helloTimeoutMs);

  const beginClose = (reason = 'converter protocol closing') => {
    if (closing) return;
    closing = true;
    settlePending(cancelledError(reason));
  };

  api = {
    get ready() { return hello.promise; },
    get linuxPid() { return linuxPid; },
    get healthy() { return fault === null; },
    get fault() { return fault; },
    get closing() { return closing; },
    get exitInfo() { return exitInfo === null ? null : { ...exitInfo }; },
    get stderrBytesRetained() { return stderrBytesRetained; },
    get pendingCount() { return pending === null ? 0 : 1; },

    async convert(fullHex) {
      validateFullBlock(fullHex, cfg.maxBlockBytes);
      await hello.promise;
      if (fault) throw fault;
      if (closing) throw cancelledError('converter protocol is closing');
      if (pending !== null) throw closedError('busy', 'converter already has one outstanding request');
      if (nextId > UINT32_MAX) throw latch('id_exhausted', 'converter request id space is exhausted');
      const id = nextId;
      nextId += 1;
      const response = deferred();
      pending = { id, resolve: response.resolve, reject: response.reject };
      requestTimer = setTimeout(() => latch('request_timeout', 'converter request timed out'),
        cfg.requestTimeoutMs);
      // This is the ONLY boundary where the submit-ready block is emitted, and it is stdin.
      writeLine(`CONVERT ${id} ${fullHex}`);
      return await response.promise;
    },

    beginClose(reason = 'converter protocol closing') {
      beginClose(reason);
    },

    async close(reason = 'converter protocol closing') {
      if (exitInfo !== null) {
        throw closedError('abnormal_close', 'converter had already exited before a canonical goodbye');
      }
      await hello.promise;
      beginClose(reason);
      if (fault) throw fault;
      if (quitWritten) throw closedError('already_closing', 'converter QUIT was already written');
      quitWritten = true;
      writeLine('QUIT');
      quitTimer = setTimeout(() => latch('quit_timeout', 'converter did not complete QUIT/BYE in time'),
        cfg.quitTimeoutMs);
      try {
        await goodbye.promise;
        if (child.stdin.writable) child.stdin.end();
        let exitDeadline;
        const observedExit = await Promise.race([
          exited.promise,
          new Promise((_, reject) => {
            exitDeadline = setTimeout(
              () => reject(closedError('exit_timeout', 'converter wrapper did not exit after BYE')),
              cfg.quitTimeoutMs,
            );
          }),
        ]).finally(() => clearTimeout(exitDeadline));
        if (fault) throw fault;
        if (stdout.length !== 0) {
          throw closedError('trailing_output', 'converter left an unterminated stdout fragment');
        }
        if (byeCount !== 1 || observedExit.code !== 0 || observedExit.signal !== null) {
          throw closedError('abnormal_close', 'converter goodbye did not end in one BYE and exit 0');
        }
        return Object.freeze({ wrapperExited: true, gracefulProtocolShutdown: true });
      } finally {
        cancelTimer('quit');
      }
    },
  };

  return api;
}
