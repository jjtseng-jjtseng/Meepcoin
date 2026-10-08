// Source-specific parser for the pinned daemon's verify:ERROR timestamp refusal lines.
// This extracts positive log evidence only. Silence is UNKNOWN, never acceptance.

// The daemon's hash stream formatter wraps hashes in angle brackets. Accept the
// bare form too for older diagnostics, but never accept a mismatched bracket.
const MEDIAN = /Timestamp of block with id: (?:<([0-9a-f]{64})>|([0-9a-f]{64})), ([0-9]+), less than median of last 60 blocks, ([0-9]+)/;
const CALLER = /Block with id: (?:<([0-9a-f]{64})>|([0-9a-f]{64}))\s*(for alternative chain, )?has invalid timestamp: ([0-9]+)/;
// With file logging, std::endl causes the caller's two message lines to receive separate
// log prefixes. Pair those only when their millisecond, thread and source match, and when
// the median line came from that same thread and millisecond.
const PREFIXED_VERIFY = /^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\t(\[[^\]]+\])\tERROR\tverify\t([^\t]+)\t(.*)$/;
const CALLER_HEAD = /^Block with id: (?:<([0-9a-f]{64})>|([0-9a-f]{64}))$/;
const CALLER_TAIL = /^(for alternative chain, )?has invalid timestamp: ([0-9]+)$/;

function seconds(text) {
  const n = Number(text);
  return Number.isSafeInteger(n) ? n : null;
}

export function parseReceiverTimestampRefusals(log) {
  if (typeof log !== 'string') throw new TypeError('receiver log must be text');
  const lines = log.split(/\r?\n/);
  const refusals = [];
  for (let i = 0; i < lines.length; i += 1) {
    const match = MEDIAN.exec(lines[i]);
    if (!match) continue;
    const blockHash = match[1] ?? match[2];
    const timestamp = seconds(match[3]);
    const median = seconds(match[4]);
    if (timestamp === null || median === null || timestamp >= median) continue;
    const medianPrefix = PREFIXED_VERIFY.exec(lines[i]);
    // The caller emits a second line, sometimes with std::endl between the hash and the reason.
    // A nearby line is diagnostic only: never invent a path when the exact hash/number disagree.
    let path = 'UNKNOWN';
    for (let j = i + 1; j < Math.min(lines.length, i + 6); j += 1) {
      const caller = CALLER.exec(`${lines[j]} ${lines[j + 1] ?? ''}`);
      if (caller && (caller[1] ?? caller[2]) === blockHash && seconds(caller[4]) === timestamp) {
        path = caller[3] ? 'ALTERNATIVE' : 'MAIN';
        break;
      }
      const head = PREFIXED_VERIFY.exec(lines[j]);
      const tail = PREFIXED_VERIFY.exec(lines[j + 1] ?? '');
      if (!medianPrefix || !head || !tail
        || head[1] !== medianPrefix[1] || head[2] !== medianPrefix[2]
        || tail[1] !== head[1] || tail[2] !== head[2] || tail[3] !== head[3]) continue;
      const callerHead = CALLER_HEAD.exec(head[4]);
      const callerTail = CALLER_TAIL.exec(tail[4].trim());
      if (callerHead && callerTail && (callerHead[1] ?? callerHead[2]) === blockHash
        && seconds(callerTail[2]) === timestamp) {
        path = callerTail[1] ? 'ALTERNATIVE' : 'MAIN';
        break;
      }
    }
    refusals.push(Object.freeze({ blockHash, timestamp, median,
      path, line: i + 1 }));
  }
  return refusals;
}

export function matchingReceiverRefusal(refusals, { blockHash, timestamp, requireMain = true } = {}) {
  if (!Array.isArray(refusals) || !/^[0-9a-f]{64}$/.test(blockHash ?? '')
    || !Number.isSafeInteger(timestamp)) return null;
  return refusals.find((r) => r.blockHash === blockHash && r.timestamp === timestamp
    && r.timestamp < r.median
    && (requireMain ? r.path === 'MAIN' : ['MAIN', 'ALTERNATIVE'].includes(r.path))) ?? null;
}
