// Prospective, non-I/O pieces of a fresh-chain minority timestamp experiment.
// Both third-miner arms calculate the same candidate. Only ATTACK applies it.

export const REACHABILITY_MODES = Object.freeze({
  HONEST: 'HONEST', CONTROL: 'CONTROL', ATTACK: 'ATTACK',
});
export const FUTURE_LIMIT_SECONDS = 7200;
export const FUTURE_MARGIN_SECONDS = 5;
export const ASSIGNED_HASHES_PER_SECOND = Object.freeze({ h1: 45, h2: 45, third: 9 });

function requireInteger(value, name, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) {
    throw new RangeError(`${name} must be a safe integer >= ${min}`);
  }
  return value;
}

export function assignedThirdShare(rates = ASSIGNED_HASHES_PER_SECOND) {
  const { h1, h2, third } = rates;
  for (const [name, value] of Object.entries({ h1, h2, third })) {
    if (!Number.isSafeInteger(value) || value < 1 || value > 1000) {
      throw new RangeError(`${name} assigned rate must be 1..1000 H/s`);
    }
  }
  if (third >= h1 + h2) throw new RangeError('third miner is not assigned minority capacity');
  return { numerator: third, denominator: h1 + h2 + third };
}

export function candidateTimestamp({ height, medianTimestamp, nowSeconds }) {
  requireInteger(height, 'height', 1);
  requireInteger(medianTimestamp, 'medianTimestamp');
  requireInteger(nowSeconds, 'nowSeconds');
  const high = nowSeconds + FUTURE_LIMIT_SECONDS - FUTURE_MARGIN_SECONDS;
  if (!Number.isSafeInteger(high) || medianTimestamp > high) {
    throw new RangeError('timestamp window is not presently legal');
  }
  return height % 2 === 0
    ? Object.freeze({ timestamp: high, strategy: 'max-legal-future' })
    : Object.freeze({ timestamp: medianTimestamp, strategy: 'lowest-legal' });
}

export function thirdTimestampDecision({ mode, height, medianTimestamp, nowSeconds, templateTimestamp }) {
  if (mode !== REACHABILITY_MODES.CONTROL && mode !== REACHABILITY_MODES.ATTACK) {
    throw new RangeError('third miner mode must be CONTROL or ATTACK');
  }
  requireInteger(templateTimestamp, 'templateTimestamp');
  const computed = candidateTimestamp({ height, medianTimestamp, nowSeconds });
  if (templateTimestamp < medianTimestamp || templateTimestamp > nowSeconds + FUTURE_LIMIT_SECONDS) {
    throw new RangeError('daemon template timestamp lies outside the legal window');
  }
  return Object.freeze({
    mode, computedTimestamp: computed.timestamp, computedStrategy: computed.strategy,
    appliedTimestamp: mode === REACHABILITY_MODES.ATTACK ? computed.timestamp : templateTimestamp,
    appliedStrategy: mode === REACHABILITY_MODES.ATTACK ? computed.strategy : 'honest-template',
    candidateDiscarded: mode === REACHABILITY_MODES.CONTROL,
  });
}

// A fixed assigned opportunity schedule, anchored once per worker. Late work is missed,
// not caught up: a treatment-induced RPC stall remains an observed outcome.
export function createHashSchedule({ startMs, ratePerSecond }) {
  requireInteger(startMs, 'startMs');
  if (!Number.isSafeInteger(ratePerSecond) || ratePerSecond < 1 || ratePerSecond > 1000) {
    throw new RangeError('ratePerSecond must be 1..1000');
  }
  let nextSlot = 0;
  let missed = 0;
  return Object.freeze({
    get assignedRate() { return ratePerSecond; },
    get missedSlots() { return missed; },
    get nextSlot() { return nextSlot; },
    claim(nowMs) {
      requireInteger(nowMs, 'nowMs');
      if (nowMs < startMs) return Object.freeze({ ready: false, waitMs: startMs - nowMs });
      const elapsedSlot = Math.floor((nowMs - startMs) * ratePerSecond / 1000);
      if (elapsedSlot < nextSlot) {
        const due = startMs + Math.ceil(nextSlot * 1000 / ratePerSecond);
        return Object.freeze({ ready: false, waitMs: Math.max(1, due - nowMs) });
      }
      if (elapsedSlot > nextSlot) missed += elapsedSlot - nextSlot;
      const slot = elapsedSlot;
      nextSlot = slot + 1;
      return Object.freeze({ ready: true, slot, skippedBefore: missed });
    },
  });
}
