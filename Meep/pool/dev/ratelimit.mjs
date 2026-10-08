// Per-connection token bucket. The clock is injected so the tests can prove refill behaviour
// without sleeping.

export function createTokenBucket({ capacity = 8, refillPerSecond = 4, now = () => Date.now() } = {}) {
  if (capacity <= 0) throw new RangeError('capacity must be positive');
  if (refillPerSecond <= 0) throw new RangeError('refillPerSecond must be positive');

  let tokens = capacity;
  let lastMs = now();

  function refill() {
    const t = now();
    const elapsed = t - lastMs;
    if (elapsed <= 0) return;
    lastMs = t;
    tokens = Math.min(capacity, tokens + (elapsed / 1000) * refillPerSecond);
  }

  return {
    /** Consume one token. False means rate limited. */
    take() {
      refill();
      if (tokens < 1) return false;
      tokens -= 1;
      return true;
    },
    peek() {
      refill();
      return tokens;
    },
  };
}
