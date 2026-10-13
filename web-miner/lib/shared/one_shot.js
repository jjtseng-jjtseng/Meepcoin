// The Worker's own one-hash permit for the recorded-template simulation.
//
// WHY THIS EXISTS AS A SEPARATE, PURE MODULE. The page is supposed to compute EXACTLY ONE hash in
// this mode, and "the page only sends one command" is not containment. The permit lives here, with
// no Worker or Wasm imports, so the real Worker dispatcher (lib/worker_core.js) can use it and a
// test can drive that same dispatcher in Node.
//
// ONE PERMIT, ARMED AT init_context WITH THE SERVER'S EXACT NONCE, SPENT BY THE FIRST MATCHING
// hash_one, NEVER REISSUED.
//
// NO COERCION, ANYWHERE. The previous revision applied `msg.nonce >>> 0` BEFORE validating, so -1
// became 4294967295, 2^32 became 0, 1.5 became 1 and "7" became 7 -- each a perfectly valid uint32
// that could spend the permit. Admission now receives the RAW value, requires a safe integer inside
// the uint32 range, and requires it to be EXACTLY the armed nonce. The caller then hashes the
// PERMIT's nonce, never the message's.

export const ONE_SHOT_REFUSED = Object.freeze({
  NOT_ARMED: 'not_armed',
  STALE_GENERATION: 'stale_generation',
  WRONG_JOB: 'wrong_job',
  BAD_NONCE: 'bad_nonce',
  WRONG_NONCE: 'wrong_nonce',
  ALREADY_HASHED: 'already_hashed',
  ALREADY_ARMED: 'already_armed',
  TERMINATED: 'terminated',
});

/** A raw value that is ALREADY a uint32, with no conversion of any kind. */
export function isExactUint32(v) {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= 0xffffffff;
}

export function createOneShotPermit() {
  let armed = null;       // frozen { gen, jobId, nonce }
  let spent = false;
  let terminated = false;

  return {
    get armed() { return armed !== null; },
    get spent() { return spent; },
    get terminated() { return terminated; },
    get generation() { return armed?.gen ?? null; },
    get nonce() { return armed?.nonce ?? null; },

    /**
     * Issue the one permit, bound to a generation, a job and the server's exact nonce. A second
     * arm() is refused, so a repeated init_context cannot restore or redirect a permit.
     */
    arm({ gen, jobId, nonce }) {
      if (terminated) return { ok: false, reason: ONE_SHOT_REFUSED.TERMINATED };
      if (armed !== null) return { ok: false, reason: ONE_SHOT_REFUSED.ALREADY_ARMED };
      if (!Number.isSafeInteger(gen) || gen < 0) return { ok: false, reason: ONE_SHOT_REFUSED.STALE_GENERATION };
      if (typeof jobId !== 'string' || jobId.length === 0) return { ok: false, reason: ONE_SHOT_REFUSED.WRONG_JOB };
      if (!isExactUint32(nonce)) return { ok: false, reason: ONE_SHOT_REFUSED.BAD_NONCE };
      armed = Object.freeze({ gen, jobId, nonce });
      return { ok: true };
    },

    /**
     * Decide whether ONE hash may happen for this command, and spend the permit if so.
     *
     * `nonce` is the RAW message value. On success the result carries the ARMED nonce, which is the
     * only value the caller may hash or display.
     */
    admit({ gen, jobId, nonce }) {
      if (terminated) return { ok: false, reason: ONE_SHOT_REFUSED.TERMINATED };
      if (armed === null) return { ok: false, reason: ONE_SHOT_REFUSED.NOT_ARMED };
      if (gen !== armed.gen) return { ok: false, reason: ONE_SHOT_REFUSED.STALE_GENERATION };
      if (jobId !== armed.jobId) return { ok: false, reason: ONE_SHOT_REFUSED.WRONG_JOB };
      if (!isExactUint32(nonce)) return { ok: false, reason: ONE_SHOT_REFUSED.BAD_NONCE };
      if (nonce !== armed.nonce) return { ok: false, reason: ONE_SHOT_REFUSED.WRONG_NONCE };
      if (spent) return { ok: false, reason: ONE_SHOT_REFUSED.ALREADY_HASHED };
      spent = true;
      return { ok: true, nonce: armed.nonce };
    },

    /** A stop, or any terminal state. Irreversible: nothing re-arms a terminated permit. */
    terminate() { terminated = true; },
  };
}
