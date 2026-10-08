// The only place in this slice that touches the MeepHash-W Wasm exports.
//
// Both the browser Web Worker and the development pool's share verifier build a hasher through
// this factory, each from its OWN instance of the local build artifact that matches the committed
// frozen source and the identity pinned in pool/dev/wasm_identity.json. That is deliberate: it makes
// "client and server ran the same frozen algorithm" structurally true while keeping the two
// instances independent, so the server never reuses client state.
//
// IMPORTANT HONESTY NOTE: two instances of the SAME WebAssembly build agreeing is NOT an
// independent-implementation cross-check, and neither is Wasm agreeing with the native build or
// the daemon. Those are three distinct EXECUTION AND BUILD PATHS over the same MeepHash lineage,
// not three independently authored algorithms. What their agreement catches is a build, marshalling,
// context or transport fault in one path -- not a shared design error.
//
// TWO CONTEXTS ARE AVAILABLE. createV2Hasher() builds the FIXED SYNTHETIC context that
// meep_v2_setup() has always used, which is what the runnable browser miner still runs and what the
// committed vectors_v2.txt vectors cover. createV2HasherForContext() takes an arbitrary frozen-v2
// context, which is what a real daemon block template needs. A synthetic context carries no
// consensus meaning; a real one does, and is only ever supplied by the server.

export const V2_DATASET_BYTES = 32 * 1024 * 1024;
export const V2_SCRATCHPAD_BYTES = 8 * 1024 * 1024;

/** Mirrors MEEP_V2_MAX_TEMPLATE_BYTES / meepow::v2::MAX_TEMPLATE_BYTES. */
export const MAX_TEMPLATE_BYTES = 1 << 20;

/** Return codes from meep_v2_setup_ctx / meep_v2_run1_checked. 0 is the only success. */
export const V2_ERR = Object.freeze({
  0: 'ok',
  1: 'null_argument',
  2: 'invalid_template',
  3: 'allocation_failed',
  4: 'no_active_context',
});

const U64_MAX = (1n << 64n) - 1n;

/**
 * Normalise a block height to an exact unsigned 64-bit BigInt.
 *
 * A plain Number is accepted only when it is a safe integer, because above 2^53 a Number has
 * already lost the exact value before this function can see it -- and a height that is off by one
 * hashes a DIFFERENT context than the daemon did, silently. Strings and BigInts keep full range.
 */
export function toHeightU64(height) {
  let v;
  if (typeof height === 'bigint') {
    v = height;
  } else if (typeof height === 'number') {
    if (!Number.isInteger(height)) throw new RangeError('height must be an integer');
    if (!Number.isSafeInteger(height)) {
      throw new RangeError('height exceeds Number.MAX_SAFE_INTEGER; pass a BigInt or a decimal string');
    }
    v = BigInt(height);
  } else if (typeof height === 'string') {
    if (!/^(0|[1-9][0-9]*)$/.test(height)) throw new RangeError('height string must be canonical decimal');
    v = BigInt(height);
  } else {
    throw new TypeError('height must be a number, bigint or decimal string');
  }
  if (v < 0n || v > U64_MAX) throw new RangeError('height must fit in an unsigned 64-bit integer');
  return v;
}

function requireBytes(value, len, what) {
  if (!(value instanceof Uint8Array)) throw new TypeError(`${what} must be a Uint8Array`);
  if (value.length !== len) throw new RangeError(`${what} must be exactly ${len} bytes, got ${value.length}`);
  return value;
}

/**
 * Build a hasher over an ARBITRARY frozen-v2 context.
 *
 * `context` is the four consensus inputs the daemon supplies:
 *   epochKey  Uint8Array(32)
 *   seedHash  Uint8Array(32)
 *   height    number | bigint | decimal string, exact uint64
 *   template  Uint8Array, the block hashing blob WITH THE NONCE ZEROED, 1..MAX_TEMPLATE_BYTES
 *
 * The daemon passes the SAME 32 bytes as epoch key and seed hash (src/crypto/meep-hash.cpp calls
 * Dataset::create(seed) and Hasher::create(..., seed, ...) from one `seedhash` argument), so a
 * caller mirroring a real template simply passes `seed_hash` twice. They are separate parameters
 * here because meepow::v2_ctx_create takes them separately.
 *
 * EVERY argument is validated BEFORE any allocation or hashing. One active context per module
 * instance: this tears down whatever was active first, so a failed setup cannot leave a stale
 * context hashing the wrong template.
 */
export async function createV2HasherForContext(createModule, context) {
  if (context === null || typeof context !== 'object') throw new TypeError('context must be an object');
  const epochKey = requireBytes(context.epochKey, 32, 'epochKey');
  const seedHash = requireBytes(context.seedHash, 32, 'seedHash');
  const height = toHeightU64(context.height);
  const template = context.template;
  if (!(template instanceof Uint8Array)) throw new TypeError('template must be a Uint8Array');
  if (template.length === 0) throw new RangeError('template must not be empty');
  if (template.length > MAX_TEMPLATE_BYTES) {
    throw new RangeError(`template must be at most ${MAX_TEMPLATE_BYTES} bytes, got ${template.length}`);
  }

  // SNAPSHOT BEFORE THE FIRST await. createModule() suspends, and a caller that still holds these
  // arrays could rewrite the epoch key, seed hash or template while it is pending -- so the bytes
  // validated above would not be the bytes set up below. Copy first, then validate nothing again:
  // from here on these locals are the only inputs.
  const epochKeySnap = epochKey.slice();
  const seedHashSnap = seedHash.slice();
  const templateSnap = template.slice();

  const M = await createModule();

  // Height crosses the boundary as two uint32 halves. Marshalling a uint64 through a JS Number
  // would round above 2^53; this keeps it exact regardless of how the build maps i64.
  const heightLo = Number(height & 0xffffffffn);
  const heightHi = Number((height >> 32n) & 0xffffffffn);

  const ekPtr = M._malloc(32);
  const shPtr = M._malloc(32);
  const tmplPtr = M._malloc(templateSnap.length);
  const out = M._malloc(32);
  const release = () => {
    if (ekPtr) M._free(ekPtr);
    if (shPtr) M._free(shPtr);
    if (tmplPtr) M._free(tmplPtr);
    if (out) M._free(out);
  };
  if (!ekPtr || !shPtr || !tmplPtr || !out) {
    release();
    throw new Error('meepow wasm: could not allocate the context input buffers');
  }

  let rc;
  try {
    M.HEAPU8.set(epochKeySnap, ekPtr);
    M.HEAPU8.set(seedHashSnap, shPtr);
    M.HEAPU8.set(templateSnap, tmplPtr);
    rc = M.ccall(
      'meep_v2_setup_ctx', 'number',
      ['number', 'number', 'number', 'number', 'number', 'number'],
      [ekPtr, shPtr, heightLo, heightHi, tmplPtr, templateSnap.length],
    );
  } catch (err) {
    release();
    throw err;
  }
  // The inputs are copied into the context by setup; the staging buffers are not needed again.
  M._free(ekPtr);
  M._free(shPtr);
  M._free(tmplPtr);

  if (rc !== 0) {
    M._free(out);
    throw new Error(`meep_v2_setup_ctx failed: ${V2_ERR[rc] ?? `rc=${rc}`}`);
  }

  let calls = 0;
  let freed = false;

  return {
    /** Number of real MeepHash-W v2 hash computations performed through this hasher. */
    get hashCalls() {
      return calls;
    },
    /** The context this hasher is bound to, for assertions. Copies, so a caller cannot mutate it. */
    get context() {
      return {
        epochKey: epochKeySnap.slice(),
        seedHash: seedHashSnap.slice(),
        height,
        template: templateSnap.slice(),
      };
    },
    wasmHeapBytes() {
      return M.HEAPU8.length;
    },
    /** True while the Wasm side still holds this context. */
    isActive() {
      return !freed && M.ccall('meep_v2_active', 'number', [], []) === 1;
    },
    /** One nonce -> 32-byte little-endian hash. Copies out of the Wasm heap before returning. */
    hashOne(nonce) {
      if (freed) throw new Error('hasher already freed');
      if (!Number.isInteger(nonce) || nonce < 0 || nonce > 0xffffffff) {
        throw new RangeError('nonce must be a uint32');
      }
      calls++;
      // The CHECKED entry point: a torn-down context is an error rather than 32 zero bytes that
      // would look like a real -- and extremely low -- hash.
      const hrc = M.ccall('meep_v2_run1_checked', 'number', ['number', 'number'], [nonce >>> 0, out]);
      if (hrc !== 0) throw new Error(`meep_v2_run1_checked failed: ${V2_ERR[hrc] ?? `rc=${hrc}`}`);
      const hash = M.HEAPU8.slice(out, out + 32);
      // The caller compares this byte-for-byte against another build. A short or wrong-typed
      // result must be an explicit error here rather than something a comparison quietly treats
      // as a mismatch -- those two mean very different things.
      if (!(hash instanceof Uint8Array) || hash.length !== 32) {
        throw new Error('meepow wasm: hash result was not 32 bytes');
      }
      return hash;
    },
    /** Release the Wasm-side context AND this hasher's buffers. Idempotent. */
    free() {
      if (freed) return;
      freed = true;
      M.ccall('meep_v2_teardown', null, [], []);
      M._free(out);
    },
  };
}

/**
 * The FIXED SYNTHETIC context, unchanged.
 *
 * Kept as a thin wrapper over createV2HasherForContext so the existing local demo, the committed
 * vectors_v2.txt known-answer vectors and every existing test keep working byte-for-byte. The
 * constants are the ones meep_v2_setup() has always used.
 *
 * @param {() => Promise<any>} createModule  the default export of meepow/wasm/meepow.mjs
 */
export async function createV2Hasher(createModule) {
  return createV2HasherForContext(createModule, {
    epochKey: Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 1) & 0xff),
    seedHash: Uint8Array.from({ length: 32 }, (_, i) => (i * 3 + 9) & 0xff),
    height: 4096,
    template: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]),
  });
}
