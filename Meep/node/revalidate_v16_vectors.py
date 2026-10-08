#!/usr/bin/env python3
"""Re-verify every committed v16 block vector against the independent MeepHash-W v2 public API.

This does NOT need a running chain. Each vector records the blockhashing blob (nonce zeroed),
the epoch key, the delayed-seed input, the height and the nonce. Feeding those back through
meepow-v2-hash must reproduce `expected_meephash_w_v2` byte for byte. It also re-checks the
recorded target comparison, so a vector cannot pass while claiming the wrong verdict.
"""
import json, subprocess, sys

HASHER = sys.argv[1] if len(sys.argv) > 1 else "meepow-v2-hash"
ROOT = "/mnt/c/Users/tseng/meepcoin/meepow/vectors/"

def pow_of(epoch_key, delayed_seed, height, zeroed_hex, nonce):
    r = subprocess.run([HASHER, epoch_key, delayed_seed, str(height), zeroed_hex, str(nonce)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("hasher failed: " + r.stderr.strip())
    return r.stdout.strip().split()[-1].lower()

def le_le(h, t):  # hash <= target, both little-endian hex
    return int.from_bytes(bytes.fromhex(h), "little") <= int.from_bytes(bytes.fromhex(t), "little")

npass = nfail = 0
def chk(cond, label):
    global npass, nfail
    if cond: npass += 1; print(f"  [PASS] {label}")
    else:    nfail += 1; print(f"  [FAIL] {label}")

# ---- main-chain devnet vectors -------------------------------------------------
d = json.load(open(ROOT + "block_vectors_v16_devnet.json"))
print(f"## block_vectors_v16_devnet.json  ({len(d['vectors'])} vectors)")
for v in d["vectors"]:
    h = v["height"]
    got = pow_of(v["epoch_key"], v["delayed_seed_input"], h, v["blob_nonce_zeroed"], v["nonce"])
    exp = v["expected_meephash_w_v2"].lower()
    chk(got == exp, f"height {h:<5} PoW reproduces  {exp[:16]}…"
                    + ("" if got == exp else f"  got {got[:16]}…"))
    chk(v["daemon_pow_hash"].lower() == exp, f"height {h:<5} daemon hash == independent")
    chk(v["daemon_agrees_with_independent_meephash"] is True, f"height {h:<5} agreement flag true")
    meets = le_le(exp, v["target_le_hex"])
    chk(v["expected_result"] == "PASS", f"height {h:<5} recorded verdict is PASS")
    chk(meets, f"height {h:<5} PoW meets the recorded target (difficulty {v['difficulty']})")

# ---- alternate-chain vector ----------------------------------------------------
a = json.load(open(ROOT + "block_vectors_v16_altchain.json"))
print(f"\n## block_vectors_v16_altchain.json  ({len(a['siblings'])} siblings at height {a['height']})")
for s in a["siblings"]:
    got = pow_of(a["epoch_key"], a["delayed_seed_input"], a["height"], a["blob_nonce_zeroed"], s["nonce"])
    exp = s["pow"].lower()
    chk(got == exp, f"nonce {s['nonce']:<6} PoW reproduces  {exp[:16]}…"
                    + ("" if got == exp else f"  got {got[:16]}…"))
    chk(le_le(exp, a["target_le_hex"]), f"nonce {s['nonce']:<6} meets the recorded target (difficulty {a['difficulty']})")
    chk(s["submit_status"] == "OK", f"nonce {s['nonce']:<6} recorded submit_status OK")

print(f"\nRESULT: {npass} passed, {nfail} failed")
print("V16 BLOCK VECTORS: " + ("VALID (unchanged by the patch)" if nfail == 0 else "INVALID"))
sys.exit(1 if nfail else 0)
