#!/usr/bin/env python3
"""Produce a genuine alternate-chain block vector.

Finds TWO distinct nonces that both satisfy the target for the SAME block template. Both are valid
blocks with the same parent at the same height. The first submitted becomes the tip; the second is
an ALTERNATE block, validated through get_altblock_longhash -- the code path that received the
`height` parameter during Checkpoint B and had never been exercised until now.

Usage: alt_chain_vector.py <rpc_port> <meepow-v2-hash> <out.json>
"""
import json, subprocess, sys, urllib.request

UINT256_MAX = (1 << 256) - 1


def rpc(port, method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method,
                       "params": params if params is not None else {}}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/json_rpc", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


def nonce_offset(raw):
    off = 0
    for _ in range(3):
        while raw[off] & 0x80:
            off += 1
        off += 1
    return off + 32


def main():
    port = int(sys.argv[1])
    mh = sys.argv[2]
    outp = sys.argv[3]

    addr = ("D1fwWoMWx1YKBvtSrp3nUDE35g3a2ebpFW3SJdAMRnP2gipdMmyQiTjgUe6WtYL454WSCdhii"
            "MHZ5SBuMuVXAUfaLNKSxv5")
    if len(sys.argv) > 4:
        addr = sys.argv[4]

    t = rpc(port, "get_block_template", {"wallet_address": addr, "reserve_size": 8})["result"]
    height = t["height"]
    diff = int(t["difficulty"])
    tmpl_full = t["blocktemplate_blob"]
    hashing = t["blockhashing_blob"]
    # The seed must come from rx_seedheight(height) -- NOT from get_block_template's seed_hash,
    # which is absent at block versions below RandomX and silently fell back to genesis, producing
    # a valid-looking hash against the wrong epoch key and a rejected block.
    def seed_height(h):
        if h <= 2048 + 64:
            return 0
        return (h - 64 - 1) & ~(2048 - 1)
    sh = seed_height(height)
    seed = rpc(port, "get_block_header_by_height",
               {"height": sh})["result"]["block_header"]["hash"]
    print(f"seed_height({height}) = {sh}")

    raw_h = bytearray.fromhex(hashing)
    noff = nonce_offset(raw_h)
    z = bytearray(raw_h); z[noff:noff + 4] = b"\x00\x00\x00\x00"
    zhex = z.hex()

    print(f"template height={height} difficulty={diff} seed={seed}")
    print(f"nonce offset={noff}")

    # Find two distinct satisfying nonces for the SAME template.
    found = []
    start = 1
    for _ in range(2):
        r = subprocess.run([mh, seed, seed, str(height), zhex, str(start), str(diff), "2000000"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"search failed: {r.stderr.strip()}")
            sys.exit(1)
        n, h = r.stdout.split()
        found.append((int(n), h))
        start = int(n) + 1
        print(f"  found nonce {n} -> {h}")

    # Submit both. First becomes the tip; second is an alternate block at the same height.
    raw_f = bytearray.fromhex(tmpl_full)
    fnoff = nonce_offset(raw_f)
    results = []
    for n, h in found:
        blk = bytearray(raw_f)
        blk[fnoff:fnoff + 4] = n.to_bytes(4, "little")
        resp = rpc(port, "submit_block", [blk.hex()])
        status = resp.get("result", {}).get("status") if "result" in resp else None
        err = resp.get("error")
        results.append({"nonce": n, "pow": h,
                        "submit_status": status,
                        "submit_error": err["message"] if err else None,
                        "full_block_blob": blk.hex()})
        print(f"  submitted nonce {n}: status={status} error={err['message'] if err else None}")

    # An alternate block must be REJECTED when its PoW does not meet the target. Accepting a genuine
    # sibling proves the alt-block path RUNS; it does not prove that path still CHECKS. These use the
    # same template at the same alternate height, differing only in the nonce.
    tgt = UINT256_MAX // diff
    print("\n  invalid alternate blocks (same height, PoW above target):")
    bad_results = []
    bad_nonces = []
    probe = 0
    while len(bad_nonces) < 3 and probe < 4000:
        r = subprocess.run([mh, seed, seed, str(height), zhex, str(probe)],
                           capture_output=True, text=True)
        if r.returncode == 0:
            ph = r.stdout.strip()
            if int.from_bytes(bytes.fromhex(ph), "little") > tgt:
                bad_nonces.append((probe, ph))
        probe += 1

    for n, ph in bad_nonces:
        blk = bytearray(raw_f)
        blk[fnoff:fnoff + 4] = n.to_bytes(4, "little")
        resp = rpc(port, "submit_block", [blk.hex()])
        status = resp.get("result", {}).get("status") if "result" in resp else None
        err = resp.get("error")
        rejected = status != "OK"
        bad_results.append({"nonce": n, "pow": ph, "meets_target": False,
                            "submit_status": status,
                            "submit_error": err["message"] if err else None,
                            "rejected": rejected})
        print(f"    nonce {n}: rejected={rejected} status={status} "
              f"error={err['message'] if err else None}")

    out = {
        "case": "alternate-chain siblings",
        "description": ("Two distinct nonces satisfying the same block template. Both are valid "
                        "blocks with the same parent at the same height. The first submitted "
                        "becomes the tip; the second is validated via get_altblock_longhash."),
        "height": height,
        "difficulty": diff,
        "target_le_hex": tgt.to_bytes(32, "little").hex(),
        "seed_height": sh,
        "epoch_key": seed,
        "delayed_seed_input": seed,
        "block_hashing_blob": hashing,
        "blob_nonce_zeroed": zhex,
        "nonce_offset_bytes_hashing_blob": noff,
        "nonce_offset_bytes_full_blob": fnoff,
        "nonce_byte_order": "little-endian uint32",
        "siblings": results,
        "invalid_siblings": bad_results,
        "expected_result": ("PASS (both siblings satisfy the target and are valid at this height; "
                            "every invalid sibling is rejected)"),
    }
    with open(outp, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nwrote alternate-chain vector to {outp}")

    accepted = [r for r in results if r["submit_status"] == "OK"]
    rejected = [r for r in bad_results if r["rejected"]]
    print(f"genuine siblings accepted: {len(accepted)} of {len(results)}")
    print(f"invalid siblings rejected: {len(rejected)} of {len(bad_results)}")
    ok = (len(accepted) == len(results) and len(results) == 2
          and len(bad_results) > 0 and len(rejected) == len(bad_results))
    print("ALT-CHAIN: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    # Propagate the verdict: a caller that ignores this would report a pass on a failed run.
    sys.exit(main())
