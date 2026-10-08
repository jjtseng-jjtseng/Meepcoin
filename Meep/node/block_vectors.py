#!/usr/bin/env python3
"""Extract MeepCoin block-level consensus vectors from a running devnet node.

For each target height this records everything needed to re-verify the block's proof-of-work
independently of any MeepCoin code:

  height, block blob, nonce offset + byte order, blob with the nonce zeroed, epoch key,
  delayed-seed input, expected MeepHash-W v2 output, difficulty, target, expected pass/fail.

The expected output is recomputed with meepow-v2-hash, which goes through the PUBLIC v2 API
(meepow/v2.hpp) rather than the daemon's bridge. If the two disagree, that is a real defect and the
vector is what catches it.

Usage: block_vectors.py <rpc_port> <meepow_v2_hash_binary> [out.json]
"""
import json, subprocess, sys, urllib.request

SEEDHASH_EPOCH_BLOCKS = 2048
SEEDHASH_EPOCH_LAG = 64
UINT256_MAX = (1 << 256) - 1


def rpc(port, method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method,
                       "params": params or {}}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/json_rpc", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.loads(r.read())
    if "error" in d:
        raise RuntimeError(f"{method}: {d['error']}")
    return d["result"]


def seed_height(height):
    """Exactly rx_seedheight() from src/crypto/rx-slow-hash.c."""
    if height <= SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG:
        return 0
    return (height - SEEDHASH_EPOCH_LAG - 1) & ~(SEEDHASH_EPOCH_BLOCKS - 1)


def nonce_offset(blob):
    """Block hashing blob: 3 header varints, 32-byte prev_id, then a FIXED 4-byte LE nonce."""
    b = bytes.fromhex(blob)
    off = 0
    for _ in range(3):
        while b[off] & 0x80:
            off += 1
        off += 1
    return off + 32


def target_from_difficulty(diff):
    if diff == 0:
        return None
    return UINT256_MAX // diff


def le_hex_to_int(h):
    """Hashes/targets are little-endian 256-bit unsigned integers."""
    return int.from_bytes(bytes.fromhex(h), "little")


def hashing_blob(tool, full_blob):
    """PoW is computed over get_block_hashing_blob(), NOT the full block blob the RPC returns."""
    r = subprocess.run([tool, full_blob], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"blockhashing tool failed: {r.stderr.strip()}")
    return r.stdout.strip()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 29081
    hasher = sys.argv[2] if len(sys.argv) > 2 else "meepow-v2-hash"
    outp = sys.argv[3] if len(sys.argv) > 3 else "block_vectors.json"
    bhtool = sys.argv[4] if len(sys.argv) > 4 else "meepcoin-blockhashing"

    info = rpc(port, "get_info") if False else None  # get_info is REST, not json_rpc
    tip = rpc(port, "get_block_header_by_height", {"height": 0})  # probe
    chain_height = rpc(port, "get_last_block_header")["block_header"]["height"]
    print(f"chain tip height = {chain_height}")

    heights = [0, 1, 63, 64, 2047, 2048, 2112, 2113]
    heights = [h for h in heights if h <= chain_height]
    print(f"extracting heights: {heights}")

    hash_cache = {}

    def block_hash_at(h):
        if h not in hash_cache:
            hash_cache[h] = rpc(port, "get_block_header_by_height",
                                {"height": h})["block_header"]["hash"]
        return hash_cache[h]

    vectors = []
    for h in heights:
        blk = rpc(port, "get_block", {"height": h, "fill_pow_hash": True})
        hdr = blk["block_header"]
        full_blob = blk["blob"]
        blob = hashing_blob(bhtool, full_blob)   # the blob the PoW is actually computed over

        noff = nonce_offset(blob)
        raw = bytearray.fromhex(blob)
        nonce = int.from_bytes(raw[noff:noff + 4], "little")
        zeroed = bytearray(raw)
        zeroed[noff:noff + 4] = b"\x00\x00\x00\x00"
        zeroed_hex = zeroed.hex()

        sh = seed_height(h)
        seed = block_hash_at(sh)

        # CONSENSUS RULE: the Monero-derived epoch seed is fed as BOTH the MeepHash epoch key and
        # the delayed-seed input. See docs/BLOCK_CONSENSUS_VECTORS.md.
        epoch_key = seed
        delayed_seed = seed

        res = subprocess.run([hasher, epoch_key, delayed_seed, str(h), zeroed_hex, str(nonce)],
                             capture_output=True, text=True)
        if res.returncode != 0:
            print(f"  ! hasher failed at height {h}: {res.stderr.strip()}")
            pow_hash = None
        else:
            pow_hash = res.stdout.strip()

        # The check that catches a wrong PoW algorithm entirely: the DAEMON's own computed
        # pow_hash must equal our independent computation. Without this, a chain running some
        # other hash would still look internally consistent.
        daemon_pow = hdr.get("pow_hash")
        agrees = (daemon_pow == pow_hash) if (daemon_pow and pow_hash) else None

        diff = int(hdr["difficulty"])
        tgt = target_from_difficulty(diff)
        meets = None
        if pow_hash and tgt is not None:
            meets = le_hex_to_int(pow_hash) <= tgt

        # The block reward the daemon recorded, and the coinbase amount actually paid out. Under
        # HF_VERSION_EXACT_COINBASE (13) these must be equal at every height, so recording them
        # separately lets a vector catch them diverging instead of assuming they agree.
        block_reward = int(hdr["reward"])
        coinbase_amount = None
        try:
            mtx = json.loads(blk["json"])["miner_tx"]
            coinbase_amount = sum(int(v["amount"]) for v in mtx["vout"])
        except Exception as e:
            print(f"  ! could not read the coinbase amount at height {h}: {e}")

        vectors.append({
            "height": h,
            "block_hash": hdr["hash"],
            "prev_hash": hdr["prev_hash"],
            "timestamp": hdr["timestamp"],
            "major_version": hdr["major_version"],
            "minor_version": hdr["minor_version"],
            "full_block_blob": full_blob,
            "block_hashing_blob": blob,
            "nonce_offset_bytes": noff,
            "nonce_byte_order": "little-endian uint32",
            "nonce": nonce,
            "blob_nonce_zeroed": zeroed_hex,
            "seed_height": sh,
            "epoch_key": epoch_key,
            "delayed_seed_input": delayed_seed,
            "expected_meephash_w_v2": pow_hash,
            "daemon_pow_hash": daemon_pow,
            "daemon_agrees_with_independent_meephash": agrees,
            "difficulty": diff,
            "target_le_hex": tgt.to_bytes(32, "little").hex() if tgt is not None else None,
            "block_reward_atomic": block_reward,
            "coinbase_amount_atomic": coinbase_amount,
            "coinbase_equals_block_reward": (coinbase_amount == block_reward)
                                            if coinbase_amount is not None else None,
            "expected_result": ("PASS" if meets else "FAIL") if meets is not None else "UNKNOWN",
        })
        agree_s = "AGREE" if agrees else ("DISAGREE" if agrees is False else "n/a")
        cb_s = "OK" if coinbase_amount == block_reward else "MISMATCH"
        print(f"  h={h:<5} nonce={nonce:<12} seed_h={sh:<5} daemon-vs-independent={agree_s:<8} "
              f"target={'PASS' if meets else 'FAIL'}  reward={block_reward} coinbase={cb_s}  {pow_hash}")

    with open(outp, "w") as f:
        json.dump({"network": "meepcoin-devnet",
                   "consensus_rule": ("The Monero-derived epoch seed is fed as BOTH the MeepHash-W "
                                      "v2 epoch key and the delayed-seed input."),
                   "vectors": vectors}, f, indent=2)
    print(f"\nwrote {len(vectors)} vectors to {outp}")


if __name__ == "__main__":
    main()
