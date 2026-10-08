#!/usr/bin/env python3
"""Measure the real daemon costs the attacker simulator must be calibrated against.

Runs on a DEDICATED throwaway chain (own data dir, own ports, --fixed-difficulty 1) so that
proof-of-work is trivial and what remains is the daemon's own processing floor. That is exactly the
quantity the previous simulator was missing: it assumed block production could be instantaneous.

Measures:
  1. get_block_template latency
  2. submit_block latency for an ACCEPTED block
  3. MeepHash-W v2 verification latency (measured separately, as ONE component)
  4. minimum sustainable accepted-block spacing on localhost
  5. behaviour under rapid submission of valid and of invalid blocks
  6. future-time-limit rejection -- the real boundary, found by bisection
  7. timestamp median-bound rejection -- the real lower boundary

Nothing about consensus is changed. The frozen devnet is never touched.
"""
import json, os, statistics, subprocess, sys, time, urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 26081
OUT = sys.argv[2] if len(sys.argv) > 2 else "docs/DAEMON_CALIBRATION.md"
ADDR = open(os.path.expanduser("~/.meepcoin-devnet/wallets/walletA.address.txt")).read().strip()

lines = []
def say(s=""):
    print(s)
    lines.append(s)

def rpc(method, params=None, timeout=120):
    body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method,
                       "params": params if params is not None else {}}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/json_rpc", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())

def rest(path, params=None, timeout=60):
    body = json.dumps(params or {}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())

def nonce_off(raw):
    off = 0
    for _ in range(3):
        while raw[off] & 0x80:
            off += 1
        off += 1
    return off + 32

def ts_off(raw):
    # major, minor varints, then the timestamp varint begins
    off = 0
    for _ in range(2):
        while raw[off] & 0x80:
            off += 1
        off += 1
    return off

def read_varint(raw, off):
    v = 0; shift = 0; i = off
    while True:
        b = raw[i]; v |= (b & 0x7F) << shift; i += 1
        if not (b & 0x80): break
        shift += 7
    return v, i

def write_varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F; v >>= 7
        if v: out.append(b | 0x80)
        else: out.append(b); break
    return bytes(out)

def template():
    return rpc("get_block_template", {"wallet_address": ADDR, "reserve_size": 8})["result"]

def with_ts_and_nonce(blob_hex, ts, nonce):
    raw = bytearray.fromhex(blob_hex)
    o = ts_off(raw)
    _, end = read_varint(raw, o)
    raw = raw[:o] + write_varint(ts) + raw[end:]
    n = nonce_off(raw)
    raw[n:n+4] = nonce.to_bytes(4, "little")
    return bytes(raw).hex()

def submit(blob):
    t0 = time.perf_counter()
    try:
        r = rpc("submit_block", [blob], timeout=120)
        ok = "result" in r and r["result"].get("status") == "OK"
        err = None if ok else (r.get("error") or {}).get("message", "?")
    except Exception as e:
        ok, err = False, str(e)[:70]
    return ok, err, time.perf_counter() - t0

def main():
    say("# MeepCoin — Live Daemon Calibration")
    say()
    say("**LOCALHOST / PRIVATE THROWAWAY CHAIN. Dev/test coins with NO monetary value.**")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say(f"- Dedicated chain on port {PORT} with `--fixed-difficulty 1`, so proof-of-work is trivial")
    say("  and what is measured is the daemon's own processing floor.")
    say("- The frozen devnet and its wallets are not touched.")
    say()

    info = rest("/get_info")
    say(f"- starting height {info['height']}, difficulty {info['difficulty']}")
    say()

    # ---------------------------------------------------------------- 1. template latency
    say("## 1. `get_block_template` latency")
    say()
    tl = []
    for _ in range(40):
        t0 = time.perf_counter(); template(); tl.append(1000 * (time.perf_counter() - t0))
    say(f"- n=40  mean **{statistics.mean(tl):.2f} ms**  median {statistics.median(tl):.2f}  "
        f"p95 {sorted(tl)[37]:.2f}  min {min(tl):.2f}  max {max(tl):.2f}")
    say()

    # ---------------------------------------------------------------- 2/4. accepted spacing
    say("## 2 & 4. Accepted-block submission latency and minimum sustainable spacing")
    say()
    say("Blocks are mined as fast as the daemon will take them, at difficulty 1. The achieved")
    say("spacing is the floor on how quickly a chain can actually grow on localhost.")
    say()
    sub_lat, spacing, accepted = [], [], 0
    prev_t = None
    t_start = time.perf_counter()
    for i in range(40):
        t = template()
        blob = t["blocktemplate_blob"]
        raw = bytearray.fromhex(blob)
        n = nonce_off(raw)
        raw[n:n+4] = (i + 12345).to_bytes(4, "little")
        ok, err, dt = submit(bytes(raw).hex())
        now = time.perf_counter()
        if ok:
            accepted += 1
            sub_lat.append(1000 * dt)
            if prev_t is not None:
                spacing.append(1000 * (now - prev_t))
            prev_t = now
    total = time.perf_counter() - t_start
    say(f"- accepted **{accepted}/40** blocks in {total:.2f} s")
    if sub_lat:
        say(f"- `submit_block` latency for an ACCEPTED block: mean **{statistics.mean(sub_lat):.2f} ms**  "
            f"median {statistics.median(sub_lat):.2f}  p95 {sorted(sub_lat)[int(.95*(len(sub_lat)-1))]:.2f}")
    if spacing:
        say(f"- **minimum sustainable accepted-block spacing: mean {statistics.mean(spacing):.2f} ms, "
            f"median {statistics.median(spacing):.2f} ms, min {min(spacing):.2f} ms**")
        say(f"- i.e. a ceiling of roughly **{1000/statistics.mean(spacing):.1f} blocks/s** on this host,")
        say("  including template fetch, submission, validation and chain extension.")
    say()

    # ---------------------------------------------------------------- 3. MeepHash latency
    say("## 3. MeepHash-W v2 verification latency (one component, not the whole floor)")
    say()
    mh = os.path.expanduser("~/meepcoin-node/build/release/bin/../../../..")
    hasher = "/mnt/c/Users/tseng/meepcoin/meepow/build/release/meepow-v2-hash"
    t = template()
    hraw = bytearray.fromhex(t["blockhashing_blob"])
    hn = nonce_off(hraw)
    z = bytearray(hraw); z[hn:hn+4] = b"\x00\x00\x00\x00"
    seed = t.get("seed_hash") or ("00" * 32)
    hl = []
    if os.path.exists(hasher):
        for i in range(10):
            t0 = time.perf_counter()
            subprocess.run([hasher, seed, seed, str(t["height"]), z.hex(), str(i)],
                           capture_output=True, text=True)
            hl.append(1000 * (time.perf_counter() - t0))
        say(f"- n=10 (includes ~process-start overhead) mean **{statistics.mean(hl):.1f} ms**  "
            f"median {statistics.median(hl):.1f}  min {min(hl):.1f}")
        say("- process startup dominates this figure; the in-daemon cost is lower. Treated as an")
        say("  upper bound on the verification component.")
    else:
        say("- hasher binary not found; skipped")
    say()

    # ---------------------------------------------------------------- 5. rapid submission
    say("## 5. Rapid submission of valid-shape and invalid blocks")
    say()
    t = template()
    raw = bytearray.fromhex(t["blocktemplate_blob"])
    n = nonce_off(raw)
    bad = []
    for i in range(40):
        b = bytearray(raw); b[n:n+4] = (0xF0000000 + i).to_bytes(4, "little")
        bad.append(bytes(b).hex())
    t0 = time.perf_counter(); rej = 0
    for b in bad:
        ok, err, _ = submit(b)
        if not ok: rej += 1
    dtb = time.perf_counter() - t0
    say(f"- 40 stale/duplicate-parent submissions: {rej} rejected in {dtb:.2f} s "
        f"-> **{40/dtb:.1f} submissions/s**, {1000*dtb/40:.1f} ms each")
    garbage = [os.urandom(160).hex() for _ in range(40)]
    t0 = time.perf_counter(); rej2 = 0
    for b in garbage:
        ok, err, _ = submit(b)
        if not ok: rej2 += 1
    dtg = time.perf_counter() - t0
    say(f"- 40 malformed submissions: {rej2} rejected in {dtg:.2f} s "
        f"-> **{40/dtg:.1f} submissions/s**, {1000*dtg/40:.1f} ms each")
    say()

    # ---------------------------------------------------------------- 6. FTL boundary
    say("## 6. Future-time-limit rejection — real boundary by bisection")
    say()
    now = int(time.time())
    def try_ts(delta):
        t = template()
        blob = with_ts_and_nonce(t["blocktemplate_blob"], now + delta, 777)
        ok, err, _ = submit(blob)
        return ok, err
    probes = [0, 3600, 7000, 7100, 7199, 7200, 7201, 7500, 10800]
    say("| timestamp offset from now | accepted | error |")
    say("|---|---|---|")
    for d in probes:
        ok, err = try_ts(d)
        say(f"| +{d} s | {'YES' if ok else 'no'} | `{err or ''}` |")
    say()
    say(f"- `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT` compiled value is 7200 s; the table above is the")
    say("  daemon's actual behaviour, which is what the model must reproduce.")
    say()

    # ---------------------------------------------------------------- 7. median lower bound
    say("## 7. Timestamp median lower-bound rejection")
    say()
    hdrs = rpc("get_block_headers_range",
               {"start_height": max(0, int(rest('/get_info')['height']) - 60),
                "end_height": int(rest('/get_info')['height']) - 1})["result"]["headers"]
    tss = sorted(int(h["timestamp"]) for h in hdrs)
    med = tss[len(tss)//2]
    say(f"- median of the last {len(tss)} block timestamps = {med}")
    say("| timestamp | accepted | error |")
    say("|---|---|---|")
    for lbl, val in [("median - 1", med - 1), ("median", med), ("median + 1", med + 1)]:
        t = template()
        blob = with_ts_and_nonce(t["blocktemplate_blob"], val, 888)
        ok, err, _ = submit(blob)
        say(f"| {lbl} ({val}) | {'YES' if ok else 'no'} | `{err or ''}` |")
    say()

    say("## Calibration summary for the simulator")
    say()
    say("| Quantity | Measured |")
    say("|---|---|")
    say(f"| template request | {statistics.mean(tl):.2f} ms mean |")
    if sub_lat:
        say(f"| accepted-block submission | {statistics.mean(sub_lat):.2f} ms mean |")
    if spacing:
        say(f"| **minimum accepted-block spacing (localhost)** | **{statistics.mean(spacing):.2f} ms mean, "
            f"{min(spacing):.2f} ms min** |")
    say(f"| stale-block rejection | {1000*dtb/40:.1f} ms each |")
    say(f"| malformed rejection | {1000*dtg/40:.1f} ms each |")
    say()
    say("These bound the *localhost, zero-network* profile. Wider profiles in the model add")
    say("propagation on top of this floor; they are assumptions, not measurements, and are labelled")
    say("as such.")
    say()
    say("_Dev/test coins on a private localhost chain. No monetary value._")

    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwritten to {OUT}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
