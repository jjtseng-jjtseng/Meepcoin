#!/usr/bin/env python3
"""Run the complete private-chain validation for the economics freeze and write the report.

One command, every check, honest verdicts. A check that cannot run is reported as SKIPPED with the
reason -- never silently omitted, and never counted as a pass.

Usage (from the repo root, inside WSL):
    python3 node/validate_freeze.py [--out docs/ECONOMICS_FREEZE_VALIDATION.md]

Assumes the devnet is already running (node/scripts/devnet.ps1 -Action start) and that the chain is
deep enough for the epoch-boundary vectors (height > 2113). Checks that depend on that depth are
reported as SKIPPED if it is not met, with the height stated.

LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.
"""
import argparse, json, os, re, subprocess, sys, time, urllib.request

HOME = os.path.expanduser("~")
NODE_BIN = f"{HOME}/meepcoin-node/build/release/bin"
MEEPOW = "/mnt/c/Users/tseng/meepcoin/meepow"
MEEPOW_BIN = f"{MEEPOW}/build/release"
NODE_RPC = 29081
NODE_B_RPC = 29091

results = []   # (section, name, verdict, detail)


def run(cmd, cwd=None, timeout=3600):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except FileNotFoundError as e:
        return 127, f"not found: {e}"
    except subprocess.TimeoutExpired:
        return 124, "timed out"


def record(section, name, verdict, detail=""):
    results.append((section, name, verdict, detail))
    mark = {"PASS": "[PASS]", "FAIL": "[FAIL]", "SKIP": "[SKIP]"}[verdict]
    print(f"  {mark} {name}" + (f"  -- {detail}" if detail else ""))


def check(section, name, cmd, want_re, cwd=None, timeout=3600):
    """Run a command; PASS iff exit 0 and the output matches want_re."""
    rc, out = run(cmd, cwd=cwd, timeout=timeout)
    m = re.search(want_re, out, re.MULTILINE)
    if rc == 0 and m:
        record(section, name, "PASS", m.group(0).strip())
    else:
        tail = " / ".join(l.strip() for l in out.strip().split("\n")[-3:])
        record(section, name, "FAIL", f"exit {rc}: {tail[:200]}")
    return rc == 0 and bool(m)


def rest(port, path, params=None, timeout=30):
    body = json.dumps(params or {}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="docs/ECONOMICS_FREEZE_VALIDATION.md")
    ap.add_argument("--no-vectors", action="store_true",
                    help="verify the COMMITTED vectors instead of regenerating them. Use once the "
                         "vectors are frozen: regenerating them would submit new blocks and mint "
                         "new artifacts, which is exactly what a frozen baseline must not do.")
    args = ap.parse_args()

    t0 = time.time()

    # ---------------------------------------------------------------- compiled rules
    print("\n== Compiled consensus rules ==")
    check("Compiled rules", "approved economics compile and assert",
          [f"{NODE_BIN}/meepcoin-econ-dump"],
          r"RESULT: compiled economics MATCH the approved values")
    check("Compiled rules", "emission boundary at MONEY_SUPPLY (underflow regression)",
          [f"{NODE_BIN}/meepcoin-emission-probe"],
          r"EMISSION BOUNDARY: PASS")
    check("Compiled rules", "11-decimal amount handling",
          [f"{NODE_BIN}/meepcoin-decimal-test"],
          r"11-DECIMAL AMOUNT TESTS: PASS")
    check("Compiled rules", "hard-fork schedule guard",
          [f"{NODE_BIN}/meepcoin-hardfork-test"],
          r"HARDFORK SCHEDULE TESTS: PASS")
    check("Compiled rules", "wallet fee fallback (derivation and margin)",
          [f"{NODE_BIN}/meepcoin-fee-fallback-test"],
          r"FEE FALLBACK TEST: PASS")

    # ---------------------------------------------------------------- frozen PoW
    print("\n== Frozen MeepHash-W v2 ==")
    check("Frozen PoW", "Checkpoint A public-API KATs",
          [f"{MEEPOW_BIN}/meepow-kat-v2-api"], r"KAT v2 API: PASS", cwd=MEEPOW)
    check("Frozen PoW", "full meepow unit suite",
          [f"{MEEPOW_BIN}/meepow-unit"], r"Status: SUCCESS!", cwd=MEEPOW)
    rc, out = run(["git", "diff", "--stat", "v2-frozen", "HEAD", "--",
                   "meepow/include/meepow/dataset_v2.hpp", "meepow/include/meepow/meepow_v2.hpp",
                   "meepow/include/meepow/meepow_v1.hpp", "meepow/include/meepow/vm.hpp",
                   "meepow/include/meepow/program.hpp", "meepow/include/meepow/blake3_xof.hpp",
                   "meepow/include/meepow/params_v1.hpp", "meepow/include/meepow/target.hpp",
                   "meepow/include/meepow/epoch.hpp", "meepow/vectors/vectors_v2.txt"])
    if rc == 0 and out.strip() == "":
        record("Frozen PoW", "frozen v2 surface is byte-identical to tag v2-frozen", "PASS",
               "empty diff")
    else:
        record("Frozen PoW", "frozen v2 surface is byte-identical to tag v2-frozen", "FAIL",
               out.strip()[:200])

    # ---------------------------------------------------------------- chain state
    print("\n== Chain ==")
    try:
        info_a = rest(NODE_RPC, "/get_info")
        height = int(info_a["height"])
        tip_a = info_a["top_block_hash"]
        record("Chain", "node A responds", "PASS", f"height {height}")
    except Exception as e:
        record("Chain", "node A responds", "FAIL", str(e)[:150])
        height, tip_a = 0, None

    try:
        info_b = rest(NODE_B_RPC, "/get_info")
        tip_b = info_b["top_block_hash"]
        hb = int(info_b["height"])
        if tip_a and tip_b and len(tip_a) == 64 and len(tip_b) == 64:
            if tip_a == tip_b and height == hb:
                record("Chain", "two-node synchronization", "PASS",
                       f"both at height {height}, tip {tip_a[:16]}...")
            else:
                record("Chain", "two-node synchronization", "FAIL",
                       f"A={height}/{tip_a[:16]} B={hb}/{tip_b[:16]}")
        else:
            record("Chain", "two-node synchronization", "FAIL", "a tip was missing or malformed")
    except Exception as e:
        record("Chain", "two-node synchronization", "FAIL", str(e)[:150])

    # Genesis: generator prediction vs the running daemon.
    EXPECTED_GENESIS = "871bc633e7fa6b1698e8d9864472b12850baa5c7dc9c56e02e9f476d1d875c74"
    rc, out = run([f"{NODE_BIN}/meepcoin-genesis16", "gen", "devnet", "1192092895507",
                   "20001", "1785283200"])
    m = re.search(r"genesis_block_hash\s+=\s+([0-9a-f]{64})", out)
    gen_hash = m.group(1) if m else None
    try:
        daemon_genesis = json.loads(urllib.request.urlopen(urllib.request.Request(
            f"http://127.0.0.1:{NODE_RPC}/json_rpc",
            data=json.dumps({"jsonrpc": "2.0", "id": "0",
                             "method": "get_block_header_by_height",
                             "params": {"height": 0}}).encode(),
            headers={"Content-Type": "application/json"}), timeout=30).read()
        )["result"]["block_header"]["hash"]
    except Exception as e:
        daemon_genesis = None
    # Never report a match until BOTH values are present and well formed.
    if not gen_hash or not daemon_genesis or len(daemon_genesis) != 64:
        record("Chain", "genesis: generator vs daemon", "FAIL",
               f"generator={gen_hash} daemon={daemon_genesis}")
    elif gen_hash == daemon_genesis == EXPECTED_GENESIS:
        record("Chain", "genesis: generator vs daemon", "PASS", gen_hash)
    else:
        record("Chain", "genesis: generator vs daemon", "FAIL",
               f"generator={gen_hash} daemon={daemon_genesis} expected={EXPECTED_GENESIS}")

    # ---------------------------------------------------------------- vectors
    print("\n== Block consensus vectors ==")
    if args.no_vectors:
        # Verify what is committed. revalidate_v16_vectors.py needs no chain: it re-derives every
        # recorded PoW from the recorded blockhashing blob through the public MeepHash-W v2 API and
        # re-checks each target verdict. That is a stronger statement about the frozen artifacts
        # than regenerating them would be, and it mints nothing.
        check("Vectors", "committed v16 vectors re-verify independently (no regeneration)",
              ["python3", "node/revalidate_v16_vectors.py", f"{MEEPOW_BIN}/meepow-v2-hash"],
              r"V16 BLOCK VECTORS: VALID")
        for name, path in (("main-chain vector file present",
                            "meepow/vectors/block_vectors_v16_devnet.json"),
                           ("alternate-chain vector file present",
                            "meepow/vectors/block_vectors_v16_altchain.json")):
            if os.path.exists(path):
                record("Vectors", name, "PASS", f"{os.path.getsize(path)} bytes")
            else:
                record("Vectors", name, "FAIL", "missing")
    elif height <= 2113:
        record("Vectors", "regenerate v16 block vectors", "SKIP",
               f"chain height {height} <= 2113; the epoch-boundary vectors need more depth")
        record("Vectors", "alternate-chain accept + invalid reject", "SKIP",
               f"chain height {height} <= 2113")
    else:
        ok_main = check("Vectors", "regenerate v16 block vectors (8 heights)",
                        ["python3", "node/block_vectors.py", str(NODE_RPC),
                         f"{MEEPOW_BIN}/meepow-v2-hash",
                         "meepow/vectors/block_vectors_v16_devnet.json",
                         f"{NODE_BIN}/meepcoin-blockhashing"],
                        r"wrote 8 vectors")
        # The alternate-chain vector must be regenerated BEFORE revalidation, because
        # revalidate_v16_vectors.py reads both files. Running it after made revalidation fail on a
        # missing file -- an ordering bug, not a consensus problem, but it reported as a FAIL.
        ok_alt = check("Vectors", "alternate-chain accept + invalid reject",
                       ["python3", "node/alt_chain_vector.py", str(NODE_RPC),
                        f"{MEEPOW_BIN}/meepow-v2-hash",
                        "meepow/vectors/block_vectors_v16_altchain.json"],
                       r"ALT-CHAIN: PASS")
        if ok_main and ok_alt:
            check("Vectors", "every regenerated vector re-verifies independently",
                  ["python3", "node/revalidate_v16_vectors.py", f"{MEEPOW_BIN}/meepow-v2-hash"],
                  r"V16 BLOCK VECTORS: VALID")
        else:
            record("Vectors", "every regenerated vector re-verifies independently", "SKIP",
                   "a vector file was not produced, so there is nothing to re-verify")

    # ---------------------------------------------------------------- write report
    npass = sum(1 for r in results if r[2] == "PASS")
    nfail = sum(1 for r in results if r[2] == "FAIL")
    nskip = sum(1 for r in results if r[2] == "SKIP")

    L = []
    a = L.append
    a("# MeepCoin — Economics Freeze Validation")
    a("")
    a("**LOCALHOST / PRIVATE ONLY. Dev/test coins with NO monetary value.**")
    a("")
    a(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    a(f"- Elapsed: {int(time.time() - t0)} s")
    a(f"- Chain height at validation: {height}")
    a("- Reproduce: `python3 node/validate_freeze.py`")
    a("")
    a(f"**{npass} passed, {nfail} failed, {nskip} skipped**")
    a("")
    section = None
    for sec, name, verdict, detail in results:
        if sec != section:
            a("")
            a(f"## {sec}")
            a("")
            a("| Check | Verdict | Detail |")
            a("|---|---|---|")
            section = sec
        a(f"| {name} | **{verdict}** | `{detail}` |" if detail
          else f"| {name} | **{verdict}** | |")
    a("")
    a("---")
    a("")
    if nfail == 0 and nskip == 0:
        a("**ECONOMICS FREEZE VALIDATION: PASS**")
    elif nfail == 0:
        a(f"**ECONOMICS FREEZE VALIDATION: INCOMPLETE** — {nskip} check(s) skipped, 0 failed. "
          "A skipped check is not a passed check.")
    else:
        a(f"**ECONOMICS FREEZE VALIDATION: FAIL** — {nfail} check(s) failed.")
    a("")
    a("Checks covered elsewhere, with their own reports:")
    a("")
    a("- wallet sync, RingCT/Bulletproof+ transfer of exactly 1 MEEP, invalid-nonce rejection,")
    a("  daemon-versus-independent MeepHash on main-chain blocks — `DEVNET_INTEGRATION_TEST.md`")
    a("- the burned genesis reward never appearing as spendable balance — `GENESIS_SPENDABILITY_TEST.md`")
    a("- fee, change and sender-balance arithmetic at 11 decimals — `FEE_ACCOUNTING_11DP.md`")
    a("")
    a("_Dev/test coins on a private localhost chain. No monetary value._")

    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L) + "\n")
    print(f"\n{npass} passed, {nfail} failed, {nskip} skipped -> {args.out}")
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
