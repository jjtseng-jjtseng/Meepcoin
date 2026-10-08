#!/usr/bin/env python3
"""Validate all three network slots on fresh daemons.

Each slot gets a brand-new data directory and is launched on the ports its own config declares, so
"the configured port" and "the port actually bound" are checked against each other rather than
assumed equal. The frozen ~/.meepcoin-devnet is never touched.

Checks per slot: live genesis hash == the generator's prediction, nettype, ports bound, hard-fork
version, block target, economics, burned genesis reward. Then across slots: NETWORK_ID isolation
(a cross-slot P2P handshake must fail) and address-prefix isolation (an address from one slot must
be rejected by another).

Usage: validate_network_slots.py [out.md]

LOCALHOST / PRIVATE ONLY. Dev/test coins with no monetary value. Nothing is exposed publicly.
"""
import json, os, re, shutil, signal, subprocess, sys, time, urllib.request

BIN = os.path.expanduser("~/meepcoin-node/build/release/bin")
BASE = os.path.expanduser("~/.meepcoin-slotcheck")
OUT = sys.argv[1] if len(sys.argv) > 1 else "docs/NETWORK_SLOT_VALIDATION.md"

# slot -> (daemon flag, context label, nonce, p2p, rpc, zmq, addr prefix, expected genesis)
SLOTS = {
    "mainnet":  ("",           "mainnet",  20000, 19080, 19081, 19082, 61,
                 "5ee183402674af0316053bcf27ff159df18e8f62edef8137cb13a67dbb6f211f"),
    "testnet":  ("--testnet",  "devnet",   20001, 29080, 29081, 29082, 71,
                 "871bc633e7fa6b1698e8d9864472b12850baa5c7dc9c56e02e9f476d1d875c74"),
    "stagenet": ("--stagenet", "stagenet", 20002, 39080, 39081, 39082, 81,
                 "825a2f71d74fe8f5db559c42e81cd7f940de16c47461038aa1be4459b8e0df88"),
}

EXPECT_REWARD = 1192092895507
EXPECT_TARGET = 60
EXPECT_HF = 16

lines, npass, nfail = [], 0, 0
procs = {}


def say(s=""):
    print(s)
    lines.append(s)


def chk(cond, label):
    global npass, nfail
    if cond:
        npass += 1
        say(f"  [PASS] {label}")
    else:
        nfail += 1
        say(f"  [FAIL] {label}")
    return cond


def rpc(port, method, params=None, timeout=30):
    body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method,
                       "params": params if params is not None else {}}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/json_rpc", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def rest(port, path, params=None, timeout=30):
    body = json.dumps(params or {}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def port_open(p):
    import socket
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect(("127.0.0.1", p))
        return True
    except Exception:
        return False
    finally:
        s.close()


def generator_genesis(label, nonce):
    r = subprocess.run([f"{BIN}/meepcoin-genesis16", "gen", label, str(EXPECT_REWARD),
                        str(nonce), "1785283200"], capture_output=True, text=True)
    m = re.search(r"genesis_block_hash\s+=\s+([0-9a-f]{64})", r.stdout)
    return m.group(1) if m else None


def launch(slot):
    flag, label, nonce, p2p, rpcp, zmq, prefix, expect = SLOTS[slot]
    d = os.path.join(BASE, slot)
    if os.path.isdir(d):
        shutil.rmtree(d)
    os.makedirs(d)
    cmd = [f"{BIN}/meepcoind"]
    if flag:
        cmd.append(flag)
    cmd += ["--data-dir", d,
            "--p2p-bind-ip", "127.0.0.1", "--p2p-bind-port", str(p2p),
            "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", str(rpcp),
            "--zmq-rpc-bind-ip", "127.0.0.1", "--zmq-rpc-bind-port", str(zmq),
            "--no-igd", "--hide-my-port", "--disable-dns-checkpoints",
            "--non-interactive", "--log-level", "0",
            "--log-file", os.path.join(d, "meepcoind.log"),
            "--detach", "--pidfile", f"/tmp/meep-slot-{slot}.pid"]
    subprocess.run(cmd, capture_output=True)
    for _ in range(90):
        try:
            if "height" in rest(rpcp, "/get_info", timeout=3):
                return True
        except Exception:
            time.sleep(1)
    return False


def stop(slot):
    """Prefer stop_daemon over signalling a pidfile: the pidfile route left daemons running."""
    _, _, _, _, rpcp, _, _, _ = SLOTS[slot]
    try:
        rest(rpcp, "/stop_daemon", timeout=20)
        return
    except Exception:
        pass
    try:
        pid = int(open(f"/tmp/meep-slot-{slot}.pid").read().strip())
        os.kill(pid, signal.SIGTERM)
    except Exception:
        pass


def main():
    say("# MeepCoin — All-Network-Slot Validation")
    say()
    say("**LOCALHOST / PRIVATE ONLY. Dev/test coins with NO monetary value.** No slot is exposed "
        "to the internet; every daemon runs on 127.0.0.1 with `--no-igd --hide-my-port`.")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say("- Each slot uses a FRESH data directory under `~/.meepcoin-slotcheck/` and the ports its")
    say("  own config declares, so configured-vs-bound is checked rather than assumed.")
    say(f"- The frozen `~/.meepcoin-devnet` baseline is not touched.")
    say()

    os.makedirs(BASE, exist_ok=True)

    # ---------------------------------------------------------------- per slot
    live = {}
    for slot in ("mainnet", "testnet", "stagenet"):
        flag, label, nonce, p2p, rpcp, zmq, prefix, expect = SLOTS[slot]
        say(f"## Slot `{slot}` (context label `{label}`)")
        say()
        ok = launch(slot)
        chk(ok, f"{slot}: daemon started on a fresh data directory")
        if not ok:
            say()
            continue

        info = rest(rpcp, "/get_info")
        hdr = rpc(rpcp, "get_block_header_by_height", {"height": 0})["result"]["block_header"]
        gen_live = hdr["hash"]
        gen_tool = generator_genesis(label, nonce)
        live[slot] = dict(rpcp=rpcp, p2p=p2p, genesis=gen_live)

        say("| Property | Expected | Observed |")
        say("|---|---|---|")
        say(f"| genesis hash | `{expect}` | `{gen_live}` |")
        say(f"| generator predicts | `{gen_tool}` | — |")
        say(f"| nettype | {slot} | {info.get('nettype')} |")
        say(f"| genesis reward | {EXPECT_REWARD} | {hdr['reward']} |")
        say(f"| major/minor version | {EXPECT_HF}/{EXPECT_HF} | "
            f"{hdr['major_version']}/{hdr['minor_version']} |")
        say(f"| P2P / RPC / ZMQ | {p2p} / {rpcp} / {zmq} | "
            f"{'bound' if port_open(p2p) else 'NOT BOUND'} / bound / "
            f"{'bound' if port_open(zmq) else 'NOT BOUND'} |")
        say()

        # Never claim a match unless both sides are present and well formed.
        wellformed = (isinstance(gen_live, str) and len(gen_live) == 64
                      and isinstance(gen_tool, str) and len(gen_tool) == 64)
        chk(wellformed, f"{slot}: both genesis hashes present and 64 hex chars")
        if wellformed:
            chk(gen_live == gen_tool,
                f"{slot}: live genesis == generator prediction")
            chk(gen_live == expect,
                f"{slot}: live genesis == the hash recorded in the baseline manifest")
        chk(info.get("nettype") == slot, f"{slot}: daemon reports nettype '{slot}'")
        chk(int(hdr["reward"]) == EXPECT_REWARD,
            f"{slot}: burned genesis reward is {EXPECT_REWARD} atomic (11.92092895507 MEEP)")
        chk(int(hdr["major_version"]) == EXPECT_HF and int(hdr["minor_version"]) == EXPECT_HF,
            f"{slot}: genesis is hard-fork version {EXPECT_HF}/{EXPECT_HF}")
        chk(port_open(p2p), f"{slot}: P2P bound on the configured port {p2p}")
        chk(port_open(zmq), f"{slot}: ZMQ bound on the configured port {zmq}")
        # Block target and economics are compile-time and identical across slots; assert via the
        # daemon's own fee estimate path being alive plus the econ-dump tool.
        try:
            fe = rpc(rpcp, "get_fee_estimate")["result"]
            chk(int(fe["fee"]) > 0, f"{slot}: dynamic fee estimate responds ({fe['fee']}/byte)")
        except Exception as e:
            chk(False, f"{slot}: dynamic fee estimate responds ({e})")
        say()

    # ---------------------------------------------------------------- economics, once
    say("## Economics (compile-time, shared by all slots)")
    say()
    r = subprocess.run([f"{BIN}/meepcoin-econ-dump"], capture_output=True, text=True)
    chk("compiled economics MATCH the approved values" in r.stdout,
        "compiled economics match the approved values (all 10 assertions)")
    m = re.search(r"DIFFICULTY_TARGET_V2\s+=\s+(\d+)", r.stdout)
    chk(m and int(m.group(1)) == EXPECT_TARGET, f"block target is {EXPECT_TARGET} s")
    say()

    # ---------------------------------------------------------------- isolation
    say("## Cross-network isolation")
    say()
    say("### NETWORK_ID: a cross-slot P2P handshake must fail")
    say()
    # Ask the mainnet-slot daemon to connect to the testnet-slot daemon's P2P port. Different
    # NETWORK_ID means the handshake must be refused and no peer recorded.
    if "mainnet" in live and "testnet" in live:
        before = int(rest(live["mainnet"]["rpcp"], "/get_info").get("outgoing_connections_count", 0))
        try:
            rest(live["mainnet"]["rpcp"], "/json_rpc")  # no-op to keep the shape
        except Exception:
            pass
        # There is no "connect to peer" RPC; the supported way is --add-peer at startup. Instead
        # assert the property that actually matters and IS observable: the two slots have different
        # genesis hashes, so even a successful TCP handshake could not yield a shared chain.
        say("The daemon exposes no 'connect to this peer now' RPC, so this is asserted two ways:")
        say("the NETWORK_ID constants differ in the compiled config, and the slots' genesis hashes")
        say("differ — a peer that got past the handshake still could not share a chain.")
        say()
        gm, gt = live["mainnet"]["genesis"], live["testnet"]["genesis"]
        chk(gm != gt, "mainnet-slot and testnet-slot genesis hashes differ")
        after = int(rest(live["mainnet"]["rpcp"], "/get_info").get("outgoing_connections_count", 0))
        chk(after == 0 and before == 0,
            "the mainnet-slot daemon has zero outgoing connections (no accidental peering)")
    # NETWORK_ID differences straight from the compiled header.
    cfg = os.path.expanduser("~/meepcoin-node/src/cryptonote_config.h")
    src = open(cfg).read()
    ids = re.findall(r"NETWORK_ID\s*=\s*\{\s*\{([^}]*)\}", src)
    uniq = set(re.sub(r"\s+", "", i) for i in ids)
    chk(len(ids) >= 3 and len(uniq) == len(ids),
        f"all {len(ids)} NETWORK_ID constants in the config are distinct")
    say()

    say("### Address prefixes: an address from one slot must not validate on another")
    say()
    devaddr = open(os.path.expanduser(
        "~/.meepcoin-devnet/wallets/walletA.address.txt")).read().strip()
    say(f"- devnet (testnet-slot) address under test begins `{devaddr[:12]}...`")
    prefixes = {s: SLOTS[s][6] for s in SLOTS}
    say(f"- configured prefixes: " + ", ".join(f"{s}={p}" for s, p in prefixes.items()))
    chk(len(set(prefixes.values())) == 3, "all three address prefixes are distinct")
    say()
    say("`validate_address` is a WALLET RPC, not a daemon RPC. An earlier revision of this script")
    say("called it on the daemon: every call threw, which made both 'rejected' assertions pass for")
    say("the wrong reason. The positive control below is what caught that, and it is why it is here.")
    say()

    def wallet_probe(flag, port, tag):
        """Start a throwaway wallet-rpc on the given network and validate the devnet address."""
        d = os.path.join(BASE, f"wallet-{tag}")
        if os.path.isdir(d):
            shutil.rmtree(d)
        os.makedirs(d)
        cmd = [f"{BIN}/meepcoin-wallet-rpc"]
        if flag:
            cmd.append(flag)
        cmd += ["--wallet-dir", d, "--rpc-bind-port", str(port), "--disable-rpc-login",
                "--offline", "--log-file", os.path.join(d, "w.log")]
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        up = False
        for _ in range(60):
            try:
                rpc(port, "get_version", timeout=3)
                up = True
                break
            except Exception:
                time.sleep(1)
        out = {"up": up}
        if up:
            # A wallet must be OPEN: with any_net_type=false, validate_address compares against
            # m_wallet->nettype(), so with no wallet loaded the strict check cannot succeed and
            # returns invalid for every address -- including a correct one.
            try:
                rpc(port, "create_wallet",
                    {"filename": "probe", "password": "", "language": "English"}, timeout=120)
                out["wallet_open"] = True
            except Exception as e:
                out["wallet_open"] = False
                out["wallet_err"] = str(e)[:80]
            for anynet in (False, True):
                try:
                    r = rpc(port, "validate_address",
                            {"address": devaddr, "any_net_type": anynet})
                    res = r.get("result", {})
                    out[anynet] = (bool(res.get("valid")), res.get("nettype"))
                except Exception as e:
                    out[anynet] = (False, f"error: {str(e)[:60]}")
        try:
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=30)
        except Exception:
            p.kill()
        return out

    for flag, port, tag in (("--testnet", 25101, "testnet"),
                            ("--stagenet", 25102, "stagenet"),
                            ("", 25103, "mainnet")):
        res = wallet_probe(flag, port, tag)
        if not chk(res["up"], f"{tag} wallet-rpc started for address validation"):
            continue
        chk(res.get("wallet_open"),
            f"{tag}: a wallet is open, so the strict nettype comparison is meaningful"
            + (f" ({res.get('wallet_err')})" if not res.get("wallet_open") else ""))
        strict_valid, strict_net = res[False]
        any_valid, any_net = res[True]
        say(f"  - `{tag}` wallet: strict valid={strict_valid} (nettype {strict_net}); "
            f"any_net_type valid={any_valid} (nettype {any_net})")
        if tag == "testnet":
            chk(strict_valid,
                "POSITIVE CONTROL: the devnet address IS valid on a testnet-slot wallet")
            chk(any_net == "testnet",
                "the address's own network is reported as testnet")
        else:
            chk(not strict_valid,
                f"the devnet address is REJECTED by a {tag}-slot wallet")
            chk(any_valid and any_net == "testnet",
                f"the {tag} wallet still identifies it as a testnet address under any_net_type")
    say()

    # ---------------------------------------------------------------- teardown
    say("## Teardown")
    say()
    for slot in SLOTS:
        stop(slot)
    # Judge shutdown by whether the RPC ports are still accepting connections. A `ps | grep` count
    # also counts the grep process itself, which is how an earlier revision reported "2 remaining"
    # when only one daemon was actually up.
    rpc_ports = [SLOTS[s][4] for s in SLOTS]
    still = rpc_ports
    for _ in range(90):
        still = [p for p in rpc_ports if port_open(p)]
        if not still:
            break
        time.sleep(1)
    chk(not still,
        "all three slot daemons stopped (RPC ports closed)"
        + (f" -- still open: {still}" if still else ""))
    # The frozen baseline and the difficulty-test chain must be unaffected by this run.
    chk(not port_open(29081) and not port_open(29091),
        "the frozen devnet was not started by this test (its RPC ports stay closed)")
    say(f"- data directories left under `{BASE}` for inspection; nothing else was modified")
    say()
    say("---")
    say()
    say(f"**RESULT: {npass} passed, {nfail} failed**")
    say()
    say(f"**ALL-NETWORK-SLOT VALIDATION: {'PASS' if nfail == 0 else 'FAIL'}**")
    say()
    say("_Dev/test coins on private localhost chains. No monetary value._")

    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwritten to {OUT}")
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
