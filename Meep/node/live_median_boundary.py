#!/usr/bin/env python3
"""Item 4 + item 7: LIVE median-timestamp-boundary tests and the missing daemon calibrations.

Runs against THROWAWAY chains on their own data dirs and ports. The frozen devnet at
~/.meepcoin-devnet is never opened, and no consensus code is modified.

Item 4 -- median lower bound, tested live in 8 required configurations:
    fewer than 60 prior blocks / exactly 60 / more than 60
    timestamp == daemon median / median-1 / median+1
    main-chain submission / alternative-chain submission
  Each case runs on its OWN fresh chain so an accepted probe cannot contaminate the next case.
  Recorded per case: the complete timestamp window the daemon uses, the sorted vector, the median
  index or indices, the computed median, the submitted timestamp, acceptance, the exact daemon log
  line, whether proof-of-work was reached, and what each simulator variant predicts.

Item 7 -- the previously missing measurements:
    template refresh after an accepted parent, two-daemon P2P propagation, competing valid blocks
    to different nodes, node under CPU load, node under disk load, concurrent block processing.

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
"""
import hashlib, http.client, json, os, shutil, socket, statistics, subprocess, sys
import threading, time
import urllib.error, urllib.request

HOME = os.path.expanduser("~")
# MEEP_DAEMON lets a run target a specific build (baseline / T1+T2 / candidate A / B)
# without editing anything. Every report records which binary it used.
DAEMON = os.environ.get("MEEP_DAEMON",
                        os.path.join(HOME, "meepcoin-node/build/release/bin/meepcoind"))
ADDR = open(os.path.join(HOME, ".meepcoin-devnet/wallets/walletA.address.txt")).read().strip()
ROOT = os.path.join(HOME, ".meepcoin-live-median")
OUT = sys.argv[1] if len(sys.argv) > 1 else "docs/LIVE_MEDIAN_BOUNDARY.md"
TS_WINDOW = 60            # BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW
HUGE_DIFF = 10 ** 12      # makes every submitted block fail proof-of-work

lines = []
def say(s=""):
    print(s, flush=True)
    lines.append(s)


# ----------------------------------------------------------------- RPC plumbing
# A busy daemon under sustained submit_block load occasionally resets an RPC socket. That is a
# transport failure, not a consensus answer, and it aborted a measured STAR run once. Transient
# transport errors are retried; RPC-level errors in the response body are never retried, and
# submit_block passes retries=1 so a lost response can never be replayed as a second submission.
_TRANSIENT = (ConnectionResetError, ConnectionAbortedError, http.client.RemoteDisconnected,
              http.client.BadStatusLine, socket.timeout, TimeoutError)


class RpcMetrics:
    """Thread-safe per-port, per-method RPC accounting.

    The previous manifest recorded `Daemon.rpc_retries`, an attribute that never existed, so every
    measured run stored three nulls where the retry evidence should have been. These counters are
    real and are serialised per node."""
    def __init__(self):
        self._lock = threading.Lock()
        self.d = {}

    def _slot(self, port, method):
        key = (int(port), method)
        with self._lock:
            return self.d.setdefault(key, {"calls": 0, "http_attempts": 0, "retries": 0,
                                           "transient_terminal_failures": 0, "rpc_errors": 0,
                                           "submit_unknown": 0})

    def bump(self, port, method, field, n=1):
        slot = self._slot(port, method)
        with self._lock:
            slot[field] += n

    def export(self):
        with self._lock:
            out = {}
            for (port, method), v in self.d.items():
                out.setdefault(str(port), {})[method] = dict(v)
            return out


METRICS = RpcMetrics()


def _post(url, body, timeout, retries, port=None, method="?"):
    last = None
    if port is not None:
        METRICS.bump(port, method, "calls")
    for i in range(max(1, retries)):
        if port is not None:
            METRICS.bump(port, method, "http_attempts")
            if i:
                METRICS.bump(port, method, "retries")
        try:
            req = urllib.request.Request(url, data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                out = json.loads(r.read())
            if port is not None and isinstance(out, dict) and out.get("error"):
                METRICS.bump(port, method, "rpc_errors")
            return out
        except _TRANSIENT as e:
            last = e
        except urllib.error.URLError as e:
            if not isinstance(getattr(e, "reason", None), _TRANSIENT):
                raise
            last = e
        time.sleep(0.15 * (i + 1))
    if port is not None:
        METRICS.bump(port, method, "transient_terminal_failures")
    raise last


def rpc(port, method, params=None, timeout=120, retries=3):
    body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method,
                       "params": params if params is not None else {}}).encode()
    return _post(f"http://127.0.0.1:{port}/json_rpc", body, timeout, retries, port, method)


def rest(port, path, params=None, timeout=60, retries=3):
    body = json.dumps(params or {}).encode()
    return _post(f"http://127.0.0.1:{port}{path}", body, timeout, retries, port, path)


# ----------------------------------------------------------------- block blob surgery
def _skip_varints(raw, n, off=0):
    for _ in range(n):
        while raw[off] & 0x80:
            off += 1
        off += 1
    return off

def ts_off(raw):        return _skip_varints(raw, 2)          # after major+minor
def prev_off(raw):      return _skip_varints(raw, 3)          # after major+minor+timestamp
def nonce_off(raw):     return prev_off(raw) + 32

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

def rebuild(blob_hex, ts=None, nonce=None, prev_hex=None):
    raw = bytearray.fromhex(blob_hex)
    if ts is not None:
        o = ts_off(raw)
        _, end = read_varint(raw, o)
        raw = bytearray(raw[:o] + write_varint(ts) + raw[end:])
    if prev_hex is not None:
        p = prev_off(raw)
        raw[p:p + 32] = bytes.fromhex(prev_hex)
    if nonce is not None:
        n = nonce_off(raw)
        raw[n:n + 4] = nonce.to_bytes(4, "little")
    return bytes(raw).hex()


# ----------------------------------------------------------------- daemon lifecycle
class Daemon:
    def __init__(self, tag, p2p, rpcp, fixed_diff=1, offline=True, extra=None, wipe=True,
                 data_dir=None, hide_port=True, max_conn_per_ip=8):
        self.tag, self.p2p, self.rpc, self.fixed = tag, p2p, rpcp, fixed_diff
        # data_dir lets a caller point at an existing chain (always a COPY -- never the preserved
        # devnet) instead of a scratch directory under ROOT.
        self.dir = data_dir or os.path.join(ROOT, tag)
        if wipe and os.path.isdir(self.dir):
            shutil.rmtree(self.dir)
        os.makedirs(self.dir, exist_ok=True)
        self.log = os.path.join(self.dir, "meepcoind.log")
        self.log_mark = os.path.getsize(self.log) if os.path.exists(self.log) else 0
        cmd = [DAEMON, "--testnet", "--data-dir", self.dir,
               "--p2p-bind-ip", "127.0.0.1", "--p2p-bind-port", str(p2p),
               "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", str(rpcp),
               "--no-igd", "--non-interactive",
               # --max-connections-per-ip defaults to 1 (net_node.cpp:179). Every node in these
               # experiments lives on 127.0.0.1, so with the default each daemon accepts exactly
               # ONE inbound connection from loopback and a three-node full mesh is impossible:
               # the survivors form a star and the refused dials log
               #   "CONNECTION FROM 127.0.0.1 REFUSED, too many connections from the same address"
               # This is a loopback test-harness artifact, not consensus behaviour, and it shaped
               # the topology of every earlier multi-node run in this project.
               "--max-connections-per-ip", str(max_conn_per_ip),
               "--fixed-difficulty", str(fixed_diff),
               # the ZMQ port defaults to 29082 on testnet for EVERY instance, so two daemons on
               # one host collide there even with distinct p2p and RPC ports
               "--zmq-rpc-bind-ip", "127.0.0.1", "--zmq-rpc-bind-port", str(rpcp + 3000),
               "--log-file", self.log, "--log-level", "0"]
        # --hide-my-port advertises port 0, so a peer cannot dial back on the listening port. That
        # is harmless for a single link but it is one candidate explanation for the incomplete mesh
        # seen in earlier runs, so it is now switchable and recorded per run.
        if hide_port:
            cmd.append("--hide-my-port")
        if offline:
            cmd.append("--offline")
        cmd += (extra or [])
        self.argv = list(cmd)
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, start_new_session=True)
        self.wait_up()
        # MERROR_VER lines live in the "verify" category, which log-level 0 suppresses.
        try:
            rest(self.rpc, "/set_log_categories",
                 {"categories": "*:WARNING,verify:ERROR,global:INFO"})
        except Exception as e:
            say(f"  ! could not raise log categories on {tag}: {e}")

    def wait_up(self, secs=90):
        t0 = time.time()
        while time.time() - t0 < secs:
            try:
                rest(self.rpc, "/get_info", timeout=3)
                return
            except Exception:
                time.sleep(0.25)
        raise RuntimeError(f"daemon {self.tag} did not come up on {self.rpc}")

    def stop_record(self):
        """Structured shutdown outcome, for the manifest."""
        return {"tag": self.tag, "path": getattr(self, "stop_path", None),
                "exited": self.proc.poll() is not None,
                "returncode": self.proc.poll(), "pid": self.proc.pid}

    def stop(self, clean_wait=5.0):
        """Shut the daemon down and RETURN PROMPTLY.

        `clean_wait` is how long to wait for a polite stop_daemon exit before escalating. The 5 s
        default keeps large case sweeps fast; callers that need a genuinely clean LMDB close
        (snapshot builders) pass a longer window and check `stop_path == "clean"`.

        The old version called proc.wait(timeout=30) and, because stop_daemon does not always make
        the process exit quickly, hit the full 30 s on essentially every call. With two daemons per
        case that added 60 s of pure waiting to every test case, which is what made the height-31
        regression look like a hang: 15 cases x 60 s per height, multiplied across 11 heights.
        Measured, not guessed -- see docs/H31_DIAGNOSIS.md.

        Now: ask politely, poll briefly, then escalate. Records which path was taken."""
        self.stop_path = "clean"
        try:
            rpc(self.rpc, "stop_daemon", timeout=5)
        except Exception:
            self.stop_path = "rpc-failed"
        deadline = time.time() + clean_wait
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return
            time.sleep(0.1)
        self.stop_path = "terminated"
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
            return
        except Exception:
            pass
        self.stop_path = "killed"
        try:
            self.proc.kill()
            self.proc.wait(timeout=5)
        except Exception:
            pass

    def mark_log(self):
        self.log_mark = os.path.getsize(self.log) if os.path.exists(self.log) else 0

    def new_log(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log, "r", errors="replace") as f:
            f.seek(self.log_mark)
            return [l.rstrip("\n") for l in f.readlines()]

    # -- convenience
    def info(self):     return rest(self.rpc, "/get_info")
    def height(self):   return int(self.info()["height"])

    def wait_synced(self, secs=120):
        """get_block_template returns CORE_BUSY until the daemon considers itself synchronized,
        which a non-offline daemon only does after its sync loop settles."""
        t0 = time.time()
        while time.time() - t0 < secs:
            try:
                if self.info().get("synchronized", False):
                    return True
            except Exception:
                pass
            time.sleep(0.5)
        return False

    def template(self, tries=60):
        last = None
        for _ in range(tries):
            r = rpc(self.rpc, "get_block_template",
                    {"wallet_address": ADDR, "reserve_size": 8})
            if "result" in r:
                return r["result"]
            last = (r.get("error") or {}).get("message", str(r)[:80])
            time.sleep(0.5)
        raise RuntimeError(f"get_block_template on {self.tag} kept failing: {last}")

    def submit_detailed(self, blob):
        """Submit a block and return a STRUCTURED, serialisable outcome.

        The daemon's COMMAND_RPC_SUBMITBLOCK response carries `block_id`, which on_submitblock
        computes with parse_and_validate_block_from_blob() from the submitted bytes themselves
        (core_rpc_server.cpp: `res.block_id = pod_to_hex(blk_id)`). That identifier is exact.

        The previous attribution scheme instead called get_block_header_by_height() after a
        successful submit and assumed the canonical block at that height belonged to the submitter.
        With concurrent miners and sub-second blocks that lookup races and can return a competing
        miner's block, so every aggregate derived from it was potentially misattributed.

        Outcomes:
          ACCEPTED                        status OK, exact block_id returned
          REJECTED                        the daemon answered with an RPC error
          UNKNOWN_AFTER_TRANSPORT_ERROR   no answer arrived. The candidate may or may not have been
                                          accepted. It is NEVER resubmitted automatically and must
                                          never be counted as an ordinary rejection.
        """
        raw = bytes.fromhex(blob)
        rec = {"blob_sha256": hashlib.sha256(raw).hexdigest(), "blob_bytes": len(raw),
               "submitted_wall": time.time()}
        t0 = time.perf_counter()
        try:
            # retries=1: a reset after a successful submit must not be replayed
            r = rpc(self.rpc, "submit_block", [blob], timeout=120, retries=1)
            res = r.get("result") or {}
            if res.get("status") == "OK":
                rec.update(outcome="ACCEPTED", block_id=res.get("block_id"),
                           status=res.get("status"), error=None)
            else:
                rec.update(outcome="REJECTED", block_id=None, status=res.get("status"),
                           error=(r.get("error") or {}).get("message", "?"))
        except _TRANSIENT as e:
            METRICS.bump(self.rpc, "submit_block", "submit_unknown")
            rec.update(outcome="UNKNOWN_AFTER_TRANSPORT_ERROR", block_id=None, status=None,
                       error=f"{type(e).__name__}: {str(e)[:120]}")
        except Exception as e:
            METRICS.bump(self.rpc, "submit_block", "submit_unknown")
            rec.update(outcome="UNKNOWN_AFTER_TRANSPORT_ERROR", block_id=None, status=None,
                       error=f"{type(e).__name__}: {str(e)[:120]}")
        rec["latency_s"] = round(time.perf_counter() - t0, 6)
        return rec

    def submit(self, blob):
        """Backwards-compatible three-value API kept for existing callers.

        An UNKNOWN transport outcome is reported here as not-accepted with the transport message,
        exactly as before. Callers that need to distinguish UNKNOWN from REJECTED -- which any
        producer-attributed analysis must -- use submit_detailed()."""
        d = self.submit_detailed(blob)
        return d["outcome"] == "ACCEPTED", d.get("error"), d["latency_s"]

    def mine(self, n, nonce_base=0):
        got = 0
        for i in range(n * 4):
            if got >= n:
                break
            t = self.template()
            ok, err, _ = self.submit(rebuild(t["blocktemplate_blob"], nonce=nonce_base + i))
            if ok:
                got += 1
        if got < n:
            raise RuntimeError(f"only mined {got}/{n} on {self.tag}")

    def rpc_block_header(self, height):
        return rpc(self.rpc, "get_block_header_by_height",
                   {"height": height})["result"]["block_header"]

    def timestamps(self, lo, hi):
        """Block timestamps for heights lo..hi inclusive."""
        if hi < lo:
            return []
        hdrs = rpc(self.rpc, "get_block_headers_range",
                   {"start_height": lo, "end_height": hi})["result"]["headers"]
        return [int(h["timestamp"]) for h in hdrs]


# ----------------------------------------------------------------- the rules, in Python
def epee_median(v):
    """epee::misc_utils::median -- what the daemon actually calls."""
    if not v: return 0
    if len(v) == 1: return v[0]
    s = sorted(v)
    n = len(s) // 2
    return s[n] if len(s) % 2 else (s[n - 1] + s[n]) // 2

def main_chain_window(d, chain_h):
    """Blockchain::check_block_timestamp -- heights h-60 .. h-1, and NO check below 60 blocks."""
    if chain_h < TS_WINDOW:
        return [], (0, -1), None, False
    lo, hi = chain_h - TS_WINDOW, chain_h - 1
    ts = d.timestamps(lo, hi)
    return ts, (lo, hi), epee_median(ts), True

def alt_chain_window(d, prev_h):
    """Blockchain::complete_timestamps_vector -> check_block_timestamp, taken by
    handle_alternative_block. Two documented differences from the main-chain path:
      * it walks heights prev_h down to stop_offset+1, so on a short chain it EXCLUDES genesis;
      * there is no `if (h < 60) return true` guard, so the median applies at ANY height."""
    stop_offset = prev_h - TS_WINDOW if prev_h > TS_WINDOW else 0
    lo, hi = stop_offset + 1, prev_h
    ts = d.timestamps(lo, hi)
    return ts, (lo, hi), epee_median(ts), True

def netsim_round2_rule(window_ts, chain_h):
    """What the ROUND-2 simulator did: sorted[n/2] over up to 60, applied at every height."""
    if not window_ts:
        return 0, True
    s = sorted(window_ts)
    return s[len(s) // 2], True


# ----------------------------------------------------------------- item 4
CASES = [
    # tag, prior blocks to mine, which timestamp, chain
    ("A", 30, "median",      "main"),
    ("B", 30, "median-1",    "main"),
    ("C", 30, "median+1",    "main"),
    ("D", 60, "median",      "main"),
    ("E", 60, "median-1",    "main"),
    ("F", 60, "median+1",    "main"),
    ("G", 90, "median-1",    "main"),
    ("H", 90, "median-1",    "alt"),
    ("I", 90, "median",      "alt"),
    ("J", 59, "median-1",    "main"),   # boundary control: one block short of the window
    ("K", 30, "median-1",    "alt"),    # the main/alt asymmetry below 60 blocks
    ("L", 30, "median",      "alt"),
]

def item4():
    say("## Item 4 — live median-timestamp-boundary tests")
    say()
    say("Each case runs on its own freshly wiped chain, so an accepted probe cannot move the median")
    say("seen by the next case. `chain_h` is `m_db->height()` (the block COUNT), which is what")
    say("`Blockchain::check_block_timestamp` compares against `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW`.")
    say()
    results = []
    port = 26180
    for tag, mine_to, which, chain in CASES:
        d = Daemon(f"case{tag}", port, port + 1, fixed_diff=1)
        port += 4
        try:
            # mine_to counts blocks ON TOP of genesis, so chain_h ends at mine_to+1
            need = mine_to + 1 - d.height()
            if need > 0:
                d.mine(need, nonce_base=1000)
            h = d.height()                      # block count; tip height is h-1
            if chain == "main":
                window, (lo, hi), med, applies = main_chain_window(d, h)
            else:
                window, (lo, hi), med, applies = alt_chain_window(d, h - 1)

            # what the ROUND-2 simulator would have computed: sorted[n/2] over the last 60
            # timestamps INCLUDING genesis, applied unconditionally at every height
            r2_win = d.timestamps(max(0, h - TS_WINDOW), h - 1)
            sim2 = netsim_round2_rule(r2_win, h)[0]

            base = med if med is not None else epee_median(d.timestamps(max(0, h - TS_WINDOW), h - 1))
            ts = {"median": base, "median-1": base - 1, "median+1": base + 1}[which]

            tip = d.info()["top_block_hash"]
            t = d.template()
            parent_of_template = t["prev_hash"]

            d.mark_log()
            if chain == "main":
                blob = rebuild(t["blocktemplate_blob"], ts=ts, nonce=0xABCD00)
                ok, err, dt = d.submit(blob)
                submitted_parent = parent_of_template
            else:
                # alternative chain: accept one block first, then submit a SECOND block at the same
                # height on the same parent. Its coinbase height is correct, so the only novelty is
                # that it takes handle_alternative_block().
                first = rebuild(t["blocktemplate_blob"], nonce=0x111111)
                ok0, err0, _ = d.submit(first)
                if not ok0:
                    raise RuntimeError(f"alt setup failed: {err0}")
                d.mark_log()
                blob = rebuild(t["blocktemplate_blob"], ts=ts, nonce=0x222222)
                ok, err, dt = d.submit(blob)
                submitted_parent = parent_of_template

            log = [l for l in d.new_log()
                   if any(k in l for k in ("timestamp", "proof of work", "Block with id",
                                           "alternative", "invalid"))]
            results.append(dict(
                tag=tag, chain=chain, which=which, chain_h=h, window_lo=lo, window_hi=hi,
                window=window, median=med, applies=applies, sim_r2=sim2,
                ts=ts, accepted=ok, err=err, ms=1000 * dt, log=log, tip=tip,
                parent=submitted_parent))
            say(f"  case {tag}: chain_h={h} n_window={len(window)} "
                f"daemon_median={med} ts={ts} ({which}, {chain}) -> "
                f"{'ACCEPTED' if ok else 'rejected'} {err or ''}")
        finally:
            d.stop()
    return results


def item4_pow_order():
    """Does the timestamp check run BEFORE proof-of-work? Decide it, do not assume it."""
    say()
    say("### Was proof-of-work reached?")
    say()
    say("Decided by experiment rather than by reading the source: a chain is mined at")
    say("`--fixed-difficulty 1`, the daemon is restarted on the SAME data dir at")
    say(f"`--fixed-difficulty {HUGE_DIFF}` so that no submitted block can pass proof-of-work, and two")
    say("blocks are then submitted -- one with a valid timestamp, one below the median. Whichever")
    say("rejection reason the daemon reports is the check that ran first.")
    say()
    d = Daemon("poworder", 26240, 26241, fixed_diff=1)
    try:
        d.mine(90 - d.height() + 1, nonce_base=7000)
        h = d.height()
        window = d.timestamps(max(0, h - TS_WINDOW), h - 1)
        med = epee_median(window)
        t = d.template()
    finally:
        d.stop()
    d2 = Daemon("poworder", 26240, 26241, fixed_diff=HUGE_DIFF, wipe=False)
    out = []
    try:
        for label, ts in [("valid timestamp, bad PoW", med + 100),
                          ("timestamp below median, bad PoW", med - 1)]:
            d2.mark_log()
            ok, err, dt = d2.submit(rebuild(t["blocktemplate_blob"], ts=ts, nonce=0x5150))
            log = [l for l in d2.new_log() if "verify" in l or "Block with id" in l]
            out.append((label, ts, ok, err, log))
            say(f"  {label}: ts={ts} -> {'ACCEPTED' if ok else 'rejected'} `{err}`")
            for l in log[:3]:
                say("      log: " + l.split(chr(9))[-1][:150])
    finally:
        d2.stop()
    return med, out


# ----------------------------------------------------------------- item 7
def busy_load(n, stop_evt):
    def spin():
        x = 0
        while not stop_evt.is_set():
            x = (x * 1103515245 + 12345) & 0xFFFFFFFF
    return [threading.Thread(target=spin, daemon=True) for _ in range(n)]

def measure_submit_and_refresh(d, n=40, nonce_base=0):
    """Measurement 2: parent accepted -> next template available at the new height."""
    subs, refresh = [], []
    for i in range(n):
        t = d.template()
        h_before = int(t["height"])
        ok, err, dt = d.submit(rebuild(t["blocktemplate_blob"], nonce=nonce_base + i))
        if not ok:
            continue
        subs.append(1000 * dt)
        t0 = time.perf_counter()
        for _ in range(400):
            t2 = d.template()
            if int(t2["height"]) > h_before:
                break
            time.sleep(0.001)
        refresh.append(1000 * (time.perf_counter() - t0))
    return subs, refresh

def item7():
    say()
    say("## Item 7 — the previously missing daemon calibrations")
    say()
    say("All figures are **measured on this host, over localhost loopback**. The datacenter,")
    say("regional, global and congested profiles in the simulator are **assumptions**; nothing here")
    say("measures them, and they are labelled as assumptions wherever they appear.")
    say()
    res = {}

    # ---- 2. template refresh after an accepted parent, and the baseline submit cost
    d = Daemon("calibA", 26200, 26201, fixed_diff=1)
    try:
        d.mine(40, nonce_base=100)
        subs, refresh = measure_submit_and_refresh(d, 40, nonce_base=2000)
        res["submit_quiet"] = subs
        res["refresh_quiet"] = refresh
        say(f"- **template refresh after an accepted parent** (n={len(refresh)}): "
            f"mean {statistics.mean(refresh):.2f} ms, median {statistics.median(refresh):.2f}, "
            f"min {min(refresh):.2f}, max {max(refresh):.2f}  "
            f"_(1 ms poll granularity is the resolution floor)_")
        say(f"- accepted-block submit, quiet host (n={len(subs)}): "
            f"mean {statistics.mean(subs):.2f} ms, median {statistics.median(subs):.2f}, "
            f"min {min(subs):.2f}, max {max(subs):.2f}")

        # ---- 7. concurrent block processing
        say()
        errs = []
        def one(i, acc):
            t = d.template()
            ok, err, dt = d.submit(rebuild(t["blocktemplate_blob"], nonce=0x900000 + i))
            acc.append((ok, 1000 * dt))
        for k in (2, 4, 8):
            acc = []
            th = [threading.Thread(target=one, args=(k * 100 + i, acc)) for i in range(k)]
            t0 = time.perf_counter()
            for x in th: x.start()
            for x in th: x.join()
            wall = 1000 * (time.perf_counter() - t0)
            nok = sum(1 for o, _ in acc if o)
            lat = [l for _, l in acc]
            res[f"concurrent{k}"] = (wall, nok, lat)
            say(f"- **{k} concurrent submissions**: wall {wall:.1f} ms, {nok}/{k} accepted "
                f"(only one can extend a given tip), per-call mean {statistics.mean(lat):.1f} ms, "
                f"max {max(lat):.1f} ms")

        # ---- 5. node under CPU load
        say()
        stop = threading.Event()
        threads = busy_load(max(2, os.cpu_count() - 2), stop)
        for t_ in threads: t_.start()
        time.sleep(1.0)
        subs_c, refresh_c = measure_submit_and_refresh(d, 30, nonce_base=3000)
        stop.set()
        res["submit_cpu"], res["refresh_cpu"] = subs_c, refresh_c
        say(f"- **node under CPU load** ({len(threads)} busy threads): submit mean "
            f"{statistics.mean(subs_c):.2f} ms (quiet {statistics.mean(subs):.2f}), "
            f"template refresh mean {statistics.mean(refresh_c):.2f} ms "
            f"(quiet {statistics.mean(refresh):.2f})")

        # ---- 6. node under disk load
        stopd = threading.Event()
        def diskspin():
            p = os.path.join(ROOT, "diskload.bin")
            buf = os.urandom(4 << 20)
            while not stopd.is_set():
                with open(p, "wb") as f:
                    f.write(buf); f.flush(); os.fsync(f.fileno())
            try: os.remove(p)
            except Exception: pass
        dth = [threading.Thread(target=diskspin, daemon=True) for _ in range(2)]
        for t_ in dth: t_.start()
        time.sleep(1.0)
        subs_d, refresh_d = measure_submit_and_refresh(d, 30, nonce_base=4000)
        stopd.set()
        res["submit_disk"], res["refresh_disk"] = subs_d, refresh_d
        say(f"- **node under disk load** (2 fsync writers): submit mean "
            f"{statistics.mean(subs_d):.2f} ms (quiet {statistics.mean(subs):.2f}), "
            f"template refresh mean {statistics.mean(refresh_d):.2f} ms "
            f"(quiet {statistics.mean(refresh):.2f})")
    finally:
        d.stop()

    # ---- 3. two-daemon P2P propagation, and 4. competing blocks to different nodes
    say()
    a = Daemon("p2pA", 26210, 26211, fixed_diff=1, offline=False)
    b = Daemon("p2pB", 26220, 26221, fixed_diff=1, offline=False,
               extra=["--add-exclusive-node", "127.0.0.1:26210"])
    try:
        sa, sb = a.wait_synced(), b.wait_synced()
        say(f"- daemons report synchronized: A={sa} B={sb} "
            f"_(get_block_template refuses to build until then)_")
        t0 = time.time()
        while time.time() - t0 < 60:
            try:
                if int(a.info().get("outgoing_connections_count", 0)) + \
                   int(a.info().get("incoming_connections_count", 0)) > 0:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        say(f"- P2P link established: A in/out = "
            f"{a.info().get('incoming_connections_count')}/{a.info().get('outgoing_connections_count')}")

        prop = []
        for i in range(25):
            hb = b.height()
            t = a.template()
            ok, err, _ = a.submit(rebuild(t["blocktemplate_blob"], nonce=0x770000 + i))
            if not ok:
                continue
            t0 = time.perf_counter()
            seen = None
            while time.perf_counter() - t0 < 20:
                if b.height() > hb:
                    seen = time.perf_counter() - t0
                    break
                time.sleep(0.0005)
            if seen is not None:
                prop.append(1000 * seen)
        res["prop"] = prop
        if prop:
            say(f"- **two-daemon P2P propagation, localhost** (n={len(prop)}): mean "
                f"{statistics.mean(prop):.1f} ms, median {statistics.median(prop):.1f}, "
                f"min {min(prop):.1f}, max {max(prop):.1f}  "
                f"_(measured by polling B's height; the poll loop plus B's own RPC cost is included,"
                f" so this is an UPPER bound on true propagation)_")
        else:
            say("- two-daemon P2P propagation: **no samples** (link did not carry blocks)")

        # 4. competing valid blocks to different nodes
        say()
        ha = a.height()
        ta, tb = a.template(), b.template()
        outs = {}
        def push(node, blob, key):
            outs[key] = node.submit(blob)
        th = [threading.Thread(target=push, args=(a, rebuild(ta["blocktemplate_blob"], nonce=0xAA01), "A")),
              threading.Thread(target=push, args=(b, rebuild(tb["blocktemplate_blob"], nonce=0xBB01), "B"))]
        t0 = time.perf_counter()
        for x in th: x.start()
        for x in th: x.join()
        conv = None
        while time.perf_counter() - t0 < 20:
            if a.info()["top_block_hash"] == b.info()["top_block_hash"]:
                conv = time.perf_counter() - t0
                break
            time.sleep(0.001)
        res["competing"] = (outs, conv, ha)
        say(f"- **competing valid blocks to different nodes**: A -> {outs.get('A')[0]}, "
            f"B -> {outs.get('B')[0]}; "
            + (f"tips reconverged after {1000*conv:.1f} ms" if conv is not None
               else "tips had NOT reconverged within 20 s"))
        say(f"  A tip {a.info()['top_block_hash'][:16]}  B tip {b.info()['top_block_hash'][:16]} "
            f"heights {a.height()}/{b.height()}")
    except Exception as e:
        # A failure here must not discard the measurements already taken. Record it and say so.
        res["p2p_error"] = f"{type(e).__name__}: {e}"
        say(f"- **two-daemon P2P section FAILED**: `{res['p2p_error']}`. The propagation and")
        say("  competing-block figures are therefore NOT AVAILABLE in this run. Recorded as a gap.")
    finally:
        b.stop(); a.stop()
    return res


# ----------------------------------------------------------------- report
def main():
    if not os.path.exists(DAEMON):
        say(f"daemon not found at {DAEMON}"); return 1
    os.makedirs(ROOT, exist_ok=True)

    say("# MeepCoin — Live Median Boundary and Daemon Calibration Ranges")
    say()
    say("> **ANALYSIS ONLY.** Throwaway private chains on their own data dirs and ports. No")
    say("> consensus, genesis, economics, frozen tag or public infrastructure is touched.")
    say("> Dev/test coins with no monetary value.")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say(f"- `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` = {TS_WINDOW}")
    say()

    r4 = item4()
    med, powout = item4_pow_order()
    r7 = item7()

    # ---------------- item 4 table
    say()
    say("### Per-case evidence")
    say()
    say("| case | chain | chain_h | window heights | n | daemon median | rule applies | submitted ts "
        "| daemon verdict | round-2 sim predicted | corrected sim predicted |")
    say("|---|---|---|---|---|---|---|---|---|---|---|")
    mismatch_r2 = mismatch_fix = 0
    for r in r4:
        n = len(r["window"])
        pred_r2 = "reject" if r["ts"] < r["sim_r2"] else "accept"
        pred_fix = "accept" if not r["applies"] else ("reject" if r["ts"] < r["median"] else "accept")
        actual = "accept" if r["accepted"] else "reject"
        if pred_r2 != actual: mismatch_r2 += 1
        if pred_fix != actual: mismatch_fix += 1
        say(f"| {r['tag']} | {r['chain']} | {r['chain_h']} | {r['window_lo']}..{r['window_hi']} | {n} "
            f"| {r['median'] if r['median'] is not None else '_n/a — fewer than 60 blocks_'} "
            f"| {'yes' if r['applies'] else '**no**'} | {r['ts']} ({r['which']}) "
            f"| **{actual.upper()}** {('`'+r['err']+'`') if r['err'] else ''} "
            f"| {pred_r2} {'✗' if pred_r2 != actual else '✓'} "
            f"| {pred_fix} {'✗' if pred_fix != actual else '✓'} |")
    say()
    say(f"**Round-2 simulator rule: {mismatch_r2}/{len(r4)} cases mispredicted.**")
    say(f"**Corrected rule: {mismatch_fix}/{len(r4)} cases mispredicted.**")
    say()

    say("### Full timestamp windows, sorting and median index")
    say()
    for r in r4:
        s = sorted(r["window"])
        say(f"<details><summary>case {r['tag']} — chain_h={r['chain_h']}, n={len(s)}</summary>")
        say()
        say(f"- raw window (heights {r['window_lo']}..{r['window_hi']}, chain order): `{r['window']}`")
        say(f"- sorted: `{s}`")
        if r["applies"]:
            n = len(s) // 2
            if len(s) % 2:
                say(f"- odd length -> median index {n} -> **{s[n]}**")
            else:
                say(f"- even length -> indices {n-1},{n} = {s[n-1]},{s[n]} -> "
                    f"`({s[n-1]}+{s[n]})/2` = **{r['median']}**")
        else:
            say(f"- chain_h {r['chain_h']} < {TS_WINDOW}: `check_block_timestamp` returns true "
                f"before computing any median")
        say(f"- submitted timestamp {r['ts']}, parent `{r['parent'][:16]}…`, "
            f"verdict **{'accepted' if r['accepted'] else 'rejected'}**"
            + (f", daemon error `{r['err']}`" if r["err"] else ""))
        say(f"- submit latency {r['ms']:.1f} ms")
        if r["log"]:
            say("- daemon log:")
            for l in r["log"][:6]:
                say(f"  - `{l.split(chr(9))[-1][:200]}`")
        else:
            say("- daemon log: no matching line")
        say()
        say("</details>")
        say()

    say("### Proof-of-work ordering")
    say()
    say(f"Chain mined at difficulty 1 to 91 blocks (median of the last {TS_WINDOW} = {med}), then the")
    say(f"same data dir reopened at `--fixed-difficulty {HUGE_DIFF}` so no submitted block can pass.")
    say()
    say("| submitted | timestamp | verdict | daemon error | log |")
    say("|---|---|---|---|---|")
    for label, ts, ok, err, log in powout:
        first = log[0].split("\t")[-1][:120] if log else ""
        say(f"| {label} | {ts} | {'accepted' if ok else 'rejected'} | `{err}` | `{first}` |")
    say()

    # ---------------- calibration summary
    say()
    say("### Measured localhost ranges (item 7)")
    say()
    say("| quantity | n | min | median | mean | max | status |")
    say("|---|---|---|---|---|---|---|")
    def row(name, v, status="**measured, localhost**"):
        if not v:
            say(f"| {name} | 0 | — | — | — | — | not obtained |"); return
        say(f"| {name} | {len(v)} | {min(v):.2f} | {statistics.median(v):.2f} | "
            f"{statistics.mean(v):.2f} | {max(v):.2f} | {status} |")
    row("accepted-block submit, quiet (ms)", r7.get("submit_quiet"))
    row("accepted-block submit, CPU load (ms)", r7.get("submit_cpu"))
    row("accepted-block submit, disk load (ms)", r7.get("submit_disk"))
    row("template refresh after parent, quiet (ms)", r7.get("refresh_quiet"))
    row("template refresh after parent, CPU load (ms)", r7.get("refresh_cpu"))
    row("template refresh after parent, disk load (ms)", r7.get("refresh_disk"))
    row("two-daemon P2P propagation (ms)", r7.get("prop"))
    say()
    if r7.get("p2p_error"):
        say(f"> **Gap in this run:** the two-daemon P2P section failed with "
            f"`{r7['p2p_error']}`, so propagation and competing-block latency were not obtained.")
        say()
    say("| profile | propagation | processing | provenance |")
    say("|---|---|---|---|")
    if r7.get("prop"):
        p = r7["prop"]
        say(f"| localhost | {min(p):.1f}–{max(p):.1f} ms (median {statistics.median(p):.1f}) "
            f"| {min(r7['submit_quiet']):.1f}–{max(r7['submit_disk'] or r7['submit_quiet']):.1f} ms "
            f"| **MEASURED on this host** |")
    say("| datacenter | assumed | assumed | **ASSUMPTION — never measured** |")
    say("| regional | assumed | assumed | **ASSUMPTION — never measured** |")
    say("| global | assumed | assumed | **ASSUMPTION — never measured** |")
    say("| congested | assumed | assumed | **ASSUMPTION — never measured** |")
    say()
    say("_Dev/test coins on private localhost chains. No monetary value._")

    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwritten to {OUT}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
