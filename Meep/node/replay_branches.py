#!/usr/bin/env python3
"""LD-G: deterministically replay recorded branches into clean validators.

When nodes end on different canonical tips, three explanations are still open:
    consensus-context   a node's verdict on a block depends on which branch it is already holding
    relay/topology      the block never arrived, so no verdict was ever formed
    harness artifact    the experiment, not the daemon, produced the divergence

Replay separates them. Blocks are captured as raw blobs during the live run, then fed by
`submit_block` into daemons started from a fresh copy of the SAME pre-run snapshot -- so arrival is
guaranteed and topology is removed from the picture entirely. If a block is rejected here, the
rejection is a property of consensus given that validator's current chain, not of the network.

Each branch is replayed in recorded parent order, and the branches are also interleaved in
alternate arrival orders, to find the FIRST block where two validators disagree.

Nothing in this file changes consensus. It only submits recorded bytes and records verdicts.
"""
import json, os, shutil, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L
from live_median_boundary import rpc, rest

BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
SNAPROOT = os.path.expanduser(ARG.get("--snaproot", "~/.meepcoin-lowdiff"))
SRC = os.path.join(SNAPROOT, "snap_src")


def capture_branch(d, lo, hi):
    """Raw block blobs in parent order from ONE node's canonical chain, for later replay."""
    out = []
    for h in range(lo, hi + 1):
        try:
            r = rpc(d.rpc, "get_block", {"height": h}, timeout=60)
            b = r.get("result") or {}
            if "blob" not in b:
                break
            out.append({"height": h, "hash": b["block_header"]["hash"],
                        "prev_hash": b["block_header"]["prev_hash"],
                        "timestamp": int(b["block_header"]["timestamp"]),
                        "difficulty": int(b["block_header"]["difficulty"]),
                        "blob": b["blob"]})
        except Exception:
            break
    return out


def fresh(name, port, gts):
    dst = os.path.join(SNAPROOT, name)
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    r = subprocess.run(["cp", "-a", "--sparse=always", SRC, dst], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"copy failed: {r.stderr[:200]}")
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    return L.Daemon(name, port, port + 1, fixed_diff=0, offline=True, wipe=False, data_dir=dst)


def feed(d, blocks, label):
    """Submit blocks in the given order, recording a verdict per block."""
    rows = []
    for i, b in enumerate(blocks):
        ok, err, dt = d.submit(b["blob"])
        try:
            info = d.info()
            tip, height = info["top_block_hash"], int(info["height"])
        except Exception:
            tip, height = None, None
        rows.append({"order_index": i, "label": label, "height": b["height"], "hash": b["hash"],
                     "accepted": ok, "error": err, "tip_after": tip, "height_after": height,
                     "submit_s": round(dt, 4)})
    return rows


def first_divergence(a_rows, b_rows):
    """First block hash on which two replay runs return different verdicts."""
    bv = {r["hash"]: r for r in b_rows}
    for r in a_rows:
        o = bv.get(r["hash"])
        if o is not None and bool(o["accepted"]) != bool(r["accepted"]):
            return {"hash": r["hash"], "height": r["height"],
                    "verdict_a": r["accepted"], "error_a": r["error"],
                    "verdict_b": o["accepted"], "error_b": o["error"]}
    return None


def replay(branches, gts, port0, out_path, ancestor_height):
    """branches: {name: [block,...]} in parent order, all descending from the same ancestor."""
    rec = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "common_ancestor_height": ancestor_height,
           "branch_lengths": {k: len(v) for k, v in branches.items()},
           "orders": {}}
    names = list(branches)
    plans = []
    for n in names:
        plans.append((f"{n}_only", [(n, b) for b in branches[n]]))
    if len(names) >= 2:
        a, b = names[0], names[1]
        plans.append((f"{a}_then_{b}",
                      [(a, x) for x in branches[a]] + [(b, x) for x in branches[b]]))
        plans.append((f"{b}_then_{a}",
                      [(b, x) for x in branches[b]] + [(a, x) for x in branches[a]]))
        inter = []
        for i in range(max(len(branches[a]), len(branches[b]))):
            if i < len(branches[a]):
                inter.append((a, branches[a][i]))
            if i < len(branches[b]):
                inter.append((b, branches[b][i]))
        plans.append((f"interleaved_{a}_{b}", inter))

    port = port0
    for label, plan in plans:
        d = None
        try:
            d = fresh(f"replay_{label}", port, gts)
            d.wait_synced(90)
            d.mark_log()
            rows = []
            for src, blk in plan:
                ok, err, dt = d.submit(blk["blob"])
                info = d.info()
                rows.append({"branch": src, "height": blk["height"], "hash": blk["hash"],
                             "accepted": ok, "error": err,
                             "tip_after": info["top_block_hash"],
                             "height_after": int(info["height"]), "submit_s": round(dt, 4)})
            info = d.info()
            alts = rest(d.rpc, "/get_alt_blocks_hashes").get("blks_hashes") or []
            rec["orders"][label] = {
                "rows": rows,
                "final_height": int(info["height"]), "final_tip": info["top_block_hash"],
                "alt_blocks": len(alts),
                "accepted": sum(1 for r in rows if r["accepted"]),
                "rejected": sum(1 for r in rows if not r["accepted"]),
                "first_rejection": next((r for r in rows if not r["accepted"]), None),
                "reject_reasons": sorted({r["error"] for r in rows
                                          if not r["accepted"] and r["error"]}),
                "log_reject_lines": [l for l in d.new_log()
                                     if "less than median" in l or "bigger than local time" in l][:200],
            }
        except Exception as e:
            rec["orders"][label] = {"error": f"{type(e).__name__}: {e}"}
        finally:
            if d:
                try: d.stop()
                except Exception: pass
        port += 10

    # cross-order comparison: does arrival order change any verdict?
    labels = [k for k, v in rec["orders"].items() if "rows" in v]
    rec["order_dependence"] = {}
    for i, a in enumerate(labels):
        for b in labels[i + 1:]:
            div = first_divergence(rec["orders"][a]["rows"], rec["orders"][b]["rows"])
            if div:
                rec["order_dependence"][f"{a} vs {b}"] = div
    rec["verdict"] = {
        "any_block_rejected_with_guaranteed_delivery":
            any(v.get("rejected", 0) > 0 for v in rec["orders"].values() if "rows" in v),
        "order_dependent_verdicts": bool(rec["order_dependence"]),
        "interpretation":
            "blocks are delivered directly by submit_block, so a rejection here cannot be a relay "
            "or topology effect; an order-dependent verdict is consensus-context behaviour",
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)
    return rec


def load_archive(path):
    """Blob archive written by branch_evidence.blob_archive(), keyed by exact block id."""
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                r = json.loads(line)
                out[r["block_id"]] = r
    return out


def window_state(d, height, window=60):
    """The exact timestamp window, sorted vector and median the daemon would use to validate a
    block at `height` -- recorded at the first divergence so the verdict can be explained rather
    than merely observed."""
    lo = max(0, height - window)
    hi = height - 1
    if hi < lo:
        return {"height": height, "window": [], "median": None}
    hdrs = rpc(d.rpc, "get_block_headers_range",
               {"start_height": lo, "end_height": hi}, timeout=120)["result"]["headers"]
    ts = sorted(int(h["timestamp"]) for h in hdrs)
    med = ts[len(ts) // 2] if ts else None
    return {"height": height, "window_lo": lo, "window_hi": hi, "window_size": len(ts),
            "sorted_timestamps": ts, "median": med,
            "note": "check_block_timestamp rejects a candidate whose timestamp is < this median"}


def replay_with_prefix(archive, shared_prefix, branches, gts, port0, out_path,
                       ancestor_height=None):
    """Replay the COMPLETE shared prefix, then each branch, in several arrival orders.

    `shared_prefix` is the ordered list of block ids up to and including the last common ancestor.
    Feeding it first means each validator reaches the true fork point before the contested blocks
    arrive, so a divergence is attributable to the contested block rather than to missing history.
    """
    rec = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "common_ancestor_height": ancestor_height,
           "shared_prefix_len": len(shared_prefix),
           "branch_lengths": {k: len(v) for k, v in branches.items()},
           "orders": {}}
    names = list(branches)
    plans = [(f"{n}_only", [(n, b) for b in branches[n]]) for n in names]
    if len(names) >= 2:
        a, b = names[0], names[1]
        plans.append((f"{a}_then_{b}",
                      [(a, x) for x in branches[a]] + [(b, x) for x in branches[b]]))
        plans.append((f"{b}_then_{a}",
                      [(b, x) for x in branches[b]] + [(a, x) for x in branches[a]]))
        inter = []
        for i in range(max(len(branches[a]), len(branches[b]))):
            if i < len(branches[a]):
                inter.append((a, branches[a][i]))
            if i < len(branches[b]):
                inter.append((b, branches[b][i]))
        plans.append((f"interleaved_{a}_{b}", inter))

    port = port0
    for label, plan in plans:
        d = None
        try:
            d = fresh(f"replay_{label}", port, gts)
            d.wait_synced(90)
            d.mark_log()
            prefix_rows = []
            for bid in shared_prefix:
                blk = archive.get(bid)
                if not blk:
                    prefix_rows.append({"block_id": bid, "error": "not in archive"})
                    continue
                r = d.submit_detailed(blk["blob"])
                prefix_rows.append({"block_id": bid, "outcome": r["outcome"],
                                    "error": r.get("error")})
            rows, first_div = [], None
            for src, bid in plan:
                blk = archive.get(bid)
                if not blk:
                    rows.append({"branch": src, "block_id": bid, "error": "not in archive"})
                    continue
                before = d.info()
                r = d.submit_detailed(blk["blob"])
                after = d.info()
                row = {"branch": src, "block_id": bid, "height": blk.get("height"),
                       "timestamp": blk.get("timestamp"), "outcome": r["outcome"],
                       "error": r.get("error"), "returned_block_id": r.get("block_id"),
                       "tip_before": before["top_block_hash"],
                       "tip_after": after["top_block_hash"],
                       "height_after": int(after["height"])}
                if r["outcome"] != "ACCEPTED" and first_div is None:
                    # explain the verdict with the exact window the daemon used
                    try:
                        row["validation_context"] = window_state(d, int(blk.get("height") or 0))
                        row["candidate_timestamp"] = blk.get("timestamp")
                        med = row["validation_context"].get("median")
                        row["timestamp_minus_median"] = (
                            (blk.get("timestamp") - med) if (med is not None and
                                                             blk.get("timestamp")) else None)
                    except Exception as e:
                        row["validation_context"] = {"error": f"{type(e).__name__}: {e}"}
                    first_div = row
                rows.append(row)
            info = d.info()
            alts = rest(d.rpc, "/get_alt_blocks_hashes").get("blks_hashes") or []
            rec["orders"][label] = {
                "prefix_rows": prefix_rows,
                "prefix_accepted": sum(1 for r in prefix_rows if r.get("outcome") == "ACCEPTED"),
                "rows": rows, "first_divergence": first_div,
                "final_height": int(info["height"]), "final_tip": info["top_block_hash"],
                "alt_blocks": len(alts),
                "accepted": sum(1 for r in rows if r.get("outcome") == "ACCEPTED"),
                "rejected": sum(1 for r in rows if r.get("outcome") == "REJECTED"),
                "unknown": sum(1 for r in rows
                               if r.get("outcome") == "UNKNOWN_AFTER_TRANSPORT_ERROR"),
                "log_reject_lines": [l for l in d.new_log()
                                     if "less than median" in l or
                                     "bigger than local time" in l][:200]}
        except Exception as e:
            rec["orders"][label] = {"error": f"{type(e).__name__}: {e}"}
        finally:
            if d:
                try: d.stop(clean_wait=15.0)
                except Exception: pass
        port += 10

    labels = [k for k, v in rec["orders"].items() if "rows" in v]
    rec["order_dependence"] = {}
    for i, a in enumerate(labels):
        for b in labels[i + 1:]:
            av = {r["block_id"]: r.get("outcome") for r in rec["orders"][a]["rows"]}
            bv = {r["block_id"]: r.get("outcome") for r in rec["orders"][b]["rows"]}
            diff = [{"block_id": k, a: av[k], b: bv[k]} for k in av
                    if k in bv and av[k] != bv[k]]
            if diff:
                rec["order_dependence"][f"{a} vs {b}"] = diff[:10]
    rec["verdict"] = {
        "any_block_rejected_with_guaranteed_delivery":
            any(v.get("rejected", 0) > 0 for v in rec["orders"].values() if "rows" in v),
        "order_dependent_verdicts": bool(rec["order_dependence"]),
        "interpretation":
            "blocks are delivered directly by submit_block after the complete shared prefix, so a "
            "rejection here cannot be a relay or topology effect; an order-dependent verdict is "
            "consensus-context behaviour"}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)
    return rec


def main():
    print(__doc__)
    print("Driven by a partition run: it loads the blob archive written by "
          "branch_evidence.blob_archive(), replays the complete shared prefix through the recorded "
          "last common ancestor, then replays the contested branches in controlled arrival orders "
          "and records the exact 60-block timestamp window, computed median, candidate timestamp "
          "and verdict at the first divergence.\n"
          "Import load_archive() and replay_with_prefix().")
    return 0


if __name__ == "__main__":
    sys.exit(main())
