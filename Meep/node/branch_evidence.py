#!/usr/bin/env python3
"""Branch-aware evidence: every node's own canonical view, never one node promoted to "the chain".

Last round reconstructed H1's chain and called it final, which is wrong whenever nodes disagree --
and in the run that mattered, H2 finished with greater cumulative difficulty than H1. Here each
node's canonical sequence is collected independently, pairwise common ancestors are computed from
the sequences themselves, and every block is classified per node as canonical / alternative /
known-but-not-canonical / unknown.

`get_block_header_by_hash` returning a header proves the node KNOWS the block. It does not prove
canonical acceptance, and the two are kept apart everywhere below.
"""
import json, re

# Import daemon RPC helpers only in functions that contact a daemon. Importing
# live_median_boundary at module load reads a wallet address from HOME, which
# makes the pure chain-analysis helpers unusable in a sterile environment.


def rpc(*args, **kwargs):
    from live_median_boundary import rpc as daemon_rpc

    return daemon_rpc(*args, **kwargs)


def rest(*args, **kwargs):
    from live_median_boundary import rest as daemon_rest

    return daemon_rest(*args, **kwargs)

FOUND_RE = re.compile(r"Found block <?([0-9a-f]{64})>? at height (\d+) for difficulty:?\s*(\d+)")
REORG_RE = re.compile(r"REORGANIZE.*?on height:?\s*(\d+)")
# Rejection lines that name a block id, so a reason can be keyed to a hash rather than counted loose
REJECT_WITH_ID = re.compile(
    r"(?:Timestamp of block with id|Block with id|block with id)[: ]*<?([0-9a-f]{64})>?[,:]?\s*(.*)")


class InconsistentView(RuntimeError):
    """A paginated chain read that cannot be trusted as one coherent view."""


def canonical(d, lo, hi, chunk=500, expect_tip=None, strict=True, single_call=True):
    """Canonical header sequence [lo, hi] inclusive from ONE node's point of view.

    P0-5: the previous version silently stopped on an empty or partial chunk and never checked
    height coverage, ordering or parent linkage. At this experiment's block cadence a paginated read
    can straddle a reorganisation and mix pre- and post-reorg state, and that mixture was then used
    as a fork verdict. Strict mode rejects such a view instead of returning it.
    """
    out = []
    if hi < lo:
        return out
    span = hi - lo + 1
    # E: request the whole anchor-to-tip range in ONE coherent call when possible. Fixed 500-header
    # pagination was the actual source of the InconsistentView seen in the live run
    # results/SMOKE_20260815_gateC4 ("prev_hash break at height 603"): a reorganisation landing
    # BETWEEN two chunk requests yields an assembled view that never existed on the node. A single
    # call cannot straddle itself. The daemon's 1000-header cap applies only to RESTRICTED rpc
    # (core_rpc_server.cpp:2562) and these daemons run unrestricted, so the cap does not bind here;
    # pagination is kept as a fallback. The strict validation below is IDENTICAL on both paths --
    # a broken or partial chain is never accepted merely to improve coverage.
    got_single = False
    if single_call:
        try:
            r = rpc(d.rpc, "get_block_headers_range",
                    {"start_height": lo, "end_height": hi}, timeout=240)
            hdrs = (r.get("result") or {}).get("headers") or []
            if len(hdrs) == span:
                out, got_single = hdrs, True
        except Exception:
            got_single = False          # fall through to pagination, never accept a partial view
    start = lo
    while (not got_single) and start <= hi:
        end = min(start + chunk - 1, hi)
        r = rpc(d.rpc, "get_block_headers_range",
                {"start_height": start, "end_height": end}, timeout=240)
        hdrs = (r.get("result") or {}).get("headers") or []
        if not hdrs:
            if strict:
                raise InconsistentView(f"empty chunk at {start}-{end} of {lo}-{hi}")
            break
        out += hdrs
        start = end + 1
    seq = [{"height": int(h["height"]), "hash": h["hash"], "prev_hash": h["prev_hash"],
            "timestamp": int(h["timestamp"]), "difficulty": int(h["difficulty"]),
            "cumulative_difficulty": int(h.get("cumulative_difficulty", 0))} for h in out]
    if strict:
        want = hi - lo + 1
        if len(seq) != want:
            raise InconsistentView(f"got {len(seq)} headers, expected {want} for {lo}-{hi}")
        for i, b in enumerate(seq):
            if b["height"] != lo + i:
                raise InconsistentView(f"height {b['height']} out of order at index {i}")
            if i and b["prev_hash"] != seq[i - 1]["hash"]:
                raise InconsistentView(f"prev_hash break at height {b['height']}")
        if expect_tip is not None and seq and seq[-1]["hash"] != expect_tip:
            raise InconsistentView(f"last hash {seq[-1]['hash'][:12]} != captured tip "
                                   f"{expect_tip[:12]}")
    return seq


def node_view(d, start_height, retries=2):
    """Anchored view: it ALWAYS includes the shared snapshot block at start_height-1.

    P0-5: the previous view began at start_height, so a node still sitting on the shared snapshot
    tip had a tip that appeared in no peer sequence and could be called genuinely forked rather than
    simply lagging. The anchor makes the shared prefix explicit."""
    anchor_h = max(0, start_height - 1)
    last_err = None
    attempts = 0
    for _ in range(retries + 1):
        attempts += 1
        i = d.info()
        h = int(i["height"])
        tip = i["top_block_hash"]
        try:
            seq = canonical(d, anchor_h, h - 1, expect_tip=tip, strict=True)
        except InconsistentView as e:
            last_err = str(e)
            continue
        alts = set(rest(d.rpc, "/get_alt_blocks_hashes").get("blks_hashes") or [])
        anchor = seq[0] if seq else None
        after = [b for b in seq if b["height"] >= start_height]
        return {"height": h, "tip": tip, "attempts": attempts,
                "tip_cumulative_difficulty": seq[-1]["cumulative_difficulty"] if seq else None,
                "anchor_height": anchor_h,
                "anchor_hash": anchor["hash"] if anchor else None,
                "canonical": after,
                "anchored": seq,
                "canonical_hashes": [b["hash"] for b in after],
                "anchored_hashes": [b["hash"] for b in seq],
                "alt_block_hashes": sorted(alts)}
    # the retry count travels with the exception so a sample can record how hard it tried
    err = InconsistentView(f"view still inconsistent after {retries} retries: {last_err}")
    err.attempts = attempts
    err.retries = retries
    raise err


def common_ancestor(seq_a, seq_b):
    """Last height at which two canonical sequences still agree, plus fork geometry.

    Computed from the sequences, not from a log line, so it is valid even when neither node ever
    logged a reorganisation."""
    by_h_b = {b["height"]: b["hash"] for b in seq_b}
    last = None
    for blk in seq_a:
        o = by_h_b.get(blk["height"])
        if o is not None and o == blk["hash"]:
            last = blk
        elif o is not None:
            break
    if last is None:
        return {"common_ancestor_height": None, "common_ancestor_hash": None,
                "forked": bool(seq_a and seq_b),
                "a_branch_len": len(seq_a), "b_branch_len": len(seq_b)}
    ha = seq_a[-1]["height"] if seq_a else last["height"]
    hb = seq_b[-1]["height"] if seq_b else last["height"]
    return {"common_ancestor_height": last["height"], "common_ancestor_hash": last["hash"],
            "forked": (ha > last["height"] or hb > last["height"]),
            "a_branch_len": ha - last["height"], "b_branch_len": hb - last["height"]}


def is_lagging(view_a, view_b):
    """True if A's tip is an earlier point of B's ANCHORED chain (lag, not a fork).

    Using the anchored sequence matters: a node still at the shared snapshot tip is lagging, and
    the unanchored sequence could not express that."""
    return view_a["tip"] in set(view_b.get("anchored_hashes")
                                or view_b.get("canonical_hashes") or [])


def fork_state(views):
    """Pairwise relationships between every node's canonical view."""
    out = {}
    names = list(views)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            ca = common_ancestor(views[a].get("anchored") or views[a]["canonical"],
                                 views[b].get("anchored") or views[b]["canonical"])
            lag = is_lagging(views[a], views[b]) or is_lagging(views[b], views[a])
            out[f"{a}|{b}"] = {**ca, "same_tip": views[a]["tip"] == views[b]["tip"],
                               "one_is_prefix_of_other": lag,
                               "genuinely_forked": (views[a]["tip"] != views[b]["tip"]) and not lag}
    return out


def classify(d, block_hashes, view):
    """Per node: canonical / alternative / known_noncanonical / unknown, for each hash."""
    canon = set(view["canonical_hashes"])
    alts = set(view["alt_block_hashes"])
    out = {}
    for bh in block_hashes:
        if bh in canon:
            out[bh] = "canonical"
            continue
        if bh in alts:
            out[bh] = "alternative"
            continue
        try:
            r = rpc(d.rpc, "get_block_header_by_hash", {"hash": bh}, timeout=20)
            out[bh] = "known_noncanonical" if "result" in r else "unknown"
        except Exception:
            out[bh] = "unknown"
    return out


def parse_log(lines):
    """Producer attribution and rejection reasons from a node's COMPLETE log.

    Returns found (hash -> height/difficulty), rejects (hash -> [reasons]), reorg heights, and the
    total line count so a summary can be given without truncating the stored log."""
    found, rejects, reorgs = {}, {}, []
    for line in lines:
        m = FOUND_RE.search(line)
        if m:
            found[m.group(1)] = {"height": int(m.group(2)), "difficulty": int(m.group(3))}
            continue
        m = REORG_RE.search(line)
        if m:
            reorgs.append(int(m.group(1)))
            continue
        m = REJECT_WITH_ID.search(line)
        if m:
            reason = m.group(2).strip()[:200]
            if reason:
                rejects.setdefault(m.group(1), []).append(reason)
    return {"found": found, "rejects_by_hash": rejects, "reorg_heights": reorgs,
            "log_lines": len(lines)}


def reject_summary(rejects_by_hash):
    """Counts by normalised reason, so complete logs can be kept while the report stays readable."""
    counts = {}
    for reasons in rejects_by_hash.values():
        for r in reasons:
            key = re.sub(r"\b\d{6,}\b", "<N>", r)
            key = re.sub(r"<?[0-9a-f]{64}>?", "<hash>", key)
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def rolling_window_occupancy(seq, producer_of, window=60):
    """Share of each rolling `window`-block timestamp-median window held by each producer, on THIS
    node's canonical sequence. This is the quantity the median rule actually depends on."""
    out = []
    for i in range(0, max(0, len(seq) - window + 1)):
        win = seq[i:i + window]
        counts = {}
        for b in win:
            p = producer_of.get(b["hash"], "unattributed")
            counts[p] = counts.get(p, 0) + 1
        ts = sorted(b["timestamp"] for b in win)
        middle = len(ts) // 2
        # Match epee::misc_utils::median: for an even window, floor the mean
        # of the two middle integer timestamps. Taking only ts[middle] makes
        # the reported bound too high, especially in a manipulated window.
        median_ts = (ts[middle - 1] + ts[middle]) // 2 if len(ts) % 2 == 0 else ts[middle]
        out.append({"start_height": win[0]["height"], "counts": counts,
                    "ts_span_s": ts[-1] - ts[0], "median_ts": median_ts,
                    "median_minus_min_s": median_ts - ts[0]})
    return out


def max_occupancy(occ, producer):
    vals = [w["counts"].get(producer, 0) for w in occ]
    return max(vals) if vals else 0


def blob_archive(nodes, hashes, out_path):
    """Raw block blobs keyed by exact block id, for every canonical and known alternative block.

    Without this a partition cannot actually be replayed: the branch is gone once the throwaway
    data directories are reused. Blobs are fetched by HASH (never by height) from whichever node
    knows the block, so the archive is keyed by the same identifier attribution uses.

    Returns a summary; the archive itself is written as JSON Lines so it stays streamable."""
    import hashlib
    got, missing = 0, []
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        for bh in sorted(hashes):
            rec = None
            for name, d in nodes.items():
                try:
                    r = rpc(d.rpc, "get_block", {"hash": bh}, timeout=60)
                    b = r.get("result") or {}
                    if "blob" in b:
                        hd = b.get("block_header") or {}
                        rec = {"block_id": bh, "from_node": name, "blob": b["blob"],
                               "blob_sha256": hashlib.sha256(
                                   bytes.fromhex(b["blob"])).hexdigest(),
                               "height": hd.get("height"), "prev_hash": hd.get("prev_hash"),
                               "timestamp": hd.get("timestamp"),
                               "difficulty": hd.get("difficulty"),
                               "cumulative_difficulty": hd.get("cumulative_difficulty")}
                        break
                except Exception:
                    continue
            if rec is None:
                missing.append(bh)
            else:
                f.write(json.dumps(rec) + "\n")
                got += 1
    return {"path": out_path, "archived": got, "missing": missing[:50],
            "missing_count": len(missing), "requested": len(hashes)}
