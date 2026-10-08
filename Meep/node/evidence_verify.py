#!/usr/bin/env python3
"""Recompute every producer-derived aggregate from SAVED evidence only, and fail closed.

The PRIMARY source is the per-attempt event stream (`miner_evidence[*].events`). Everything else --
`block_ids`, `producer_of`, miner stats, accepted counters, stored aggregates -- is treated as a
redundant claim to be checked against it, never as an input.

Why: an earlier version rebuilt `producer_of` from `block_ids` and compared it against aggregates
derived from the same list, so a set of mutually consistent but unsupported values passed. A fixture
with `candidates: []` and a populated `block_ids` passed too. Attribution is only as good as the
evidence it is derived from, and that evidence is the event stream.

A producer block id is accepted ONLY from an event with `outcome == "ACCEPTED"` and an exact
daemon-returned `block_id`. Anything else -- UNKNOWN, accepted-without-id, duplicate id, malformed
id, blob-hash mismatch, counter disagreement, or a canonical block that no event explains -- is a
failure, not a footnote.

Usage: python3 node/evidence_verify.py <raw condition json> [...]
Exit 0 only if every record passes.
"""
import hashlib, json, os, re, sys

# F: a bundled verifier must NEVER add a file to the sealed bundle it is checking. Running the
# copied series validator used to emit inputs/harness/__pycache__/*.pyc, after which the very
# next isolated bundle verification failed on unlisted files. Suppressing bytecode BEFORE the
# sibling imports below keeps post-seal verification side-effect-free and repeatable in any
# order. `python3 -B` / PYTHONDONTWRITEBYTECODE stay useful as defence in depth, but the code
# must not depend on the caller remembering them.
sys.dont_write_bytecode = True

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def rolling_occupancy(seq, pof, window=60):
    out = []
    for i in range(0, max(0, len(seq) - window + 1)):
        counts = {}
        for b in seq[i:i + window]:
            p = pof.get(b["hash"], "unattributed")
            counts[p] = counts.get(p, 0) + 1
        out.append(counts)
    return out


def derive_from_events(rec, res):
    """producer_of built ONLY from ACCEPTED events carrying an exact block_id."""
    pof, per_miner, problems = {}, {}, []
    total_events, by_phase = 0, {}
    for name, ev in (rec.get("miner_evidence") or {}).items():
        events = ev.get("events")
        if events is None:
            problems.append(f"{name}: no event stream (`events` absent) -- producer aggregates "
                            f"cannot be derived from saved evidence")
            continue
        ids = set()
        for e in events:
            total_events += 1
            by_phase[e.get("phase")] = by_phase.get(e.get("phase"), 0) + 1
            if e.get("miner") != name:
                problems.append(f"{name}: event claims miner={e.get('miner')}")
            oc = e.get("outcome")
            if oc == "ACCEPTED":
                bid = e.get("block_id")
                if not bid:
                    problems.append(f"{name}: ACCEPTED event seq={e.get('seq')} has no block_id")
                    continue
                if not HEX64.match(str(bid)):
                    problems.append(f"{name}: malformed block_id {bid!r}")
                    continue
                if bid in pof and pof[bid] != name:
                    problems.append(f"block_id {bid[:16]} claimed by {pof[bid]} and {name}")
                if bid in ids:
                    problems.append(f"{name}: duplicate block_id {bid[:16]} in its own events")
                ids.add(bid)
                pof[bid] = name
                blob = e.get("blob")
                if blob:
                    got = hashlib.sha256(bytes.fromhex(blob)).hexdigest()
                    if got != e.get("blob_sha256"):
                        problems.append(f"{name}: blob hash mismatch on {bid[:16]} "
                                        f"({got[:12]} != {str(e.get('blob_sha256'))[:12]})")
            elif oc == "UNKNOWN_AFTER_TRANSPORT_ERROR":
                problems.append(f"{name}: UNKNOWN_AFTER_TRANSPORT_ERROR event seq={e.get('seq')} "
                                f"is unresolved; producer attribution cannot be exact")
            elif oc != "REJECTED":
                problems.append(f"{name}: unknown outcome {oc!r}")
        per_miner[name] = ids
        st = ev.get("stats") or {}
        if st.get("candidate_attempts") is not None and st["candidate_attempts"] != len(events):
            problems.append(f"{name}: stats.candidate_attempts={st['candidate_attempts']} but "
                            f"{len(events)} events saved -- attempt evidence is incomplete")
        acc = sum(1 for e in events if e.get("outcome") == "ACCEPTED")
        if st.get("local_accepted") is not None and st["local_accepted"] != acc:
            problems.append(f"{name}: stats.local_accepted={st['local_accepted']} != {acc} "
                            f"ACCEPTED events")
        claimed = set(ev.get("block_ids") or [])
        if claimed != ids:
            problems.append(f"{name}: block_ids list disagrees with the event stream "
                            f"(+{len(claimed - ids)} unsupported, -{len(ids - claimed)} missing)")
    res["event_total"] = total_events
    res["events_by_phase"] = by_phase
    return pof, per_miner, problems


def verify(path):
    rec = json.load(open(path, encoding="utf-8"))
    res = {"file": path, "condition": rec.get("condition"), "replicate": rec.get("replicate"),
           "attempt_id": rec.get("attempt_id"), "checks": [], "failures": []}

    def check(name, recomputed, stored):
        ok = recomputed == stored
        res["checks"].append({"check": name, "ok": ok, "recomputed": recomputed, "stored": stored})
        if not ok:
            res["failures"].append(f"{name}: recomputed {recomputed} != stored {stored}")
        return ok

    if "miner_evidence" not in rec:
        res["failures"].append("miner_evidence absent -- this record predates the corrected schema "
                               "and its producer-attributed aggregates are NOT independently "
                               "reproducible")
        res["verifiable"] = False
        res["passed"] = False
        res["attribution_exact"] = None
        return res
    res["verifiable"] = True

    pof, per_miner, problems = derive_from_events(rec, res)
    res["failures"] += problems

    # the stored mapping must equal the one derived from events
    if rec.get("producer_of") is not None:
        check("producer_of_mapping", pof, rec["producer_of"])
    else:
        res["failures"].append("producer_of absent from the record")

    amb = sum(len(ev.get("accepted_without_block_id", []))
              for ev in rec["miner_evidence"].values())
    unk = sum(len(ev.get("unknown_after_transport_error", []))
              for ev in rec["miner_evidence"].values())
    res["ambiguous_accepted_without_block_id"] = amb
    res["unknown_after_transport_error"] = unk
    recon = rec.get("reconciliation") or {}
    resolved = bool(recon.get("resolved_all"))
    res["reconciliation_resolved_all"] = resolved
    if (amb or unk) and not resolved:
        res["failures"].append(f"{amb} accepted-without-id and {unk} UNKNOWN outcomes are "
                               f"unresolved and no deterministic blob-identity reconciliation "
                               f"record resolves them")

    # per-node aggregates recomputed from the derived mapping
    unattributed_total = 0
    for node, stored in (rec.get("per_node") or {}).items():
        seq = (rec.get("canonical_headers") or {}).get(node)
        if seq is None:
            res["failures"].append(f"{node}: canonical_headers absent -- cannot recompute")
            continue
        blocks, work = {}, {}
        for b in seq:
            p = pof.get(b["hash"], "unattributed")
            blocks[p] = blocks.get(p, 0) + 1
            work[p] = work.get(p, 0) + b["difficulty"]
        unattributed_total += blocks.get("unattributed", 0)
        totw = sum(work.values()) or 1
        aw = {p: {"blocks": blocks.get(p, 0), "work": w, "work_share": round(w / totw, 5)}
              for p, w in work.items()}
        check(f"{node}.accepted_work", aw, stored.get("accepted_work"))
        occ = rolling_occupancy(seq, pof)
        mx = {p: max([w.get(p, 0) for w in occ] or [0])
              for p in ("h1", "h2", "atk", "unattributed")}
        check(f"{node}.max_window_occupancy", mx, stored.get("max_window_occupancy"))
        check(f"{node}.canonical_blocks_after_start", len(seq),
              stored.get("canonical_blocks_after_start"))
    res["unattributed_canonical_blocks"] = unattributed_total

    # censorship counts
    stored_c = rec.get("censorship") or {}
    if stored_c:
        for p, ids in per_miner.items():
            for node, seq in (rec.get("canonical_headers") or {}).items():
                canon = {b["hash"] for b in seq}
                absent = len([h for h in ids if h not in canon])
                st = ((stored_c.get(p) or {}).get("per_observer") or {}).get(node) or {}
                if "absent_from_canonical" in st:
                    check(f"censorship.{p}@{node}.absent", absent, st["absent_from_canonical"])

    # blob archive completeness, if the record claims one
    ba = rec.get("blob_archive")
    if ba is not None:
        if ba.get("missing_count"):
            res["failures"].append(f"blob archive incomplete: {ba['missing_count']} missing")
        if ba.get("archived") != ba.get("requested"):
            res["failures"].append(f"blob archive archived {ba.get('archived')} of "
                                   f"{ba.get('requested')} requested")

    res["attribution_exact"] = (amb == 0 and unk == 0 and unattributed_total == 0 and
                                not problems)
    if rec.get("attribution_exact") is not None:
        check("attribution_exact_flag", res["attribution_exact"], rec["attribution_exact"])
    if unattributed_total and rec.get("attribution_exact"):
        res["failures"].append(f"record claims attribution_exact while {unattributed_total} "
                               f"canonical blocks are unattributed")

    res["passed"] = not res["failures"]
    return res


def digest(res):
    return hashlib.sha256(json.dumps(res, sort_keys=True, default=str).encode()).hexdigest()


def main(argv):
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print(__doc__)
        return 2
    bad = 0
    for p in paths:
        r = verify(p)
        tag = "PASS" if r.get("passed") else ("UNVERIFIABLE" if not r.get("verifiable") else "FAIL")
        print(f"[{tag}] {os.path.basename(p)}  checks={len(r['checks'])} "
              f"events={r.get('event_total')} "
              f"exact={r.get('attribution_exact')} "
              f"unattributed={r.get('unattributed_canonical_blocks')} "
              f"digest={digest(r)[:16]}")
        for f in r["failures"][:12]:
            print(f"    ! {f}")
        if len(r["failures"]) > 12:
            print(f"    ! ... {len(r['failures']) - 12} more")
        if not r.get("passed"):
            bad += 1
    print(f"\n{len(paths) - bad}/{len(paths)} records verified")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
