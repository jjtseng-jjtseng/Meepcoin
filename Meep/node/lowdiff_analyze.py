#!/usr/bin/env python3
"""LD-E analysis: producer shares by difficulty phase, and the 60-block median window that the
observed rejection reason ("timestamp less than median of last 60 blocks") depends on.

Reads the per-block evidence written by lowdiff_matched.py. No daemons, no consensus code.
"""
import collections, json, sys

FILES = [("none", "docs/lowdiff/matched_none.json"),
         ("control", "docs/lowdiff/matched_control.json"),
         ("attack", "docs/lowdiff/matched_attack.json"),
         ("attack+recovery", "docs/lowdiff_rec/matched_attack.json")]


def share(sub):
    c = collections.Counter(b["producer"] for b in sub)
    n = len(sub) or 1
    return f"n={n:<4} " + "  ".join(f"{k}={v}({100 * v / n:.0f}%)" for k, v in c.most_common())


def main():
    for tag, f in FILES:
        try:
            d = json.load(open(f))
        except FileNotFoundError:
            print(f"--- {tag}: missing {f}")
            continue
        ch = sorted([b for b in d["blocks"] if b["on_final_chain"]], key=lambda b: b["height"])
        lo = [b for b in ch if b["difficulty"] <= 10]
        hi = [b for b in ch if b["difficulty"] > 10]
        print(f"=== {tag} ===  final-chain {len(ch)}  converged={d['converged']}")
        print(f"   D<=10 phase : {share(lo)}")
        print(f"   D>10  phase : {share(hi)}")
        orph = collections.Counter(b["producer"] for b in d["blocks"] if b.get("orphan"))
        print(f"   orphans     : {dict(orph)}")
        print(f"   {'window':>14} | {'atk share of 60':>16} | {'ts span':>9} | median-vs-first")
        for w in range(0, max(1, len(ch) - 60), 120):
            win = ch[w:w + 60]
            if len(win) < 60:
                break
            a = sum(1 for b in win if b["producer"] == "atk")
            ts = sorted(b["timestamp"] for b in win)
            med = ts[len(ts) // 2]
            print(f"   blocks[{w:>4}:{w + 60:>4}] | {a:>7}/60 = {100 * a / 60:>3.0f}% | "
                  f"{ts[-1] - ts[0]:>8}s | median-min = {med - ts[0]}s")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
