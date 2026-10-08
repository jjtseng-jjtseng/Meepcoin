#!/usr/bin/env python3
"""Check the T1+T2 timestamp lower bound in an existing header CSV.

This is an offline diagnostic, not a full consensus replay or an attack verdict.
The CSV comes from collect_difficulty_trace.py. The check includes genesis in
the available-history window and uses at most 60 preceding timestamps. It
cannot replay the wall-clock future limit, alternative branches, or reorgs.
"""

import csv
import json
import sys


COLUMNS = (
    "height", "timestamp", "interval_s", "difficulty",
    "cumulative_difficulty", "recomputed",
)
WINDOW = 60


def median(values):
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) // 2


def predecessor_window(rows, height):
    """T1+T2 window: available heights max(0, h-60) through h-1."""
    if height < 1:
        raise ValueError("genesis has no predecessor window")
    return [row["timestamp"] for row in rows[max(0, height - WINDOW):height]]


def load_rows(path):
    with open(path, newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != COLUMNS:
            raise ValueError("unexpected CSV columns")
        rows = []
        for record in reader:
            if None in record or any(value is None for value in record.values()):
                raise ValueError("malformed CSV row")
            row = {}
            for name in COLUMNS:
                value = record[name]
                if name == "recomputed" and value == "":
                    row[name] = None
                elif value.isdecimal() or (name == "interval_s" and value.startswith("-") and value[1:].isdecimal()):
                    row[name] = int(value)
                else:
                    raise ValueError(f"non-integer {name}")
            rows.append(row)
    return rows


def analyze(rows):
    if not rows:
        raise ValueError("empty header trace")
    equal_to_median = 0
    minimum_margin = None
    comparable = 0
    for height, row in enumerate(rows):
        if row["height"] != height:
            raise ValueError("missing or out-of-order height")
        if row["difficulty"] < 1:
            raise ValueError("nonpositive difficulty")
        previous = rows[height - 1] if height else None
        expected_interval = row["timestamp"] - previous["timestamp"] if previous else 0
        if row["interval_s"] != expected_interval:
            raise ValueError("interval does not match header timestamps")
        expected_work = (previous["cumulative_difficulty"] if previous else 0) + row["difficulty"]
        if row["cumulative_difficulty"] != expected_work:
            raise ValueError("cumulative difficulty does not match headers")
        if row["recomputed"] is not None:
            comparable += 1
            if row["recomputed"] != row["difficulty"]:
                raise ValueError("stored difficulty recomputation disagrees")
        if not height:
            continue
        lower_bound = median(predecessor_window(rows, height))
        margin = row["timestamp"] - lower_bound
        if margin < 0:
            raise ValueError(f"height {height} timestamp below T1+T2 median")
        equal_to_median += margin == 0
        minimum_margin = margin if minimum_margin is None else min(minimum_margin, margin)
    return {
        "schema": "meepcoin-offline-timestamp-lower-bound/1",
        "heights": len(rows),
        "tip_height": len(rows) - 1,
        "checked_lower_bounds": len(rows) - 1,
        "equal_to_median": equal_to_median,
        "minimum_margin_seconds": minimum_margin,
        "difficulty_comparable_rows": comparable,
        "difficulty_uncomparable_rows": len(rows) - comparable,
        "first_full_predecessor_window_height": WINDOW if len(rows) > WINDOW else None,
        "limitations": ["no wall-clock future-limit replay", "no alternative branches or reorgs", "no attacker attribution or security verdict"],
    }


def main(argv):
    if len(argv) != 2:
        print("usage: offline_timestamp_trace.py <existing-trace.csv>", file=sys.stderr)
        return 2
    try:
        print(json.dumps(analyze(load_rows(argv[1])), sort_keys=True))
    except (OSError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
