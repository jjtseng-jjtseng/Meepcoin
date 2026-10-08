#!/usr/bin/env python3
"""Non-live tests for the canonical-header timestamp lower-bound diagnostic."""

import csv
import tempfile
import unittest
from pathlib import Path

from offline_timestamp_trace import COLUMNS, analyze, load_rows, median, predecessor_window


def rows_for(timestamps, difficulties=None):
    difficulties = difficulties or [1] * len(timestamps)
    rows = []
    work = 0
    for height, (timestamp, difficulty) in enumerate(zip(timestamps, difficulties)):
        work += difficulty
        rows.append({
            "height": height,
            "timestamp": timestamp,
            "interval_s": timestamp - timestamps[height - 1] if height else 0,
            "difficulty": difficulty,
            "cumulative_difficulty": work,
            "recomputed": None,
        })
    return rows


class OfflineTimestampTraceTests(unittest.TestCase):
    def test_even_median_uses_floor_and_equality_is_legal(self):
        self.assertEqual(median([8, 9]), 8)
        self.assertEqual(median([7, 8, 9]), 8)
        self.assertEqual(analyze(rows_for([8, 8]))["equal_to_median"], 1)

    def test_genesis_is_in_short_window(self):
        with self.assertRaisesRegex(ValueError, "below T1\\+T2 median"):
            analyze(rows_for([100, 99]))

    def test_legal_backward_timestamp_has_signed_interval(self):
        # A timestamp may retreat relative to its parent while remaining above
        # the median of the preceding history. Its CSV interval is negative.
        rows = rows_for([100, 110, 106])
        self.assertEqual(rows[2]["interval_s"], -4)
        self.assertEqual(analyze(rows)["checked_lower_bounds"], 2)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.csv"
            with path.open("w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=COLUMNS)
                writer.writeheader()
                writer.writerows(rows)
            self.assertEqual(load_rows(path)[2]["interval_s"], -4)

    def test_full_window_excludes_old_genesis(self):
        stamps = [1000] + [1001] * 59 + [1001, 1001]
        rows = rows_for(stamps)
        self.assertEqual(predecessor_window(rows, 60)[0], 1000)
        self.assertEqual(predecessor_window(rows, 61)[0], 1001)
        self.assertEqual(len(predecessor_window(rows, 61)), 60)
        summary = analyze(rows)
        self.assertEqual(summary["first_full_predecessor_window_height"], 60)
        self.assertEqual(summary["checked_lower_bounds"], 61)

    def test_signed_header_interval_and_work_are_checked(self):
        rows = rows_for([100, 101], [1, 3])
        rows[1]["interval_s"] = 0
        with self.assertRaisesRegex(ValueError, "interval"):
            analyze(rows)
        rows[1]["interval_s"] = 1
        rows[1]["cumulative_difficulty"] = 3
        with self.assertRaisesRegex(ValueError, "cumulative"):
            analyze(rows)

    def test_recomputed_mismatch_and_height_gap_refuse(self):
        rows = rows_for([100, 101])
        rows[1]["recomputed"] = 2
        with self.assertRaisesRegex(ValueError, "recomputation"):
            analyze(rows)
        rows[1]["recomputed"] = None
        rows[1]["height"] = 2
        with self.assertRaisesRegex(ValueError, "height"):
            analyze(rows)

    def test_closed_csv_schema_and_real_parse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.csv"
            with path.open("w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=COLUMNS)
                writer.writeheader()
                writer.writerows(rows_for([100, 100]))
            self.assertEqual(analyze(load_rows(path))["tip_height"], 1)
            path.write_text("height,timestamp\n0,100\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "columns"):
                load_rows(path)


if __name__ == "__main__":
    unittest.main()
