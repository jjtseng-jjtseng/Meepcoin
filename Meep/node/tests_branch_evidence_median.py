#!/usr/bin/env python3
"""Non-live regression for the protocol's integer timestamp median."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from branch_evidence import rolling_window_occupancy


def chain(timestamps):
    return [
        {"height": height, "hash": f"{height:064x}", "timestamp": timestamp}
        for height, timestamp in enumerate(timestamps)
    ]


class RollingMedianTests(unittest.TestCase):
    def test_import_does_not_load_wallet_dependent_rpc_module(self):
        with tempfile.TemporaryDirectory() as home:
            env = dict(os.environ, HOME=home, USERPROFILE=home, PYTHONDONTWRITEBYTECODE="1")
            result = subprocess.run(
                [sys.executable, "-B", "-c",
                 "import sys, branch_evidence; assert 'live_median_boundary' not in sys.modules"],
                cwd=Path(__file__).resolve().parent, env=env,
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_even_window_uses_floored_mean_not_upper_middle(self):
        seq = chain([100, 101, 104, 110])
        row = rolling_window_occupancy(seq, {}, window=4)[0]
        self.assertEqual(row["median_ts"], 102)
        self.assertEqual(row["median_minus_min_s"], 2)
        self.assertEqual(row["ts_span_s"], 10)

    def test_odd_window_uses_middle_timestamp(self):
        row = rolling_window_occupancy(chain([100, 101, 104]), {}, window=3)[0]
        self.assertEqual(row["median_ts"], 101)

    def test_sliding_sixty_block_window_and_producer_count(self):
        seq = chain([100] * 30 + [101] * 31)
        producer = {block["hash"]: "third" for block in seq[30:]}
        rows = rolling_window_occupancy(seq, producer)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["median_ts"], 100)
        self.assertEqual(rows[0]["counts"], {"unattributed": 30, "third": 30})
        self.assertEqual(rows[1]["median_ts"], 101)
        self.assertEqual(rows[1]["counts"], {"unattributed": 29, "third": 31})


if __name__ == "__main__":
    unittest.main()
