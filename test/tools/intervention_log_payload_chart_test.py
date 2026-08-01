#!/usr/bin/env python3

"""Unit tests for the intervention log payload chart data renderer."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "tools"
    / "render-intervention-log-payload-chart.py"
)
SNAPSHOT = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "performance"
    / "intervention-log-payload-ab-chart.json"
)
SPEC = importlib.util.spec_from_file_location("intervention_log_payload_chart", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class InterventionLogPayloadChartTest(unittest.TestCase):
    def test_committed_snapshot_preserves_primary_effect(self):
        data = MODULE.load_chart_data(SNAPSHOT)

        primary = data["workloads"][0]
        self.assertEqual(primary["name"], "phase1_block_c1")
        self.assertAlmostEqual(primary["change"], 10.845864606360545)
        self.assertEqual(primary["wins"], 5)
        self.assertEqual(primary["blocks"], 5)

    def test_effect_label_distinguishes_clear_and_inconclusive_intervals(self):
        clear = {
            "change": 10.85,
            "change_minimum": 4.55,
            "change_maximum": 12.95,
            "wins": 5,
            "blocks": 5,
        }
        inconclusive = {
            "change": -0.11,
            "change_minimum": -0.77,
            "change_maximum": 1.48,
            "wins": 2,
            "blocks": 5,
        }

        self.assertEqual(
            MODULE.effect_label(clear),
            ("+10.8% [+4.5%, +12.9%]", "5/5 blocks improved"),
        )
        self.assertEqual(
            MODULE.effect_label(inconclusive),
            ("-0.1% [-0.8%, +1.5%]", "no clear change"),
        )

    def test_normalized_snapshot_requires_expected_workload_order(self):
        payload = {
            "schema": MODULE.SCHEMA,
            "source": {},
            "workloads": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "expected order"):
                MODULE.load_chart_data(path)


if __name__ == "__main__":
    unittest.main()
