#!/usr/bin/env python3

"""Unit tests for the WAF performance chart renderer."""

import importlib.util
from pathlib import Path
import unittest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "tools"
    / "render-waf-performance-chart.py"
)
SPEC = importlib.util.spec_from_file_location(
    "render_waf_performance_chart",
    SCRIPT_PATH,
)
CHART = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHART)


class AxisHelpersTest(unittest.TestCase):
    def test_summary_axis_expands_for_new_extremes(self):
        minimum, maximum, ticks = CHART.summary_ratio_axis(
            [{"minimum": 0.4, "maximum": 31}]
        )

        self.assertEqual(minimum, 0.25)
        self.assertEqual(maximum, 35.0)
        self.assertEqual(ticks[0], 0.25)
        self.assertEqual(ticks[-1], 35)

    def test_log_axis_expands_to_enclosing_powers_of_two(self):
        minimum, maximum, ticks = CHART.ratio_log_axis(
            [{"minimum": 0.2, "maximum": 100}]
        )

        self.assertEqual((minimum, maximum), (-3, 7))
        self.assertEqual(ticks[0], 0.125)
        self.assertEqual(ticks[-1], 128)

    def test_linear_axis_preserves_preferred_scale_when_it_fits(self):
        maximum, ticks = CHART.linear_axis(
            1644,
            1800,
            (0, 600, 1200, 1800),
        )

        self.assertEqual(maximum, 1800)
        self.assertEqual(ticks, (0, 600, 1200, 1800))

    def test_linear_axis_expands_without_clipping(self):
        maximum, ticks = CHART.linear_axis(
            1900,
            1800,
            (0, 600, 1200, 1800),
        )

        self.assertGreaterEqual(maximum, 1900)
        self.assertEqual(ticks[0], 0)
        self.assertEqual(ticks[-1], maximum)

    def test_environment_label_comes_from_snapshot_platform(self):
        data = {
            "source": {
                "platform": "Darwin-25.0.0-arm64",
                "envoy_version": "envoy version: /1.39.0/",
                "versions": {"crs": "v4.28.0"},
                "parameters": {"envoy_concurrency": 1},
                "build_profile": "diagnostic",
            },
            "workloads": [
                {
                    "metrics": {
                        metric["name"]: {"repeats": 3}
                        for metric in CHART.METRICS
                    }
                }
            ],
        }

        self.assertEqual(
            CHART.benchmark_environment(data)["platform"],
            "Darwin arm64",
        )


if __name__ == "__main__":
    unittest.main()
