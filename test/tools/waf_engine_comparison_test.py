#!/usr/bin/env python3

"""Unit tests for WAF benchmark measurement helpers."""

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "tools" / "waf-engine-comparison.py"
)
SPEC = importlib.util.spec_from_file_location("waf_engine_comparison", SCRIPT_PATH)
WAF_COMPARISON = importlib.util.module_from_spec(SPEC)
with mock.patch.object(
    sys,
    "argv",
    [
        "waf-engine-comparison.py",
        "--envoy-binary",
        "/nonexistent/envoy",
        "--coraza-module",
        "/nonexistent/module",
    ],
):
    SPEC.loader.exec_module(WAF_COMPARISON)


class MeasurementHelpersTest(unittest.TestCase):
    def test_process_cpu_seconds_uses_user_and_system_ticks(self):
        fields = ["R"] + ["0"] * 10 + ["123", "77"] + ["0"] * 20
        contents = f"42 (worker name) {' '.join(fields)}"

        self.assertEqual(
            WAF_COMPARISON.proc_stat_cpu_seconds(contents, 100, 42), 2.0
        )

    def test_process_cpu_seconds_accepts_closing_parenthesis_in_name(self):
        fields = ["S"] + ["0"] * 10 + ["7", "3"] + ["0"] * 20
        contents = f"9 (worker) name) {' '.join(fields)}"

        self.assertEqual(
            WAF_COMPARISON.proc_stat_cpu_seconds(contents, 100, 9), 0.1
        )

    def test_process_cpu_seconds_rejects_incomplete_stat(self):
        with self.assertRaisesRegex(RuntimeError, "incomplete process stat"):
            WAF_COMPARISON.proc_stat_cpu_seconds("42 (worker) R 0", 100, 42)

    def test_profile_request_count_is_independent_from_comparison_count(self):
        workload = {"requests": 6000, "profile_requests": 600}

        self.assertEqual(
            WAF_COMPARISON.workload_request_count(workload, 0.5, False), 3000
        )
        self.assertEqual(
            WAF_COMPARISON.workload_request_count(workload, 50, True), 30000
        )

    def test_request_count_has_a_minimum_of_one(self):
        self.assertEqual(
            WAF_COMPARISON.workload_request_count(
                {"requests": 10}, 0.001, False
            ),
            1,
        )

    def test_tiny_upstream_responses_disable_nagle(self):
        self.assertTrue(WAF_COMPARISON.UpstreamHandler.disable_nagle_algorithm)


if __name__ == "__main__":
    unittest.main()
