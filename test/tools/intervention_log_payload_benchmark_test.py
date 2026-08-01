#!/usr/bin/env python3

"""Unit tests for the intervention log payload A/B benchmark."""

import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "tools/intervention-log-payload-benchmark.py"
SPEC = importlib.util.spec_from_file_location("intervention_log_payload_benchmark", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class InterventionLogPayloadBenchmarkTest(unittest.TestCase):
    def test_proc_stat_parser_handles_spaces_in_process_name(self):
        fields = ["S"] + ["0"] * 10 + ["120", "30"] + ["0"] * 10
        contents = "123 (envoy worker) " + " ".join(fields)
        self.assertEqual(MODULE.proc_stat_cpu_seconds(contents, 100, 123), 1.5)

    def test_cpu_partition_reserves_one_cpu_for_envoy(self):
        self.assertEqual(MODULE.partition_cpu_affinity({5, 2, 9}), (2, (5, 9)))
        self.assertEqual(MODULE.partition_cpu_affinity({5}), (None, (5,)))

    def test_crossover_summary_cancels_symmetric_order_effect(self):
        summary = MODULE.crossover_ratio_summary([1.20, 1.05, 1.20, 1.05])
        self.assertAlmostEqual(summary["median"], (1.20 * 1.05) ** 0.5)
        self.assertEqual(summary["candidate_wins"], 2)
        self.assertEqual(summary["crossover_blocks"], 2)

    def test_decision_requires_every_predeclared_check(self):
        favorable = {
            "median": 1.10,
            "candidate_wins": 5,
            "crossover_blocks": 5,
            "bootstrap_95_ci": {"minimum": 1.03, "maximum": 1.15},
        }
        comparisons = {
            MODULE.PRIMARY_WORKLOAD: {
                "cpu_baseline_over_candidate": favorable,
                "throughput_candidate_over_baseline": favorable,
                "p99_baseline_over_candidate": favorable,
            }
        }
        self.assertEqual(
            MODULE.performance_decision(comparisons)["status"],
            "confirmed_improvement",
        )
        comparisons[MODULE.PRIMARY_WORKLOAD]["throughput_candidate_over_baseline"] = {
            **favorable,
            "median": 0.99,
        }
        self.assertEqual(
            MODULE.performance_decision(comparisons)["status"],
            "not_confirmed",
        )


if __name__ == "__main__":
    unittest.main()
