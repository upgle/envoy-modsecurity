#!/usr/bin/env python3

"""Unit tests for WAF benchmark measurement helpers."""

from concurrent.futures import Future
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "tools" / "waf-engine-comparison.py"
)
BOOTSTRAP_TEMPLATE_PATH = (
    Path(__file__).resolve().parents[2]
    / "test"
    / "performance"
    / "waf_comparison_bootstrap.yaml.tmpl"
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

    def test_baseline_status_can_match_an_early_block(self):
        workload = {"baseline_status": 403, "waf_status": 403}

        self.assertEqual(
            WAF_COMPARISON.expected_workload_status("baseline", workload), 403
        )
        self.assertEqual(
            WAF_COMPARISON.expected_workload_status("native", workload), 403
        )

    def test_baseline_status_defaults_to_success(self):
        self.assertEqual(
            WAF_COMPARISON.expected_workload_status(
                "baseline", {"waf_status": 403}
            ),
            200,
        )

    def test_phase_one_baseline_direct_response_precedes_upstream_route(self):
        template = BOOTSTRAP_TEMPLATE_PATH.read_text(encoding="utf-8")

        direct_response = template.index("exact: phase1-block")
        upstream_route = template.index("cluster: waf_comparison_upstream")
        self.assertLess(direct_response, upstream_route)
        self.assertIn("direct_response:\n                            status: 403", template)

    def test_tiny_upstream_responses_disable_nagle(self):
        self.assertTrue(WAF_COMPARISON.UpstreamHandler.disable_nagle_algorithm)

    def test_client_process_count_covers_warmup_and_peak_concurrency(self):
        self.assertEqual(
            WAF_COMPARISON.max_client_processes(
                [{"concurrency": 1}, {"concurrency": 16}]
            ),
            16,
        )
        self.assertEqual(
            WAF_COMPARISON.max_client_processes([{"concurrency": 1}]),
            WAF_COMPARISON.WARMUP_CONCURRENCY,
        )

    def test_cpu_affinity_partition_reserves_one_envoy_cpu(self):
        self.assertEqual(
            WAF_COMPARISON.partition_cpu_affinity({5, 2, 9}),
            (2, (5, 9)),
        )
        self.assertEqual(
            WAF_COMPARISON.partition_cpu_affinity({7}),
            (None, (7,)),
        )

    def test_client_topology_reports_processes_and_affinity(self):
        description = WAF_COMPARISON.client_topology_description(
            {
                "client_processes": 16,
                "envoy_cpu": 2,
                "client_cpus": (5, 9),
            }
        )

        self.assertIn("16 persistent spawned client processes", description)
        self.assertIn("Envoy threads are pinned to CPU 2", description)
        self.assertIn("CPUs 5,9", description)

    def test_patch_ab_ratio_summary_reports_paired_wins_and_interval(self):
        summary = WAF_COMPARISON.patch_ab_ratio_summary(
            [1.01, 1.02, 0.99, 1.03, 1.04, 0.98]
        )

        self.assertEqual(summary["patched_wins"], 3)
        self.assertEqual(summary["crossover_blocks"], 3)
        self.assertEqual(summary["repeats"], 6)
        self.assertLessEqual(
            summary["bootstrap_95_ci"]["minimum"], summary["median"]
        )
        self.assertGreaterEqual(
            summary["bootstrap_95_ci"]["maximum"], summary["median"]
        )

    def test_patch_ab_ratio_summary_is_deterministic(self):
        values = [0.98, 1.01, 1.02, 1.03, 1.05, 0.99]

        self.assertEqual(
            WAF_COMPARISON.patch_ab_ratio_summary(values),
            WAF_COMPARISON.patch_ab_ratio_summary(values),
        )

    def test_patch_ab_aggregation_uses_same_repeat_pairs(self):
        def run(variant, repeat, throughput, cpu, p50, p99):
            return {
                "engine": variant,
                "repeat": repeat,
                "startup_ms": 10,
                "rss_after_warmup_bytes": 100,
                "rss_after_suite_bytes": 120,
                "workloads": {
                    "headers": {
                        "throughput_rps": throughput,
                        "envoy_cpu_ms_per_request": cpu,
                        "latency_ms": {
                            "median": p50,
                            "p95": p99,
                            "p99": p99,
                            "maximum": p99,
                        },
                    }
                },
            }

        runs = [
            run("patched", 0, 110, 1.0, 1.0, 2.0),
            run("unpatched", 0, 100, 1.1, 1.1, 2.2),
            run("patched", 1, 200, 2.0, 2.0, 4.0),
            run("unpatched", 1, 200, 2.0, 2.0, 4.0),
        ]
        with mock.patch.object(WAF_COMPARISON.ARGS, "repeats", 2):
            _aggregate, comparisons = WAF_COMPARISON.aggregate_patch_ab_results(
                runs, [{"name": "headers"}]
            )

        ratios = comparisons["headers"]["paired_repeat_ratios"]
        expected_crossover_ratio = 1.1**0.5
        self.assertAlmostEqual(
            ratios["throughput_patched_over_unpatched"]["median"],
            expected_crossover_ratio,
        )
        self.assertAlmostEqual(
            ratios["cpu_unpatched_over_patched"]["median"],
            expected_crossover_ratio,
        )
        self.assertEqual(
            ratios["throughput_patched_over_unpatched"]["patched_wins"], 1
        )

    def test_patch_ab_decision_uses_predeclared_primary_thresholds(self):
        def summary(median, lower=1.01, wins=4):
            return {
                "median": median,
                "bootstrap_95_ci": {"minimum": lower, "maximum": 1.06},
                "patched_wins": wins,
                "crossover_blocks": 5,
            }

        comparisons = {
            "phase1_block_c1": {
                "paired_repeat_ratios": {
                    "cpu_unpatched_over_patched": summary(1.03),
                    "throughput_patched_over_unpatched": summary(1.01),
                    "p99_unpatched_over_patched": summary(0.99),
                }
            }
        }

        self.assertEqual(
            WAF_COMPARISON.patch_ab_decision(comparisons)["status"],
            "confirmed_improvement",
        )
        comparisons["phase1_block_c1"]["paired_repeat_ratios"][
            "cpu_unpatched_over_patched"
        ] = summary(1.01)
        self.assertEqual(
            WAF_COMPARISON.patch_ab_decision(comparisons)["status"],
            "not_confirmed",
        )

    def test_concurrent_workload_uses_shared_process_pool(self):
        class FakePool:
            def __init__(self):
                self.calls = []

            def submit(self, function, *args):
                self.calls.append((function, args))
                future = Future()
                future.set_result([0.1] * args[2])
                return future

        workload = {
            "name": "concurrent",
            "requests": 4,
            "concurrency": 2,
            "method": "GET",
            "path": "/",
            "body": None,
            "headers": {},
            "waf_status": 200,
        }
        pool = FakePool()
        with mock.patch.object(WAF_COMPARISON, "CLIENT_PROCESS_POOL", pool), mock.patch.object(
            WAF_COMPARISON, "process_cpu_seconds", side_effect=[1.0, 1.1]
        ), mock.patch.object(
            WAF_COMPARISON.time, "perf_counter", side_effect=[10.0, 11.0]
        ):
            result = WAF_COMPARISON.run_workload(10000, 42, "baseline", workload)

        self.assertEqual(len(pool.calls), 2)
        self.assertEqual(result["requests"], 4)
        self.assertEqual(result["throughput_rps"], 4.0)

    def test_single_connection_runs_without_process_pool(self):
        workload = {
            "name": "serial",
            "requests": 3,
            "concurrency": 1,
            "method": "GET",
            "path": "/",
            "body": None,
            "headers": {},
            "waf_status": 200,
        }
        with mock.patch.object(WAF_COMPARISON, "CLIENT_PROCESS_POOL", None), mock.patch.object(
            WAF_COMPARISON, "request_worker", return_value=[0.1, 0.2, 0.3]
        ) as request_worker, mock.patch.object(
            WAF_COMPARISON, "process_cpu_seconds", side_effect=[1.0, 1.1]
        ), mock.patch.object(
            WAF_COMPARISON.time, "perf_counter", side_effect=[10.0, 11.0]
        ):
            result = WAF_COMPARISON.run_workload(10000, 42, "baseline", workload)

        request_worker.assert_called_once()
        self.assertEqual(result["latency_ms"]["median"], 0.2)


if __name__ == "__main__":
    unittest.main()
