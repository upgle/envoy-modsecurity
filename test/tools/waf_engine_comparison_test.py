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
