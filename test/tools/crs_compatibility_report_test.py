#!/usr/bin/env python3

"""Unit tests for fail-closed CRS qualification result validation."""

import importlib.util
from pathlib import Path
import unittest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "tools" / "crs-compatibility-report.py"
)
SPEC = importlib.util.spec_from_file_location("crs_compatibility_report", SCRIPT_PATH)
CRS_REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CRS_REPORT)


class QualificationFailuresTest(unittest.TestCase):
    def failures(
        self,
        results,
        *,
        returncode=0,
        expected_ids=("100-1", "100-2"),
        expected_count=2,
        full_run=True,
        apply_platform_overrides=False,
        fail_on_test_failure=True,
    ):
        return CRS_REPORT.qualification_failures(
            results=results,
            returncode=returncode,
            expected_test_ids=expected_ids,
            expected_test_count=expected_count,
            full_run=full_run,
            apply_platform_overrides=apply_platform_overrides,
            fail_on_test_failure=fail_on_test_failure,
        )

    def assert_failure_contains(self, failures, text):
        self.assertTrue(
            any(text in failure for failure in failures),
            f"{text!r} was not found in {failures!r}",
        )

    def test_accepts_complete_successful_result(self):
        self.assertEqual(self.failures({"success": ["100-1", "100-2"]}), [])

    def test_rejects_nonzero_go_ftw_exit_with_complete_json(self):
        failures = self.failures(
            {"success": ["100-1", "100-2"]}, returncode=2
        )

        self.assert_failure_contains(failures, "exited with status 2")

    def test_rejects_skipped_result(self):
        failures = self.failures(
            {"success": ["100-1"], "skipped": ["100-2"]}
        )

        self.assert_failure_contains(failures, "skipped tests")

    def test_rejects_incomplete_full_result_set(self):
        failures = self.failures({"success": ["100-1"]})

        self.assert_failure_contains(failures, "1 result entries; expected 2")
        self.assert_failure_contains(failures, "omitted expected test IDs: 100-2")

    def test_rejects_duplicate_result_ids(self):
        failures = self.failures(
            {"success": ["100-1", "100-2"], "failed": ["100-2"]}
        )

        self.assert_failure_contains(failures, "duplicate test IDs: 100-2")

    def test_rejects_pinned_corpus_count_mismatch(self):
        failures = self.failures(
            {"success": ["100-1"]},
            expected_ids=("100-1",),
            expected_count=2,
        )

        self.assert_failure_contains(failures, "metadata contains 1 tests; expected 2")

    def test_allows_subset_completeness_for_diagnostics(self):
        self.assertEqual(
            self.failures({"success": ["100-1"]}, full_run=False), []
        )

    def test_accepts_exact_reviewed_ignore_set(self):
        self.assertEqual(
            self.failures(
                {"success": ["100-1"], "ignored": ["920430-5"]},
                expected_ids=("100-1", "920430-5"),
                apply_platform_overrides=True,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
