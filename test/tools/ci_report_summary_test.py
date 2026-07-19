#!/usr/bin/env python3

"""Unit tests for the GitHub Actions QA report summary."""

from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "tools" / "ci-report-summary.py"
SPEC = importlib.util.spec_from_file_location("ci_report_summary", SCRIPT_PATH)
CI_SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI_SUMMARY)


class CiReportSummaryTest(unittest.TestCase):
    def test_extracts_only_crs_summary_section(self):
        report = """# CRS report

## Summary

| Passed | Failed |
| ---: | ---: |
| 10 | 0 |

## Results by traffic side

details
"""

        self.assertEqual(
            CI_SUMMARY.markdown_section(report, "## Summary"),
            "| Passed | Failed |\n| ---: | ---: |\n| 10 | 0 |",
        )

    def test_builds_summary_and_uniquely_named_previews(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifacts = root / "artifacts"
            preview = root / "preview"
            crs = artifacts / "crs-compatibility-linux-amd64"
            qualification = artifacts / "qualification-benchmark"
            body_pressure = artifacts / "body-pressure-stress"
            crs.mkdir(parents=True)
            qualification.mkdir()
            body_pressure.mkdir()
            (crs / "crs-compatibility-report.md").write_text(
                "# CRS\n\n## Summary\n\nPassed: 10\n\n## Details\n\nLong details\n",
                encoding="utf-8",
            )
            benchmark = "# Benchmark\n\n| p99 | RSS |\n| ---: | ---: |\n| 12 | 34 |\n"
            (qualification / "qualification-benchmark.md").write_text(
                benchmark, encoding="utf-8"
            )
            (body_pressure / "qualification-benchmark.md").write_text(
                benchmark, encoding="utf-8"
            )

            summary = CI_SUMMARY.build_summary(artifacts, preview)

            self.assertIn("Passed: 10", summary)
            self.assertNotIn("Long details", summary)
            self.assertIn("| p99 | RSS |", summary)
            self.assertTrue((preview / "crs-compatibility-report.md").is_file())
            self.assertTrue((preview / "qualification-benchmark-report.md").is_file())
            self.assertTrue((preview / "body-pressure-stress-report.md").is_file())

    def test_marks_missing_reports_without_failing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)

            summary = CI_SUMMARY.build_summary(root / "artifacts", root / "preview")

            self.assertEqual(summary.count("Not produced"), 3)
            self.assertEqual(summary.count("earlier QA stage may have failed"), 3)

    def test_uses_error_for_enforced_and_warning_for_diagnostic_violations(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            enforced = root / "enforced.json"
            diagnostic = root / "diagnostic.json"
            enforced.write_text(
                json.dumps({"enforced": True, "violations": ["p99: 300, limit 250"]}),
                encoding="utf-8",
            )
            diagnostic.write_text(
                json.dumps({"enforced": False, "violations": ["RSS grew 300%"]}),
                encoding="utf-8",
            )
            output = io.StringIO()

            with redirect_stdout(output):
                CI_SUMMARY.benchmark_annotations(enforced, "Enforced: threshold")
                CI_SUMMARY.benchmark_annotations(diagnostic, "Diagnostic")

            annotations = output.getvalue()
            self.assertIn("::error title=Enforced%3A threshold::p99: 300, limit 250", annotations)
            self.assertIn("::warning title=Diagnostic::RSS grew 300%25", annotations)


if __name__ == "__main__":
    unittest.main()
