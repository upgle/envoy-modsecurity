load("@rules_python//python:defs.bzl", "py_test")

licenses(["notice"])  # Apache-2.0 OR MIT

py_test(
    name = "ci_report_summary_test",
    srcs = ["ci_report_summary_test.py"],
    data = ["//tools:ci-report-summary.py"],
)

py_test(
    name = "crs_compatibility_report_test",
    srcs = ["crs_compatibility_report_test.py"],
    data = ["//tools:crs-compatibility-report.py"],
)
