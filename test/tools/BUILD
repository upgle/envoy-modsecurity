load("@rules_python//python:defs.bzl", "py_test")

licenses(["notice"])  # Apache-2.0 OR MIT

py_test(
    name = "crs_compatibility_report_test",
    srcs = ["crs_compatibility_report_test.py"],
    data = ["//tools:crs-compatibility-report.py"],
)

py_test(
    name = "waf_engine_comparison_test",
    srcs = ["waf_engine_comparison_test.py"],
    data = ["//tools:waf-engine-comparison.py"],
)
