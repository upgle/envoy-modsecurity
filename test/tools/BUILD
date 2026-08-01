load("@rules_python//python:defs.bzl", "py_test")

licenses(["notice"])  # Apache-2.0 OR MIT

py_test(
    name = "crs_compatibility_report_test",
    srcs = ["crs_compatibility_report_test.py"],
    data = ["//tools:crs-compatibility-report.py"],
)

py_test(
    name = "intervention_log_payload_benchmark_test",
    srcs = ["intervention_log_payload_benchmark_test.py"],
    data = ["//tools:intervention-log-payload-benchmark.py"],
)
