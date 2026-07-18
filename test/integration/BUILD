load("@rules_python//python:defs.bzl", "py_test")

licenses(["notice"])  # Apache-2.0 OR MIT

py_test(
    name = "envoy_http_integration_test",
    size = "large",
    srcs = ["envoy_http_integration_test.py"],
    args = [
        "--config-template=$(location :modsecurity_bootstrap.yaml.tmpl)",
        "--envoy-binary=$(location //:envoy-modsecurity)",
    ],
    data = [
        ":modsecurity_bootstrap.yaml.tmpl",
        "//:envoy-modsecurity",
    ],
    tags = [
        "integration",
        "nocoverage",
        "skip_on_windows",
    ],
)
