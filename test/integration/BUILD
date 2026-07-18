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

py_test(
    name = "owasp_crs_smoke_test",
    size = "large",
    srcs = ["owasp_crs_smoke_test.py"],
    args = [
        "--config-template=$(location :owasp_crs_bootstrap.yaml.tmpl)",
        "--crs-config-template=$(location :owasp_crs.conf.tmpl)",
        "--crs-rules-marker=$(location //third_party:owasp_crs_rules_marker)",
        "--crs-setup=$(location //third_party:owasp_crs_setup)",
        "--envoy-binary=$(location //:envoy-modsecurity)",
        "--unicode-mapping=$(location //third_party:modsecurity_unicode_mapping)",
    ],
    data = [
        ":owasp_crs.conf.tmpl",
        ":owasp_crs_bootstrap.yaml.tmpl",
        "//:envoy-modsecurity",
        "//third_party:modsecurity_unicode_mapping",
        "//third_party:owasp_crs_rules",
        "//third_party:owasp_crs_rules_marker",
        "//third_party:owasp_crs_setup",
    ],
    tags = [
        "integration",
        "nocoverage",
        "skip_on_windows",
    ],
)
