load("@rules_python//python:defs.bzl", "py_test")
load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_test")

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

envoy_cc_test(
    name = "filter_protocol_integration_test",
    size = "large",
    repository = "@envoy",
    srcs = ["filter_protocol_integration_test.cc"],
    tags = [
        "integration",
        "nocoverage",
        "skip_on_windows",
    ],
    deps = [
        "//api/envoy_modsecurity/extensions/filters/http/modsecurity/v3:pkg_cc_proto",
        "//source/extensions/filters/http/modsecurity:config",
        "@envoy//test/integration:http_protocol_integration_lib",
        "@envoy//test/test_common:utility_lib",
        "@envoy_api//envoy/extensions/filters/network/http_connection_manager/v3:pkg_cc_proto",
        "@com_google_absl//absl/strings",
    ],
)

envoy_cc_test(
    name = "filter_ecds_integration_test",
    size = "large",
    repository = "@envoy",
    srcs = ["filter_ecds_integration_test.cc"],
    tags = [
        "integration",
        "nocoverage",
        "skip_on_windows",
    ],
    deps = [
        "//api/envoy_modsecurity/extensions/filters/http/modsecurity/v3:pkg_cc_proto",
        "//source/extensions/filters/http/modsecurity:config",
        "@envoy//test/common/grpc:grpc_client_integration_lib",
        "@envoy//test/config:v2_link_hacks",
        "@envoy//test/integration:http_integration_lib",
        "@envoy//test/test_common:utility_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/network/http_connection_manager/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/discovery/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/extension/v3:pkg_cc_proto",
        "@com_google_absl//absl/strings",
    ],
)
