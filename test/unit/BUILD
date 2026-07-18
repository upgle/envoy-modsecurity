load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_test", "envoy_package")

licenses(["notice"])  # Apache-2.0 OR MIT

envoy_package()

envoy_cc_test(
    name = "config_test",
    repository = "@envoy",
    srcs = ["config_test.cc"],
    deps = [
        "//api/envoy_modsecurity/extensions/filters/http/modsecurity/v3:pkg_cc_proto",
        "//source/extensions/filters/http/modsecurity:config",
        "@envoy//test/mocks/server:server_mocks",
    ],
)

envoy_cc_test(
    name = "filter_test",
    repository = "@envoy",
    srcs = ["filter_test.cc"],
    deps = [
        "//source/engine:engine_interface",
        "//source/extensions/filters/http/modsecurity:filter_lib",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/common/stats:isolated_store_lib",
        "@envoy//test/mocks/http:http_mocks",
        "@envoy//test/test_common:simulated_time_system_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
    ],
)
