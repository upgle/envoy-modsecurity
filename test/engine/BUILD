load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_test", "envoy_package")

licenses(["notice"])  # Apache-2.0 OR MIT

envoy_package()

envoy_cc_test(
    name = "exception_test",
    repository = "@envoy",
    srcs = ["exception_test.cc"],
    deps = [
        "//source/engine:exception_lib",
        "@abseil-cpp//absl/status",
    ],
)

envoy_cc_test(
    name = "rules_test",
    repository = "@envoy",
    srcs = ["rules_test.cc"],
    deps = [
        "//source/engine:rules_lib",
        "@abseil-cpp//absl/status",
    ],
)

envoy_cc_test(
    name = "engine_integration_test",
    repository = "@envoy",
    srcs = ["engine_integration_test.cc"],
    deps = [
        "//source/engine:engine_lib",
        "@abseil-cpp//absl/status",
        "@envoy//test/test_common:environment_lib",
    ],
)
