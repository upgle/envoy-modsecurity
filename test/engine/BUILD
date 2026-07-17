load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_test", "envoy_package")

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test(
    name = "rules_test",
    srcs = ["rules_test.cc"],
    deps = [
        "//source/engine:rules_lib",
        "@abseil-cpp//absl/status",
    ],
)
