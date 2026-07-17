load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_library", "envoy_package")

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_library(
    name = "engine_interface",
    hdrs = ["engine.h"],
    deps = [
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings:string_view",
    ],
)

envoy_cc_library(
    name = "rules_lib",
    srcs = ["rules.cc"],
    hdrs = ["rules.h"],
    deps = [
        ":engine_interface",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
    ],
)

envoy_cc_library(
    name = "transaction_lib",
    srcs = ["transaction.cc"],
    hdrs = ["transaction.h"],
    deps = [
        ":engine_interface",
        "//third_party:libmodsecurity",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
    ],
)

envoy_cc_library(
    name = "engine_lib",
    srcs = ["engine.cc"],
    deps = [
        ":engine_interface",
        ":rules_lib",
        ":transaction_lib",
        "//third_party:libmodsecurity",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
    ],
)
