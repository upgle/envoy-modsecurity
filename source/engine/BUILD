load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_library", "envoy_package")

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_library(
    name = "engine_interface",
    repository = "@envoy",
    hdrs = ["engine.h"],
    deps = [
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings:string_view",
    ],
)

envoy_cc_library(
    name = "exception_lib",
    repository = "@envoy",
    hdrs = ["exception.h"],
    deps = [
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:string_view",
    ],
)

envoy_cc_library(
    name = "rules_lib",
    repository = "@envoy",
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
    repository = "@envoy",
    srcs = ["transaction.cc"],
    hdrs = ["transaction.h"],
    deps = [
        ":engine_interface",
        ":exception_lib",
        "//third_party:libmodsecurity",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
    ],
)

envoy_cc_library(
    name = "engine_lib",
    repository = "@envoy",
    srcs = ["engine.cc"],
    deps = [
        ":engine_interface",
        ":exception_lib",
        ":rules_lib",
        ":transaction_lib",
        "//third_party:libmodsecurity",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
    ],
)
