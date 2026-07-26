load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_library", "envoy_package")

licenses(["notice"])  # Apache-2.0 OR MIT

envoy_package()

config_setting(
    name = "libmodsecurity_connector_optimizations_disabled",
    define_values = {"libmodsecurity_connector_optimizations": "disabled"},
    visibility = ["//visibility:private"],
)

envoy_cc_library(
    name = "engine_interface",
    repository = "@envoy",
    hdrs = ["engine.h"],
    deps = [
        "@abseil-cpp//absl/container:inlined_vector",
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
    local_defines = select({
        ":libmodsecurity_connector_optimizations_disabled": [
            "ENVOY_MODSECURITY_CONNECTOR_OPTIMIZATIONS_DISABLED",
        ],
        "//conditions:default": [],
    }),
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
