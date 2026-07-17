load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package(default_visibility = ["//visibility:public"])

envoy_cc_library(
    name = "filter_lib",
    repository = "@envoy",
    srcs = [
        "filter.cc",
        "filter_config.cc",
    ],
    hdrs = [
        "filter.h",
        "filter_config.h",
        "stats.h",
    ],
    deps = [
        "//source/engine:engine_interface",
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//envoy/common:time_interface",
        "@envoy//envoy/http:codes_interface",
        "@envoy//envoy/http:filter_interface",
        "@envoy//envoy/network:address_interface",
        "@envoy//envoy/router:router_interface",
        "@envoy//envoy/stats:stats_macros",
        "@envoy//source/common/http:utility_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
    ],
)

envoy_cc_extension(
    name = "config",
    repository = "@envoy",
    visibility = ["//visibility:public"],
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":filter_lib",
        "//api/envoy_modsecurity/extensions/filters/http/modsecurity/v3:pkg_cc_proto",
        "//source/engine:engine_lib",
        "@envoy//envoy/registry",
        "@envoy//envoy/server:factory_context_interface",
        "@envoy//envoy/singleton:manager_interface",
        "@envoy//source/extensions/filters/http/common:factory_base_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
    ],
)
