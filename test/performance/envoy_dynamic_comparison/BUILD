load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_binary")

licenses(["notice"])  # Apache-2.0 OR MIT

package(default_visibility = ["//visibility:public"])

# Benchmark-only Envoy binary that registers both the native ModSecurity filter and Envoy's
# Dynamic Modules HTTP filter. The comparison build command injects this package as a local
# repository so the production binary does not gain an additional extension or loading surface.
envoy_cc_binary(
    name = "envoy-waf-comparison",
    repository = "@envoy",
    srcs = ["//:source/exe/main.cc"],
    stamped = True,
    deps = [
        "//source/extensions/filters/http/modsecurity:config",
        "@envoy//source/common/formatter:formatter_extension_lib",
        "@envoy//source/exe:envoy_main_common_with_core_extensions_lib",
        "@envoy//source/exe:envoy_stripped_main_base_lib",
        "@envoy//source/extensions/clusters/static:static_cluster_lib",
        "@envoy//source/extensions/filters/http/dynamic_modules:factory_registration",
        "@envoy//source/exe:platform_impl_lib",
        "@envoy//source/exe:scm_impl_lib",
        "@envoy//source/server:options_lib",
        "@abseil-cpp//absl/debugging:symbolize",
    ],
)
