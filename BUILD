load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_binary")

licenses(["notice"])  # Apache-2.0 OR MIT

package(default_visibility = ["//visibility:public"])

exports_files([
    "Cargo.Bazel.lock",
    "DEPENDENCIES.lock",
])

# Build the public language bindings consumed by the filter and downstream tooling.
# Envoy's api_proto_package also creates an internal descriptor helper target; it is
# intentionally excluded because it is not part of the out-of-tree API contract.
filegroup(
    name = "api_bindings",
    srcs = [
        "//api/envoy_modsecurity/extensions/filters/http/modsecurity/v3:pkg_cc_proto",
        "//api/envoy_modsecurity/extensions/filters/http/modsecurity/v3:pkg_go_proto",
        "//api/envoy_modsecurity/extensions/filters/http/modsecurity/v3:pkg_java_proto",
        "//api/envoy_modsecurity/extensions/filters/http/modsecurity/v3:pkg_py_proto",
    ],
)

# Custom Envoy with the out-of-tree filter linked for static factory registration.
envoy_cc_binary(
    name = "envoy-modsecurity",
    repository = "@envoy",
    srcs = ["source/exe/main.cc"],
    stamped = True,
    deps = [
        "//source/extensions/filters/http/modsecurity:config",
        "@envoy//source/common/formatter:formatter_extension_lib",
        "@envoy//source/exe:envoy_main_common_with_core_extensions_lib",
        "@envoy//source/exe:envoy_stripped_main_base_lib",
        "@envoy//source/extensions/clusters/static:static_cluster_lib",
        "@envoy//source/exe:platform_impl_lib",
        "@envoy//source/exe:scm_impl_lib",
        "@envoy//source/server:options_lib",
        "@abseil-cpp//absl/debugging:symbolize",
    ],
)
