load("@envoy_api//bazel:api_build_system.bzl", "api_proto_package")

licenses(["notice"])  # Apache-2.0 OR MIT

api_proto_package(
    deps = [
        "@envoy_api//envoy/config/core/v3:pkg",
        "@envoy_api//envoy/type/v3:pkg",
        "@xds//udpa/annotations:pkg",
        "@xds//xds/annotations/v3:pkg",
    ],
)
