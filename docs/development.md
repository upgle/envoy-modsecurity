# Development

## Prerequisites

- Git with submodule support
- Bazelisk or Bazel 8.7.0
- A Linux C++20 toolchain compatible with the pinned Envoy release
- Build prerequisites for ModSecurity v3 when working on the engine adapter

The CI environment is the reference environment. macOS may be used for API and source work, but a
release must be produced and tested on Linux.

## Setup

```shell
make bootstrap
make check
```

`make bootstrap` initializes all top-level and nested submodules, then verifies their commits
against `DEPENDENCIES.lock`.

`Cargo.Bazel.lock` is a symlink to Envoy's external-consumer lockfile for the pinned release. Do
not repin it in this repository; update it only by moving to an Envoy release that carries a new
external lockfile.

## Delivery sequence

1. Add the engine abstraction and libmodsecurity build target.
2. Load and validate rules during filter-config construction.
3. Implement request headers and request-body phases with bounded buffering.
4. Implement interventions and fail-open/fail-closed behavior.
5. Add optional response phases and per-route configuration.
6. Add the custom Envoy binary and runtime container.
7. Gate the first release on the complete test matrix below.

The filter factory and custom Envoy binary are deliberately deferred until the engine adapter is
available. Registering a pass-through placeholder under the production filter name could make a
deployment appear protected when no rules are being evaluated.

## Required tests

- Engine unit tests that do not link Envoy.
- Filter unit tests for headers, data, trailers, callbacks, limits, and destruction.
- Envoy integration tests for HTTP/1.1, HTTP/2, local replies, resets, and route overrides.
- OWASP CRS regression tests with an explicit, reviewed exclusion file.
- ASAN and UBSAN builds.
- Concurrency tests for shared engine and rules lifetimes.
- Benchmarks for large JSON, form, multipart, and response payloads.

## Release artifacts

The release pipeline will produce multi-architecture Linux images, checksums, an SBOM, signatures,
and a compatibility manifest. A standalone filter library is not an initial release artifact.
