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

## Implementation status

The repository currently includes:

- the Envoy-independent engine abstraction and real libmodsecurity adapter;
- ordered file and inline rule loading with safe-profile validation;
- statically registered filter factory and custom Envoy binary;
- request, optional response, intervention, and logging phases;
- per-route overrides, per-stream limits, aggregate body-memory budgeting, and early release;
- explicit handling for gRPC/Connect streaming, WebSocket/CONNECT tunnels, event streams, chunks,
  oversized payloads, and trailers;
- engine, filter, and custom-Envoy HTTP integration suites.

The first supported release remains gated on the missing qualification and packaging work below.

## Required tests

- Engine unit and exception-boundary tests that do not link Envoy. Implemented.
- Filter tests for headers, data, trailers, callbacks, limits, streaming bypass, and destruction.
  Implemented.
- Custom Envoy HTTP integration tests for allowed, blocked, chunked, oversized, streaming, upgrade,
  and trailer paths. Implemented; expand to an explicit HTTP/2 and reset matrix before release.
- OWASP CRS regression tests with an explicit, reviewed exclusion file. Required before release.
- ASAN, UBSAN, and leak-sanitizer builds on Linux. Required before release.
- Concurrency and update-churn tests for runtime, rule generations, budgets, and transaction
  lifetimes. Required before release.
- Benchmarks and memory profiles for large JSON, form, multipart, streaming, and response payloads.
  Required before release.

## Release artifacts

The release pipeline will produce multi-architecture Linux images, checksums, an SBOM, signatures,
and a compatibility manifest. Image creation is intentionally deferred until the qualification
gates pass. A standalone filter library is not an initial release artifact.
