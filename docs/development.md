# Development

## Prerequisites

- Git with submodule support
- Bazelisk or Bazel 8.7.0
- A Linux C++20 toolchain compatible with the pinned Envoy release
- Autoconf, Automake, GNU Libtool, `pkg-config`, and development headers for PCRE2 and YAJL

On Ubuntu, the native dependencies used by CI can be installed with:

```shell
sudo apt-get update
sudo apt-get install autoconf automake libpcre2-dev libtool libyajl-dev pkg-config
```

Ubuntu 24.04 CI is the reference environment. macOS builds are best-effort and are not CI-qualified;
release qualification must run on Linux.

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

- the Envoy-independent engine abstraction and native libmodsecurity adapter;
- ordered file and inline rule loading with an inline-rule capability denylist;
- statically registered filter factory and custom Envoy binary;
- request, optional response, intervention, and logging phases;
- per-route overrides, per-stream limits, aggregate body-memory budgeting, and early release;
- explicit handling for gRPC requests, Connect streaming, WebSocket/CONNECT tunnels, event streams,
  chunked bodies, oversized payloads, and trailers;
- engine, filter, custom-Envoy HTTP integration, and pinned OWASP CRS PL1 smoke suites.

The missing qualification and packaging items below block a supported release.

## Verification status

| Scope | Status | Command or remaining work |
| --- | --- | --- |
| API, engine layer, HTTP filter, and custom Envoy HTTP/1.1 | Available | `make check` |
| OWASP CRS PL1 smoke against custom Envoy | Available | `make integration-test` |
| Explicit HTTP/2 and stream-reset matrix | Missing | Required before a supported release |
| Complete OWASP CRS regression with exact rule IDs and reviewed exclusions | Missing | Required before a supported release |
| ASAN, UBSAN, and leak detection on Linux | Missing | Required before a supported release |
| Concurrent ECDS updates and transaction-lifetime stress | Missing | Required before a supported release |
| Latency and memory profiles for representative payloads | Missing | Required before a supported release |

The engine-layer tests exercise rule loading, exception boundaries, and libmodsecurity behavior
without running the HTTP filter or custom Envoy binary.

## Planned release artifacts

No release pipeline is implemented yet. A supported release is expected to include
multi-architecture Linux images, checksums, an SBOM, signatures, a compatibility manifest, and all
third-party license and notice material required by Envoy, ModSecurity, OWASP CRS, and their bundled
dependencies. Image creation remains deferred until the qualification gates pass. A standalone
filter library is not planned as an initial release artifact.
