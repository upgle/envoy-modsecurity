# Development

## Prerequisites

- Git with submodule support
- Bazelisk or Bazel 8.7.0
- curl and Python 3 for the full CRS compatibility runner
- A Linux C++20 toolchain compatible with the pinned Envoy release
- Autoconf, Automake, GNU Libtool, `pkg-config`, and development headers for PCRE2, LibXML2, and
  YAJL

On Ubuntu, the native dependencies used by CI can be installed with:

```shell
sudo apt-get update
sudo apt-get install \
  autoconf automake curl libpcre2-dev libtool libxml2-dev libyajl-dev pkg-config python3
```

On Apple Silicon macOS, the best-effort local build expects the Homebrew prefixes declared in
`third_party/BUILD`:

```shell
brew install autoconf automake libtool libxml2 pcre2 pkg-config yajl
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
| Complete OWASP CRS regression with exact rule IDs and reviewed exclusions | Harness available | Run `./tools/run-crs-compatibility.sh`; a reviewed Linux baseline is still required |
| ASAN, UBSAN, and leak detection on Linux | Missing | Required before a supported release |
| Concurrent ECDS updates and transaction-lifetime stress | Missing | Required before a supported release |
| Latency and memory profiles for representative payloads | Missing | Required before a supported release |

The engine-layer tests exercise rule loading, exception boundaries, and libmodsecurity behavior
without running the HTTP filter or custom Envoy binary.

## Local OWASP CRS web lab

Run the loopback-only web lab to build the current custom Envoy binary and send controlled requests
through the filter with the pinned OWASP CRS in paranoia-level-1 blocking mode:

```shell
make owasp-lab
```

Open `http://127.0.0.1:8080/` and choose a clean or attack preset. The result view shows whether the
request reached the local echo upstream, the HTTP response, bounded rule IDs, and available CRS
anomaly scores from the filter's dynamic metadata. The generated bootstrap, root rule file, and
Envoy log live in a temporary directory printed at startup and are removed when the lab stops.

The UI, upstream, Envoy listener, and admin endpoint all bind to loopback. The web API targets only
the lab-managed Envoy listener, rejects hop-by-hop headers, limits request and response bodies to 1
MiB, and uses a per-process token for request submission. To select an available UI port
automatically or retain generated files, run:

```shell
./tools/run-owasp-crs-lab.sh --ui-port 0
./tools/run-owasp-crs-lab.sh --work-directory /tmp/envoy-modsecurity-crs-lab
```

The wrapper forwards command-line arguments to the Python lab server and supports these additional
controls:

| Control | Purpose |
| --- | --- |
| `--open-browser` | Open the lab URL in the default browser after Envoy becomes ready. |
| `--log-level LEVEL` | Set the Envoy log level; the default is `warning`. |
| `--envoy-binary PATH` | Run a specific prebuilt custom Envoy binary instead of `bazel-bin/envoy-modsecurity`. |
| `BAZEL=/path/to/bazel` | Select the Bazel or Bazelisk executable used by the build wrapper. Without it, the wrapper searches `PATH` for `bazel` and then `bazelisk`. |

Run `python3 tools/owasp-crs-lab.py --help` for the complete server option reference.

## Full OWASP CRS compatibility report

Run the complete pinned CRS go-ftw corpus against the custom Envoy binary with:

```shell
./tools/run-crs-compatibility.sh
```

The wrapper downloads pinned go-ftw and Albedo release binaries for the host platform, verifies
their SHA-256 digests, builds the custom Envoy binary when needed, and writes JSON plus Markdown
results under `artifacts/`. Set `CRS_GO_FTW_BINARY` and `CRS_ALBEDO_BINARY` to use preinstalled test
tools instead. Additional arguments are passed to the Python runner; for example,
`--include '^942100-'` limits a diagnostic run to one rule ID.

CI runs the complete corpus after the normal Linux checks and uploads
`crs-compatibility-linux-amd64` as a 30-day workflow artifact. Regression mismatches are recorded
without failing the job while the baseline is under review; runner, configuration, or process
failures still fail CI.

The test-only ruleset runs CRS at paranoia level 4 in `DetectionOnly`, enables request and response
inspection, and uses a serial audit log containing message metadata but no request or response body
parts. This lets go-ftw assert exact rule IDs without changing the production connector's disabled
native server-log callback. The report applies no platform overrides, ignores, or forced results.

Five pinned CRS stages use `retry_once`. go-ftw 2.4.0 aborts the complete run without producing JSON
when the retry also fails, so the runner disables that flag in a temporary copy of the corpus and
reports each affected stage after one attempt. The pinned CRS sources are not modified.

macOS output is diagnostic because the release reference environment is Linux. The build now fails
if the JSON or XML parser dependency is unavailable, but a supported compatibility row still
requires a reviewed full Linux run, documented explanations for every remaining failure, and
explicit approval of any expected platform deviation.

## Planned release artifacts

No release pipeline is implemented yet. A supported release is expected to include
multi-architecture Linux images, checksums, an SBOM, signatures, a compatibility manifest, and all
third-party license and notice material required by Envoy, ModSecurity, OWASP CRS, and their bundled
dependencies. Image creation remains deferred until the qualification gates pass. A standalone
filter library is not planned as an initial release artifact.
