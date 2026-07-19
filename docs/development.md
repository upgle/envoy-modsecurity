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
- engine, filter, custom-Envoy HTTP integration, and pinned OWASP CRS PL1 smoke suites;
- HTTP/1.1 and HTTP/2 boundary, trailer, downstream-reset, upstream-reset, multiplexing, and
  explicit unbounded-route tests, including actual chunked-response overflow and concurrent HTTP/2
  aggregate-body-budget exhaustion;
- multi-worker ECDS ACK/NACK, last-good retention, generation pinning, and update-churn tests;
- Linux ASAN/LSan/UBSAN and TSAN CI gates; and
- a thresholded latency, throughput, pathological-regex CPU, and RSS qualification benchmark plus
  a scheduled body-pressure stress profile.

These gates must pass for the exact release candidate. Their presence alone is not release evidence,
and packaging and operational qualification still block a supported release.

The GitHub Actions workflow separates release verification into three jobs. The `build` job first
compiles the normal custom Envoy binary and publishes reusable Bazel outputs to the configured
remote cache. After it succeeds, the `qa` and `sanitizers` jobs run in parallel with independent
180-minute timeouts. QA runs the normal suites, complete CRS corpus, and qualification benchmark;
the sanitizer job rebuilds the selected targets with ASAN/LSan/UBSAN and TSAN instrumentation.
Sanitizer actions may reuse compilation outputs, but their test-result cache is disabled so every
release-gate run executes the instrumented binaries.
The separate `body-pressure stress` workflow runs daily and on manual dispatch. It exercises
concurrent 1 MiB requests and responses plus repeated 256 KiB body waves, records sampled peak RSS,
and uploads its report for 30 days without extending every pull-request run. Request failures,
unexpected statuses, timeouts, and non-zero terminal gauges fail the workflow. Performance and RSS
thresholds remain diagnostic until a reviewed Linux baseline is available.

## Verification status

| Scope | Status | Command or remaining work |
| --- | --- | --- |
| API, engine layer, HTTP filter, and custom Envoy HTTP/1.1 | Available | `make check` |
| OWASP CRS PL1 smoke against custom Envoy | Available | `make integration-test` |
| Explicit HTTP/2 and stream-reset matrix | Gate implemented | `//test/integration:filter_protocol_integration_test` |
| Complete OWASP CRS regression with exact rule IDs and reviewed exclusions | Required CI gate | `./tools/run-crs-compatibility.sh --apply-platform-overrides --fail-on-test-failure` |
| ASAN, UBSAN, and leak detection on Linux | Required CI gate | `tools/ci-envoy-build.sh sanitizers` runs the in-process lifetime suites with `--config=asan` |
| Data-race detection | Required CI gate | `tools/ci-envoy-build.sh sanitizers` runs engine, budget, and multi-worker ECDS churn with `--config=tsan` |
| Concurrent ECDS updates and transaction-lifetime stress | Required TSAN gate | `//test/integration:filter_ecds_integration_test` overlaps requests on four exactly balanced workers with accepted configuration updates |
| Latency, CPU, throughput, and RSS profile | Required CI gate | `make qualification-benchmark` |
| Concurrent large-body pressure and longer RSS sampling | Scheduled CI evidence; functional gate | `make body-pressure-stress` |

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

CI runs the complete corpus after the normal Linux and sanitizer checks and uploads
`crs-compatibility-linux-amd64` as a 30-day workflow artifact. The project-owned
Envoy/libmodsecurity3 overrides account only for reviewed codec normalization, native audit
behavior, and connector differences. Each entry records its alternative rejection, sanitization,
or exact-rule signal; the smoke and protocol suites verify those alternative security controls.
Any non-zero go-ftw exit, skipped test, incomplete or duplicate result set, failed test, or forced
result fails CI. Passed, failed, skipped, ignored, and forced results remain separate in the report;
an override cannot silently disappear from the evidence. The runner also fails unless the complete
result ID set matches the pinned 5,003-test corpus and the actual ignored set exactly equals its
reviewed list. The sole current ignored entry, `920430-5`, records its owner, go-ftw limitation, and
2026-10-18 review date in the runner.

The test-only ruleset runs CRS at paranoia level 4 in `DetectionOnly`, enables request and response
inspection, and uses a serial audit log containing message metadata but no request or response body
parts. This lets go-ftw assert exact rule IDs without changing the production connector's disabled
native server-log callback. A diagnostic run applies no override by default. The required CI
command explicitly applies only the reviewed Envoy/libmodsecurity3 override file and reports
every ignored or forced result.

Five pinned CRS stages use `retry_once`. go-ftw 2.4.0 aborts the complete run without producing JSON
when the retry also fails, so the runner disables that flag in a temporary copy of the corpus and
reports each affected stage after one attempt. The pinned CRS sources are not modified.

macOS output is diagnostic because the release reference environment is Linux. The build now fails
if the JSON or XML parser dependency is unavailable, but a supported compatibility row still
requires a reviewed full Linux run, documented explanations for every remaining failure, and
explicit approval of any expected platform deviation.

## Qualification benchmark

Run the release-threshold workload against the custom Envoy binary with:

```shell
make qualification-benchmark
```

The benchmark starts four Envoy workers and a loopback upstream with request and response body
inspection enabled. It measures safe header-only requests, 4 KiB inspected bodies, blocked attacks,
a bounded worst-case regex input, and repeated 16 KiB body waves. The JSON and Markdown evidence
under `artifacts/qualification-benchmark/` records throughput, p50/p95/p99/p99.9/max latency, Envoy
process CPU per request, baseline and post-soak RSS, sampled peak RSS, and terminal transaction/body
gauges. The default release thresholds are 50 requests/second, 250 ms p99 for representative
traffic, 1 second p99 and 250 ms of Envoy CPU per pathological request, and no more than 64 MiB of
sampled peak RSS growth. CI fails when a threshold or request expectation is violated and uploads
the report for 30 days.

Run the scheduled profile locally with:

```shell
make body-pressure-stress
```

This profile adds 96 requests and 96 responses at the 1 MiB inspection limit, uses client
concurrency 48, and performs twelve 250-request waves with 256 KiB bodies. The profile is intended
to expose memory amplification and tail-latency regressions on GitHub-hosted runners; it remains a
portable regression floor rather than a production capacity claim. Its request expectations and
terminal gauges are enforced immediately. Review the first stable Linux runs before enabling its
performance and RSS thresholds with `--enforce`.

These values are repository qualification floors, not a deployment SLO. A deployment must rerun
the workload with its release binary, production CRS and exclusions, target hardware, body-size
distribution, concurrency, and overload settings, then select tighter limits from that evidence.

## Planned release artifacts

No release pipeline is implemented yet. A supported release is expected to include
multi-architecture Linux images, checksums, an SBOM, signatures, a compatibility manifest, and all
third-party license and notice material required by Envoy, ModSecurity, OWASP CRS, and their bundled
dependencies. Image creation remains deferred until the qualification gates pass. A standalone
filter library is not planned as an initial release artifact.
