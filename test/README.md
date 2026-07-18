# Test suites

The test tree is split by scope:

- `test/engine`: rule validation, exception boundaries, and behavior against libmodsecurity and
  SecLang rules without running the HTTP filter.
- `test/unit`: Envoy filter callbacks, state transitions, limits, lifetime, protocol classification,
  memory budgets, and failure semantics.
- `test/integration`: black-box HTTP/1.1 tests against the custom Envoy binary, HTTP/1.1 and HTTP/2
  in-process boundary/reset/multiplexing tests, multi-worker ECDS update tests, and a pinned OWASP
  CRS paranoia level 1 smoke suite with exact rule and anomaly-score assertions.
- `test/performance`: the custom-Envoy release-qualification configuration for latency,
  throughput, pathological-regex CPU, and RSS workloads.

Run the suites from the repository root:

```shell
make test              # engine and filter tests
make integration-test # custom Envoy HTTP tests
make check             # all current verification
make qualification-benchmark
./tools/run-crs-compatibility.sh --apply-platform-overrides --fail-on-test-failure
```

See [docs/development.md](../docs/development.md) for prerequisites, threshold definitions, Linux
sanitizer commands, and the distinction between an implemented gate and candidate-specific release
evidence.

The required CI path additionally runs:

- the complete pinned CRS go-ftw corpus with exact rule-ID assertions and reviewed
  Envoy/libmodsecurity3 overrides whose alternative security signals are covered separately;
- ASAN, LSan, and UBSAN over the lifetime, protocol, and ECDS suites;
- TSAN over native generation churn and aggregate-budget contention; and
- the thresholded qualification benchmark with JSON and Markdown artifacts.

CI compiles the normal binary in a `build` job, then runs `qa` and `sanitizers` as parallel jobs.
Each job has an independent 180-minute timeout. The sanitizer job recompiles its targets because
instrumented objects cannot reuse the normal build artifacts.

Any project-specific CRS exclusion added in the future must record its reason, affected rule ID,
responsible maintainer or tracking issue, and expiration or review date. Unreviewed failures and
forced results remain release-blocking. The runner rejects any ignored set that differs from the
reviewed project list.
