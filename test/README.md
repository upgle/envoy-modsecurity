# Test suites

The test tree is split by scope:

- `test/engine`: rule validation, exception boundaries, and behavior against libmodsecurity and
  SecLang rules without running the HTTP filter.
- `test/unit`: configuration conversion, Envoy filter callbacks, state transitions, limits,
  lifetime, protocol classification, memory budgets, and failure semantics.
- `test/integration`: black-box HTTP/1.1 tests against a two-worker custom Envoy binary, including
  parallel traffic, chunked and oversized bodies, gRPC, SSE, WebSocket upgrades, trailers, and a
  pinned OWASP CRS paranoia level 1 smoke suite with all referenced data files declared as Bazel
  runfiles.

Run the suites from the repository root:

```shell
make test              # engine and filter tests
make integration-test # custom Envoy HTTP tests
make check             # all current verification
```

See [docs/development.md](../docs/development.md) for prerequisites and release-qualification gaps.

The following release suites are not present yet:

- `test/ftw`: the complete OWASP CRS regression corpus with exact rule-ID assertions and reviewed
  exclusions;
- `test/benchmark`: latency, throughput, allocation, and concurrent-stream memory limits;
- Linux sanitizer and live ECDS update stress coverage.

When the CRS regression suite is added, each security-relevant exclusion must record its reason,
affected rule ID, responsible maintainer or tracking issue, and expiration or review date.
