# Test suites

The test tree is split by failure domain:

- `test/engine`: Envoy-independent rule validation, exception boundaries, and real ModSecurity/
  SecLang behavior.
- `test/unit`: Envoy filter callbacks, state transitions, limits, lifetime, protocol classification,
  memory budgets, and failure semantics.
- `test/integration`: custom Envoy binary and HTTP behavior, including chunking, oversized bodies,
  streaming protocols, upgrades, and trailers.

The following release suites are not present yet:

- `test/ftw`: OWASP CRS regression configuration and reviewed exclusions;
- `test/benchmark`: latency, throughput, allocation, and concurrent-stream memory limits;
- Linux sanitizer and update/concurrency stress coverage.

Security-relevant exclusions must include a reason, owner, affected rule ID, and expiration or
review date.
