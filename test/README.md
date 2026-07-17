# Test suites

The test tree will be split by failure domain:

- `test/engine`: Envoy-independent ModSecurity and SecLang behavior.
- `test/unit`: Envoy filter callback and state-machine behavior.
- `test/integration`: real Envoy binary and protocol behavior.
- `test/ftw`: OWASP CRS regression configuration and reviewed exclusions.
- `test/benchmark`: latency, throughput, and per-stream memory limits.

Security-relevant exclusions must include a reason, owner, affected rule ID, and expiration or
review date.
