# Envoy ModSecurity filter

This repository builds an out-of-tree native Envoy HTTP filter backed by ModSecurity v3. The
filter is maintained separately from the Envoy core repository.

## Status

The filter links against libmodsecurity and includes a v3 protobuf configuration API, a custom
Envoy binary, and HTTP integration tests. It is pre-release and is not yet supported for production
use. OWASP CRS regression coverage, sanitizer and concurrency testing, performance baselines, and
release packaging are still required.

## Packaging

The initial distribution model is a custom Envoy binary with the filter statically linked. Envoy
remains an unmodified, pinned submodule, and the filter uses Envoy's native C++ extension API.

See [docs/architecture.md](docs/architecture.md) for the component boundaries,
[docs/configuration-api.md](docs/configuration-api.md) for the configuration and failure contract,
and [docs/development.md](docs/development.md) for the remaining release work.

## Features

- ModSecurity phases 1 and 2 for request headers and finite request bodies.
- Opt-in phases 3 and 4 for response headers and finite response bodies. Phase 5 runs on normal
  completion, interventions, and stream teardown when the transaction remains usable.
- Ordered SecLang sources using absolute local `filename` entries, bounded `inline_rules`, or both.
- Static bootstrap configuration and atomic whole-filter ECDS replacement with last-good retention
  when validation or rule compilation fails.
- Per-route disable and request/response buffering overrides without per-route rule replacement.
- Per-body limits, a per-configuration active-body memory budget, Envoy memory accounting, and
  fail-closed handling for overflow and budget exhaustion.
- Disruptive intervention handling, configurable fail-open handling for non-resource-exhaustion
  runtime errors, and fixed-name counters, gauges, and latency histograms.
- Bounded structured security-event dynamic metadata with rule IDs, phases, disruptive status,
  CRS anomaly scores, stable outcomes, and process-local rule-generation correlation. Native audit
  file logging can remain disabled.
- Header-phase inspection with explicit body-bypass counters for recognized gRPC requests, Connect
  streaming requests, Upgrade/CONNECT tunnels, and event-stream responses.

## Configuration API

The v3 protobuf is defined in
[`modsecurity.proto`](api/envoy_modsecurity/extensions/filters/http/modsecurity/v3/modsecurity.proto).
The canonical filter name is `envoy.filters.http.modsecurity`, and its top-level type URL is
`type.googleapis.com/envoy_modsecurity.extensions.filters.http.modsecurity.v3.ModSecurity`.
Its primary fields are:

| Field | Purpose |
| --- | --- |
| `rules` | Ordered `filename` and `inline_rules` SecLang sources. At least one is required. |
| `request_body.max_bytes` | Required per-request body limit; maximum 32 MiB. |
| `response.body.max_bytes` | Enables response inspection and sets its per-response limit. |
| `max_active_body_bytes` | Aggregate admitted body budget for one accepted filter configuration; defaults to 64 MiB. |
| `failure_mode_allow` | Continues the stream after runtime engine or transaction errors other than resource exhaustion. Resource-exhaustion errors always fail closed. |
| `status_on_error` | Local-reply status for runtime errors, response overflow, and body-budget exhaustion; defaults to 500. |
| `stat_prefix` | Optional suffix for distinguishing filter-instance statistics. |

`ModSecurityPerRoute` may disable the filter or override request/response buffering. It cannot
replace rules or weaken the filter-wide failure policy. See
[docs/configuration-api.md](docs/configuration-api.md) for validation, failure, and per-route
semantics.

## Minimal static configuration

Place the filter in the HTTP connection manager after any request decompressor whose output must
be inspected and before the router:

```yaml
http_filters:
  - name: envoy.filters.http.modsecurity
    typed_config:
      "@type": type.googleapis.com/envoy_modsecurity.extensions.filters.http.modsecurity.v3.ModSecurity
      rules:
        - filename: /etc/modsecurity/main.conf
        - inline_rules:
            name: local-exclusions.conf
            rules: |
              SecRuleRemoveById 920350
      request_body:
        max_bytes:
          value: 8388608
      response:
        body:
          max_bytes:
            value: 524288
      max_active_body_bytes:
        value: 67108864
      failure_mode_allow: false
      stat_prefix: edge_waf
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

Every filename must be an absolute path to a regular file available to the Envoy process. A root
file can include the deployment's ModSecurity configuration, CRS setup, CRS rules, and local
policy. Inline sources are intended for small exclusions, emergency rules, and tests.

For dynamic delivery, replace `typed_config` with ECDS `config_discovery`. Every accepted update
must contain the complete `ModSecurity` message; existing streams keep their pinned rule generation
and new streams use the new generation. Inline rule text travels in the xDS resource, but a
`filename` is only a path: each Envoy host reads that local file while constructing the candidate
configuration. See
[the ECDS architecture](docs/architecture.md#dynamic-configuration-with-ecds) for the listener
configuration and update lifecycle.

## Pinned inputs

| Component | Version | Source |
| --- | --- | --- |
| Envoy | `v1.39.0` | `envoy/` |
| ModSecurity | `v3.0.16` | `third_party/modsecurity/` |
| OWASP CRS | `v4.28.0` | `third_party/coreruleset/` |
| Bazel | `8.7.0` | `.bazelversion` |

The exact commit SHAs are recorded in `DEPENDENCIES.lock` and verified in CI.

## Build, test, and run

Install the prerequisites in [docs/development.md](docs/development.md), then run:

```shell
make bootstrap
make build
./bazel-bin/envoy-modsecurity -c /path/to/envoy.yaml
```

To build the custom Envoy binary and explore the pinned OWASP CRS through a loopback-only web UI,
run:

```shell
make owasp-lab
```

See the [local OWASP CRS web lab guide](docs/development.md#local-owasp-crs-web-lab) for runtime
options and security boundaries.

Envoy builds are resource intensive. Bazel reuses its output base across these targets; the pinned
submodules do not need to be installed system-wide. CI and release qualification target Linux.
macOS builds are best-effort and are not CI-qualified. Run `make check` for the API, engine, filter,
and custom-Envoy HTTP suites, or `make integration-test` to run only the HTTP suite.

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report suspected
vulnerabilities through the private process in [SECURITY.md](SECURITY.md).

## License

Except where otherwise noted, project-owned code and documentation are licensed under either the
[Apache License 2.0](LICENSE-APACHE) or the [MIT License](LICENSE-MIT), at your option.

Pinned third-party sources and dependencies are not covered by this choice and remain governed by
their respective license and notice files.
