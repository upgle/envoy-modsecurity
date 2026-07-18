# Envoy ModSecurity filter

An out-of-tree HTTP filter project for integrating ModSecurity v3 with Envoy without adding the
filter source to the Envoy core repository.

## Status

The repository contains a statically registered native filter, a custom Envoy binary, real
libmodsecurity integration, the v3 configuration API, and HTTP integration tests. The project is
still pre-release: OWASP CRS regression, sanitizer/concurrency qualification, performance gates,
and release-image hardening remain before a supported production release.

## Architecture decision

The first production path is a statically linked custom Envoy binary built from this repository.
This keeps the source out of Envoy core while retaining the native C++ filter API and predictable
libmodsecurity integration. A Dynamic Modules adapter may be added later, but it must use the same
engine abstraction and pass an Envoy-version compatibility matrix before release.

See [docs/architecture.md](docs/architecture.md) for the component boundaries,
[docs/configuration-api.md](docs/configuration-api.md) for the configuration and failure contract,
and [docs/development.md](docs/development.md) for the remaining release work.

## Features

- ModSecurity phases 1 and 2 for request headers and finite request bodies.
- Opt-in phases 3 and 4 for response headers and finite response bodies, with phase 5 logging
  finalization on every terminal stream path.
- Ordered SecLang sources using absolute local `filename` entries, bounded `inline_rules`, or both.
- Static bootstrap configuration and atomic whole-filter ECDS replacement with last-good retention
  when validation or rule compilation fails.
- Per-route disable and request/response buffering overrides without per-route rule replacement.
- Per-body limits, an aggregate active-body memory budget, Envoy memory accounting, and fail-closed
  handling for overflow and budget exhaustion.
- Disruptive intervention handling, configurable runtime-error fail-open behavior, and bounded
  filter statistics.
- Header-phase inspection with explicit body bypass counters for known gRPC/Connect streams,
  Upgrade/CONNECT tunnels, and event-stream responses.

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
| `max_active_body_bytes` | Aggregate admitted body budget; defaults to 64 MiB. |
| `failure_mode_allow` | Allows only runtime engine/transaction failures; defaults to fail-closed. |
| `status_on_error` | Local-reply status for fail-closed runtime and response errors; defaults to 500. |
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

The filename must be an absolute regular file available to the Envoy process. A production root
file normally includes the recommended ModSecurity configuration, CRS setup, CRS rules, and stable
local policy. Inline sources are intended for small exclusions, emergency rules, and tests.

For dynamic delivery, replace `typed_config` with ECDS `config_discovery`. Every accepted update
must contain the complete `ModSecurity` message; existing streams keep their pinned rule generation
and new streams use the new generation. See
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

```shell
make bootstrap
make build
./bazel-bin/envoy-modsecurity -c /path/to/envoy.yaml
```

Envoy builds are resource intensive. Bazel reuses its output base across these targets; no
system-wide installation of the pinned submodules is required. Linux remains the release target,
while the current local integration harness also validates the custom binary on macOS. Run
`make check` for the API, engine, filter, and custom-Envoy HTTP suites, or `make integration-test`
to run only the HTTP suite.

## License

Except where otherwise noted, project-owned code and documentation are licensed under either the
[Apache License 2.0](LICENSE-APACHE) or the [MIT License](LICENSE-MIT), at your option.

Pinned third-party sources and dependencies are not covered by this choice and remain governed by
their respective license and notice files.
