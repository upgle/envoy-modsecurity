# Configuration API

The configuration follows Envoy v1.39 HTTP-filter naming and validation conventions while keeping
the protobuf package in this project's namespace. The implementation is pre-release and the proto
is marked work-in-progress, so compatibility is not guaranteed until the first supported release.

## Canonical names

| Purpose | Value |
| --- | --- |
| Envoy extension category | `envoy.filters.http` |
| Factory and canonical filter name | `envoy.filters.http.modsecurity` |
| Proto path | `api/envoy_modsecurity/extensions/filters/http/modsecurity/v3/modsecurity.proto` |
| Proto package | `envoy_modsecurity.extensions.filters.http.modsecurity.v3` |
| Top-level message | `ModSecurity` |
| Per-route message | `ModSecurityPerRoute` |
| Type URL | `type.googleapis.com/envoy_modsecurity.extensions.filters.http.modsecurity.v3.ModSecurity` |

`HttpFilter.name` is also the lookup key for `typed_per_filter_config`. Use the canonical name
consistently even though Envoy permits an instance-specific name.

## Configuration ownership

The protobuf owns settings required by the Envoy adapter:

- ordered rule sources and their diagnostic identity;
- per-stream request and response body limits;
- the aggregate active-body memory budget;
- whether response phases run;
- runtime engine failure behavior and its local-reply status;
- a narrow set of per-route buffering overrides.

SecLang remains the source of truth for `SecRuleEngine`, CRS includes, audit and debug logging,
request/response MIME selection, rule exclusions, and ModSecurity's internal body limits. The
protobuf does not duplicate those directives.

## Static example

```yaml
name: envoy.filters.http.modsecurity
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
  status_on_error:
    code: InternalServerError
  stat_prefix: edge_waf
```

The root rule file can include `modsecurity.conf`, `crs-setup.conf`, CRS rules, and durable local
policy files. Additional file and inline sources are loaded in list order. Production filenames
must be absolute regular files. Inline rules are individually limited to 1 MiB and collectively
limited to 8 MiB; the initial safe profile rejects filesystem, subprocess, remote-rule, persistent
collection, and similar high-risk capabilities in inline content.

For ECDS configuration and update-generation semantics, see
[architecture.md](architecture.md#dynamic-configuration-with-ecds).

## Failure and buffering semantics

| Event | Required behavior |
| --- | --- |
| Invalid proto or rule parse/load failure | Reject configuration at startup or NACK the xDS update. Never replace a valid generation with the failed candidate. |
| Disruptive ModSecurity intervention | Stop iteration and honor the valid intervention status or redirect. `failure_mode_allow` does not apply. |
| Request exceeds `request_body.max_bytes` | Return HTTP 413 before phase 2; never process a partial request body. |
| Response exceeds `response.body.max_bytes` | Discard the buffered upstream response and return `status_on_error`, default HTTP 500. |
| Aggregate active-body budget is exhausted | Return `status_on_error`; `failure_mode_allow` does not override the memory bound. |
| Runtime engine/transaction failure | Return `status_on_error`, unless `failure_mode_allow` is explicitly true. |
| Response configuration is absent | Skip ModSecurity phases 3 and 4; phase 5 logging still finalizes the transaction. |

The protobuf limits each request or response body to 32 MiB. `max_active_body_bytes` defaults to
64 MiB, may be configured up to 1 GiB, and must be at least the largest configured body limit.
Envoy-side limits and SecLang limits are independent; operators should align them deliberately and
account for concurrent streams plus libmodsecurity's internal copies and parser state.

Known gRPC/Connect streaming requests, Upgrade/CONNECT tunnels, and event-stream responses receive
header-phase inspection but bypass whole-body buffering. Trailer fields pass through uninspected,
while their arrival completes a pending body phase. Dedicated statistics expose these cases.

## Per-route policy

`ModSecurityPerRoute` may disable the filter or change request/response buffering. It cannot replace
rules, change `failure_mode_allow`, alter `status_on_error`, or replace the aggregate budget. This
keeps rules filter-wide and prevents a route update from silently weakening the global failure
policy.

```yaml
typed_per_filter_config:
  envoy.filters.http.modsecurity:
    "@type": type.googleapis.com/envoy_modsecurity.extensions.filters.http.modsecurity.v3.ModSecurityPerRoute
    overrides:
      request_body:
        max_bytes:
          value: 8388608
      disable_response: true
```

The route-level request or response limit remains subject to the same 32 MiB protobuf maximum and
the filter configuration's aggregate body budget.

## Filter ordering

Place any request decompressor whose output must be inspected before this filter. Place the
ModSecurity filter before `envoy.filters.http.router`. Response callbacks execute in reverse order,
so placement also determines which encoded representation reaches response inspection.
