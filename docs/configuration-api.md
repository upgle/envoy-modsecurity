# Configuration API

The filter uses Envoy's v3 typed-extension API and a project-owned protobuf package. The proto is
marked work-in-progress; compatibility is not guaranteed until the first supported release.

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

## Configuration scope

The filter configuration controls:

- ordered rule sources and their names in diagnostics;
- per-stream request and response body limits;
- the aggregate active-body memory budget;
- the enforced PCRE2 match limit;
- whether response phases run;
- runtime engine failure behavior and its local-reply status;
- per-route buffering overrides.

SecLang controls `SecRuleEngine`, CRS includes, request/response MIME selection, rule exclusions,
and ModSecurity's internal body limits. Trusted filename sources may also configure audit and debug
logging; inline sources reject those directives. The protobuf does not duplicate these settings.

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
  pcre_match_limit:
    value: 1000
  failure_mode_allow: false
  status_on_error:
    code: InternalServerError
  stat_prefix: edge_waf
```

The root rule file can include `modsecurity.conf`, `crs-setup.conf`, CRS rules, and local policy
files. Additional file and inline sources are loaded in list order. Every filename must be an
absolute path to a regular file.

Inline rules are limited to 1 MiB per source and 8 MiB in total. A conservative textual denylist
rejects directives associated with filesystem access, subprocesses, remote rules, native logging,
uploads and temporary files, external entities, and persistent collections. This check is defense
in depth, not a SecLang sandbox. The filter enforces `pcre_match_limit` before loading these sources,
but non-PCRE operators and aggregate rule volume can still consume excessive CPU or trigger
unexpected engine behavior. The configuration source and xDS control plane must remain trusted.

`pcre_match_limit` defaults to 1000 and is bounded to 1,000,000. It is installed before every
configured source, so a trusted filename or inline source cannot silently raise or remove it.
Exceeding the limit returns a resource-exhaustion error, fails request or response inspection closed
even when `failure_mode_allow` is true, and increments `pcre_match_limit_exceeded`. A phase-5-only
exceedance occurs after stream completion and is recorded as a logging error instead of changing the
completed response. This is a practical first guard for pathological regular expressions, not a
wall-clock deadline: the native phase remains synchronous and non-PCRE work is outside this limit.

The corresponding local reply uses response-code detail
`modsecurity_pcre_match_limit_exceeded`, allowing bounded access-log classification without
including request data.

For ECDS configuration and update-generation semantics, see
[architecture.md](architecture.md#dynamic-configuration-with-ecds).

ECDS carries inline text directly. A `filename` carries only a path, and every Envoy host reads its
own local file while constructing the candidate configuration.

## Failure and buffering semantics

| Event | Required behavior |
| --- | --- |
| Invalid proto or rule parse/load failure | Reject configuration at startup or NACK the xDS update. Never replace a valid generation with the failed candidate. |
| Disruptive ModSecurity intervention | Stop iteration and honor the valid intervention status or redirect. `failure_mode_allow` does not apply. |
| Request exceeds `request_body.max_bytes` | Return HTTP 413 before phase 2; never process a partial request body. |
| Response exceeds `response.body.max_bytes` | Discard the buffered upstream response and return `status_on_error`, default HTTP 500. |
| Aggregate active-body budget is exhausted | Return `status_on_error`; `failure_mode_allow` does not override the memory bound. |
| Runtime engine/transaction error | Return `status_on_error`, unless `failure_mode_allow` is true and the error is not resource exhaustion. |
| Runtime resource exhaustion | Return `status_on_error`; `failure_mode_allow` does not apply. |
| PCRE match limit exceeded | Return `status_on_error`, increment the dedicated counter, and fail closed. |
| Response configuration is absent | Skip ModSecurity phases 3 and 4; attempt phase 5 after request inspection completes. |

The protobuf limits each request or response body to 32 MiB. `max_active_body_bytes` defaults to
64 MiB, may be configured up to 1 GiB, and is validated against the filter-level body limits. Each
accepted ECDS configuration has a separate budget, and old and new generations may overlap while
streams drain. The value is not a process-wide memory or RSS limit. Envoy-side limits and SecLang
limits are independent; account for concurrent streams, overlapping generations, libmodsecurity's
internal copies, and parser state.

All recognized gRPC requests, including unary calls, and recognized Connect streaming requests
receive request-header inspection but bypass request-body buffering. Upgrade/CONNECT tunnel data
and event-stream response bodies also bypass buffering. Trailer fields pass through uninspected,
while their arrival completes a pending body phase. Dedicated statistics expose these cases.

## Operational observability

All metric dimensions are bounded under the filter's statistics prefix. The primary signals are:

- `request_interventions` and `response_interventions` for disruptive WAF decisions;
- `pcre_match_limit_exceeded`, `runtime_errors`, `failure_mode_allowed`, and `logging_errors` for
  engine health and fail-open behavior;
- `active_rule_generations`, `active_transactions`, and `modsecurity_buffer_bytes` for generation,
  transaction, and buffered-body lifetime;
- request/response overflow, aggregate-budget, streaming-bypass, and uninspected-trailer counters;
- per-phase and logging duration histograms in microseconds.

At info log level an intervention emits only its side, normalized status, and at most eight numeric
rule IDs selected by libmodsecurity for logging. `intervention_rule_ids_truncated` reports when more
IDs existed. Metric names never contain rule IDs or request attributes, and the adapter does not log
raw bodies or matched values.

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
the filter configuration's aggregate body budget. A route override can exceed that aggregate
budget; if it does, the request or response fails closed when the budget is exhausted, before the
route limit is reached.

## Filter ordering

Place any request decompressor whose output must be inspected before this filter. Place the
ModSecurity filter before `envoy.filters.http.router`. Response callbacks execute in reverse order,
so placement also determines which encoded representation reaches response inspection.
