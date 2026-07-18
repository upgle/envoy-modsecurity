# Architecture

## Packaging model

The project builds a custom Envoy binary with a statically registered native C++ HTTP filter.
The filter source and its build and test configuration stay in this repository while Envoy remains
an unmodified, pinned upstream submodule.

The root `//:envoy-modsecurity` target links the filter factory and the Envoy executable libraries
needed by the pinned release. This uses Envoy's native filter API without copying the extension
into Envoy core.

## Component and ownership boundaries

```text
v3 typed config / ECDS
          |
          v
filter factory -- compile --> immutable RuleGeneration
          |                         |
          |                         v
          +-- shared settings --> per-stream Transaction
                                      |
                                      v
                              pinned libmodsecurity
```

- One process-wide `Runtime` singleton owns the native `modsecurity::ModSecurity` instance.
- Every accepted filter configuration owns a newly compiled, immutable `RuleGeneration`.
- `FilterConfig` owns the effective settings, statistics, aggregate body-memory budget, and the
  generation used to create new streams.
- Each enabled stream creates at most one native transaction. The transaction pins its generation,
  so an in-flight stream cannot switch rules during an ECDS update.
- After transaction creation, the stream filter releases its `FilterConfig` reference. It keeps
  copies or shared references to the effective settings, statistics, body-memory budget, and rule
  generation lifetime handle; the native transaction keeps the runtime and compiled rules alive.
  `active_rule_generations` therefore remains charged while either the accepted configuration or an
  in-flight transaction still references that generation.
- Request and response callbacks for a stream remain confined to its Envoy worker. No filter
  callback is invoked concurrently for that stream.

The adapter itself does not initiate filesystem, network, or subprocess work from worker
callbacks. Filename-based sources are not subject to the inline-rule denylist and may use any
capability enabled in this libmodsecurity build, including directives that perform logging,
persistent storage, or external work. Because rule evaluation is synchronous, deployments must
review those directives for worker blocking and contention.

Before configured sources are loaded, each candidate ruleset receives a protobuf-controlled
`SecPcreMatchLimit`. A request or response inspection phase returns resource exhaustion when
libmodsecurity reports that limit, and the filter fails closed. Phase 5 can only record the error
because the stream has completed. This bounds work inside each PCRE2 match but cannot interrupt an
already-running native call, bound a complete phase by wall time, or constrain non-PCRE operators.
Representative latency testing and stronger process isolation remain release work.

The engine adapter does not expose Envoy header maps or buffers, so it can be tested against
libmodsecurity without running the custom Envoy binary.

## Rule sources and load order

The top-level configuration contains an ordered list of sources. Both forms may be mixed:

- `filename` must be an absolute path to a regular file loaded through libmodsecurity. Production
  deployments should provide it through an immutable image or read-only mounted configuration.
- `inline_rules` carries bounded SecLang text and a stable diagnostic name. It is intended for
  small exclusions, emergency rules, and tests rather than an entire CRS distribution. Its
  capability denylist is defense in depth, not a sandbox; the xDS control plane remains trusted.

SecLang remains responsible for `SecRuleEngine`, `Include`, CRS setup, body inspection directives,
audit/debug logging, and rule exclusions. The protobuf controls Envoy integration, ordering,
buffering, failure policy, and dynamic delivery.

A typical source order is:

1. baseline ModSecurity configuration;
2. CRS setup;
3. pre-CRS exclusions;
4. CRS rules;
5. post-CRS exclusions;
6. emergency blocking rules.

Order is significant because later SecLang sources may update or remove rules from earlier sources.
The internal PCRE match-limit directive is the deliberate exception: it is installed first and
cannot be replaced by a configured source.
Files are read when the configuration is constructed and are not reread afterward. Their contents
must therefore be immutable for the lifetime of a deployment revision; changing a file in place is
not a supported update mechanism.

## Dynamic configuration with ECDS

Dynamic filter configuration uses Envoy Extension Config Discovery Service (ECDS):

```yaml
http_filters:
  - name: envoy.filters.http.modsecurity
    config_discovery:
      config_source:
        ads: {}
        resource_api_version: V3
      type_urls:
        - type.googleapis.com/envoy_modsecurity.extensions.filters.http.modsecurity.v3.ModSecurity
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

Every update carries the complete `ModSecurity` message, including unchanged filenames and all
inline sources. A filename remains a path on the Envoy host; ECDS does not transfer that file's
contents. ECDS replaces the complete extension resource, and Delta xDS does not change the
protobuf's replacement semantics.

For each update, the filter factory performs these steps:

1. Validates the typed resource and protobuf constraints.
2. Creates a fresh rule set and loads every source in order.
3. Constructs a new immutable filter configuration and generation.
4. Publishes it for new streams and ACKs the resource.

Native exceptions are converted to status errors. If validation, file loading, or SecLang parsing
fails, the factory returns an error. Envoy NACKs the update and keeps the previously accepted
callback and rule generation active. Existing streams continue with the generation pinned by their
transaction; new streams use the newly accepted generation only after publication.

Do not configure an empty or weaker default through `apply_default_config_without_warming` for a
security filter. A listener should wait for a valid ECDS resource, or fail activation according to
the deployment's control-plane policy.

## Request, response, and streaming behavior

A regular finite request follows ModSecurity phases 1 and 2. Response phases 3 and 4 are opt-in.
Phase 5 is attempted at most once after the last configured inspection phase or when an active
transaction completes or is destroyed. Runtime-error and overflow paths release the transaction
without phase 5. Disruptive interventions stop iteration and send one local reply.

Whole-body inspection is incompatible with an unbounded stream. Known protocol shapes therefore
use explicit protocol-specific behavior:

- all recognized gRPC requests, including unary calls, and recognized Connect streaming requests
  receive header-phase inspection and bypass body buffering;
- Upgrade and CONNECT requests receive header-phase inspection. Response data bypasses buffering
  after a successful tunnel handshake; rejected responses can still be inspected;
- `text/event-stream` responses bypass response-body buffering;
- HTTP trailers end a pending body phase, but trailer fields themselves are not inspected because
  libmodsecurity has no trailer phase.

Dedicated counters expose body bypass and uninspected trailers. Routes with unrecognized unbounded
request streams must disable the filter. Routes with unrecognized unbounded responses must disable
response inspection or use a separate bounded inspection design.

## Buffering and memory control

The request and response limits are independent, with a protobuf upper bound of 32 MiB per body.
The default aggregate `max_active_body_bytes` budget is 64 MiB per accepted filter configuration.
Validation requires it to cover the filter-level request and response limits. A per-route override
can be larger than the aggregate budget, in which case reservation fails closed before the route
limit is reached. Overlapping ECDS generations retain separate budgets, so this value is neither a
process-wide limit nor an RSS bound. Operators should use smaller limits when possible because
Envoy and libmodsecurity may retain multiple body representations and parser state.

The filter:

- checks a valid declared `Content-Length` before admitting a body;
- charges admitted bytes to a shared atomic budget;
- associates buffered bytes with Envoy's stream memory account for overload-manager selection;
- releases body charges, configuration references, and native transactions on all terminal paths;
- fails closed on request overflow, response overflow, or aggregate-budget exhaustion.

The filter belongs after any request decompressor whose output must be inspected and before
`envoy.filters.http.router`. Response callbacks run in reverse order, so chain placement also
determines the representation seen during response inspection.

## Failure semantics

| Event | Behavior |
| --- | --- |
| Invalid proto, unreadable file, or rule parse failure | Reject startup config or NACK ECDS; retain the previous accepted generation. |
| Disruptive rule intervention | Stop iteration and honor the valid intervention status or redirect. |
| Request body exceeds its limit | Return HTTP 413; never inspect a partial request body. |
| Response body exceeds its limit | Discard the buffered response and return `status_on_error`. |
| Aggregate body budget exhausted | Return `status_on_error`; `failure_mode_allow` does not override memory safety. |
| Runtime engine or transaction error | Return `status_on_error`, unless `failure_mode_allow` is enabled and the error is not resource exhaustion. |
| Runtime resource exhaustion | Return `status_on_error`; `failure_mode_allow` does not apply. |
| PCRE match limit exceeded | Return `status_on_error`, increment `pcre_match_limit_exceeded`, and fail closed. |
| Response inspection absent | Skip phases 3 and 4; attempt phase 5 after request inspection completes. |

Rule-load failures, body limits, resource exhaustion, and interventions are always fail-closed.
`failure_mode_allow` applies only to other runtime engine or transaction errors.

## Observability

The filter exposes bounded counters for interventions, PCRE-limit exhaustion, runtime and logging
errors, body overflow and budget exhaustion, streaming bypass, and uninspected trailers. Gauges
track live compiled generations, native transactions, and admitted body bytes; phase histograms
track synchronous native duration. A generation gauge remains charged while an accepted config or
an in-flight transaction pins that generation, including overlap during an update.

Intervention logs are opt-in through Envoy's info log level and contain only the message side,
normalized status, and up to eight numeric rule IDs selected for logging by libmodsecurity. A
counter reports truncation. Request bodies, response bodies, matched values, URIs, client addresses,
and free-form native errors are not logged or used as metric dimensions.

## Non-goals

The current protocol does not provide a rules-only xDS resource, field patches, file watching,
remote rule downloads, mutable file reloads, or per-route ruleset replacement. Dynamic Modules and
`ext_proc` packaging are also outside the current implementation.
