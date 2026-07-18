# Architecture

## Status and packaging decision

The project builds a custom Envoy binary with a statically registered native C++ HTTP filter.
The filter source and release automation stay in this repository while Envoy remains an
unmodified, pinned upstream submodule.

The root `//:envoy-modsecurity` target links the filter factory and the Envoy executable libraries
needed by the pinned release. This preserves Envoy's native filter API and predictable
libmodsecurity integration without copying the extension into Envoy core.

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
- Each HTTP stream owns exactly one native transaction. The transaction pins its generation, so
  an in-flight stream cannot switch rules during an ECDS update.
- After transaction creation, the stream filter releases its `FilterConfig` reference. This lets
  obsolete configurations and budgets be reclaimed without waiting for unrelated long-lived
  streams; the transaction retains only the runtime and rules it needs.
- Request and response callbacks for a stream remain confined to its Envoy worker. No filter
  callback performs filesystem, network, or subprocess work.

The engine adapter does not expose Envoy header maps or buffers. It can therefore be tested with
real libmodsecurity independently of a full Envoy binary and can be reused by a future packaging
adapter.

## Rule sources and load order

The top-level configuration contains an ordered list of sources. Both forms may be mixed:

- `filename` loads SecLang from a local file through libmodsecurity. Production deployments should
  use absolute paths in an immutable image or read-only mounted configuration.
- `inline_rules` carries bounded SecLang text and a stable diagnostic name. It is intended for
  small exclusions, emergency rules, and tests rather than an entire CRS distribution.

SecLang remains responsible for `SecRuleEngine`, `Include`, CRS setup, body inspection directives,
audit/debug logging, and rule exclusions. The protobuf controls Envoy integration, ordering,
buffering, failure policy, and dynamic delivery.

A typical production order is:

1. baseline ModSecurity configuration;
2. CRS setup;
3. dynamic pre-CRS exclusions;
4. CRS rules;
5. dynamic post-CRS exclusions;
6. emergency blocking rules.

Order is significant because later SecLang sources may update or remove rules from earlier sources.
Files named by a configuration are read only while that configuration is being constructed. File
contents must therefore be immutable for the lifetime of a deployment revision; changing a file
in place is not a supported update mechanism.

## Dynamic configuration with ECDS

The first dynamic-update mechanism is Envoy Extension Config Discovery Service (ECDS):

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
inline sources. ECDS replaces the complete extension resource; Delta xDS changes transport
delivery, not protobuf field-level merge semantics.

For an update, Envoy and the exception-free filter factory:

1. validate the typed resource and protobuf constraints;
2. create a fresh rule set and load every source in order;
3. construct a new immutable filter configuration and generation;
4. publish it for new streams and ACK the resource.

If validation, file loading, or SecLang parsing fails, the factory returns an error. Envoy NACKs
the update and keeps the previously accepted callback and rule generation active. Existing streams
continue with the generation pinned by their transaction; new streams use the newly accepted
generation only after publication.

Do not configure an empty or weaker default through `apply_default_config_without_warming` for a
security filter. A listener should wait for a valid ECDS resource, or fail activation according to
the deployment's control-plane policy.

## Request, response, and streaming behavior

A regular finite request follows ModSecurity phases 1 and 2. Response phases 3 and 4 are opt-in;
phase 5 logging is finalized exactly once on completion, local reply, reset, or destruction.
Disruptive interventions stop iteration and send one local reply.

Whole-body inspection is incompatible with an unbounded stream. Known protocol shapes therefore
use explicit bounded behavior:

- gRPC and Connect streaming requests receive header-phase inspection and bypass body buffering;
- Upgrade and CONNECT tunnels receive header-phase inspection and bypass tunnel data;
- `text/event-stream` responses bypass response-body buffering;
- HTTP trailers end a pending body phase, but trailer fields themselves are not inspected because
  libmodsecurity has no trailer phase.

Dedicated counters expose body bypass and uninspected trailers. Generic application streams that
cannot be identified from headers must disable this filter or response inspection on their route,
or use a separate bounded inspection architecture.

## Buffering and memory control

The request and response limits are independent, with a protobuf upper bound of 32 MiB per body.
The default aggregate `max_active_body_bytes` budget is 64 MiB per accepted filter configuration
and must be at least the largest per-body limit. Operators should use substantially smaller limits
when possible because Envoy and libmodsecurity may retain multiple body representations and parser
state.

The filter:

- checks declared `Content-Length` before admitting a body;
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
| Runtime engine or transaction error | Return `status_on_error`, unless `failure_mode_allow` is explicitly enabled. |
| Response inspection absent | Skip phases 3 and 4; still finalize logging. |

Rule-load failures, body limits, and interventions are always fail-closed. `failure_mode_allow`
applies only to runtime engine/transaction errors.

## Deferred scope and alternatives

The initial protocol deliberately excludes a rules-only custom xDS resource, field patches, file
watching, remote rule downloads, independently mutable filename contents, and per-route ruleset
replacement. If frequent full ECDS resources become operationally expensive, a future dedicated
`RuleSet` resource may reference versioned immutable bundles while preserving generation pinning
and atomic validation.

Dynamic Modules remain a future packaging option and require feature parity, an Envoy-minor ABI
matrix, load-failure tests, and equivalent performance and CRS results. An `ext_proc` deployment is
a separate choice for operators who prioritize process isolation over in-process latency.
