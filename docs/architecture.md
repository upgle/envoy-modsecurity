# Architecture

## Decision

The primary artifact will be a custom Envoy binary containing a statically registered native C++
HTTP filter. Filter source and release automation remain in this repository; Envoy itself remains
an unmodified, pinned upstream submodule.

This is intentionally different from copying the filter into Envoy core. The root Bazel target
will link the filter factory with `@envoy//source/exe:envoy_main_entry_lib`, following Envoy's
official out-of-tree extension pattern.

## Component boundaries

```text
typed v3 config
      |
      v
Envoy filter adapter  ---> metrics and structured audit events
      |
      v
ModSecurity engine adapter ---> pinned libmodsecurity
      |
      v
per-stream transaction ---> pinned OWASP CRS and custom rules
```

The ModSecurity engine adapter must not include Envoy header-map or buffer types. Keeping the
engine boundary independent allows unit testing without a full Envoy build and leaves room for a
future Dynamic Modules adapter.

## Ownership and lifetime

- Parsed configuration, the ModSecurity engine, and immutable rules are owned by the filter config.
- Each HTTP stream owns exactly one ModSecurity transaction.
- Request and response data stays on its Envoy worker thread.
- No callback may perform blocking filesystem, network, or subprocess work.
- Logging finalization runs exactly once for normal completion, local reply, reset, or destruction.

Thread-safety assumptions about shared libmodsecurity objects must be documented and covered by a
concurrency test before the first release. If an object is not explicitly safe to share, it is
created per worker through Envoy thread-local storage.

## Transaction state machine

```text
created
  -> request_headers
  -> request_body_complete
  -> response_headers       (when response inspection is enabled)
  -> response_body_complete (when response inspection is enabled)
  -> logging_complete
  -> destroyed
```

An intervention can occur after every ModSecurity processing phase. A disruptive intervention
sends one local reply and stops upstream iteration. Internal errors follow the configured failure
mode, which defaults to fail-closed.

## Buffering and filter order

The filter is inserted before `envoy.filters.http.router`. If compressed payloads are expected to
be inspected after decompression, the corresponding decompressor must appear before this filter.

Request and response limits are independent and bounded by both the filter configuration and Envoy
connection-manager limits. Tests must cover chunked transfer encoding, trailers, early resets,
oversized bodies, and HTTP/2 pseudo-header mapping.

## Deferred alternatives

Dynamic Modules are a future packaging option, not the initial production path. Adoption requires:

- feature parity with the native adapter;
- builds against each supported Envoy minor version;
- ABI compatibility and load-failure integration tests;
- equivalent throughput, memory, and CRS regression results.

An `ext_proc` implementation is a separate architecture choice for deployments that prioritize
process isolation over in-process latency. It is not part of the initial filter binary.
