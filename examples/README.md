# Examples

A runnable Envoy configuration will be added with the first integration-tested filter factory.
Until then, this directory intentionally contains no configuration referencing the planned filter
name, because current Envoy builds must reject that unknown extension rather than appear protected.

The first example will demonstrate:

- filter placement after request decompression and before the router;
- bounded request and response buffering;
- fail-closed behavior;
- OWASP CRS includes from a read-only filesystem;
- per-route disable and override configuration;
- structured access and audit logging.
