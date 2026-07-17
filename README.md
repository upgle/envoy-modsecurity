# Envoy ModSecurity filter

An out-of-tree HTTP filter project for integrating ModSecurity v3 with Envoy without adding the
filter source to the Envoy core repository.

## Status

The repository currently contains the reproducible project foundation: pinned upstream sources,
the v3 configuration API, Bazel workspace wiring, CI, and the implementation and test contracts.
The runtime filter is intentionally not registered yet. Until the ModSecurity adapter and its
integration tests land together, Envoy cannot be configured with this filter and there is no
silent pass-through mode that could be mistaken for WAF enforcement.

## Architecture decision

The first production path is a statically linked custom Envoy binary built from this repository.
This keeps the source out of Envoy core while retaining the native C++ filter API and predictable
libmodsecurity integration. A Dynamic Modules adapter may be added later, but it must use the same
engine abstraction and pass an Envoy-version compatibility matrix before release.

See [docs/architecture.md](docs/architecture.md) for the component boundaries and
[docs/development.md](docs/development.md) for the delivery plan.

## Pinned inputs

| Component | Version | Source |
| --- | --- | --- |
| Envoy | `v1.39.0` | `envoy/` |
| ModSecurity | `v3.0.16` | `third_party/modsecurity/` |
| OWASP CRS | `v4.28.0` | `third_party/coreruleset/` |
| Bazel | `8.7.0` | `.bazelversion` |

The exact commit SHAs are recorded in `DEPENDENCIES.lock` and verified in CI.

## Bootstrap

```shell
make bootstrap
make build-api
```

Envoy builds are resource intensive and are expected to run on Linux or in the project build
container once that target is introduced. No system-wide installation of the pinned submodules is
required.

## Planned filter name and type URL

```text
filter name: envoy_modsecurity.filters.http.modsecurity
type URL:    type.googleapis.com/envoy_modsecurity.extensions.filters.http.modsecurity.v3.ModSecurity
```

The filter must be placed after any request decompressor that it relies on and before
`envoy.filters.http.router`.

## License

Apache License 2.0. Pinned third-party sources remain governed by their own license files.
