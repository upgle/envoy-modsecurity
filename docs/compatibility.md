# Compatibility

## Pinned dependency matrix

| Filter | Envoy | ModSecurity | OWASP CRS | Status |
| --- | --- | --- | --- | --- |
| unreleased | 1.39.0 | 3.0.16 | 4.28.0 | pre-release; not supported |

This row records the combination pinned by the current repository. Envoy and ModSecurity are built
and exercised by the current test suite; OWASP CRS regression coverage is still missing. See
[development.md](development.md#verification-status) for the current qualification scope. This is
not a production support declaration. Each future supported dependency combination will have its
own filter release and compatibility row.

## Update policy

- Pin each upstream submodule to an immutable Git commit.
- Record the human-readable release and commit in `DEPENDENCIES.lock`.
- Do not track upstream `main` or a moving release branch in a release build.
- Run unit, Envoy integration, OWASP CRS regression, sanitizer, and benchmark suites for every
  compatibility row before marking it supported.
- Evaluate security updates to supported Envoy and ModSecurity versions and publish a newly
  qualified compatibility row when an update is required.

Before a row is marked supported, release artifacts must record the filter, Envoy, ModSecurity, and
CRS versions in image labels and SBOM metadata. The custom binary must also report those versions at
startup.
