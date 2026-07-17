# Compatibility

## Initial support matrix

| Filter | Envoy | ModSecurity | OWASP CRS | Status |
| --- | --- | --- | --- | --- |
| unreleased | 1.39.0 | 3.0.16 | 4.28.0 | project scaffold |

Only combinations listed here are supported. A dependency update is released as a new filter
version even when no project-owned C++ source changes.

## Update policy

- Pin each upstream to an immutable Git commit through the parent repository's gitlink.
- Record the human-readable release and commit in `DEPENDENCIES.lock`.
- Do not track upstream `main` or a moving release branch in a production build.
- Run unit, Envoy integration, OWASP CRS regression, sanitizer, and benchmark suites for every
  compatibility row before marking it supported.
- Rebuild and release promptly for supported Envoy and ModSecurity security updates.

The filter version, Envoy version, ModSecurity version, and CRS version must be present in image
labels, SBOM metadata, and the startup log.
