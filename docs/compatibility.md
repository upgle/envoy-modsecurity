# Compatibility

## Initial support matrix

| Filter | Envoy | ModSecurity | OWASP CRS | Status |
| --- | --- | --- | --- | --- |
| unreleased | 1.39.0 | 3.0.16 | 4.28.0 | pre-release implementation |

The row records the pinned build combination; it is not a production support declaration while the
filter version remains unreleased. A dependency update will require a new filter release even when
no project-owned C++ source changes.

## Update policy

- Pin each upstream to an immutable Git commit through the parent repository's gitlink.
- Record the human-readable release and commit in `DEPENDENCIES.lock`.
- Do not track upstream `main` or a moving release branch in a production build.
- Run unit, Envoy integration, OWASP CRS regression, sanitizer, and benchmark suites for every
  compatibility row before marking it supported.
- Rebuild and release promptly for supported Envoy and ModSecurity security updates.

The filter version, Envoy version, ModSecurity version, and CRS version must be present in image
labels, SBOM metadata, and the startup log.
