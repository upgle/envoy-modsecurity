# Container contract

The runtime image will be added with the first working filter implementation. It will use a
multi-stage build and contain only:

- the custom Envoy binary;
- the runtime libraries that cannot be linked statically;
- the recommended ModSecurity configuration;
- the pinned OWASP CRS files;
- version, revision, source, license, and SBOM image labels.

Build and runtime base images must be pinned by digest. The runtime container will run as a
non-root user with a read-only root filesystem and writable paths limited to explicitly configured
audit-log or temporary directories.

No placeholder image is published before the filter evaluates rules successfully; doing so could
look like a protected Envoy deployment while only proxying traffic.
