# Security policy

This project runs in the Envoy data path and treats parser, buffering, and failure-mode defects as
security-sensitive.

## Supported versions

There is no supported production release yet. Reports against the current `main` branch and the
pinned dependencies are welcome, but fixes are provided on a best-effort basis until a supported
release is published. This section will list supported release lines when they exist.

## Reporting a vulnerability

Do not disclose vulnerability details in a public issue or pull request. Use GitHub's
[private vulnerability reporting form](https://github.com/upgle/envoy-modsecurity/security/advisories/new).
If the form is unavailable, open an issue that asks the maintainers to establish private contact;
do not include any vulnerability details in that issue.

Repository administrators must keep private vulnerability reporting enabled whenever this
repository is public.

Include:

- the affected commit SHA or image digest and dependency versions;
- a minimal Envoy and ModSecurity configuration;
- a reproducer with sensitive data removed;
- the expected and observed behavior, security impact, and any known mitigations.

The current dependency combination and qualification status are documented in
[docs/compatibility.md](docs/compatibility.md).
