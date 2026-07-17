# Security policy

This project runs in the Envoy data path and treats parser, buffering, and failure-mode defects as
security-sensitive.

Do not disclose a suspected vulnerability in a public issue. Use GitHub private vulnerability
reporting for the repository when available, and include:

- the affected filter and dependency versions;
- a minimal Envoy and ModSecurity configuration;
- a reproducer with sensitive data removed;
- the expected and observed blocking behavior.

Dependency support follows the compatibility table in `docs/compatibility.md`. Unsupported
versions may not receive fixes.
