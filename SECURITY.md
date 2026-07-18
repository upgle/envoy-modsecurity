# Security policy

This project runs in the Envoy data path and treats parser, buffering, and failure-mode defects as
security-sensitive.

Do not disclose a suspected vulnerability in a public issue. Use GitHub private vulnerability
reporting for the repository when available, and include:

- the affected filter and dependency versions;
- a minimal Envoy and ModSecurity configuration;
- a reproducer with sensitive data removed;
- the expected and observed blocking behavior.

The project has no supported production release yet. The pinned combination and qualification
status are tracked in [docs/compatibility.md](docs/compatibility.md); security reports against the
pre-release implementation are still welcome. After the first release, only combinations
explicitly marked supported there are eligible for fixes.
