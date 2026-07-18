# Contributing

## Development flow

1. Create a focused branch from `main`.
2. Initialize the pinned dependencies with `make bootstrap`.
3. Run `make check` before opening a pull request.
4. Keep dependency updates separate from filter behavior changes.

Changes that affect request blocking, failure mode, buffering, or rule evaluation must include
integration tests and an update to the relevant contract document:

- `docs/architecture.md` for ownership, lifecycle, ECDS, protocol, security, memory, concurrency,
  or performance behavior;
- `docs/configuration-api.md` for protobuf and operator-visible semantics.

## Commit messages

Use an imperative subject and keep the first line concise. Conventional Commit prefixes are
preferred, for example:

```text
feat: evaluate request headers with ModSecurity
fix: finalize logging after downstream reset
chore: update Envoy to v1.39.1
```

## Dependency updates

Envoy, ModSecurity, and OWASP CRS are security-sensitive build inputs. Update the submodule and
its entry in `DEPENDENCIES.lock` in the same commit, then run the compatibility and regression
test suites described in `docs/development.md`.
