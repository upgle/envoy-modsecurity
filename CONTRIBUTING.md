# Contributing

## Security reports

Do not disclose suspected vulnerabilities in an issue or pull request. Follow the private reporting
process in [SECURITY.md](SECURITY.md).

## Development flow

1. Create a focused branch based on `main`, in your fork when necessary.
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
chore: update the pinned Envoy release
```

## Dependency updates

Envoy, ModSecurity, and OWASP CRS are security-sensitive build inputs. Update the submodule and
its entry in `DEPENDENCIES.lock` in the same commit. Run `make check` and update
`docs/compatibility.md`. If the change affects a qualification area that has no test suite yet, note
that gap in the pull request.

## Contribution license

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in
this project, as defined in the Apache License 2.0, is licensed under `Apache-2.0 OR MIT`, at the
recipient's option, without additional terms or conditions. By submitting a contribution, you
confirm that you have the right to license it on those terms.
