# Envoy WAF engine comparison

This benchmark compares the repository's native libmodsecurity filter with the Coraza WAF from
Tetrate Built On Envoy's `libcomposer.so`. The comparison binary registers both HTTP filters so
baseline, native, and Dynamic Module measurements use one Envoy executable.

## CI validation

The `waf-engine-comparison` workflow performs the complete Linux pipeline in the Envoy v1.39.0
build image:

1. Build the comparison Envoy target with Bazel `opt`, stripping, and ThinLTO.
2. Add LLVM instrumentation and train baseline, native, and Dynamic Module paths equally.
3. Merge all raw profiles with the LLVM toolchain shipped in the build image.
4. Rebuild the same target with ThinLTO and the merged instrumentation profile.
5. Run the order-rotated comparison and upload JSON, Markdown, profile summary, and build manifest
   artifacts.

The expensive workflow runs only for manual dispatches and pushes to the dedicated
`codex/linux-waf-pgo-benchmark` validation branch; it is not a pull-request gate. It does not
enforce a winner, and fails only on build, profile generation, configuration, or response
mismatches. The default measurement uses seven repeats and triples each workload's request count
to reduce process CPU clock quantization on optimized builds.

The profile workload deliberately exercises all three modes. This gives the common Envoy path and
both filter integration paths training coverage. The native static library receives the same LLVM
instrumentation and profile-use cycle as the Bazel C++ code. The separately built Go shared
library keeps the upstream release's normal optimized build settings.

## Build inputs

- Build `libcomposer.so` from a fixed Built On Envoy release with the Go version and build tags in
  that release's `extensions/composer/go.mod` and `Makefile.common`.
- Use the same local CRS setup file and rule directory for both engines. Do not compare the
  module's embedded CRS with a different native CRS version.
- Use an optimized Linux build for release evidence. The local macOS DEBUG build is diagnostic.
- The CI source pins Built On Envoy `v0.6.2` to commit
  `82b1f9357429aa171d6788a4901db54033f1dd00`. That source pins Coraza `v3.7.0` and Go `1.26.4`.

The comparison Envoy target is intentionally outside the production dependency graph. The example
injects the current checkout as the otherwise-unused `benchmark` external repository, which makes
it possible to benchmark a worktree while reusing another checkout's Bazel output base. Disable
Bazel's visibility check only for this benchmark target:

```shell
"${BAZEL_BINARY}" build \
  --macos_minimum_os=10.15 \
  --nocheck_visibility \
  --override_repository=benchmark="${REPOSITORY_ROOT}" \
  @benchmark//test/performance/envoy_dynamic_comparison:envoy-waf-comparison
```

For a Linux optimized build without PGO training, replace the macOS option with
`--compilation_mode=opt --strip=always '--per_file_copt=.*@-flto=thin' --linkopt=-flto=thin`.
The per-file form keeps Envoy's CMake-based foreign dependencies on their normal object format.
The CI script `tools/ci-waf-engine-comparison.sh` is the source of truth for the two-pass
instrumentation PGO build because its merged profile is generated during the same job.

Run the order-rotated comparison after setting paths to the generated Envoy binary, Coraza module,
and initialized CRS submodule:

```shell
python3 tools/waf-engine-comparison.py \
  --envoy-binary "${COMPARISON_ENVOY}" \
  --coraza-module "${CORAZA_MODULE}" \
  --crs-rules-directory "${CRS_ROOT}/rules" \
  --crs-setup "${CRS_ROOT}/crs-setup.conf.example" \
  --repeats 5 \
  --build-profile "local diagnostic build" \
  --coraza-release v0.6.2 \
  --coraza-engine-version v3.7.0 \
  --libmodsecurity-version v3.0.16 \
  --crs-version v4.28.0
```

The runner measures safe headers, a clean query, 1 KiB form bodies, 4 KiB and 64 KiB JSON bodies,
SQL injection and XSS blocks, a direct phase-1 header block, and selected workloads at concurrency
16. It records throughput, latency percentiles, Envoy process CPU, startup time, RSS, terminal
native-filter gauges, raw runs, paired-repeat ranges, and medians in JSON and Markdown.
