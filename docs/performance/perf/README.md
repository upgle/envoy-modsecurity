# Archived Linux perf reports

These files preserve the textual Linux `perf` output used for the phase-1 diagnostics in
[GitHub Actions run 29941453306](https://github.com/upgle/envoy-modsecurity/actions/runs/29941453306).
The reports cover the sequential (`c1`) and 16-connection (`c16`) native phase-1 blocking
workloads:

- `*-stat.txt` contains `perf stat` process counters.
- `*-self.txt.gz` contains the self-cost `perf report` output.
- `*-callgraph.txt.gz` contains the inclusive call-graph `perf report` output.

Use `gzip -cd FILE.txt.gz` to inspect a compressed report. The original `perf.data` recordings are
not committed because they total approximately 31 MiB and are tied to the exact measured binary.
They remain in the source Actions artifact for its retention period. The archived text reports,
phase-1 JSON, build manifest, and binary hashes preserve the reviewable result after that artifact
expires.

The hosted runner did not expose hardware cycle, instruction, branch, or cache-miss counters.
Those entries therefore appear as `<not supported>` in the `perf stat` output; `perf record` used
the `cpu-clock` sampling event.

File digests are recorded in [SHA256SUMS](SHA256SUMS).
