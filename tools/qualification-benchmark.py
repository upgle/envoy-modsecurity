#!/usr/bin/env python3

"""Run release-qualification latency, throughput, CPU-risk, and RSS workloads."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import threading
import time


STARTUP_TIMEOUT_SECONDS = 30
REQUEST_TIMEOUT_SECONDS = 10
EXPECTED_CRS_RULE_FILE_COUNT = 27


def parse_args():
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--envoy-binary", default=repository / "bazel-bin/envoy-modsecurity", type=Path
    )
    parser.add_argument(
        "--config-template",
        default=repository / "test/performance/qualification_bootstrap.yaml.tmpl",
        type=Path,
    )
    parser.add_argument(
        "--output-directory",
        default=repository / "artifacts/qualification-benchmark",
        type=Path,
    )
    parser.add_argument(
        "--crs-rules-directory",
        default=repository / "third_party/coreruleset/rules",
        type=Path,
    )
    parser.add_argument(
        "--crs-setup",
        default=repository / "third_party/coreruleset/crs-setup.conf.example",
        type=Path,
    )
    parser.add_argument(
        "--unicode-mapping",
        default=repository / "third_party/modsecurity/unicode.mapping",
        type=Path,
    )
    parser.add_argument("--concurrency", default=24, type=int)
    parser.add_argument("--request-scale", default=1.0, type=float)
    parser.add_argument("--minimum-throughput-rps", default=50.0, type=float)
    parser.add_argument("--maximum-p99-ms", default=250.0, type=float)
    parser.add_argument("--maximum-pathological-p99-ms", default=1000.0, type=float)
    parser.add_argument(
        "--maximum-pathological-cpu-ms-per-request", default=250.0, type=float
    )
    parser.add_argument("--maximum-rss-growth-mib", default=64.0, type=float)
    parser.add_argument("--enforce", action="store_true")
    return parser.parse_args()


ARGS = parse_args()


def seclang_path(path):
    value = str(Path(path).resolve())
    if any(character.isspace() for character in value) or "#" in value:
        raise ValueError(f"path cannot be represented safely in SecLang: {value!r}")
    return value


def write_crs_config(workdir):
    rule_files = sorted(ARGS.crs_rules_directory.resolve().glob("*.conf"))
    if len(rule_files) != EXPECTED_CRS_RULE_FILE_COUNT:
        raise RuntimeError(
            f"expected {EXPECTED_CRS_RULE_FILE_COUNT} CRS rule files, found {len(rule_files)}"
        )
    lines = [
        "SecRuleEngine On",
        "SecRequestBodyAccess On",
        "SecRequestBodyLimit 1048576",
        "SecRequestBodyNoFilesLimit 1048576",
        "SecRequestBodyLimitAction Reject",
        "SecRequestBodyJsonDepthLimit 64",
        "SecArgumentsLimit 1000",
        "SecResponseBodyAccess Off",
        "SecAuditEngine Off",
        f"SecUnicodeMapFile {seclang_path(ARGS.unicode_mapping)} 20127",
        "SecPcreMatchLimit 100000",
        (
            'SecAction "id:1400000,phase:1,pass,t:none,nolog,'
            "tag:'OWASP_CRS',setvar:tx.blocking_paranoia_level=1\""
        ),
        (
            'SecRule REQUEST_HEADERS:Content-Type "^application/json(?:\\\\s*;|$)" '
            '"id:1400001,phase:1,t:none,t:lowercase,pass,nolog,'
            'ctl:requestBodyProcessor=JSON"'
        ),
        f"Include {seclang_path(ARGS.crs_setup)}",
        *[f"Include {seclang_path(path)}" for path in rule_files],
        (
            'SecRule REQUEST_URI "@streq /pathological" '
            '"id:1400002,phase:2,pass,nolog,chain"'
        ),
        'SecRule REQUEST_BODY "@rx ^(?:a|aa)+$" "t:none"',
        "",
    ]
    config_path = workdir / "qualification-crs.conf"
    config_path.write_text("\n".join(lines), encoding="utf-8")
    config_path.chmod(0o444)
    return config_path


class Upstream(ThreadingHTTPServer):
    daemon_threads = True


class UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._respond()

    def do_POST(self):
        content_length = int(self.headers.get("content-length", "0"))
        if content_length:
            self.rfile.read(content_length)
        self._respond()

    def _respond(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


def admin_request(host, port, path):
    connection = http.client.HTTPConnection(host, port, timeout=REQUEST_TIMEOUT_SECONDS)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def wait_for_admin(process, address_path, log_path):
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    last_error = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"Envoy exited with {process.returncode}:\n"
                + log_path.read_text(encoding="utf-8", errors="replace")
            )
        if address_path.exists():
            address = address_path.read_text(encoding="utf-8").strip()
            if address:
                try:
                    host, port = address.rsplit(":", 1)
                    host = host.strip("[]")
                    status, _body = admin_request(host, int(port), "/ready")
                    if status == 200:
                        return host, int(port)
                except (ConnectionError, OSError, ValueError, http.client.HTTPException) as error:
                    last_error = error
        time.sleep(0.05)
    raise RuntimeError(f"Envoy admin did not become ready: {last_error}")


def listener_port(admin_host, admin_port):
    status, body = admin_request(admin_host, admin_port, "/listeners?format=json")
    if status != 200:
        raise RuntimeError(f"listener discovery returned HTTP {status}")
    for listener in json.loads(body)["listener_statuses"]:
        if listener["name"] == "modsecurity_qualification_listener":
            return listener["local_address"]["socket_address"]["port_value"]
    raise RuntimeError("qualification listener was not found")


def process_rss_bytes(pid):
    status_path = Path(f"/proc/{pid}/status")
    if status_path.exists():
        for line in status_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    result = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(pid)],
        capture_output=True,
        check=True,
        text=True,
        timeout=5,
    )
    return int(result.stdout.strip()) * 1024


def process_cpu_seconds(pid):
    stat_path = Path(f"/proc/{pid}/stat")
    if stat_path.exists():
        fields = stat_path.read_text(encoding="utf-8").split()
        clock_ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        return (int(fields[13]) + int(fields[14])) / clock_ticks
    result = subprocess.run(
        ["ps", "-o", "time=", "-p", str(pid)],
        capture_output=True,
        check=True,
        text=True,
        timeout=5,
    )
    value = result.stdout.strip()
    days = 0
    if "-" in value:
        day_value, value = value.split("-", 1)
        days = int(day_value)
    parts = [float(part) for part in value.split(":")]
    if len(parts) == 3:
        hours, minutes, seconds = parts
    else:
        hours = 0
        minutes, seconds = parts
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def percentile(values, fraction):
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(len(ordered) * fraction) - 1))
    return ordered[index]


def one_request(port, method, path, body, expected_status):
    started = time.perf_counter_ns()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=REQUEST_TIMEOUT_SECONDS)
    try:
        headers = {"host": "qualification.test"}
        if body is not None:
            headers["content-type"] = "application/x-www-form-urlencoded"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response.read()
        if response.status != expected_status:
            raise RuntimeError(
                f"{method} {path} returned {response.status}; expected {expected_status}"
            )
    finally:
        connection.close()
    return (time.perf_counter_ns() - started) / 1_000_000


def run_workload(port, pid, name, count, concurrency, method, path, body, expected_status):
    cpu_before = process_cpu_seconds(pid)
    started = time.perf_counter()
    latencies = []
    errors = []
    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix=name) as executor:
        futures = [
            executor.submit(one_request, port, method, path, body, expected_status)
            for _ in range(count)
        ]
        for future in as_completed(futures):
            try:
                latencies.append(future.result())
            except Exception as error:
                errors.append(str(error))
    elapsed = time.perf_counter() - started
    if errors:
        raise RuntimeError(f"{name} had {len(errors)} errors: {errors[:3]}")
    cpu_seconds = max(0, process_cpu_seconds(pid) - cpu_before)
    return {
        "requests": count,
        "concurrency": concurrency,
        "elapsed_seconds": elapsed,
        "throughput_rps": count / elapsed,
        "envoy_cpu_seconds": cpu_seconds,
        "envoy_cpu_ms_per_request": cpu_seconds * 1000 / count,
        "latency_ms": {
            "median": statistics.median(latencies),
            "p95": percentile(latencies, 0.95),
            "p99": percentile(latencies, 0.99),
            "maximum": max(latencies),
        },
    }


def scaled(value):
    return max(1, int(value * ARGS.request_scale))


def zero_modsecurity_gauges(admin_host, admin_port):
    deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
    last = {}
    while time.monotonic() < deadline:
        status, body = admin_request(admin_host, admin_port, "/stats?filter=modsecurity&format=json")
        if status != 200:
            raise RuntimeError(f"stats endpoint returned HTTP {status}")
        last = {
            stat["name"]: stat["value"]
            for stat in json.loads(body)["stats"]
            if stat.get("name", "").endswith(
                (".active_transactions", ".modsecurity_buffer_bytes")
            )
        }
        if last and all(value == 0 for value in last.values()):
            return last
        time.sleep(0.05)
    raise RuntimeError(f"ModSecurity gauges did not return to zero: {last}")


def write_markdown(path, result):
    lines = [
        "# ModSecurity qualification benchmark",
        "",
        f"Generated: {result['generated_at']}",
        "",
        f"Platform: `{result['platform']}`",
        "",
        "| Workload | Requests | Concurrency | Throughput (rps) | Envoy CPU (ms/request) | p50 (ms) | p95 (ms) | p99 (ms) | Max (ms) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, workload in result["workloads"].items():
        latency = workload["latency_ms"]
        lines.append(
            f"| {name} | {workload['requests']} | {workload['concurrency']} | "
            f"{workload['throughput_rps']:.2f} | {workload['envoy_cpu_ms_per_request']:.2f} | "
            f"{latency['median']:.2f} | "
            f"{latency['p95']:.2f} | {latency['p99']:.2f} | {latency['maximum']:.2f} |"
        )
    lines.extend(
        [
            "",
            f"RSS baseline: {result['rss']['baseline_bytes'] / 1048576:.2f} MiB",
            "",
            f"RSS after soak: {result['rss']['after_soak_bytes'] / 1048576:.2f} MiB",
            "",
            f"RSS growth: {result['rss']['growth_bytes'] / 1048576:.2f} MiB",
            "",
            f"Qualification: **{'PASS' if result['passed'] else 'FAIL'}**",
            "",
        ]
    )
    if result["violations"]:
        lines.extend(["Violations:", ""] + [f"- {value}" for value in result["violations"]])
    path.write_text("\n".join(lines), encoding="utf-8")


def main():
    envoy_binary = ARGS.envoy_binary.resolve()
    if not envoy_binary.is_file() or not os.access(envoy_binary, os.X_OK):
        raise RuntimeError(f"Envoy binary is not executable: {envoy_binary}")
    output_directory = ARGS.output_directory.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    upstream = Upstream(("127.0.0.1", 0), UpstreamHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()

    envoy = None
    with tempfile.TemporaryDirectory(
        prefix="envoy-modsecurity-benchmark-", dir=os.environ.get("TEST_TMPDIR")
    ) as temporary_directory:
        workdir = Path(temporary_directory)
        crs_config_path = write_crs_config(workdir)
        config = (
            ARGS.config_template.read_text(encoding="utf-8")
            .replace("__UPSTREAM_PORT__", str(upstream.server_port))
            .replace("__CRS_ROOT_CONFIG__", json.dumps(str(crs_config_path)))
        )
        config_path = workdir / "bootstrap.yaml"
        config_path.write_text(config, encoding="utf-8")
        admin_address_path = workdir / "admin-address.txt"
        log_path = workdir / "envoy.log"
        log = log_path.open("w", encoding="utf-8")
        try:
            validation = subprocess.run(
                [str(envoy_binary), "--mode", "validate", "-c", str(config_path)],
                capture_output=True,
                check=False,
                text=True,
                timeout=STARTUP_TIMEOUT_SECONDS,
            )
            if validation.returncode != 0:
                raise RuntimeError(f"Envoy rejected benchmark config: {validation.stderr}")
            envoy = subprocess.Popen(
                [
                    str(envoy_binary),
                    "-c",
                    str(config_path),
                    "--admin-address-path",
                    str(admin_address_path),
                    "--concurrency",
                    "4",
                    "--disable-hot-restart",
                    "--log-level",
                    "warning",
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            admin_host, admin_port = wait_for_admin(envoy, admin_address_path, log_path)
            port = listener_port(admin_host, admin_port)
            run_workload(
                port, envoy.pid, "warmup", scaled(100), ARGS.concurrency, "GET", "/safe", None, 200
            )
            rss_baseline = process_rss_bytes(envoy.pid)

            workloads = {
                "safe_headers": run_workload(
                    port, envoy.pid, "safe", scaled(800), ARGS.concurrency, "GET", "/safe", None, 200
                ),
                "request_body_4k": run_workload(
                    port,
                    envoy.pid,
                    "body",
                    scaled(500),
                    ARGS.concurrency,
                    "POST",
                    "/body",
                    "value=" + "b" * 4090,
                    200,
                ),
                "blocked_attack": run_workload(
                    port,
                    envoy.pid,
                    "attack",
                    scaled(300),
                    ARGS.concurrency,
                    "POST",
                    "/attack",
                    "user=1234+OR+1%3D1",
                    403,
                ),
                "pathological_regex": run_workload(
                    port,
                    envoy.pid,
                    "pathological",
                    scaled(40),
                    min(4, ARGS.concurrency),
                    "POST",
                    "/pathological",
                    "a" * 256 + "!",
                    200,
                ),
            }
            for soak_round in range(3):
                run_workload(
                    port,
                    envoy.pid,
                    f"soak-{soak_round}",
                    scaled(250),
                    ARGS.concurrency,
                    "POST",
                    "/body",
                    "value=" + "c" * 16378,
                    200,
                )
            gauges = zero_modsecurity_gauges(admin_host, admin_port)
            rss_after_soak = process_rss_bytes(envoy.pid)
        finally:
            if envoy is not None and envoy.poll() is None:
                envoy.terminate()
                try:
                    envoy.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    envoy.kill()
                    envoy.wait(timeout=5)
            log.close()
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=5)

    rss_growth = max(0, rss_after_soak - rss_baseline)
    violations = []
    for name, workload in workloads.items():
        if workload["throughput_rps"] < ARGS.minimum_throughput_rps:
            violations.append(
                f"{name} throughput {workload['throughput_rps']:.2f} rps is below "
                f"{ARGS.minimum_throughput_rps:.2f} rps"
            )
        maximum_p99 = (
            ARGS.maximum_pathological_p99_ms
            if name == "pathological_regex"
            else ARGS.maximum_p99_ms
        )
        if workload["latency_ms"]["p99"] > maximum_p99:
            violations.append(
                f"{name} p99 {workload['latency_ms']['p99']:.2f} ms exceeds {maximum_p99:.2f} ms"
            )
        if (
            name == "pathological_regex"
            and workload["envoy_cpu_ms_per_request"]
            > ARGS.maximum_pathological_cpu_ms_per_request
        ):
            violations.append(
                f"{name} Envoy CPU {workload['envoy_cpu_ms_per_request']:.2f} ms/request exceeds "
                f"{ARGS.maximum_pathological_cpu_ms_per_request:.2f} ms/request"
            )
    if rss_growth > ARGS.maximum_rss_growth_mib * 1048576:
        violations.append(
            f"RSS growth {rss_growth / 1048576:.2f} MiB exceeds "
            f"{ARGS.maximum_rss_growth_mib:.2f} MiB"
        )

    result = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "envoy_binary": str(envoy_binary),
        "thresholds": {
            "minimum_throughput_rps": ARGS.minimum_throughput_rps,
            "maximum_p99_ms": ARGS.maximum_p99_ms,
            "maximum_pathological_p99_ms": ARGS.maximum_pathological_p99_ms,
            "maximum_pathological_cpu_ms_per_request": (
                ARGS.maximum_pathological_cpu_ms_per_request
            ),
            "maximum_rss_growth_mib": ARGS.maximum_rss_growth_mib,
        },
        "workloads": workloads,
        "rss": {
            "baseline_bytes": rss_baseline,
            "after_soak_bytes": rss_after_soak,
            "growth_bytes": rss_growth,
        },
        "terminal_gauges": gauges,
        "violations": violations,
        "passed": not violations,
    }
    (output_directory / "qualification-benchmark.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    write_markdown(output_directory / "qualification-benchmark.md", result)
    print(output_directory / "qualification-benchmark.md")
    return 1 if ARGS.enforce and violations else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"qualification benchmark failed: {error}", file=sys.stderr)
        sys.exit(2)
