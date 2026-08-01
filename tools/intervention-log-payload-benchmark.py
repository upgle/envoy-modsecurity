#!/usr/bin/env python3

"""Run a paired Envoy A/B benchmark for intervention log payload generation."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import datetime
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import multiprocessing
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time


STARTUP_TIMEOUT_SECONDS = 45
REQUEST_TIMEOUT_SECONDS = 15
EXPECTED_CRS_RULE_FILE_COUNT = 27
VARIANTS = ("baseline", "candidate")
PRIMARY_WORKLOAD = "phase1_block_c1"
MIN_CPU_RATIO = 1.02
MIN_CROSSOVER_BLOCKS = 5
MIN_BLOCK_WIN_FRACTION = 0.8
MAX_P99_REGRESSION = 1.05
BOOTSTRAP_SEED = 20260801
CLIENT_PROCESS_POOL = None
ENVOY_CPU = None
CLIENT_CPUS = None


def parse_args():
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-envoy-binary", required=True, type=Path)
    parser.add_argument("--baseline-envoy-binary", required=True, type=Path)
    parser.add_argument(
        "--config-template",
        default=repository / "test/performance/qualification_bootstrap.yaml.tmpl",
        type=Path,
    )
    parser.add_argument(
        "--output-directory",
        default=repository / "artifacts/intervention-log-payload-ab",
        type=Path,
    )
    parser.add_argument("--run-log-directory", type=Path)
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
    parser.add_argument("--repeats", default=10, type=int)
    parser.add_argument("--request-scale", default=5.0, type=float)
    parser.add_argument("--envoy-concurrency", default=1, type=int)
    parser.add_argument("--build-profile", default="unspecified")
    parser.add_argument("--baseline-revision", default="unspecified")
    parser.add_argument("--candidate-revision", default="unspecified")
    parser.add_argument("--workload", action="append")
    return parser.parse_args()


def seclang_path(path):
    value = str(Path(path).resolve())
    if any(character.isspace() for character in value) or "#" in value:
        raise ValueError(f"path cannot be represented safely in SecLang: {value!r}")
    return value


def write_rules(workdir, arguments):
    rule_files = sorted(arguments.crs_rules_directory.resolve().glob("*.conf"))
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
        "SecPcreMatchLimit 100000",
        (
            'SecAction "id:1400000,phase:1,pass,t:none,nolog,'
            "tag:'OWASP_CRS',setvar:tx.blocking_paranoia_level=1\""
        ),
        (
            'SecRule REQUEST_HEADERS:X-WAF-Benchmark "@streq phase1-block" '
            '"id:1400001,phase:1,deny,status:403,t:none,nolog,'
            "severity:'CRITICAL',tag:'performance',"
            "msg:'Representative phase-one intervention payload used to measure "
            "connector-side formatting and allocation costs'\""
        ),
        f"Include {seclang_path(arguments.crs_setup)}",
        *[f"Include {seclang_path(path)}" for path in rule_files],
        "",
    ]
    path = workdir / "intervention-log-payload-crs.conf"
    path.write_text("\n".join(lines), encoding="utf-8")
    path.chmod(0o444)
    return path, rule_files


class Upstream(ThreadingHTTPServer):
    daemon_threads = True


class UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

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


def admin_request(host, port, path, method="GET"):
    connection = http.client.HTTPConnection(host, port, timeout=REQUEST_TIMEOUT_SECONDS)
    try:
        connection.request(method, path)
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
                    status, _ = admin_request(host.strip("[]"), int(port), "/ready")
                    if status == 200:
                        return host.strip("[]"), int(port)
                except (ConnectionError, OSError, ValueError, http.client.HTTPException) as error:
                    last_error = error
        time.sleep(0.025)
    raise RuntimeError(f"Envoy admin did not become ready: {last_error}")


def listener_port(admin_host, admin_port):
    status, body = admin_request(admin_host, admin_port, "/listeners?format=json")
    if status != 200:
        raise RuntimeError(f"listener discovery returned HTTP {status}")
    for listener in json.loads(body)["listener_statuses"]:
        if listener["name"] == "modsecurity_qualification_listener":
            return listener["local_address"]["socket_address"]["port_value"]
    raise RuntimeError("benchmark listener was not found")


def process_rss_bytes(pid):
    status_path = Path(f"/proc/{pid}/status")
    if status_path.is_file():
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


def proc_stat_cpu_seconds(contents, ticks_per_second, pid):
    fields = contents.rsplit(") ", 1)
    if len(fields) != 2:
        raise RuntimeError(f"unexpected process stat format for pid {pid}")
    values = fields[1].split()
    if len(values) <= 12:
        raise RuntimeError(f"incomplete process stat for pid {pid}")
    return (int(values[11]) + int(values[12])) / ticks_per_second


def process_cpu_seconds(pid):
    stat_path = Path(f"/proc/{pid}/stat")
    if stat_path.is_file():
        return proc_stat_cpu_seconds(
            stat_path.read_text(encoding="utf-8"), os.sysconf("SC_CLK_TCK"), pid
        )
    result = subprocess.run(
        ["ps", "-o", "time=", "-p", str(pid)],
        capture_output=True,
        check=True,
        text=True,
        timeout=5,
    )
    parts = [float(part) for part in result.stdout.strip().split(":")]
    hours, minutes, seconds = (parts if len(parts) == 3 else (0, *parts))
    return hours * 3600 + minutes * 60 + seconds


def percentile(values, fraction):
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(len(ordered) * fraction) - 1))
    return ordered[index]


def request_worker(port, workload, count):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=REQUEST_TIMEOUT_SECONDS)
    latencies = []
    try:
        for _ in range(count):
            started = time.perf_counter_ns()
            headers = {"host": "benchmark.test", **workload["headers"]}
            connection.request(
                workload["method"], workload["path"], body=workload["body"], headers=headers
            )
            response = connection.getresponse()
            response.read()
            if response.status != workload["status"]:
                raise RuntimeError(
                    f"{workload['name']} returned {response.status}; "
                    f"expected {workload['status']}"
                )
            latencies.append((time.perf_counter_ns() - started) / 1_000_000)
    finally:
        connection.close()
    return latencies


def configure_client_process(client_cpus):
    if client_cpus and hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, set(client_cpus))


def prime_client_process(_index):
    time.sleep(0.05)
    return os.getpid()


def partition_cpu_affinity(available_cpus):
    cpus = tuple(sorted(available_cpus))
    if len(cpus) < 2:
        return None, cpus
    return cpus[0], cpus[1:]


def pin_process_threads(pid, cpu):
    if cpu is None or not hasattr(os, "sched_setaffinity"):
        return
    affinity = {cpu}
    os.sched_setaffinity(pid, affinity)
    task_directory = Path(f"/proc/{pid}/task")
    if task_directory.is_dir():
        for task in task_directory.iterdir():
            try:
                os.sched_setaffinity(int(task.name), affinity)
            except (FileNotFoundError, ProcessLookupError):
                pass


def workloads():
    form_headers = {"content-type": "application/x-www-form-urlencoded"}
    return [
        {
            "name": "headers_c1",
            "requests": 1000,
            "concurrency": 1,
            "method": "GET",
            "path": "/safe",
            "body": None,
            "headers": {},
            "status": 200,
        },
        {
            "name": "phase1_block_c1",
            "requests": 6000,
            "concurrency": 1,
            "method": "GET",
            "path": "/blocked",
            "body": None,
            "headers": {"x-waf-benchmark": "phase1-block"},
            "status": 403,
        },
        {
            "name": "blocked_sqli_c1",
            "requests": 500,
            "concurrency": 1,
            "method": "POST",
            "path": "/attack",
            "body": "user=1234+OR+1%3D1",
            "headers": form_headers,
            "status": 403,
        },
        {
            "name": "headers_c16",
            "requests": 3000,
            "concurrency": 16,
            "method": "GET",
            "path": "/safe",
            "body": None,
            "headers": {},
            "status": 200,
        },
        {
            "name": "phase1_block_c16",
            "requests": 12000,
            "concurrency": 16,
            "method": "GET",
            "path": "/blocked",
            "body": None,
            "headers": {"x-waf-benchmark": "phase1-block"},
            "status": 403,
        },
        {
            "name": "blocked_sqli_c16",
            "requests": 1500,
            "concurrency": 16,
            "method": "POST",
            "path": "/attack",
            "body": "user=1234+OR+1%3D1",
            "headers": form_headers,
            "status": 403,
        },
    ]


def run_workload(port, pid, workload, request_scale):
    count = max(1, int(workload["requests"] * request_scale))
    concurrency = min(count, workload["concurrency"])
    counts = [count // concurrency] * concurrency
    for index in range(count % concurrency):
        counts[index] += 1
    cpu_before = process_cpu_seconds(pid)
    started = time.perf_counter()
    latencies = []
    errors = []
    if concurrency == 1:
        try:
            latencies = request_worker(port, workload, count)
        except Exception as error:
            errors.append(str(error))
    else:
        futures = [
            CLIENT_PROCESS_POOL.submit(request_worker, port, workload, worker_count)
            for worker_count in counts
        ]
        for future in as_completed(futures):
            try:
                latencies.extend(future.result())
            except Exception as error:
                errors.append(str(error))
    elapsed = time.perf_counter() - started
    if errors:
        raise RuntimeError(f"{workload['name']} had {len(errors)} errors: {errors[:3]}")
    cpu_seconds = max(0.0, process_cpu_seconds(pid) - cpu_before)
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


def terminal_gauges(admin_host, admin_port):
    status, body = admin_request(admin_host, admin_port, "/stats?format=json")
    if status != 200:
        raise RuntimeError(f"stats endpoint returned HTTP {status}")
    values = {
        stat["name"]: stat["value"]
        for stat in json.loads(body)["stats"]
        if "modsecurity" in stat.get("name", "")
    }
    for suffix in ("active_transactions", "modsecurity_buffer_bytes"):
        matches = [value for name, value in values.items() if name.endswith(f".{suffix}")]
        if len(matches) != 1 or int(matches[0]) != 0:
            raise RuntimeError(f"expected one zero terminal gauge ending in {suffix}: {matches}")
    return values


def run_variant(variant, repeat, binary, config_path, workdir, cases, arguments):
    address_path = workdir / f"admin-{repeat}-{variant}.txt"
    log_path = workdir / f"envoy-{repeat}-{variant}.log"
    log = log_path.open("w", encoding="utf-8")
    envoy = subprocess.Popen(
        [
            str(binary),
            "-c", str(config_path),
            "--admin-address-path", str(address_path),
            "--concurrency", str(arguments.envoy_concurrency),
            "--disable-hot-restart",
            "--log-level", "warning",
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    pin_process_threads(envoy.pid, ENVOY_CPU)
    admin_address = None
    started = time.monotonic()
    try:
        admin_host, admin_port = wait_for_admin(envoy, address_path, log_path)
        admin_address = (admin_host, admin_port)
        pin_process_threads(envoy.pid, ENVOY_CPU)
        startup_ms = (time.monotonic() - started) * 1000
        port = listener_port(admin_host, admin_port)
        warmup = {
            "name": "warmup",
            "requests": 500,
            "concurrency": 8,
            "method": "GET",
            "path": "/safe",
            "body": None,
            "headers": {},
            "status": 200,
        }
        run_workload(port, envoy.pid, warmup, 1.0)
        pin_process_threads(envoy.pid, ENVOY_CPU)
        rss_after_warmup = process_rss_bytes(envoy.pid)
        results = {
            case["name"]: run_workload(port, envoy.pid, case, arguments.request_scale)
            for case in cases
        }
        rss_after_suite = process_rss_bytes(envoy.pid)
        gauges = terminal_gauges(admin_host, admin_port)
        return {
            "variant": variant,
            "repeat": repeat,
            "startup_ms": startup_ms,
            "rss_after_warmup_bytes": rss_after_warmup,
            "rss_after_suite_bytes": rss_after_suite,
            "workloads": results,
            "terminal_stats": gauges,
        }
    finally:
        if envoy.poll() is None:
            if admin_address is not None:
                try:
                    admin_request(*admin_address, "/quitquitquit", method="POST")
                except (ConnectionError, OSError, http.client.HTTPException):
                    pass
            try:
                envoy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                envoy.terminate()
                try:
                    envoy.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    envoy.kill()
                    envoy.wait(timeout=5)
        log.close()
        if arguments.run_log_directory is not None and log_path.exists():
            target = arguments.run_log_directory.resolve()
            target.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(log_path, target / log_path.name)


def crossover_ratio_summary(values):
    if not values or len(values) % 2 != 0:
        raise ValueError("ratio summaries require a nonempty balanced crossover sample")
    blocks = [math.sqrt(values[index] * values[index + 1]) for index in range(0, len(values), 2)]
    log_blocks = [math.log(value) for value in blocks]
    randomizer = random.Random(BOOTSTRAP_SEED)
    bootstrap = []
    for _ in range(10000):
        sample = [log_blocks[randomizer.randrange(len(log_blocks))] for _ in log_blocks]
        bootstrap.append(math.exp(statistics.median(sample)))
    bootstrap.sort()
    return {
        "median": math.exp(statistics.median(log_blocks)),
        "minimum": min(blocks),
        "maximum": max(blocks),
        "candidate_wins": sum(value > 1.0 for value in blocks),
        "crossover_blocks": len(blocks),
        "repeats": len(values),
        "bootstrap_95_ci": {
            "minimum": percentile(bootstrap, 0.025),
            "maximum": percentile(bootstrap, 0.975),
        },
    }


def aggregate_results(runs, cases, repeats):
    aggregate = {}
    for variant in VARIANTS:
        variant_runs = [run for run in runs if run["variant"] == variant]
        aggregate[variant] = {"workloads": {}}
        for case in cases:
            values = [run["workloads"][case["name"]] for run in variant_runs]
            aggregate[variant]["workloads"][case["name"]] = {
                "throughput_rps": statistics.median(value["throughput_rps"] for value in values),
                "envoy_cpu_ms_per_request": statistics.median(value["envoy_cpu_ms_per_request"] for value in values),
                "latency_ms": {
                    key: statistics.median(value["latency_ms"][key] for value in values)
                    for key in ("median", "p95", "p99", "maximum")
                },
            }
    indexed = {(run["repeat"], run["variant"]): run for run in runs}
    comparisons = {}
    for case in cases:
        name = case["name"]
        ratios = {"throughput": [], "cpu": [], "p50": [], "p99": []}
        for repeat in range(repeats):
            baseline = indexed[(repeat, "baseline")]["workloads"][name]
            candidate = indexed[(repeat, "candidate")]["workloads"][name]
            ratios["throughput"].append(candidate["throughput_rps"] / baseline["throughput_rps"])
            ratios["cpu"].append(baseline["envoy_cpu_ms_per_request"] / candidate["envoy_cpu_ms_per_request"])
            ratios["p50"].append(baseline["latency_ms"]["median"] / candidate["latency_ms"]["median"])
            ratios["p99"].append(baseline["latency_ms"]["p99"] / candidate["latency_ms"]["p99"])
        comparisons[name] = {
            "throughput_candidate_over_baseline": crossover_ratio_summary(ratios["throughput"]),
            "cpu_baseline_over_candidate": crossover_ratio_summary(ratios["cpu"]),
            "p50_baseline_over_candidate": crossover_ratio_summary(ratios["p50"]),
            "p99_baseline_over_candidate": crossover_ratio_summary(ratios["p99"]),
        }
    return aggregate, comparisons


def performance_decision(comparisons):
    primary = comparisons[PRIMARY_WORKLOAD]
    cpu = primary["cpu_baseline_over_candidate"]
    throughput = primary["throughput_candidate_over_baseline"]
    p99 = primary["p99_baseline_over_candidate"]
    checks = {
        "minimum_sample": cpu["crossover_blocks"] >= MIN_CROSSOVER_BLOCKS,
        "cpu_effect_size": cpu["median"] >= MIN_CPU_RATIO,
        "cpu_interval_excludes_parity": cpu["bootstrap_95_ci"]["minimum"] > 1.0,
        "cpu_block_consistency": cpu["candidate_wins"] / cpu["crossover_blocks"] >= MIN_BLOCK_WIN_FRACTION,
        "throughput_corroborates": throughput["median"] > 1.0,
        "p99_regression_guard": p99["median"] >= 1.0 / MAX_P99_REGRESSION,
    }
    return {
        "status": "confirmed_improvement" if all(checks.values()) else "not_confirmed",
        "primary_workload": PRIMARY_WORKLOAD,
        "checks": checks,
        "thresholds": {
            "minimum_cpu_ratio": MIN_CPU_RATIO,
            "minimum_crossover_blocks": MIN_CROSSOVER_BLOCKS,
            "minimum_block_win_fraction": MIN_BLOCK_WIN_FRACTION,
            "maximum_p99_regression": MAX_P99_REGRESSION,
        },
    }


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_output(command):
    result = subprocess.run(command, capture_output=True, check=True, text=True, timeout=15)
    return result.stdout.strip() or result.stderr.strip()


def format_ratio(summary):
    confidence = summary["bootstrap_95_ci"]
    return (
        f"{summary['median']:.4f}x [{confidence['minimum']:.4f}, "
        f"{confidence['maximum']:.4f}], {summary['candidate_wins']}/"
        f"{summary['crossover_blocks']} blocks"
    )


def write_markdown(path, result):
    lines = [
        "# Intervention log payload Envoy A/B",
        "",
        f"Generated: {result['generated_at']}",
        "",
        f"Platform: `{result['platform']}`",
        "",
        f"Build profile: `{result['build_profile']}`",
        "",
        f"Baseline dependency: `{result['revisions']['baseline']}`",
        "",
        f"Candidate dependency: `{result['revisions']['candidate']}`",
        "",
        f"Repeats: {result['parameters']['repeats']}; crossover blocks: "
        f"{result['parameters']['repeats'] // 2}; request scale: "
        f"{result['parameters']['request_scale']}; Envoy workers: "
        f"{result['parameters']['envoy_concurrency']}",
        "",
        "The baseline uses the previous dependency revision and omits the new runtime API "
        "call. The candidate changes only the dependency revision and disables generation of "
        "a free-form payload that this connector does not consume. Both binaries otherwise "
        "use the same project revision, compiler flags, rules, and filter configuration.",
        "",
        "Fresh Envoy processes run in alternating baseline-first and candidate-first order. "
        "Each adjacent pair of order-reversed repeats forms one crossover block. Ratios are "
        "geometric block means summarized by their median and a deterministic 95% "
        "block-bootstrap interval. Ratios above 1.0 favor the candidate.",
        "",
        f"Decision for `{PRIMARY_WORKLOAD}`: **{result['decision']['status']}**",
        "",
        "| Workload | Candidate/baseline throughput | Baseline/candidate CPU | "
        "Baseline/candidate p50 | Baseline/candidate p99 |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for workload in result["workload_names"]:
        comparison = result["comparisons"][workload]
        lines.append(
            f"| {workload} | {format_ratio(comparison['throughput_candidate_over_baseline'])} | "
            f"{format_ratio(comparison['cpu_baseline_over_candidate'])} | "
            f"{format_ratio(comparison['p50_baseline_over_candidate'])} | "
            f"{format_ratio(comparison['p99_baseline_over_candidate'])} |"
        )
    lines.extend([
        "",
        "## Median measurements",
        "",
        "| Workload | Variant | Throughput (rps) | Envoy CPU (ms/request) | p50 (ms) | p99 (ms) |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ])
    for workload in result["workload_names"]:
        for variant in VARIANTS:
            value = result["aggregate"][variant]["workloads"][workload]
            lines.append(
                f"| {workload} | {variant} | {value['throughput_rps']:.2f} | "
                f"{value['envoy_cpu_ms_per_request']:.4f} | "
                f"{value['latency_ms']['median']:.3f} | {value['latency_ms']['p99']:.3f} |"
            )
    lines.extend([
        "",
        "Every response status is validated, and every run must end with zero active native "
        "transactions and zero charged body bytes. Hosted-runner intervals describe this run "
        "only; they are not hardware-independent confidence claims.",
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def validate_args(arguments):
    if arguments.repeats < 2 or arguments.repeats % 2 != 0:
        raise ValueError("--repeats must be an even integer of at least 2")
    if arguments.request_scale <= 0:
        raise ValueError("--request-scale must be positive")
    if arguments.envoy_concurrency < 1:
        raise ValueError("--envoy-concurrency must be positive")


def main():
    global CLIENT_CPUS, CLIENT_PROCESS_POOL, ENVOY_CPU
    arguments = parse_args()
    validate_args(arguments)
    binaries = {
        "baseline": arguments.baseline_envoy_binary.resolve(),
        "candidate": arguments.candidate_envoy_binary.resolve(),
    }
    for variant, binary in binaries.items():
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError(f"{variant} Envoy binary is not executable: {binary}")
    cases = workloads()
    if arguments.workload:
        requested = set(arguments.workload)
        known = {case["name"] for case in cases}
        if requested - known:
            raise ValueError(f"unknown workload names: {sorted(requested - known)}")
        cases = [case for case in cases if case["name"] in requested]
    if PRIMARY_WORKLOAD not in {case["name"] for case in cases}:
        raise ValueError(f"the primary workload {PRIMARY_WORKLOAD!r} must be selected")

    original_affinity = None
    if platform.system() == "Linux" and hasattr(os, "sched_getaffinity"):
        original_affinity = tuple(sorted(os.sched_getaffinity(0)))
        ENVOY_CPU, CLIENT_CPUS = partition_cpu_affinity(original_affinity)
        if ENVOY_CPU is not None:
            os.sched_setaffinity(0, set(CLIENT_CPUS))
    client_processes = max(8, *(case["concurrency"] for case in cases))
    CLIENT_PROCESS_POOL = ProcessPoolExecutor(
        max_workers=client_processes,
        mp_context=multiprocessing.get_context("spawn"),
        initializer=configure_client_process,
        initargs=(CLIENT_CPUS,),
    )
    for future in as_completed(
        [CLIENT_PROCESS_POOL.submit(prime_client_process, index) for index in range(client_processes)]
    ):
        future.result()

    output_directory = arguments.output_directory.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    upstream = Upstream(("127.0.0.1", 0), UpstreamHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    runs = []
    try:
        with tempfile.TemporaryDirectory(prefix="intervention-log-payload-ab-") as temporary:
            workdir = Path(temporary)
            rules_path, rule_files = write_rules(workdir, arguments)
            config = (
                arguments.config_template.resolve().read_text(encoding="utf-8")
                .replace("__UPSTREAM_PORT__", str(upstream.server_port))
                .replace("__CRS_ROOT_CONFIG__", json.dumps(str(rules_path)))
            )
            config_path = workdir / "bootstrap.yaml"
            config_path.write_text(config, encoding="utf-8")
            for variant, binary in binaries.items():
                validation = subprocess.run(
                    [str(binary), "--mode", "validate", "-c", str(config_path)],
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=STARTUP_TIMEOUT_SECONDS,
                )
                if validation.returncode != 0:
                    raise RuntimeError(
                        f"{variant} Envoy rejected benchmark config:\n"
                        f"{validation.stdout}\n{validation.stderr}"
                    )
            order_patterns = (("baseline", "candidate"), ("candidate", "baseline"))
            for repeat in range(arguments.repeats):
                for variant in order_patterns[repeat % 2]:
                    print(f"repeat {repeat + 1}/{arguments.repeats}: {variant}", flush=True)
                    runs.append(
                        run_variant(
                            variant, repeat, binaries[variant], config_path, workdir, cases, arguments
                        )
                    )
            aggregate, comparisons = aggregate_results(runs, cases, arguments.repeats)
            result = {
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "platform": platform.platform(),
                "build_profile": arguments.build_profile,
                "revisions": {
                    "baseline": arguments.baseline_revision,
                    "candidate": arguments.candidate_revision,
                },
                "binaries": {
                    variant: {
                        "path": str(binary),
                        "sha256": sha256(binary),
                        "version": command_output([str(binary), "--version"]),
                    }
                    for variant, binary in binaries.items()
                },
                "crs_rule_file_count": len(rule_files),
                "parameters": {
                    "repeats": arguments.repeats,
                    "request_scale": arguments.request_scale,
                    "envoy_concurrency": arguments.envoy_concurrency,
                    "client_processes": client_processes,
                    "envoy_cpu": ENVOY_CPU,
                    "client_cpus": CLIENT_CPUS,
                    "order_patterns": order_patterns,
                },
                "workload_names": [case["name"] for case in cases],
                "runs": runs,
                "aggregate": aggregate,
                "comparisons": comparisons,
                "decision": performance_decision(comparisons),
            }
    finally:
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=5)
        CLIENT_PROCESS_POOL.shutdown(wait=True)
        CLIENT_PROCESS_POOL = None
        if original_affinity is not None and ENVOY_CPU is not None:
            os.sched_setaffinity(0, set(original_affinity))

    json_path = output_directory / "intervention-log-payload-ab.json"
    markdown_path = output_directory / "intervention-log-payload-ab.md"
    json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    write_markdown(markdown_path, result)
    print(markdown_path)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"intervention log payload benchmark failed: {error}", file=sys.stderr)
        sys.exit(2)
