#!/usr/bin/env python3

"""Compare native libmodsecurity and the Coraza Envoy Dynamic Module."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time


STARTUP_TIMEOUT_SECONDS = 45
REQUEST_TIMEOUT_SECONDS = 15
EXPECTED_CRS_RULE_FILE_COUNT = 27
ENGINES = ("baseline", "libmodsecurity", "coraza")


def parse_args():
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--envoy-binary", required=True, type=Path)
    parser.add_argument("--coraza-module", required=True, type=Path)
    parser.add_argument(
        "--config-template",
        default=repository / "test/performance/waf_comparison_bootstrap.yaml.tmpl",
        type=Path,
    )
    parser.add_argument(
        "--output-directory",
        default=repository / "artifacts/waf-engine-comparison",
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
    parser.add_argument("--repeats", default=5, type=int)
    parser.add_argument("--request-scale", default=1.0, type=float)
    parser.add_argument("--envoy-concurrency", default=1, type=int)
    parser.add_argument("--coraza-release", default="unspecified")
    parser.add_argument("--coraza-engine-version", default="unspecified")
    parser.add_argument("--libmodsecurity-version", default="unspecified")
    parser.add_argument("--crs-version", default="unspecified")
    parser.add_argument("--build-profile", default="unspecified")
    parser.add_argument(
        "--native-phase1-profile",
        action="store_true",
        help="Profile the native phase-1 blocking path instead of running the comparison",
    )
    parser.add_argument(
        "--perf-binary",
        type=Path,
        help="Linux perf executable used by --native-phase1-profile",
    )
    parser.add_argument("--perf-frequency", default=499, type=int)
    parser.add_argument(
        "--workload",
        action="append",
        help="Run only the named workload; may be supplied more than once",
    )
    return parser.parse_args()


ARGS = parse_args()


def seclang_path(path):
    value = str(Path(path).resolve())
    if any(character.isspace() for character in value) or "#" in value:
        raise ValueError(f"path cannot be represented safely in SecLang: {value!r}")
    return value


def write_common_crs_config(workdir):
    rule_files = sorted(ARGS.crs_rules_directory.resolve().glob("*.conf"))
    if len(rule_files) != EXPECTED_CRS_RULE_FILE_COUNT:
        raise RuntimeError(
            f"expected {EXPECTED_CRS_RULE_FILE_COUNT} CRS rule files, found {len(rule_files)}"
        )
    lines = [
        "SecRuleEngine On",
        "SecRequestBodyAccess On",
        "SecRequestBodyLimit 1048576",
        "SecRequestBodyLimitAction Reject",
        "SecRequestBodyJsonDepthLimit 64",
        "SecArgumentsLimit 1000",
        "SecResponseBodyAccess Off",
        "SecAuditEngine Off",
        (
            'SecAction "id:1400000,phase:1,pass,t:none,nolog,'
            "tag:'OWASP_CRS',setvar:tx.blocking_paranoia_level=1\""
        ),
        (
            'SecRule REQUEST_HEADERS:Content-Type "^application/json(?:\\\\s*;|$)" '
            '"id:1400001,phase:1,t:none,t:lowercase,pass,nolog,'
            'ctl:requestBodyProcessor=JSON"'
        ),
        (
            'SecRule REQUEST_HEADERS:X-WAF-Benchmark "@streq phase1-block" '
            '"id:1400002,phase:1,deny,status:403,t:none,nolog"'
        ),
        f"Include {seclang_path(ARGS.crs_setup)}",
        *[f"Include {seclang_path(path)}" for path in rule_files],
        "",
    ]
    config_path = workdir / "common-crs.conf"
    config_path.write_text("\n".join(lines), encoding="utf-8")
    config_path.chmod(0o444)
    return config_path, rule_files


def http_filter_yaml(engine, crs_config_path):
    if engine == "baseline":
        return ""
    if engine == "libmodsecurity":
        return "\n".join(
            [
                "                  - name: envoy.filters.http.modsecurity",
                "                    typed_config:",
                "                      \"@type\": type.googleapis.com/envoy_modsecurity.extensions.filters.http.modsecurity.v3.ModSecurity",
                "                      rules:",
                f"                        - filename: {json.dumps(str(crs_config_path))}",
                "                      request_body:",
                "                        max_bytes:",
                "                          value: 1048576",
                "                      failure_mode_allow: false",
                "                      stat_prefix: comparison",
                "                      max_active_body_bytes:",
                "                        value: 67108864",
            ]
        )
    plugin_config = json.dumps(
        {
            "directives": [f"Include {seclang_path(crs_config_path)}"],
            "mode": "REQUEST_ONLY",
        },
        separators=(",", ":"),
    )
    return "\n".join(
        [
            "                  - name: envoy.filters.http.dynamic_modules",
            "                    typed_config:",
            "                      \"@type\": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter",
            "                      dynamic_module_config:",
            "                        name: composer",
            "                        do_not_close: true",
            "                        metrics_namespace: coraza_comparison",
            "                      filter_name: coraza-waf",
            "                      filter_config:",
            "                        \"@type\": type.googleapis.com/google.protobuf.StringValue",
            f"                        value: {json.dumps(plugin_config)}",
        ]
    )


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
                    host = host.strip("[]")
                    status, _body = admin_request(host, int(port), "/ready")
                    if status == 200:
                        return host, int(port)
                except (ConnectionError, OSError, ValueError, http.client.HTTPException) as error:
                    last_error = error
        time.sleep(0.025)
    raise RuntimeError(f"Envoy admin did not become ready: {last_error}")


def listener_port(admin_host, admin_port):
    status, body = admin_request(admin_host, admin_port, "/listeners?format=json")
    if status != 200:
        raise RuntimeError(f"listener discovery returned HTTP {status}")
    for listener in json.loads(body)["listener_statuses"]:
        if listener["name"] == "waf_comparison_listener":
            return listener["local_address"]["socket_address"]["port_value"]
    raise RuntimeError("comparison listener was not found")


def process_rss_bytes(pid):
    result = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(pid)],
        capture_output=True,
        check=True,
        text=True,
        timeout=5,
    )
    return int(result.stdout.strip()) * 1024


def process_cpu_seconds(pid):
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


def request_worker(port, workload, count, expected_status):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=REQUEST_TIMEOUT_SECONDS)
    latencies = []
    try:
        for _ in range(count):
            started = time.perf_counter_ns()
            headers = {"host": "comparison.test", **workload["headers"]}
            connection.request(
                workload["method"], workload["path"], body=workload["body"], headers=headers
            )
            response = connection.getresponse()
            response.read()
            if response.status != expected_status:
                raise RuntimeError(
                    f"{workload['method']} {workload['path'][:80]} returned "
                    f"{response.status}; expected {expected_status}"
                )
            latencies.append((time.perf_counter_ns() - started) / 1_000_000)
    finally:
        connection.close()
    return latencies


def run_workload(port, pid, engine, workload):
    count = max(1, int(workload["requests"] * ARGS.request_scale))
    concurrency = min(count, workload["concurrency"])
    counts = [count // concurrency] * concurrency
    for index in range(count % concurrency):
        counts[index] += 1
    expected_status = 200 if engine == "baseline" else workload["waf_status"]
    cpu_before = process_cpu_seconds(pid)
    started = time.perf_counter()
    latencies = []
    errors = []
    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix=workload["name"]) as pool:
        futures = [
            pool.submit(request_worker, port, workload, worker_count, expected_status)
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


def start_perf(pid, data_path):
    if ARGS.perf_binary is None:
        raise ValueError("--perf-binary is required with --native-phase1-profile")
    perf_binary = ARGS.perf_binary.resolve()
    if not perf_binary.is_file():
        raise RuntimeError(f"perf executable is not a file: {perf_binary}")
    data_path.parent.mkdir(parents=True, exist_ok=True)
    record_log_path = data_path.with_suffix(".record.log")
    stat_path = data_path.with_suffix(".stat.txt")
    record_log = record_log_path.open("w", encoding="utf-8")
    record = subprocess.Popen(
        [
            str(perf_binary),
            "record",
            "--quiet",
            "--event",
            "cpu-clock",
            "--freq",
            str(ARGS.perf_frequency),
            "--call-graph",
            "dwarf,8192",
            "--output",
            str(data_path),
            "--pid",
            str(pid),
        ],
        stdout=record_log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    stat = subprocess.Popen(
        [
            str(perf_binary),
            "stat",
            "--output",
            str(stat_path),
            "--event",
            "task-clock,cycles,instructions,branches,branch-misses,cache-misses,context-switches,cpu-migrations,page-faults",
            "--pid",
            str(pid),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    session = {
        "processes": (record, stat),
        "record_log": record_log,
        "record_log_path": record_log_path,
        "stat_path": stat_path,
        "data_path": data_path,
        "stopped": False,
    }
    time.sleep(0.25)
    for process, description in ((record, "perf record"), (stat, "perf stat")):
        if process.poll() is not None:
            try:
                stop_perf(session)
            except RuntimeError as error:
                raise RuntimeError(f"{description} exited before the workload: {error}") from error
            raise RuntimeError(f"{description} exited before the workload with {process.returncode}")
    return session


def stop_perf(session):
    if session is None or session["stopped"]:
        return
    session["stopped"] = True
    errors = []
    for process in session["processes"]:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
    for process, description in zip(session["processes"], ("perf record", "perf stat")):
        try:
            return_code = process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.terminate()
            return_code = process.wait(timeout=10)
        if return_code not in (0, 130, -signal.SIGINT):
            errors.append(f"{description} exited with {return_code}")
    session["record_log"].close()
    if errors:
        detail = session["record_log_path"].read_text(encoding="utf-8", errors="replace")
        if session["stat_path"].exists():
            detail += "\n" + session["stat_path"].read_text(
                encoding="utf-8", errors="replace"
            )
        raise RuntimeError(f"{'; '.join(errors)}:\n{detail}")


def write_perf_reports(data_path):
    perf_binary = ARGS.perf_binary.resolve()
    errors = []
    reports = (
        (
            data_path.with_suffix(".self.txt"),
            ["--no-children", "--sort", "dso,symbol"],
        ),
        (
            data_path.with_suffix(".callgraph.txt"),
            [
                "--children",
                "--sort",
                "dso,symbol",
                "--call-graph",
                "graph,0.5,caller",
            ],
        ),
    )
    for report_path, options in reports:
        try:
            with report_path.open("w", encoding="utf-8") as report:
                result = subprocess.run(
                    [
                        str(perf_binary),
                        "report",
                        "--stdio",
                        "--input",
                        str(data_path),
                        "--no-inline",
                        "--percent-limit",
                        "0.1",
                        *options,
                    ],
                    stdout=report,
                    stderr=subprocess.STDOUT,
                    check=False,
                    text=True,
                    timeout=600,
                )
        except subprocess.TimeoutExpired:
            message = f"perf report timed out after 600 seconds: {report_path.name}"
            errors.append(message)
            with report_path.open("a", encoding="utf-8") as report:
                report.write(f"\n{message}\n")
            continue
        if result.returncode != 0:
            errors.append(f"perf report exited with {result.returncode}: {report_path.name}")
    return errors


def workloads():
    clean_query = "/search?q=" + "normal-value-" * 32
    xss_query = "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    form_1k = "value=" + "b" * 1018
    json_4k = json.dumps({"message": "c" * 4078}, separators=(",", ":"))
    json_64k = json.dumps({"message": "d" * 65518}, separators=(",", ":"))
    form_headers = {"content-type": "application/x-www-form-urlencoded"}
    json_headers = {"content-type": "application/json"}
    return [
        {"name": "headers_c1", "requests": 600, "concurrency": 1, "method": "GET", "path": "/safe", "body": None, "headers": {}, "waf_status": 200},
        {"name": "clean_query_c1", "requests": 400, "concurrency": 1, "method": "GET", "path": clean_query, "body": None, "headers": {}, "waf_status": 200},
        {"name": "form_1k_c1", "requests": 300, "concurrency": 1, "method": "POST", "path": "/form", "body": form_1k, "headers": form_headers, "waf_status": 200},
        {"name": "json_4k_c1", "requests": 250, "concurrency": 1, "method": "POST", "path": "/json", "body": json_4k, "headers": json_headers, "waf_status": 200},
        {"name": "json_64k_c1", "requests": 50, "concurrency": 1, "method": "POST", "path": "/json", "body": json_64k, "headers": json_headers, "waf_status": 200},
        {"name": "blocked_sqli_c1", "requests": 150, "concurrency": 1, "method": "POST", "path": "/attack", "body": "user=1234+OR+1%3D1", "headers": form_headers, "waf_status": 403},
        {"name": "blocked_xss_c1", "requests": 150, "concurrency": 1, "method": "GET", "path": xss_query, "body": None, "headers": {}, "waf_status": 403},
        {"name": "phase1_block_c1", "requests": 600, "concurrency": 1, "method": "GET", "path": "/safe", "body": None, "headers": {"x-waf-benchmark": "phase1-block"}, "waf_status": 403},
        {"name": "headers_c16", "requests": 1200, "concurrency": 16, "method": "GET", "path": "/safe", "body": None, "headers": {}, "waf_status": 200},
        {"name": "json_4k_c16", "requests": 600, "concurrency": 16, "method": "POST", "path": "/json", "body": json_4k, "headers": json_headers, "waf_status": 200},
        {"name": "blocked_sqli_c16", "requests": 400, "concurrency": 16, "method": "POST", "path": "/attack", "body": "user=1234+OR+1%3D1", "headers": form_headers, "waf_status": 403},
        {"name": "phase1_block_c16", "requests": 1200, "concurrency": 16, "method": "GET", "path": "/safe", "body": None, "headers": {"x-waf-benchmark": "phase1-block"}, "waf_status": 403},
    ]


def render_config(template, upstream_port, engine, crs_config_path):
    return (
        template.replace("__UPSTREAM_PORT__", str(upstream_port))
        .replace("__HTTP_FILTER__", http_filter_yaml(engine, crs_config_path))
    )


def run_engine(
    engine,
    repeat,
    config_path,
    workdir,
    upstream_port,
    cases,
    enable_stage_timing=False,
    perf_data_path=None,
):
    address_path = workdir / f"admin-{repeat}-{engine}.txt"
    log_path = workdir / f"envoy-{repeat}-{engine}.log"
    environment = os.environ.copy()
    environment["ENVOY_DYNAMIC_MODULES_SEARCH_PATH"] = str(ARGS.coraza_module.parent.resolve())
    environment["GODEBUG"] = "cgocheck=0"
    if enable_stage_timing:
        environment["ENVOY_MODSECURITY_STAGE_TIMING"] = "1"
    log = log_path.open("w", encoding="utf-8")
    started = time.monotonic()
    admin_address = None
    perf_session = None
    perf_report_errors = []
    envoy = subprocess.Popen(
        [
            str(ARGS.envoy_binary.resolve()),
            "-c",
            str(config_path),
            "--admin-address-path",
            str(address_path),
            "--concurrency",
            str(ARGS.envoy_concurrency),
            "--disable-hot-restart",
            "--log-level",
            "warning",
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
        env=environment,
    )
    try:
        admin_host, admin_port = wait_for_admin(envoy, address_path, log_path)
        admin_address = (admin_host, admin_port)
        startup_ms = (time.monotonic() - started) * 1000
        port = listener_port(admin_host, admin_port)
        warmup = {
            "name": "warmup",
            "requests": 100,
            "concurrency": 8,
            "method": "GET",
            "path": "/safe",
            "body": None,
            "headers": {},
            "waf_status": 200,
        }
        run_workload(port, envoy.pid, engine, warmup)
        rss_after_warmup = process_rss_bytes(envoy.pid)
        if enable_stage_timing:
            status, body = admin_request(admin_host, admin_port, "/reset_counters", method="POST")
            if status != 200:
                raise RuntimeError(
                    f"counter reset returned HTTP {status}: {body.decode(errors='replace')}"
                )
        if perf_data_path is not None:
            perf_session = start_perf(envoy.pid, perf_data_path)
        results = {}
        for case in cases:
            results[case["name"]] = run_workload(port, envoy.pid, engine, case)
        stop_perf(perf_session)
        perf_session = None
        if perf_data_path is not None:
            perf_report_errors = write_perf_reports(perf_data_path)
        rss_after_suite = process_rss_bytes(envoy.pid)
        status, stats_body = admin_request(admin_host, admin_port, "/stats?format=json")
        if status != 200:
            raise RuntimeError(f"stats endpoint returned HTTP {status}")
        stats_payload = json.loads(stats_body)
        interesting_stats = {
            stat["name"]: stat["value"]
            for stat in stats_payload["stats"]
            if "modsecurity" in stat.get("name", "")
            or "coraza_comparison" in stat.get("name", "")
        }
        interesting_histograms = [
            histogram
            for histogram in stats_payload.get("histograms", [])
            if "modsecurity" in histogram.get("name", "")
            or "coraza_comparison" in histogram.get("name", "")
        ]
        return {
            "engine": engine,
            "repeat": repeat,
            "startup_ms": startup_ms,
            "rss_after_warmup_bytes": rss_after_warmup,
            "rss_after_suite_bytes": rss_after_suite,
            "workloads": results,
            "terminal_stats": interesting_stats,
            "terminal_histograms": interesting_histograms,
            "perf_data": str(perf_data_path) if perf_data_path is not None else None,
            "perf_report_errors": perf_report_errors,
        }
    finally:
        stop_perf(perf_session)
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


def median(values):
    return statistics.median(values)


def aggregate_results(runs, cases):
    aggregate = {}
    for engine in ENGINES:
        engine_runs = [run for run in runs if run["engine"] == engine]
        aggregate[engine] = {
            "startup_ms": median([run["startup_ms"] for run in engine_runs]),
            "rss_after_warmup_bytes": median(
                [run["rss_after_warmup_bytes"] for run in engine_runs]
            ),
            "rss_after_suite_bytes": median(
                [run["rss_after_suite_bytes"] for run in engine_runs]
            ),
            "workloads": {},
        }
        for case in cases:
            name = case["name"]
            values = [run["workloads"][name] for run in engine_runs]
            aggregate[engine]["workloads"][name] = {
                "throughput_rps": median([value["throughput_rps"] for value in values]),
                "envoy_cpu_ms_per_request": median(
                    [value["envoy_cpu_ms_per_request"] for value in values]
                ),
                "latency_ms": {
                    key: median([value["latency_ms"][key] for value in values])
                    for key in ("median", "p95", "p99", "maximum")
                },
            }
    comparisons = {}
    runs_by_repeat_and_engine = {
        (run["repeat"], run["engine"]): run for run in runs
    }

    def ratio_summary(values):
        return {
            "median": median(values),
            "minimum": min(values),
            "maximum": max(values),
            "native_wins": sum(value > 1.0 for value in values),
            "repeats": len(values),
        }

    for case in cases:
        name = case["name"]
        native = aggregate["libmodsecurity"]["workloads"][name]
        coraza = aggregate["coraza"]["workloads"][name]
        baseline = aggregate["baseline"]["workloads"][name]
        native_delta = max(
            0.0,
            native["envoy_cpu_ms_per_request"]
            - baseline["envoy_cpu_ms_per_request"],
        )
        coraza_delta = max(
            0.0,
            coraza["envoy_cpu_ms_per_request"]
            - baseline["envoy_cpu_ms_per_request"],
        )
        paired_throughput = []
        paired_raw_cpu = []
        paired_p99 = []
        for repeat in range(ARGS.repeats):
            native_run = runs_by_repeat_and_engine[(repeat, "libmodsecurity")][
                "workloads"
            ][name]
            coraza_run = runs_by_repeat_and_engine[(repeat, "coraza")]["workloads"][name]
            paired_throughput.append(
                native_run["throughput_rps"] / coraza_run["throughput_rps"]
            )
            if native_run["envoy_cpu_ms_per_request"] > 0:
                paired_raw_cpu.append(
                    coraza_run["envoy_cpu_ms_per_request"]
                    / native_run["envoy_cpu_ms_per_request"]
                )
            paired_p99.append(
                coraza_run["latency_ms"]["p99"]
                / native_run["latency_ms"]["p99"]
            )
        comparisons[name] = {
            "throughput_native_over_coraza": (
                native["throughput_rps"] / coraza["throughput_rps"]
            ),
            "p99_coraza_over_native": (
                coraza["latency_ms"]["p99"] / native["latency_ms"]["p99"]
            ),
            "raw_cpu_coraza_over_native": (
                coraza["envoy_cpu_ms_per_request"]
                / native["envoy_cpu_ms_per_request"]
                if native["envoy_cpu_ms_per_request"] > 0
                else None
            ),
            "baseline_adjusted_cpu_ms_per_request": {
                "libmodsecurity": native_delta,
                "coraza": coraza_delta,
            },
            "baseline_adjusted_cpu_coraza_over_native": (
                coraza_delta / native_delta if native_delta > 0 else None
            ),
            "paired_repeat_ratios": {
                "throughput_native_over_coraza": ratio_summary(paired_throughput),
                "raw_cpu_coraza_over_native": (
                    ratio_summary(paired_raw_cpu) if paired_raw_cpu else None
                ),
                "p99_coraza_over_native": ratio_summary(paired_p99),
            },
        }
    return aggregate, comparisons


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_output(command):
    result = subprocess.run(command, capture_output=True, check=True, text=True, timeout=15)
    return result.stdout.strip() or result.stderr.strip()


STAGE_PROFILE_METRICS = (
    ("transaction_create", "stage_profile_transaction_create_ns"),
    ("process_connection", "stage_profile_process_connection_ns"),
    ("process_uri", "stage_profile_process_uri_ns"),
    ("add_request_headers", "stage_profile_add_request_headers_ns"),
    ("process_request_headers", "stage_profile_process_request_headers_ns"),
    ("intervention_lookup", "stage_profile_intervention_lookup_ns"),
    ("intervention_response", "stage_profile_intervention_response_ns"),
    ("logging", "stage_profile_logging_ns"),
    ("process_logging", "stage_profile_process_logging_ns"),
    ("security_event", "stage_profile_security_event_ns"),
    ("local_reply", "stage_profile_local_reply_ns"),
    ("release_resources", "stage_profile_release_resources_ns"),
)


def terminal_stat(run, suffix):
    matches = [
        value
        for name, value in run["terminal_stats"].items()
        if name == suffix or name.endswith(f".{suffix}")
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected one terminal stat ending in {suffix!r}, found {len(matches)}")
    return int(matches[0])


def stage_profile_summary(run, workload_name):
    samples = terminal_stat(run, "stage_profile_samples")
    requests = run["workloads"][workload_name]["requests"]
    interventions = terminal_stat(run, "request_interventions")
    if samples != requests or interventions != requests:
        raise RuntimeError(
            f"stage profile expected {requests} samples and interventions, got "
            f"{samples} samples and {interventions} interventions"
        )
    decode_total = terminal_stat(run, "stage_profile_decode_headers_ns")
    stages = {}
    for name, suffix in STAGE_PROFILE_METRICS:
        total = terminal_stat(run, suffix)
        stages[name] = {
            "total_ns": total,
            "ns_per_request": total / samples,
            "percent_of_decode_headers": 100 * total / decode_total if decode_total else None,
        }
    additive_names = (
        "transaction_create",
        "process_connection",
        "process_uri",
        "add_request_headers",
        "process_request_headers",
        "intervention_lookup",
        "intervention_response",
    )
    additive_total = sum(stages[name]["total_ns"] for name in additive_names)
    residual = max(0, decode_total - additive_total)
    return {
        "samples": samples,
        "intervention_lookups": terminal_stat(run, "stage_profile_intervention_lookups"),
        "intervention_lookups_per_request": terminal_stat(
            run, "stage_profile_intervention_lookups"
        )
        / samples,
        "decode_headers": {
            "total_ns": decode_total,
            "ns_per_request": decode_total / samples,
        },
        "additive_residual": {
            "total_ns": residual,
            "ns_per_request": residual / samples,
            "percent_of_decode_headers": 100 * residual / decode_total if decode_total else None,
        },
        "stages": stages,
    }


def write_phase1_profile_markdown(path, result):
    lines = [
        "# Native phase-1 block profile",
        "",
        f"Generated: {result['generated_at']}",
        "",
        f"Platform: `{result['platform']}`",
        "",
        f"Envoy: `{result['envoy_version']}`",
        "",
        f"Build profile: `{result['build_profile']}`",
        "",
        "Stage counters use monotonic nanosecond measurements and are reset after warmup. Linux perf sampling covers only the measured workload. The stage-instrumented run is diagnostic and must not be used as an engine comparison result.",
        "",
    ]
    for profile_run in result["profile_runs"]:
        workload_name = profile_run["workload"]
        stage_workload = profile_run["stage_run"]["workloads"][workload_name]
        perf_workload = profile_run["perf_run"]["workloads"][workload_name]
        stage = profile_run["stage_timing"]
        lines.extend(
            [
                f"## {workload_name}",
                "",
                f"Uninstrumented perf run: {perf_workload['requests']} requests; concurrency: {perf_workload['concurrency']}; throughput: {perf_workload['throughput_rps']:.2f} rps; p50: {perf_workload['latency_ms']['median']:.3f} ms; p99: {perf_workload['latency_ms']['p99']:.3f} ms.",
                "",
                f"Stage-instrumented run: throughput: {stage_workload['throughput_rps']:.2f} rps; p50: {stage_workload['latency_ms']['median']:.3f} ms; p99: {stage_workload['latency_ms']['p99']:.3f} ms.",
                "",
                f"decodeHeaders total: {stage['decode_headers']['ns_per_request'] / 1000:.3f} us/request; intervention lookups: {stage['intervention_lookups_per_request']:.2f}/request.",
                "",
                "### Additive request-header path",
                "",
                "| Stage | us/request | Percent of decodeHeaders |",
                "| --- | ---: | ---: |",
            ]
        )
        for name in (
            "transaction_create",
            "process_connection",
            "process_uri",
            "add_request_headers",
            "process_request_headers",
            "intervention_lookup",
            "intervention_response",
        ):
            value = stage["stages"][name]
            lines.append(
                f"| {name} | {value['ns_per_request'] / 1000:.3f} | "
                f"{value['percent_of_decode_headers']:.2f}% |"
            )
        residual = stage["additive_residual"]
        lines.append(
            f"| other filter and instrumentation overhead | {residual['ns_per_request'] / 1000:.3f} | "
            f"{residual['percent_of_decode_headers']:.2f}% |"
        )
        lines.extend(
            [
                "",
                "### Intervention-response breakdown",
                "",
                "These stages are contained within `intervention_response`; do not add them to the request-header table again.",
                "",
                "| Nested stage | us/request | Percent of decodeHeaders |",
                "| --- | ---: | ---: |",
            ]
        )
        for name in (
            "logging",
            "process_logging",
            "security_event",
            "local_reply",
            "release_resources",
        ):
            value = stage["stages"][name]
            lines.append(
                f"| {name} | {value['ns_per_request'] / 1000:.3f} | "
                f"{value['percent_of_decode_headers']:.2f}% |"
            )
        perf_data = Path(profile_run["perf_run"]["perf_data"])
        lines.extend(
            [
                "",
                "### Linux perf artifacts",
                "",
                f"- Raw samples: `{perf_data.name}`",
                f"- Self-cost report: `{perf_data.with_suffix('.self.txt').name}`",
                f"- Inclusive call graph: `{perf_data.with_suffix('.callgraph.txt').name}`",
                f"- Hardware/software counters: `{perf_data.with_suffix('.stat.txt').name}`",
            ]
        )
        for error in profile_run["perf_run"]["perf_report_errors"]:
            lines.append(f"- Report warning: {error}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_markdown(path, result):
    aggregate = result["aggregate"]
    comparisons = result["comparisons"]
    lines = [
        "# Envoy WAF engine comparison",
        "",
        f"Generated: {result['generated_at']}",
        "",
        f"Platform: `{result['platform']}`",
        "",
        f"Envoy: `{result['envoy_version']}`",
        "",
        f"Build profile: `{result['build_profile']}`",
        "",
        f"CRS commit: `{result['crs_commit']}` ({result['crs_rule_file_count']} rule files)",
        "",
        f"Versions: libmodsecurity `{result['versions']['libmodsecurity']}`, Coraza engine `{result['versions']['coraza_engine']}`, Coraza Dynamic Module release `{result['versions']['coraza_release']}`, CRS `{result['versions']['crs']}`",
        "",
        f"Coraza module SHA-256: `{result['coraza_module_sha256']}`",
        "",
        f"Repeats: {result['parameters']['repeats']}; Envoy workers: {result['parameters']['envoy_concurrency']}; request scale: {result['parameters']['request_scale']}",
        "",
        "All three modes use the same Envoy executable. Both WAFs use the same generated SecLang root file and the same local CRS files. Response inspection, audit logging, access logging, and native server logging are disabled. Results are medians across order-rotated process runs.",
        "",
        "## Steady-state results",
        "",
        "| Workload | Engine | Throughput (rps) | CPU (ms/request) | p50 (ms) | p95 (ms) | p99 (ms) |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for workload in result["workload_names"]:
        for engine in ENGINES:
            value = aggregate[engine]["workloads"][workload]
            latency = value["latency_ms"]
            lines.append(
                f"| {workload} | {engine} | {value['throughput_rps']:.2f} | "
                f"{value['envoy_cpu_ms_per_request']:.4f} | {latency['median']:.3f} | "
                f"{latency['p95']:.3f} | {latency['p99']:.3f} |"
            )
    lines.extend(
        [
            "",
            "## Native versus Coraza ratios",
            "",
            "Values above 1.0 favor native libmodsecurity for all three ratio columns.",
            "",
            "| Workload | Native/Coraza throughput | Coraza/native raw CPU | Coraza/native baseline-adjusted CPU | Coraza/native p99 |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for workload in result["workload_names"]:
        value = comparisons[workload]
        raw_cpu = value["raw_cpu_coraza_over_native"]
        adjusted_cpu = value["baseline_adjusted_cpu_coraza_over_native"]
        lines.append(
            f"| {workload} | {value['throughput_native_over_coraza']:.3f}x | "
            f"{raw_cpu:.3f}x | " if raw_cpu is not None else f"| {workload} | {value['throughput_native_over_coraza']:.3f}x | n/a | "
        )
        lines[-1] += (
            f"{adjusted_cpu:.3f}x | " if adjusted_cpu is not None else "n/a | "
        )
        lines[-1] += f"{value['p99_coraza_over_native']:.3f}x |"
    lines.extend(
        [
            "",
            "## Repeat consistency",
            "",
            "Each cell is the median paired ratio with the observed range and native-win count. Ratios above 1.0 favor native libmodsecurity.",
            "",
            "| Workload | Native/Coraza throughput | Coraza/native raw CPU | Coraza/native p99 |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for workload in result["workload_names"]:
        paired = comparisons[workload]["paired_repeat_ratios"]

        def format_ratio(value):
            if value is None:
                return "n/a"
            return (
                f"{value['median']:.3f}x [{value['minimum']:.3f}, "
                f"{value['maximum']:.3f}], {value['native_wins']}/{value['repeats']}"
            )

        lines.append(
            f"| {workload} | {format_ratio(paired['throughput_native_over_coraza'])} | "
            f"{format_ratio(paired['raw_cpu_coraza_over_native'])} | "
            f"{format_ratio(paired['p99_coraza_over_native'])} |"
        )
    lines.extend(
        [
            "",
            "## Process footprint",
            "",
            "| Engine | Startup (ms) | RSS after warmup (MiB) | RSS after suite (MiB) |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for engine in ENGINES:
        value = aggregate[engine]
        lines.append(
            f"| {engine} | {value['startup_ms']:.2f} | "
            f"{value['rss_after_warmup_bytes'] / 1048576:.2f} | "
            f"{value['rss_after_suite_bytes'] / 1048576:.2f} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            "This report validates functional parity for the selected cases and measures a specific build on the current host. Shared CI runners can have noisy CPU scheduling. Publication-grade claims still require dedicated hardware, CPU isolation, more repeated order-randomized runs, confidence intervals, broader compatibility checks, and production traffic/body distributions.",
            "",
            "The comparison includes connector and module overhead because that is what an Envoy deployment pays. It does not isolate only the regex engines. The Coraza module uses its official release build tags, while libmodsecurity uses the project's pinned native build defaults.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main():
    if ARGS.repeats < 1:
        raise ValueError("--repeats must be at least 1")
    if ARGS.request_scale <= 0:
        raise ValueError("--request-scale must be positive")
    envoy_binary = ARGS.envoy_binary.resolve()
    coraza_module = ARGS.coraza_module.resolve()
    for path, description in (
        (envoy_binary, "Envoy binary"),
        (coraza_module, "Coraza module"),
        (ARGS.config_template.resolve(), "config template"),
    ):
        if not path.is_file():
            raise RuntimeError(f"{description} is not a file: {path}")
    output_directory = ARGS.output_directory.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    upstream = Upstream(("127.0.0.1", 0), UpstreamHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    runs = []
    cases = workloads()
    if ARGS.workload:
        requested = set(ARGS.workload)
        known = {case["name"] for case in cases}
        unknown = requested - known
        if unknown:
            raise ValueError(f"unknown workload names: {sorted(unknown)}")
        cases = [case for case in cases if case["name"] in requested]
    elif ARGS.native_phase1_profile:
        cases = [case for case in cases if case["name"] == "phase1_block_c1"]
    if ARGS.native_phase1_profile:
        if platform.system() != "Linux":
            raise RuntimeError("--native-phase1-profile requires Linux")
        if ARGS.perf_binary is None:
            raise ValueError("--perf-binary is required with --native-phase1-profile")
        if ARGS.perf_frequency < 1:
            raise ValueError("--perf-frequency must be positive")
        invalid = [case["name"] for case in cases if not case["name"].startswith("phase1_block_")]
        if invalid:
            raise ValueError(f"native phase-1 profile does not accept workloads: {invalid}")
    environment = os.environ.copy()
    environment["ENVOY_DYNAMIC_MODULES_SEARCH_PATH"] = str(coraza_module.parent)
    environment["GODEBUG"] = "cgocheck=0"
    with tempfile.TemporaryDirectory(
        prefix="envoy-waf-comparison-", dir=os.environ.get("TEST_TMPDIR")
    ) as temporary_directory:
        workdir = Path(temporary_directory)
        crs_config_path, rule_files = write_common_crs_config(workdir)
        template = ARGS.config_template.resolve().read_text(encoding="utf-8")
        configs = {}
        for engine in ENGINES:
            config_path = workdir / f"bootstrap-{engine}.yaml"
            config_path.write_text(
                render_config(template, upstream.server_port, engine, crs_config_path),
                encoding="utf-8",
            )
            validation = subprocess.run(
                [str(envoy_binary), "--mode", "validate", "-c", str(config_path)],
                capture_output=True,
                check=False,
                text=True,
                timeout=STARTUP_TIMEOUT_SECONDS,
                env=environment,
            )
            if validation.returncode != 0:
                raise RuntimeError(
                    f"Envoy rejected {engine} config:\n{validation.stdout}\n{validation.stderr}"
                )
            configs[engine] = config_path
        crs_repository = ARGS.crs_rules_directory.resolve().parent
        try:
            crs_commit = command_output(["git", "-C", str(crs_repository), "rev-parse", "HEAD"])
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            crs_commit = "unknown"
        common_result = {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "platform": platform.platform(),
            "envoy_binary": str(envoy_binary),
            "envoy_version": command_output([str(envoy_binary), "--version"]),
            "build_profile": ARGS.build_profile,
            "crs_commit": crs_commit,
            "crs_rule_file_count": len(rule_files),
            "versions": {
                "libmodsecurity": ARGS.libmodsecurity_version,
                "crs": ARGS.crs_version,
            },
        }
        if ARGS.native_phase1_profile:
            profile_runs = []
            for repeat in range(ARGS.repeats):
                for case in cases:
                    print(
                        f"profile {repeat + 1}/{ARGS.repeats}: {case['name']}", flush=True
                    )
                    suffix = f"-r{repeat + 1}" if ARGS.repeats > 1 else ""
                    perf_data_path = output_directory / f"{case['name']}{suffix}.perf.data"
                    stage_run = run_engine(
                        "libmodsecurity",
                        repeat * 2,
                        configs["libmodsecurity"],
                        workdir,
                        upstream.server_port,
                        [case],
                        enable_stage_timing=True,
                    )
                    perf_run = run_engine(
                        "libmodsecurity",
                        repeat * 2 + 1,
                        configs["libmodsecurity"],
                        workdir,
                        upstream.server_port,
                        [case],
                        perf_data_path=perf_data_path,
                    )
                    profile_runs.append(
                        {
                            "workload": case["name"],
                            "stage_run": stage_run,
                            "perf_run": perf_run,
                            "stage_timing": stage_profile_summary(
                                stage_run, case["name"]
                            ),
                        }
                    )
            result = {
                **common_result,
                "perf_version": command_output([str(ARGS.perf_binary.resolve()), "version"]),
                "parameters": {
                    "repeats": ARGS.repeats,
                    "request_scale": ARGS.request_scale,
                    "envoy_concurrency": ARGS.envoy_concurrency,
                    "perf_frequency": ARGS.perf_frequency,
                },
                "profile_runs": profile_runs,
            }
        else:
            order_patterns = [
                ("baseline", "libmodsecurity", "coraza"),
                ("coraza", "baseline", "libmodsecurity"),
                ("libmodsecurity", "coraza", "baseline"),
            ]
            for repeat in range(ARGS.repeats):
                for engine in order_patterns[repeat % len(order_patterns)]:
                    print(f"repeat {repeat + 1}/{ARGS.repeats}: {engine}", flush=True)
                    runs.append(
                        run_engine(
                            engine,
                            repeat,
                            configs[engine],
                            workdir,
                            upstream.server_port,
                            cases,
                        )
                    )
            aggregate, comparisons = aggregate_results(runs, cases)
            result = {
                **common_result,
                "coraza_module": str(coraza_module),
                "coraza_module_sha256": sha256(coraza_module),
                "parameters": {
                    "repeats": ARGS.repeats,
                    "request_scale": ARGS.request_scale,
                    "envoy_concurrency": ARGS.envoy_concurrency,
                },
                "versions": {
                    **common_result["versions"],
                    "coraza_release": ARGS.coraza_release,
                    "coraza_engine": ARGS.coraza_engine_version,
                },
                "workload_names": [case["name"] for case in cases],
                "runs": runs,
                "aggregate": aggregate,
                "comparisons": comparisons,
            }
    upstream.shutdown()
    upstream.server_close()
    upstream_thread.join(timeout=5)
    stem = "waf-phase1-profile" if ARGS.native_phase1_profile else "waf-engine-comparison"
    json_path = output_directory / f"{stem}.json"
    markdown_path = output_directory / f"{stem}.md"
    json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if ARGS.native_phase1_profile:
        write_phase1_profile_markdown(markdown_path, result)
    else:
        write_markdown(markdown_path, result)
    print(markdown_path)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"WAF engine comparison failed: {error}", file=sys.stderr)
        sys.exit(2)
