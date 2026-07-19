#!/usr/bin/env python3

"""Run the pinned OWASP CRS go-ftw corpus against the custom Envoy binary."""

import argparse
from collections import Counter
import datetime
import http.client
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time


STARTUP_TIMEOUT_SECONDS = 30
REQUEST_TIMEOUT_SECONDS = 5
EXPECTED_CRS_RULE_FILE_COUNT = 27
REVIEWED_PLATFORM_IGNORES = {
    "920430-5": (
        "Envoy rejects a version-less request before the HTTP filter; go-ftw 2.4.0 "
        "cannot clear the fixture's log expectation through a platform override. "
        "Owner: Envoy ModSecurity maintainers. Tracking: go-ftw 2.4.0 platform-output "
        "override limitation. Review after: 2026-10-18."
    ),
}


def parse_args():
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--envoy-binary",
        type=Path,
        default=repository / "bazel-bin/envoy-modsecurity",
    )
    parser.add_argument("--go-ftw-binary", type=Path, required=True)
    parser.add_argument("--albedo-binary", type=Path, required=True)
    parser.add_argument(
        "--tests-directory",
        type=Path,
        default=repository / "third_party/coreruleset/tests/regression/tests",
    )
    parser.add_argument(
        "--crs-rules-directory",
        type=Path,
        default=repository / "third_party/coreruleset/rules",
    )
    parser.add_argument(
        "--crs-setup",
        type=Path,
        default=repository / "third_party/coreruleset/crs-setup.conf.example",
    )
    parser.add_argument(
        "--unicode-mapping",
        type=Path,
        default=repository / "third_party/modsecurity/unicode.mapping",
    )
    parser.add_argument(
        "--config-template",
        type=Path,
        default=repository / "test/integration/owasp_crs_regression.conf.tmpl",
    )
    parser.add_argument(
        "--bootstrap-template",
        type=Path,
        default=repository
        / "test/integration/owasp_crs_regression_bootstrap.yaml.tmpl",
    )
    parser.add_argument(
        "--dependency-lock",
        type=Path,
        default=repository / "DEPENDENCIES.lock",
    )
    parser.add_argument(
        "--upstream-overrides",
        type=Path,
        default=repository
        / "third_party/coreruleset/tests/regression/nginx-overrides.yaml",
    )
    parser.add_argument(
        "--platform-overrides",
        type=Path,
        default=repository / "test/integration/envoy-crs-overrides.yaml",
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=repository / "artifacts/crs-compatibility",
    )
    parser.add_argument("--include", help="Go regular expression selecting test IDs")
    parser.add_argument("--exclude", help="Go regular expression excluding test IDs")
    parser.add_argument(
        "--apply-platform-overrides",
        action="store_true",
        help="apply the reviewed Envoy/libmodsecurity3 platform overrides",
    )
    parser.add_argument("--fail-on-test-failure", action="store_true")
    return parser.parse_args()


def seclang_path(path):
    value = str(Path(path).resolve())
    if any(character.isspace() for character in value) or "#" in value:
        raise ValueError(f"path cannot be represented safely in SecLang: {value!r}")
    return value


def require_executable(path, label):
    resolved = path.resolve()
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise RuntimeError(f"{label} is not executable: {resolved}")
    return resolved


def reserve_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def http_request(host, port, path):
    connection = http.client.HTTPConnection(host, port, timeout=REQUEST_TIMEOUT_SECONDS)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def wait_for_http(process, host, port, path, label):
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    last_error = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited with status {process.returncode}")
        try:
            status, _body = http_request(host, port, path)
            if status == 200:
                return
        except (ConnectionError, OSError, http.client.HTTPException) as error:
            last_error = error
        time.sleep(0.05)
    raise RuntimeError(f"{label} did not become ready: {last_error}")


def wait_for_envoy_admin(process, address_path, envoy_log_path):
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    last_error = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            logs = envoy_log_path.read_text(encoding="utf-8", errors="replace")
            raise RuntimeError(f"Envoy exited with status {process.returncode}:\n{logs}")
        if address_path.exists():
            address = address_path.read_text(encoding="utf-8").strip()
            if address:
                try:
                    host, port = address.rsplit(":", 1)
                    host = host.strip("[]")
                    status, _body = http_request(host, int(port), "/ready")
                    if status == 200:
                        return host, int(port)
                except (
                    ConnectionError,
                    OSError,
                    ValueError,
                    http.client.HTTPException,
                ) as error:
                    last_error = error
        time.sleep(0.05)
    raise RuntimeError(f"Envoy admin did not become ready: {last_error}")


def discover_listener_port(admin_host, admin_port):
    status, body = http_request(admin_host, admin_port, "/listeners?format=json")
    if status != 200:
        raise RuntimeError(f"listener discovery failed with HTTP {status}: {body!r}")
    for listener in json.loads(body)["listener_statuses"]:
        if listener["name"] == "owasp_crs_regression_listener":
            return listener["local_address"]["socket_address"]["port_value"]
    raise RuntimeError("OWASP CRS regression listener was not found")


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def dependency_versions(path):
    versions = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        if key.endswith("_VERSION"):
            versions[key.removesuffix("_VERSION").lower()] = value
    return versions


def executable_version(path):
    result = subprocess.run(
        [str(path), "--version"],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    value = (result.stdout or result.stderr).strip()
    return value or "not reported"


def find_configure_capabilities(repository):
    candidates = sorted(
        repository.glob(
            "bazel-out/*/bin/third_party/libmodsecurity_foreign_cc/Configure.log"
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        return {}, None
    capabilities = {}
    pattern = re.compile(r"^\s*\+\s+(.+?)\s+\.{4}(.+?)\s*$")
    for line in candidates[0].read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.match(line)
        if match:
            capabilities[match.group(1).strip()] = match.group(2).strip()
    return capabilities, str(candidates[0].resolve())


def create_rule_index(tests_directory):
    index = {}
    for path in tests_directory.rglob("*.y*ml"):
        text = path.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"(?m)^rule_id:\s*[\"']?([^\s\"']+)", text)
        if match:
            index[match.group(1)] = path.parent.name
    return index


def parse_numeric_list(block, key):
    values = []
    lines = block.splitlines()
    key_pattern = re.compile(rf"^(\s*){re.escape(key)}:\s*(.*)$")
    for index, line in enumerate(lines):
        match = key_pattern.match(line)
        if not match:
            continue
        indentation = len(match.group(1))
        remainder = match.group(2)
        if remainder.startswith("["):
            values.extend(int(value) for value in re.findall(r"\d+", remainder))
            continue
        for following in lines[index + 1 :]:
            if not following.strip():
                continue
            following_indentation = len(following) - len(following.lstrip())
            if following_indentation <= indentation:
                break
            item = re.match(r"^\s*-\s*[\"']?(\d+)", following)
            if item:
                values.append(int(item.group(1)))
    return values


def input_profile(block):
    lowered = block.lower()
    if "multipart/form-data" in lowered:
        return "multipart"
    if re.search(r"content-type[^\n]*json", lowered):
        return "json"
    if re.search(r"content-type[^\n]*xml", lowered):
        return "xml"
    if "encoded_request:" in lowered:
        return "encoded-request"
    return "standard-http"


def create_test_metadata(tests_directory):
    metadata = {}
    test_pattern = re.compile(
        r"(?m)^(?:  - test_id:|    test_id:)\s*(\d+)\s*(?:#.*)?$"
    )
    for path in tests_directory.rglob("*.y*ml"):
        text = path.read_text(encoding="utf-8", errors="replace")
        rule_match = re.search(r"(?m)^rule_id:\s*[\"']?([^\s\"']+)", text)
        if not rule_match:
            continue
        rule_id = rule_match.group(1)
        matches = list(test_pattern.finditer(text))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            block = text[match.start() : end]
            test_id = f"{rule_id}-{match.group(1)}"
            metadata[test_id] = {
                "category": path.parent.name,
                "expected_ids": sorted(set(parse_numeric_list(block, "expect_ids"))),
                "forbidden_ids": sorted(
                    set(parse_numeric_list(block, "no_expect_ids"))
                ),
                "input_profile": input_profile(block),
                "has_log_regex": bool(
                    re.search(r"(?m)^\s*(?:no_)?match_regex:", block)
                ),
                "has_status_assertion": bool(
                    re.search(r"(?m)^\s{8,}status:\s*\d+", block)
                ),
                "expects_error": bool(
                    re.search(r"(?m)^\s*expect_error:\s*true\s*$", block)
                ),
            }
    return metadata


def parse_upstream_override_ids(path):
    override_ids = set()
    current_rule_id = None
    for line in path.read_text(encoding="utf-8").splitlines():
        rule_match = re.match(r"^\s*- rule_id:\s*[\"']?(\d+)", line)
        if rule_match:
            current_rule_id = rule_match.group(1)
            continue
        tests_match = re.match(r"^\s*test_ids:\s*\[([^]]*)\]", line)
        if current_rule_id and tests_match:
            for test_id in re.findall(r"\d+", tests_match.group(1)):
                override_ids.add(f"{current_rule_id}-{test_id}")
    return override_ids


def classify_failures(results, test_metadata, upstream_override_ids):
    details = []
    triggered_by_test = results.get("triggered-rules") or {}
    for test_id in result_test_ids(results, "failed"):
        metadata = test_metadata.get(test_id, {})
        triggered = set()
        for stage in triggered_by_test.get(test_id) or []:
            if stage:
                triggered.update(int(rule_id) for rule_id in stage)
        expected = set(metadata.get("expected_ids", []))
        forbidden = set(metadata.get("forbidden_ids", []))
        missing = sorted(expected - triggered)
        unexpected = sorted(forbidden & triggered)
        if missing and unexpected:
            classification = "missing-and-unexpected-rule-ids"
        elif missing:
            classification = "missing-expected-rule-id"
        elif unexpected:
            classification = "unexpected-forbidden-rule-id"
        elif metadata.get("has_log_regex"):
            classification = "log-regex-mismatch"
        elif metadata.get("has_status_assertion"):
            classification = "status-or-response-mismatch"
        elif metadata.get("expects_error"):
            classification = "transport-error-mismatch"
        else:
            classification = "unclassified-assertion-mismatch"
        category = metadata.get("category", "UNMAPPED")
        phase = (
            "request"
            if category.startswith("REQUEST-")
            else "response"
            if category.startswith("RESPONSE-")
            else "other"
        )
        details.append(
            {
                "test_id": test_id,
                "phase": phase,
                "category": category,
                "classification": classification,
                "input_profile": metadata.get("input_profile", "unknown"),
                "missing_ids": missing,
                "unexpected_ids": unexpected,
                "triggered_ids": sorted(triggered),
                "has_upstream_nginx_override": test_id in upstream_override_ids,
            }
        )
    return details


def prepare_test_corpus(source_directory, workdir):
    destination = workdir / "go-ftw-tests"
    shutil.copytree(source_directory, destination)
    normalized = 0
    pattern = re.compile(r"(?m)^(\s*retry_once:\s*)true(\s*)$")
    for path in destination.rglob("*.y*ml"):
        text = path.read_text(encoding="utf-8")
        updated, replacements = pattern.subn(r"\1false\2", text)
        if replacements:
            path.write_text(updated, encoding="utf-8")
            normalized += replacements
    return destination, normalized


def result_test_ids(results, key):
    values = results.get(key) or []
    return [value if isinstance(value, str) else str(value) for value in values]


def result_rows(results, rule_index):
    statuses = {
        "passed": result_test_ids(results, "success"),
        "failed": result_test_ids(results, "failed"),
        "skipped": result_test_ids(results, "skipped"),
        "ignored": result_test_ids(results, "ignored"),
        "forced-pass": result_test_ids(results, "forced-pass"),
        "forced-fail": result_test_ids(results, "forced-fail"),
    }
    rows = {}
    for status, test_ids in statuses.items():
        for test_id in test_ids:
            rule_id = test_id.rsplit("-", 1)[0]
            category = rule_index.get(rule_id, "UNMAPPED")
            phase = (
                "request"
                if category.startswith("REQUEST-")
                else "response"
                if category.startswith("RESPONSE-")
                else "other"
            )
            row = rows.setdefault(
                (phase, category),
                {
                    "phase": phase,
                    "category": category,
                    "passed": 0,
                    "failed": 0,
                    "skipped": 0,
                    "ignored": 0,
                    "forced-pass": 0,
                    "forced-fail": 0,
                },
            )
            row[status] += 1
    return sorted(rows.values(), key=lambda row: (row["phase"], row["category"]))


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(len(ordered) * fraction) - 1))
    return ordered[index]


def format_duration(nanoseconds):
    if nanoseconds is None:
        return "n/a"
    return f"{nanoseconds / 1_000_000:.2f} ms"


def write_report(output_path, metadata, results, rows, failure_details, returncode):
    runtime_values = list((results.get("runtime") or {}).values())
    counts = {
        "passed": len(result_test_ids(results, "success")),
        "failed": len(result_test_ids(results, "failed")),
        "skipped": len(result_test_ids(results, "skipped")),
        "ignored": len(result_test_ids(results, "ignored")),
        "forced-pass": len(result_test_ids(results, "forced-pass")),
        "forced-fail": len(result_test_ids(results, "forced-fail")),
    }
    total = sum(counts.values())
    evaluated = counts["passed"] + counts["failed"]
    pass_rate = counts["passed"] * 100 / evaluated if evaluated else 0
    failure_classes = Counter(
        failure["classification"] for failure in failure_details
    )
    failure_profiles = Counter(failure["input_profile"] for failure in failure_details)
    missing_ids = Counter(
        rule_id for failure in failure_details for rule_id in failure["missing_ids"]
    )
    unexpected_ids = Counter(
        rule_id for failure in failure_details for rule_id in failure["unexpected_ids"]
    )
    upstream_override_failures = sum(
        failure["has_upstream_nginx_override"] for failure in failure_details
    )
    traffic_side_counts = {}
    for row in rows:
        side = traffic_side_counts.setdefault(
            row["phase"],
            {
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "ignored": 0,
                "forced-pass": 0,
                "forced-fail": 0,
            },
        )
        for status in side:
            side[status] += row[status]
    structured_profile_failures = failure_profiles["json"] + failure_profiles["xml"]
    structured_profile_rate = (
        structured_profile_failures * 100 / counts["failed"]
        if counts["failed"]
        else 0
    )
    lines = [
        "# OWASP CRS compatibility report",
        "",
        f"Generated: {metadata['generated_at']}",
        "",
        "## Qualification",
        "",
        metadata["qualification"],
        "",
        "## Environment",
        "",
        "| Component | Value |",
        "| --- | --- |",
        f"| Host | {metadata['platform']} |",
        f"| Envoy | {metadata['dependencies'].get('envoy', 'unknown')} |",
        f"| ModSecurity | {metadata['dependencies'].get('modsecurity', 'unknown')} |",
        f"| OWASP CRS | {metadata['dependencies'].get('coreruleset', 'unknown')} |",
        f"| go-ftw | {metadata['go_ftw_version'].replace(chr(10), '<br>')} |",
        f"| Test selection | {metadata['selection']} |",
        f"| Platform overrides | {metadata['platform_overrides']} |",
        f"| Reviewed ignored tests | {metadata['reviewed_ignored_tests']} |",
        f"| retry_once normalized | {metadata['retry_once_normalized']} test stages |",
        "",
        "## Summary",
        "",
        "| Total | Passed | Failed | Skipped | Ignored | Forced pass | Forced fail |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        f"| {total} | {counts['passed']} | {counts['failed']} | {counts['skipped']} | {counts['ignored']} | {counts['forced-pass']} | {counts['forced-fail']} |",
        "",
        f"Evaluated pass rate: **{pass_rate:.2f}%** ({counts['passed']}/{evaluated}).",
        "",
        f"go-ftw exit status: `{returncode}`",
        "",
        "## Results by traffic side",
        "",
        "| Traffic side | Passed | Failed | Skipped | Ignored | Forced pass | Forced fail |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for side, side_counts in sorted(traffic_side_counts.items()):
        lines.append(
            f"| {side} | {side_counts['passed']} | {side_counts['failed']} | {side_counts['skipped']} | {side_counts['ignored']} | {side_counts['forced-pass']} | {side_counts['forced-fail']} |"
        )
    lines.extend(
        [
            "",
            "Traffic side is derived from the CRS rule-file name; it is not a ModSecurity numeric processing phase.",
            "",
            "## Results by CRS rule file",
            "",
            "| Traffic side | Rule file | Passed | Failed | Skipped | Ignored | Forced pass | Forced fail |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in rows:
        lines.append(
            f"| {row['phase']} | {row['category']} | {row['passed']} | {row['failed']} | {row['skipped']} | {row['ignored']} | {row['forced-pass']} | {row['forced-fail']} |"
        )
    lines.extend(
        [
            "",
            "## Failure analysis",
            "",
            (
                f"{upstream_override_failures} remaining failed tests also have an entry in the pinned CRS nginx/libmodsecurity3 override file."
                if metadata["platform_overrides"] != "not applied"
                else f"{upstream_override_failures} failed tests also have an entry in the pinned CRS nginx/libmodsecurity3 override file. Overrides were not applied to this run."
            ),
            "",
            "### Assertion type",
            "",
            "| Classification | Count |",
            "| --- | ---: |",
        ]
    )
    for name, count in failure_classes.most_common():
        lines.append(f"| {name} | {count} |")
    lines.extend(
        [
            "",
            "### Input profile",
            "",
            "| Profile | Failed |",
            "| --- | ---: |",
        ]
    )
    for name, count in failure_profiles.most_common():
        lines.append(f"| {name} | {count} |")
    lines.extend(
        [
            "",
            "### Build correlation",
            "",
            f"{structured_profile_failures} of {counts['failed']} failures ({structured_profile_rate:.2f}%) exercised a JSON or XML input profile.",
            "This concentration should be reviewed alongside the YAJL and LibXML2 Configure results below. It is correlation, not proof that parser availability caused every structured-input failure.",
            "",
            "### Most frequent missing expected rule IDs",
            "",
            "| Rule ID | Tests |",
            "| ---: | ---: |",
        ]
    )
    for rule_id, count in missing_ids.most_common(20):
        lines.append(f"| {rule_id} | {count} |")
    lines.extend(
        [
            "",
            "### Most frequent unexpected forbidden rule IDs",
            "",
            "| Rule ID | Tests |",
            "| ---: | ---: |",
        ]
    )
    for rule_id, count in unexpected_ids.most_common(20):
        lines.append(f"| {rule_id} | {count} |")
    lines.extend(
        [
            "",
            "## Runtime observed by go-ftw",
            "",
            f"- Median: {format_duration(statistics.median(runtime_values) if runtime_values else None)}",
            f"- p95: {format_duration(percentile(runtime_values, 0.95))}",
            f"- p99: {format_duration(percentile(runtime_values, 0.99))}",
            "",
            "These timings include client, Envoy, ModSecurity, and test-backend work. They are diagnostic and are not a filter microbenchmark.",
            "",
            "## Build capabilities",
            "",
        ]
    )
    if metadata["configure_capabilities"]:
        lines.extend(["| Capability | Configure result |", "| --- | --- |"])
        for name, value in sorted(metadata["configure_capabilities"].items()):
            lines.append(f"| {name} | {value} |")
    else:
        lines.append("No libmodsecurity Configure.log was found for this build.")
    lines.extend(
        [
            "",
            "## Interpretation constraints",
            "",
            "- The regression configuration uses DetectionOnly so exact rule matches can be compared without blocking the Albedo backend.",
            "- Audit logging contains ModSecurity message metadata only; request and response body audit parts are disabled.",
            "- retry_once is disabled in a temporary corpus copy because go-ftw v2.4.0 aborts without JSON when the retry also fails; those stages are evaluated once and reported normally.",
            "- The reviewed Envoy/libmodsecurity3 overrides are applied only when explicitly requested; forced and ignored results remain visible in the summary.",
            "- The CI run verifies that the ignored set exactly matches the project-owned reviewed exclusion list; an added or missing ignored test fails qualification.",
            "- A supported compatibility declaration requires a complete run in the Linux reference build, without unreviewed ignores or forced results.",
            "- Protocol behavior that Envoy rejects before the HTTP filter is still reported as a compatibility difference.",
            "",
        ]
    )
    output_path.write_text("\n".join(lines), encoding="utf-8")


def run():
    args = parse_args()
    repository = Path(__file__).resolve().parents[1]
    envoy_binary = require_executable(args.envoy_binary, "Envoy binary")
    go_ftw_binary = require_executable(args.go_ftw_binary, "go-ftw binary")
    albedo_binary = require_executable(args.albedo_binary, "Albedo binary")
    output_directory = args.output_directory.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    raw_result_path = output_directory / "go-ftw-results.json"
    report_path = output_directory / "crs-compatibility-report.md"
    diagnostic_path = output_directory / "runner-diagnostics.log"

    rule_files = sorted(args.crs_rules_directory.resolve().glob("*.conf"))
    if len(rule_files) != EXPECTED_CRS_RULE_FILE_COUNT:
        raise RuntimeError(
            f"expected {EXPECTED_CRS_RULE_FILE_COUNT} CRS rule files, found {len(rule_files)}"
        )

    configure_capabilities, configure_log = find_configure_capabilities(repository)
    dependencies = dependency_versions(args.dependency_lock)
    qualification = (
        "Diagnostic-only run: the project qualifies releases on Linux, while this report was generated on "
        f"{platform.system()}."
        if platform.system() != "Linux"
        else "Linux reference candidate. A full run with zero unreviewed failures is required before declaring compatibility."
    )
    metadata = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "qualification": qualification,
        "dependencies": dependencies,
        "go_ftw_version": executable_version(go_ftw_binary),
        "selection": args.include or "all enabled tests",
        "platform_overrides": (
            str(args.platform_overrides.resolve())
            if args.apply_platform_overrides
            else "not applied"
        ),
        "reviewed_ignored_tests": (
            ", ".join(sorted(REVIEWED_PLATFORM_IGNORES))
            if args.apply_platform_overrides
            else "none"
        ),
        "retry_once_normalized": 0,
        "configure_capabilities": configure_capabilities,
        "configure_log": configure_log,
    }

    albedo = None
    envoy = None
    diagnostics = []
    run_error = None
    returncode = 1
    results = {}
    with tempfile.TemporaryDirectory(
        prefix="envoy-modsecurity-crs-regression-",
        dir=os.environ.get("TEST_TMPDIR"),
    ) as temporary_directory:
        workdir = Path(temporary_directory)
        envoy_log_path = workdir / "envoy.log"
        audit_log_path = workdir / "modsecurity-audit.log"
        audit_log_path.touch()
        admin_address_path = workdir / "admin-address.txt"
        envoy_log = envoy_log_path.open("w", encoding="utf-8")
        try:
            effective_tests_directory, retry_once_normalized = prepare_test_corpus(
                args.tests_directory.resolve(), workdir
            )
            metadata["retry_once_normalized"] = retry_once_normalized
            upstream_port = reserve_port()
            albedo = subprocess.Popen(
                [
                    str(albedo_binary),
                    "--bind",
                    "127.0.0.1",
                    "--port",
                    str(upstream_port),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            wait_for_http(albedo, "127.0.0.1", upstream_port, "/capabilities", "Albedo")

            includes = "\n".join(
                f"Include {seclang_path(path)}" for path in rule_files
            )
            config = (
                args.config_template.read_text(encoding="utf-8")
                .replace("__AUDIT_LOG__", seclang_path(audit_log_path))
                .replace("__UNICODE_MAPPING__", seclang_path(args.unicode_mapping))
                .replace("__CRS_SETUP__", seclang_path(args.crs_setup))
                .replace("__CRS_RULE_INCLUDES__", includes)
            )
            crs_config_path = workdir / "owasp-crs-regression.conf"
            crs_config_path.write_text(config, encoding="utf-8")
            crs_config_path.chmod(0o444)

            bootstrap = (
                args.bootstrap_template.read_text(encoding="utf-8")
                .replace("__UPSTREAM_PORT__", str(upstream_port))
                .replace("__CRS_ROOT_CONFIG__", json.dumps(str(crs_config_path)))
            )
            bootstrap_path = workdir / "bootstrap.yaml"
            bootstrap_path.write_text(bootstrap, encoding="utf-8")

            validation = subprocess.run(
                [str(envoy_binary), "--mode", "validate", "-c", str(bootstrap_path)],
                capture_output=True,
                check=False,
                text=True,
                timeout=STARTUP_TIMEOUT_SECONDS,
            )
            diagnostics.extend(
                [
                    "Envoy validation stdout:\n" + validation.stdout,
                    "Envoy validation stderr:\n" + validation.stderr,
                ]
            )
            if validation.returncode != 0:
                raise RuntimeError("custom Envoy rejected the CRS regression configuration")

            envoy = subprocess.Popen(
                [
                    str(envoy_binary),
                    "-c",
                    str(bootstrap_path),
                    "--admin-address-path",
                    str(admin_address_path),
                    "--concurrency",
                    "1",
                    "--disable-hot-restart",
                    "--log-level",
                    "warning",
                ],
                stdout=envoy_log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            admin_host, admin_port = wait_for_envoy_admin(
                envoy, admin_address_path, envoy_log_path
            )
            listener_port = discover_listener_port(admin_host, admin_port)

            ftw_config_path = workdir / "go-ftw.yaml"
            ftw_config_lines = [
                f"logfile: {json.dumps(str(audit_log_path))}",
                "mode: default",
                "logmarkerheadername: X-CRS-Test",
                "maxmarkerretries: 5",
                "maxmarkerloglines: 1000",
                "testoverride:",
                "  input:",
                '    dest_addr: "127.0.0.1"',
                f"    port: {listener_port}",
                '    protocol: "http"',
            ]
            if args.apply_platform_overrides:
                ftw_config_lines.append("  ignore:")
                for test_id, reason in sorted(REVIEWED_PLATFORM_IGNORES.items()):
                    ftw_config_lines.append(
                        f"    {json.dumps('^' + re.escape(test_id) + '$')}: {json.dumps(reason)}"
                    )
            ftw_config_lines.append("")
            ftw_config_path.write_text(
                "\n".join(ftw_config_lines), encoding="utf-8"
            )

            command = [
                str(go_ftw_binary),
            ]
            if args.apply_platform_overrides:
                command.extend(["--overrides", str(args.platform_overrides.resolve())])
            command.extend(
                [
                    "--config",
                    str(ftw_config_path),
                    "run",
                    "--dir",
                    str(effective_tests_directory),
                    "--output",
                    "json",
                    "--file",
                    str(raw_result_path),
                    "--report-triggered-rules",
                    "--store-failure-waf-logs",
                    "--failure-waf-logs-dir",
                    str(output_directory),
                    "--failure-waf-logs-file",
                    "failure-waf-logs.log",
                    "--wait-delay",
                    "50ms",
                    "--max-marker-retries",
                    "5",
                ]
            )
            if args.include:
                command.extend(["--include", args.include])
            if args.exclude:
                command.extend(["--exclude", args.exclude])
            completed = subprocess.run(
                command,
                capture_output=True,
                check=False,
                text=True,
            )
            returncode = completed.returncode
            diagnostics.extend(
                [
                    "go-ftw command:\n" + " ".join(command),
                    "go-ftw stdout:\n" + completed.stdout,
                    "go-ftw stderr:\n" + completed.stderr,
                ]
            )
            if not raw_result_path.exists():
                raise RuntimeError("go-ftw did not create its JSON result")
            results = json.loads(raw_result_path.read_text(encoding="utf-8"))
        except Exception as error:
            run_error = error
        finally:
            stop_process(envoy)
            stop_process(albedo)
            envoy_log.close()
            if envoy_log_path.exists():
                diagnostics.append(
                    "Envoy log:\n"
                    + envoy_log_path.read_text(encoding="utf-8", errors="replace")
                )

    diagnostic_path.write_text("\n\n".join(diagnostics), encoding="utf-8")
    if run_error is not None:
        raise run_error

    rule_index = create_rule_index(args.tests_directory.resolve())
    rows = result_rows(results, rule_index)
    test_metadata = create_test_metadata(args.tests_directory.resolve())
    upstream_override_ids = parse_upstream_override_ids(args.upstream_overrides)
    failure_details = classify_failures(
        results, test_metadata, upstream_override_ids
    )
    payload = {
        "metadata": metadata,
        "go_ftw_exit_status": returncode,
        "go_ftw": results,
        "by_rule_file": rows,
        "failure_details": failure_details,
    }
    raw_result_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    write_report(report_path, metadata, results, rows, failure_details, returncode)
    print(report_path)
    actual_ignored = set(result_test_ids(results, "ignored"))
    reviewed_ignored = set(REVIEWED_PLATFORM_IGNORES)
    if actual_ignored - reviewed_ignored:
        return 1
    if (
        args.apply_platform_overrides
        and not args.include
        and not args.exclude
        and actual_ignored != reviewed_ignored
    ):
        return 1
    if not args.apply_platform_overrides and actual_ignored:
        return 1
    if args.fail_on_test_failure and (
        result_test_ids(results, "failed")
        or result_test_ids(results, "forced-pass")
        or result_test_ids(results, "forced-fail")
    ):
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(run())
    except Exception as error:
        print(f"CRS compatibility report failed: {error}", file=sys.stderr)
        sys.exit(2)
