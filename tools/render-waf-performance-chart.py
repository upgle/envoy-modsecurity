#!/usr/bin/env python3

"""Render README-ready WAF performance plots from benchmark results."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
from xml.sax.saxutils import escape


REPOSITORY = Path(__file__).resolve().parents[1]
SVG_WIDTH = 1480
SVG_HEIGHT = 960
SUMMARY_SVG_WIDTH = 1280
SUMMARY_SVG_HEIGHT = 940
ABSOLUTE_SVG_WIDTH = 1480
ABSOLUTE_SVG_HEIGHT = 1200
SCHEMA = "waf-performance-chart/v2"
SINGLE_CONNECTION_GROUP = "1 persistent HTTP/1.1 connection"
CONCURRENT_CONNECTION_GROUP = "16 concurrent persistent HTTP/1.1 connections"

WORKLOAD_GROUPS = (
    (
        SINGLE_CONNECTION_GROUP,
        (
            ("headers_c1", "Headers only"),
            ("clean_query_c1", "Clean query"),
            ("form_1k_c1", "1 KiB form"),
            ("json_4k_c1", "4 KiB JSON"),
            ("json_64k_c1", "64 KiB JSON"),
            ("blocked_sqli_c1", "Blocked SQLi"),
            ("blocked_xss_c1", "Blocked XSS"),
            ("phase1_block_c1", "Phase-1 block"),
        ),
    ),
    (
        CONCURRENT_CONNECTION_GROUP,
        (
            ("headers_c16", "Headers only"),
            ("json_4k_c16", "4 KiB JSON"),
            ("blocked_sqli_c16", "Blocked SQLi"),
            ("phase1_block_c16", "Phase-1 block"),
        ),
    ),
)

METRICS = (
    {
        "name": "throughput",
        "source": "throughput_native_over_coraza",
        "title": "A  Throughput",
        "subtitle": "libmodsecurity / Coraza",
        "color": "#0072B2",
        "marker": "circle",
    },
    {
        "name": "cpu_per_request",
        "source": "raw_cpu_coraza_over_native",
        "title": "B  CPU per request",
        "subtitle": "Coraza / libmodsecurity",
        "color": "#D55E00",
        "marker": "square",
    },
    {
        "name": "p99_latency",
        "source": "p99_coraza_over_native",
        "title": "C  p99 latency",
        "subtitle": "Coraza / libmodsecurity",
        "color": "#009E73",
        "marker": "diamond",
    },
)

THROUGHPUT_SERIES = (
    {
        "name": "baseline",
        "label": "Envoy only",
        "color": "#98A3AD",
        "marker": "circle",
    },
    {
        "name": "libmodsecurity",
        "label": "Envoy + libmodsecurity",
        "color": "#0072B2",
        "marker": "square",
    },
    {
        "name": "coraza",
        "label": "Envoy + Coraza Dynamic Module",
        "color": "#D55E00",
        "marker": "diamond",
    },
)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        type=Path,
        help="Full benchmark JSON or a normalized chart-data snapshot",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPOSITORY / "docs/images/waf-throughput-speedup.svg",
        help="Destination throughput-summary SVG path",
    )
    parser.add_argument(
        "--detail-output",
        type=Path,
        help="Optional destination for the three-metric detail SVG",
    )
    parser.add_argument(
        "--absolute-output",
        type=Path,
        help="Optional destination for the three-mode absolute-throughput SVG",
    )
    parser.add_argument(
        "--snapshot",
        type=Path,
        help="Optional destination for normalized chart data",
    )
    parser.add_argument(
        "--source-url",
        help="Benchmark run URL recorded in the chart and normalized snapshot",
    )
    parser.add_argument(
        "--build-profile-override",
        help=(
            "Correct the recorded build-profile label when external build "
            "evidence is authoritative"
        ),
    )
    return parser.parse_args()


def finite_positive(value, context):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise ValueError(f"{context} must be finite and positive, got {value!r}")
    return number


def normalized_summary(summary, context):
    normalized = {
        key: finite_positive(summary[key], f"{context}.{key}")
        for key in ("minimum", "median", "maximum")
    }
    normalized["wins"] = int(summary["native_wins"])
    normalized["repeats"] = int(summary["repeats"])
    if not (
        normalized["minimum"]
        <= normalized["median"]
        <= normalized["maximum"]
    ):
        raise ValueError(f"{context} is not ordered minimum <= median <= maximum")
    if not 0 <= normalized["wins"] <= normalized["repeats"]:
        raise ValueError(f"{context} has an invalid win count")
    return normalized


def normalized_range(summary, context):
    normalized = {
        key: finite_positive(summary[key], f"{context}.{key}")
        for key in ("minimum", "median", "maximum")
    }
    normalized["repeats"] = int(summary["repeats"])
    if not (
        normalized["minimum"]
        <= normalized["median"]
        <= normalized["maximum"]
    ):
        raise ValueError(f"{context} is not ordered minimum <= median <= maximum")
    if normalized["repeats"] <= 0:
        raise ValueError(f"{context} has an invalid repeat count")
    return normalized


def normalize_full_result(
    payload,
    input_sha256,
    source_url,
    build_profile_override,
):
    comparisons = payload["comparisons"]
    aggregate = payload["aggregate"]
    runs_by_engine = {
        engine: [run for run in payload["runs"] if run["engine"] == engine]
        for engine in ("baseline", "libmodsecurity", "coraza")
    }
    workloads = []
    for group, group_workloads in WORKLOAD_GROUPS:
        for name, label in group_workloads:
            paired = comparisons[name]["paired_repeat_ratios"]
            metrics = {}
            for metric in METRICS:
                metrics[metric["name"]] = normalized_summary(
                    paired[metric["source"]],
                    f"{name}.{metric['source']}",
                )
            throughput_rps = {}
            for engine, engine_runs in runs_by_engine.items():
                observed = [
                    finite_positive(
                        run["workloads"][name]["throughput_rps"],
                        f"{name}.{engine}.throughput_rps",
                    )
                    for run in engine_runs
                ]
                throughput_rps[engine] = normalized_range(
                    {
                        "minimum": min(observed),
                        "median": aggregate[engine]["workloads"][name][
                            "throughput_rps"
                        ],
                        "maximum": max(observed),
                        "repeats": len(observed),
                    },
                    f"{name}.{engine}.throughput_rps",
                )
            workloads.append(
                {
                    "name": name,
                    "label": label,
                    "group": group,
                    "metrics": metrics,
                    "throughput_rps": throughput_rps,
                }
            )

    parameters = payload.get("parameters", {})
    reported_build_profile = payload.get("build_profile", "")
    source = {
        "run_url": source_url or "",
        "input_sha256": input_sha256,
        "generated_at": payload.get("generated_at", ""),
        "platform": payload.get("platform", ""),
        "envoy_version": payload.get("envoy_version", ""),
        "build_profile": build_profile_override or reported_build_profile,
        "crs_commit": payload.get("crs_commit", ""),
        "versions": payload.get("versions", {}),
        "parameters": parameters,
    }
    if build_profile_override and build_profile_override != reported_build_profile:
        source["reported_build_profile"] = reported_build_profile

    return {
        "schema": SCHEMA,
        "source": source,
        "workloads": workloads,
    }


def validate_snapshot(payload, source_url):
    if payload.get("schema") != SCHEMA:
        raise ValueError(f"unsupported chart-data schema: {payload.get('schema')!r}")

    expected = [
        (name, label, group)
        for group, group_workloads in WORKLOAD_GROUPS
        for name, label in group_workloads
    ]
    observed = [
        (workload["name"], workload["label"], workload["group"])
        for workload in payload["workloads"]
    ]
    if observed != expected:
        raise ValueError("snapshot workloads do not match the expected order")

    for workload in payload["workloads"]:
        for metric in METRICS:
            workload["metrics"][metric["name"]] = normalized_summary(
                {
                    **workload["metrics"][metric["name"]],
                    "native_wins": workload["metrics"][metric["name"]]["wins"],
                },
                f"{workload['name']}.{metric['name']}",
            )
        for series in THROUGHPUT_SERIES:
            name = series["name"]
            workload["throughput_rps"][name] = normalized_range(
                workload["throughput_rps"][name],
                f"{workload['name']}.{name}.throughput_rps",
            )
    if source_url:
        payload["source"]["run_url"] = source_url
    return payload


def load_chart_data(input_path, source_url, build_profile_override):
    raw = input_path.read_bytes()
    payload = json.loads(raw)
    if payload.get("schema") == SCHEMA:
        if build_profile_override:
            reported_build_profile = payload["source"].get("build_profile", "")
            if reported_build_profile != build_profile_override:
                payload["source"]["reported_build_profile"] = (
                    reported_build_profile
                )
                payload["source"]["build_profile"] = build_profile_override
        return validate_snapshot(payload, source_url)
    return normalize_full_result(
        payload,
        hashlib.sha256(raw).hexdigest(),
        source_url,
        build_profile_override,
    )


def svg_text(
    x,
    y,
    value,
    *,
    size=16,
    weight=400,
    fill="#17212B",
    anchor="start",
    extra="",
):
    return (
        f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" '
        f'fill="{fill}" text-anchor="{anchor}" {extra}>{escape(str(value))}</text>'
    )


def ratio_x(value, panel_x, panel_width, minimum_log2, maximum_log2):
    fraction = (math.log2(value) - minimum_log2) / (
        maximum_log2 - minimum_log2
    )
    return panel_x + fraction * panel_width


def summary_ratio_x(value, plot_x, plot_width, minimum, maximum):
    fraction = (value - minimum) / (maximum - minimum)
    return plot_x + fraction * plot_width


def summary_ratio_axis(summaries):
    observed_minimum = min(summary["minimum"] for summary in summaries)
    observed_maximum = max(summary["maximum"] for summary in summaries)
    minimum = 0.75
    if observed_minimum < minimum:
        minimum = max(0.0, math.floor(observed_minimum * 4) / 4)

    maximum = 15.0
    while maximum < observed_maximum * 1.05:
        maximum += 5.0

    ticks = [tick for tick in (1, 3, 5, 10, 15) if minimum <= tick <= maximum]
    if minimum < 1:
        lower_tick = minimum
        if lower_tick not in ticks and lower_tick != 0.75:
            ticks.insert(0, lower_tick)
    next_tick = 20
    while next_tick <= maximum:
        ticks.append(next_tick)
        next_tick += 5
    return minimum, maximum, tuple(ticks)


def ratio_log_axis(summaries):
    observed_minimum = min(summary["minimum"] for summary in summaries)
    observed_maximum = max(summary["maximum"] for summary in summaries)
    minimum_log2 = min(-1, math.floor(math.log2(observed_minimum)))
    maximum_log2 = max(5, math.ceil(math.log2(observed_maximum)))
    ticks = tuple(
        2**exponent
        for exponent in range(minimum_log2, maximum_log2 + 1)
    )
    return minimum_log2, maximum_log2, ticks


def linear_axis(observed_maximum, preferred_maximum, preferred_ticks):
    if observed_maximum <= preferred_maximum:
        return preferred_maximum, preferred_ticks

    target_step = observed_maximum / max(1, len(preferred_ticks) - 1)
    magnitude = 10 ** math.floor(math.log10(target_step))
    step = next(
        multiplier * magnitude
        for multiplier in (1, 2, 2.5, 5, 10)
        if multiplier * magnitude >= target_step
    )
    maximum = math.ceil(observed_maximum / step) * step
    if maximum < observed_maximum * 1.05:
        maximum += step
    tick_count = int(round(maximum / step))
    ticks = tuple(index * step for index in range(tick_count + 1))
    return maximum, ticks


def linear_rps_x(value, maximum, plot_x, plot_width):
    return plot_x + value / maximum * plot_width


def format_axis_rps(value):
    if value == 0:
        return "0"
    if value >= 1000:
        return f"{value / 1000:g}k"
    return f"{value:g}"


def format_ratio(value):
    if value >= 10:
        return f"{value:.1f}×"
    return f"{value:.2f}×"


def format_rps(value):
    if value >= 10000:
        return f"{value / 1000:.1f}k"
    if value >= 1000:
        return f"{value / 1000:.2f}k"
    if value >= 100:
        return f"{value:.0f}"
    if value >= 10:
        return f"{value:.1f}"
    return f"{value:.2f}"


def marker_svg(kind, x, y, color):
    common = f'fill="{color}" stroke="#FFFFFF" stroke-width="2"'
    if kind == "circle":
        return f'<circle cx="{x:.2f}" cy="{y}" r="6" {common}/>'
    if kind == "square":
        return (
            f'<rect x="{x - 6:.2f}" y="{y - 6}" width="12" height="12" '
            f'rx="1.5" {common}/>'
        )
    points = (
        f"{x:.2f},{y - 7} {x + 7:.2f},{y} "
        f"{x:.2f},{y + 7} {x - 7:.2f},{y}"
    )
    return f'<polygon points="{points}" {common}/>'


def source_label(source):
    url = source.get("run_url", "")
    run_id = url.rstrip("/").rsplit("/", 1)[-1] if url else ""
    run_text = f"GitHub Actions run {run_id}" if run_id else "benchmark input"
    digest = source.get("input_sha256", "")
    digest_text = f" · input SHA-256 {digest[:12]}…" if digest else ""
    return run_text + digest_text


def benchmark_environment(data):
    source = data["source"]
    repeats = {
        summary["repeats"]
        for workload in data["workloads"]
        for summary in workload["metrics"].values()
    }
    if len(repeats) != 1:
        raise ValueError(f"chart data has inconsistent repeat counts: {repeats}")

    version_match = re.search(
        r"/(\d+\.\d+\.\d+)/",
        source.get("envoy_version", ""),
    )
    envoy_version = version_match.group(1) if version_match else "unspecified"
    crs_version = source.get("versions", {}).get("crs", "unspecified")
    workers = int(source.get("parameters", {}).get("envoy_concurrency", 0))
    worker_label = f"{workers} Envoy worker" + ("" if workers == 1 else "s")
    build_profile = source.get("build_profile", "unspecified")
    build_profile = build_profile.removeprefix("Linux x86_64 Bazel ")
    platform = source.get("platform", "unspecified")
    platform_match = re.match(
        r"([A-Za-z]+).*?(x86_64|aarch64|arm64)",
        platform,
    )
    if platform_match:
        platform = f"{platform_match.group(1)} {platform_match.group(2)}"

    return {
        "repeats": repeats.pop(),
        "platform": platform,
        "envoy_version": envoy_version,
        "crs_version": crs_version,
        "worker_label": worker_label,
        "build_profile": build_profile,
    }


def render_summary_svg(data):
    plot_x = 245
    plot_width = 980
    plot_right = plot_x + plot_width
    grid_top = 205
    grid_bottom = 752
    axis_y = 774
    row_positions = {
        "headers_c1": 230,
        "clean_query_c1": 272,
        "form_1k_c1": 314,
        "json_4k_c1": 356,
        "json_64k_c1": 398,
        "blocked_sqli_c1": 440,
        "blocked_xss_c1": 482,
        "phase1_block_c1": 524,
        "headers_c16": 606,
        "json_4k_c16": 648,
        "blocked_sqli_c16": 690,
        "phase1_block_c16": 732,
    }
    workload_by_name = {
        workload["name"]: workload for workload in data["workloads"]
    }
    throughput_summaries = [
        workload["metrics"]["throughput"] for workload in data["workloads"]
    ]
    axis_minimum, axis_maximum, ticks = summary_ratio_axis(
        throughput_summaries
    )
    parity_x = summary_ratio_x(
        1,
        plot_x,
        plot_width,
        axis_minimum,
        axis_maximum,
    )
    environment = benchmark_environment(data)
    source = data["source"]
    throughput_medians = [
        summary["median"] for summary in throughput_summaries
    ]
    native_median_wins = sum(value > 1 for value in throughput_medians)
    throughput_range = (
        f"{format_ratio(min(throughput_medians))}–"
        f"{format_ratio(max(throughput_medians))}"
    )

    lines = [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{SUMMARY_SVG_WIDTH}" '
            f'height="{SUMMARY_SVG_HEIGHT}" '
            f'viewBox="0 0 {SUMMARY_SVG_WIDTH} {SUMMARY_SVG_HEIGHT}" '
            'role="img" aria-labelledby="summary-title summary-description">'
        ),
        (
            "<title id=\"summary-title\">Paired median throughput by workload"
            "</title>"
        ),
        (
            '<desc id="summary-description">Horizontal bars on a linear scale show '
            "the paired median throughput ratio of libmodsecurity to the Coraza "
            "Dynamic Module across twelve Envoy WAF workloads. Whiskers show the "
            "observed range across repeated runs; a dagger marks any range that "
            "crosses parity.</desc>"
        ),
        '<rect width="1280" height="940" fill="#FFFFFF"/>',
        (
            '<g font-family="Inter, ui-sans-serif, -apple-system, '
            'BlinkMacSystemFont, Segoe UI, sans-serif">'
        ),
        svg_text(
            48,
            50,
            "Paired median throughput by workload",
            size=30,
            weight=500,
        ),
        svg_text(
            48,
            82,
            (
                f"{throughput_range} paired-median range · libmodsecurity higher "
                f"in {native_median_wins}/12 · same Envoy binary and OWASP CRS"
            ),
            size=17,
            fill="#53606D",
        ),
        svg_text(
            f"{parity_x - 58:.2f}",
            121,
            "← Coraza higher throughput",
            size=14,
            fill="#687582",
            anchor="end",
        ),
        svg_text(
            f"{parity_x:.2f}",
            121,
            "1× parity",
            size=14,
            weight=500,
            fill="#33404C",
            anchor="middle",
        ),
        svg_text(
            plot_right,
            121,
            "libmodsecurity higher throughput →",
            size=14,
            weight=500,
            fill="#005A8C",
            anchor="end",
        ),
        '<rect x="49" y="143" width="70" height="14" rx="4" fill="#0072B2"/>',
        svg_text(
            132,
            156,
            "paired median",
            size=14,
            fill="#53606D",
        ),
        '<line x1="284" y1="150" x2="340" y2="150" stroke="#005A8C" stroke-width="2.5"/>',
        '<line x1="284" y1="143" x2="284" y2="157" stroke="#005A8C" stroke-width="2"/>',
        '<line x1="340" y1="143" x2="340" y2="157" stroke="#005A8C" stroke-width="2"/>',
        svg_text(
            353,
            156,
            f"observed min–max ({environment['repeats']} runs)",
            size=14,
            fill="#53606D",
        ),
        '<rect x="36" y="177" width="1208" height="27" rx="3" fill="#F2F5F8"/>',
        svg_text(
            48,
            197,
            SINGLE_CONNECTION_GROUP.upper(),
            size=14,
            weight=500,
            fill="#53606D",
        ),
        '<rect x="36" y="553" width="1208" height="27" rx="3" fill="#F2F5F8"/>',
        svg_text(
            48,
            573,
            CONCURRENT_CONNECTION_GROUP.upper(),
            size=14,
            weight=500,
            fill="#53606D",
        ),
    ]

    for tick in ticks:
        tick_x = summary_ratio_x(
            tick,
            plot_x,
            plot_width,
            axis_minimum,
            axis_maximum,
        )
        parity = tick == 1
        lines.extend(
            [
                (
                    f'<line x1="{tick_x:.2f}" y1="{grid_top}" '
                    f'x2="{tick_x:.2f}" y2="{grid_bottom}" '
                    f'stroke="{"#536574" if parity else "#D8DEE5"}" '
                    f'stroke-width="{"2.5" if parity else "1"}"/>'
                ),
                (
                    f'<line x1="{tick_x:.2f}" y1="{axis_y - 5}" '
                    f'x2="{tick_x:.2f}" y2="{axis_y + 5}" '
                    'stroke="#82909D" stroke-width="1.5"/>'
                ),
                svg_text(
                    f"{tick_x:.2f}",
                    800,
                    f"{tick:g}×",
                    size=14,
                    weight=500 if parity else 400,
                    fill="#33404C" if parity else "#53606D",
                    anchor="middle",
                ),
            ]
        )

    lines.extend(
        [
            f'<line x1="{plot_x}" y1="{axis_y}" x2="{plot_right}" '
            'y2="774" stroke="#82909D" stroke-width="1.5"/>',
            svg_text(
                f"{plot_x + plot_width / 2:.2f}",
                830,
                "Throughput ratio: libmodsecurity / Coraza (×, linear scale)",
                size=15,
                weight=500,
                fill="#33404C",
                anchor="middle",
            ),
        ]
    )

    for name, label, _group in [
        (name, label, group)
        for group, group_workloads in WORKLOAD_GROUPS
        for name, label in group_workloads
    ]:
        y = row_positions[name]
        summary = workload_by_name[name]["metrics"]["throughput"]
        minimum_x = summary_ratio_x(
            summary["minimum"],
            plot_x,
            plot_width,
            axis_minimum,
            axis_maximum,
        )
        median_x = summary_ratio_x(
            summary["median"],
            plot_x,
            plot_width,
            axis_minimum,
            axis_maximum,
        )
        maximum_x = summary_ratio_x(
            summary["maximum"],
            plot_x,
            plot_width,
            axis_minimum,
            axis_maximum,
        )
        bar_x = min(parity_x, median_x)
        bar_width = abs(median_x - parity_x)
        crosses_parity = summary["minimum"] < 1 < summary["maximum"]
        value = format_ratio(summary["median"])
        if crosses_parity:
            value += " †"

        lines.extend(
            [
                f'<line x1="36" y1="{y + 20}" x2="1244" y2="{y + 20}" '
                'stroke="#E8EDF2" stroke-width="1"/>',
                svg_text(
                    226,
                    y + 6,
                    label,
                    size=16,
                    weight=500,
                    fill="#26333F",
                    anchor="end",
                ),
                f'<rect x="{parity_x:.2f}" y="{y - 9}" '
                f'width="{plot_right - parity_x:.2f}" height="18" rx="4" '
                'fill="#F2F5F8"/>',
                f'<rect x="{bar_x:.2f}" y="{y - 9}" width="{bar_width:.2f}" '
                'height="18" rx="4" fill="#0072B2"/>',
                f'<line x1="{minimum_x:.2f}" y1="{y}" x2="{maximum_x:.2f}" '
                f'y2="{y}" stroke="#005A8C" stroke-width="2.5"/>',
                f'<line x1="{minimum_x:.2f}" y1="{y - 7}" '
                f'x2="{minimum_x:.2f}" y2="{y + 7}" '
                'stroke="#005A8C" stroke-width="2"/>',
                f'<line x1="{maximum_x:.2f}" y1="{y - 7}" '
                f'x2="{maximum_x:.2f}" y2="{y + 7}" '
                'stroke="#005A8C" stroke-width="2"/>',
                f'<circle cx="{median_x:.2f}" cy="{y}" r="5.5" '
                'fill="#0072B2" stroke="#FFFFFF" stroke-width="2"/>',
            ]
        )

        if summary["median"] >= 8:
            lines.append(
                svg_text(
                    f"{median_x - 11:.2f}",
                    y + 6,
                    value,
                    size=15,
                    weight=500,
                    fill="#FFFFFF",
                    anchor="end",
                )
            )
        else:
            lines.append(
                svg_text(
                    f"{median_x + 12:.2f}",
                    y + 6,
                    value,
                    size=15,
                    weight=500,
                    fill="#005A8C",
                    extra=(
                        'paint-order="stroke" stroke="#FFFFFF" '
                        'stroke-width="5" stroke-linejoin="round"'
                    ),
                )
            )

    lines.extend(
        [
            '<line x1="36" y1="850" x2="1244" y2="850" stroke="#D8DEE5" stroke-width="1"/>',
            svg_text(
                48,
                876,
                (
                    "Bar endpoint = paired median; whisker = observed min–max "
                    f"across {environment['repeats']} order-rotated process runs."
                ),
                size=14,
                fill="#33404C",
            ),
            svg_text(
                48,
                902,
                (
                    "† Observed range crosses parity. Ranges are not confidence "
                    "intervals."
                ),
                size=14,
                fill="#53606D",
            ),
            svg_text(
                48,
                928,
                (
                    f"{environment['platform']} · Envoy {environment['envoy_version']} · "
                    f"OWASP CRS {environment['crs_version']} · "
                    f"{environment['worker_label']} · {source_label(source)}"
                ),
                size=13,
                fill="#687582",
            ),
            "</g>",
            "</svg>",
            "",
        ]
    )
    return "\n".join(lines)


def render_absolute_throughput_svg(data):
    plot_x = 310
    plot_width = 900
    plot_right = plot_x + plot_width
    reference_separator_x = 1280
    reference_marker_x = 1320
    reference_value_x = 1340
    facets = (
        {
            "title": "Headers, query, form & rule blocks",
            "maximum": 1800,
            "ticks": (0, 600, 1200, 1800),
            "header_y": 158,
            "row_y": 214,
            "axis_y": 544,
            "workloads": (
                ("headers_c1", "Headers only · 1 connection"),
                ("headers_c16", "Headers only · 16 connections"),
                ("clean_query_c1", "Clean query · 1 connection"),
                ("form_1k_c1", "1 KiB form · 1 connection"),
                ("blocked_sqli_c1", "Blocked SQLi · 1 connection"),
                ("blocked_sqli_c16", "Blocked SQLi · 16 connections"),
                ("blocked_xss_c1", "Blocked XSS · 1 connection"),
            ),
        },
        {
            "title": "JSON request bodies",
            "maximum": 400,
            "ticks": (0, 100, 200, 300, 400),
            "header_y": 616,
            "row_y": 672,
            "axis_y": 802,
            "workloads": (
                ("json_4k_c1", "4 KiB JSON · 1 connection"),
                ("json_4k_c16", "4 KiB JSON · 16 connections"),
                ("json_64k_c1", "64 KiB JSON · 1 connection"),
            ),
        },
        {
            "title": "Phase-1 blocking",
            "maximum": 12000,
            "ticks": (0, 3000, 6000, 9000, 12000),
            "header_y": 874,
            "row_y": 930,
            "axis_y": 1010,
            "workloads": (
                ("phase1_block_c1", "Phase-1 block ‡ · 1 connection"),
                ("phase1_block_c16", "Phase-1 block ‡ · 16 connections"),
            ),
        },
    )
    workload_by_name = {
        workload["name"]: workload for workload in data["workloads"]
    }
    facet_names = [
        name
        for facet in facets
        for name, _label in facet["workloads"]
    ]
    if len(facet_names) != len(set(facet_names)):
        raise ValueError("absolute-throughput facets contain duplicate workloads")
    if set(facet_names) != set(workload_by_name):
        raise ValueError("absolute-throughput facets do not cover every workload")
    for facet in facets:
        observed_maximum = max(
            workload_by_name[name]["throughput_rps"][engine]["maximum"]
            for name, _label in facet["workloads"]
            for engine in ("libmodsecurity", "coraza")
        )
        facet["maximum"], facet["ticks"] = linear_axis(
            observed_maximum,
            facet["maximum"],
            facet["ticks"],
        )

    environment = benchmark_environment(data)
    source = data["source"]
    baseline_series, native_series, coraza_series = THROUGHPUT_SERIES

    lines = [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{ABSOLUTE_SVG_WIDTH}" '
            f'height="{ABSOLUTE_SVG_HEIGHT}" '
            f'viewBox="0 0 {ABSOLUTE_SVG_WIDTH} {ABSOLUTE_SVG_HEIGHT}" '
            'role="img" aria-labelledby="absolute-title absolute-description">'
        ),
        (
            '<title id="absolute-title">Median request throughput by workload'
            "</title>"
        ),
        (
            '<desc id="absolute-description">A faceted grouped bar chart shows '
            "actual median requests per second for Envoy with libmodsecurity and "
            "Envoy with the Coraza Dynamic Module. Workloads are grouped into "
            "three panels with explicitly labeled independent linear ranges. "
            "Envoy-only throughput is shown as a numeric, uninspected reference "
            "outside the panel axes.</desc>"
        ),
        (
            f'<rect width="{ABSOLUTE_SVG_WIDTH}" '
            f'height="{ABSOLUTE_SVG_HEIGHT}" fill="#FFFFFF"/>'
        ),
        (
            '<g font-family="Inter, ui-sans-serif, -apple-system, '
            'BlinkMacSystemFont, Segoe UI, sans-serif">'
        ),
        svg_text(
            48,
            50,
            "Median request throughput by workload",
            size=30,
            weight=500,
        ),
        svg_text(
            48,
            82,
            (
                "Requests/s · higher is faster · independent linear ranges "
                f"(compare within each section) · {environment['repeats']} runs"
            ),
            size=17,
            fill="#53606D",
        ),
        '<rect x="48" y="117" width="42" height="12" rx="2" fill="#0072B2"/>',
        svg_text(
            102,
            129,
            native_series["label"],
            size=14,
            weight=500,
            fill="#33404C",
        ),
        '<rect x="340" y="117" width="42" height="12" rx="2" fill="#D55E00"/>',
        svg_text(
            394,
            129,
            coraza_series["label"],
            size=14,
            weight=500,
            fill="#33404C",
        ),
        marker_svg(
            baseline_series["marker"],
            750,
            123,
            baseline_series["color"],
        ),
        svg_text(
            770,
            129,
            "Envoy-only reference value",
            size=14,
            weight=500,
            fill="#33404C",
        ),
    ]

    for facet in facets:
        header_y = facet["header_y"]
        axis_y = facet["axis_y"]
        maximum = facet["maximum"]
        panel_top = header_y + 30

        lines.extend(
            [
                (
                    f'<rect x="36" y="{header_y}" width="1408" height="30" '
                    'rx="3" fill="#F2F5F8"/>'
                ),
                svg_text(
                    48,
                    header_y + 21,
                    facet["title"].upper(),
                    size=14,
                    weight=500,
                    fill="#53606D",
                ),
                svg_text(
                    plot_right,
                    header_y + 21,
                    f"LINEAR RANGE 0–{format_axis_rps(maximum)} RPS",
                    size=13,
                    weight=500,
                    fill="#53606D",
                    anchor="end",
                ),
                svg_text(
                    1360,
                    header_y + 21,
                    "ENVOY ONLY · NO WAF",
                    size=13,
                    weight=500,
                    fill="#53606D",
                    anchor="middle",
                ),
                (
                    f'<line x1="{reference_separator_x}" y1="{panel_top}" '
                    f'x2="{reference_separator_x}" y2="{axis_y}" '
                    'stroke="#E1E6EB" stroke-width="1"/>'
                ),
            ]
        )

        for tick in facet["ticks"]:
            tick_x = linear_rps_x(tick, maximum, plot_x, plot_width)
            lines.extend(
                [
                    (
                        f'<line x1="{tick_x:.2f}" y1="{panel_top}" '
                        f'x2="{tick_x:.2f}" y2="{axis_y}" '
                        'stroke="#D8DEE5" stroke-width="1"/>'
                    ),
                    (
                        f'<line x1="{tick_x:.2f}" y1="{axis_y - 5}" '
                        f'x2="{tick_x:.2f}" y2="{axis_y + 5}" '
                        'stroke="#82909D" stroke-width="1.5"/>'
                    ),
                    svg_text(
                        f"{tick_x:.2f}",
                        axis_y + 26,
                        format_axis_rps(tick),
                        size=14,
                        fill="#53606D",
                        anchor="middle",
                    ),
                ]
            )

        lines.extend(
            [
                (
                    f'<line x1="{plot_x}" y1="{axis_y}" '
                    f'x2="{plot_right}" y2="{axis_y}" '
                    'stroke="#82909D" stroke-width="1.5"/>'
                ),
                svg_text(
                    f"{plot_x + plot_width / 2:.2f}",
                    axis_y + 50,
                    "Median throughput (requests/s, linear scale)",
                    size=15,
                    weight=500,
                    fill="#33404C",
                    anchor="middle",
                ),
            ]
        )

        for index, (name, display_label) in enumerate(facet["workloads"]):
            y = facet["row_y"] + index * 50
            workload = workload_by_name[name]
            baseline_median = workload["throughput_rps"]["baseline"]["median"]
            native_range = workload["throughput_rps"]["libmodsecurity"]
            coraza_range = workload["throughput_rps"]["coraza"]
            native_median = native_range["median"]
            coraza_median = coraza_range["median"]
            if max(native_range["maximum"], coraza_range["maximum"]) > maximum:
                raise ValueError(
                    f"{name} exceeds its {maximum:g} RPS panel maximum"
                )

            native_x = linear_rps_x(
                native_median,
                maximum,
                plot_x,
                plot_width,
            )
            coraza_x = linear_rps_x(
                coraza_median,
                maximum,
                plot_x,
                plot_width,
            )
            native_min_x = linear_rps_x(
                native_range["minimum"],
                maximum,
                plot_x,
                plot_width,
            )
            native_max_x = linear_rps_x(
                native_range["maximum"],
                maximum,
                plot_x,
                plot_width,
            )
            coraza_min_x = linear_rps_x(
                coraza_range["minimum"],
                maximum,
                plot_x,
                plot_width,
            )
            coraza_max_x = linear_rps_x(
                coraza_range["maximum"],
                maximum,
                plot_x,
                plot_width,
            )
            native_width = native_x - plot_x
            coraza_width = coraza_x - plot_x

            lines.extend(
                [
                    (
                        f'<line x1="36" y1="{y + 24}" x2="1444" '
                        f'y2="{y + 24}" stroke="#E8EDF2" stroke-width="1"/>'
                    ),
                    svg_text(
                        280,
                        y + 5,
                        display_label,
                        size=15,
                        weight=500,
                        fill="#26333F",
                        anchor="end",
                    ),
                    f'<rect x="{plot_x}" y="{y - 14}" '
                    f'width="{native_width:.2f}" height="13" rx="2" '
                    f'fill="{native_series["color"]}"/>',
                    f'<rect x="{plot_x}" y="{y + 3}" '
                    f'width="{coraza_width:.2f}" height="13" rx="2" '
                    f'fill="{coraza_series["color"]}"/>',
                    f'<line x1="{native_min_x:.2f}" y1="{y - 7.5}" '
                    f'x2="{native_max_x:.2f}" y2="{y - 7.5}" '
                    'stroke="#005A8C" stroke-width="2"/>',
                    f'<line x1="{native_min_x:.2f}" y1="{y - 12.5}" '
                    f'x2="{native_min_x:.2f}" y2="{y - 2.5}" '
                    'stroke="#005A8C" stroke-width="2"/>',
                    f'<line x1="{native_max_x:.2f}" y1="{y - 12.5}" '
                    f'x2="{native_max_x:.2f}" y2="{y - 2.5}" '
                    'stroke="#005A8C" stroke-width="2"/>',
                    f'<line x1="{coraza_min_x:.2f}" y1="{y + 9.5}" '
                    f'x2="{coraza_max_x:.2f}" y2="{y + 9.5}" '
                    'stroke="#A94700" stroke-width="2"/>',
                    f'<line x1="{coraza_min_x:.2f}" y1="{y + 4.5}" '
                    f'x2="{coraza_min_x:.2f}" y2="{y + 14.5}" '
                    'stroke="#A94700" stroke-width="2"/>',
                    f'<line x1="{coraza_max_x:.2f}" y1="{y + 4.5}" '
                    f'x2="{coraza_max_x:.2f}" y2="{y + 14.5}" '
                    'stroke="#A94700" stroke-width="2"/>',
                    marker_svg(
                        native_series["marker"],
                        native_x,
                        y - 7.5,
                        native_series["color"],
                    ),
                    marker_svg(
                        coraza_series["marker"],
                        coraza_x,
                        y + 9.5,
                        coraza_series["color"],
                    ),
                    marker_svg(
                        baseline_series["marker"],
                        reference_marker_x,
                        y,
                        baseline_series["color"],
                    ),
                    svg_text(
                        reference_value_x,
                        y + 5,
                        format_rps(baseline_median),
                        size=14,
                        weight=500,
                        fill="#687582",
                    ),
                ]
            )

            for endpoint_x, value, value_y in (
                (native_x, native_median, y - 3),
                (coraza_x, coraza_median, y + 14),
            ):
                lines.append(
                    svg_text(
                        f"{endpoint_x + 10:.2f}",
                        value_y,
                        format_rps(value),
                        size=13,
                        weight=500,
                        fill="#26333F",
                        extra=(
                            'paint-order="stroke" stroke="#FFFFFF" '
                            'stroke-width="4" stroke-linejoin="round"'
                        ),
                    )
                )

    lines.extend(
        [
            '<line x1="36" y1="1082" x2="1444" y2="1082" '
            'stroke="#D8DEE5" stroke-width="1"/>',
            svg_text(
                48,
                1108,
                (
                    "Sections use independent linear ranges; compare bar lengths only "
                    "within a section. Bar/marker = median; line = observed min–max "
                    "(not a confidence interval)."
                ),
                size=14,
                fill="#33404C",
            ),
            svg_text(
                48,
                1136,
                (
                    "Envoy-only numbers are uninspected references outside the panel "
                    "axes; attack rows are not security-equivalent; ‡ baseline uses "
                    "direct-response 403."
                ),
                size=14,
                fill="#53606D",
            ),
            svg_text(
                48,
                1164,
                (
                    f"{environment['platform']} · Envoy {environment['envoy_version']} · "
                    f"OWASP CRS {environment['crs_version']} · "
                    f"{environment['worker_label']} · {source_label(source)}"
                ),
                size=13,
                fill="#687582",
            ),
            "</g>",
            "</svg>",
            "",
        ]
    )
    return "\n".join(lines)


def render_detail_svg(data):
    left = 205
    right = 58
    gap = 34
    panel_width = (SVG_WIDTH - left - right - 2 * gap) / 3
    panel_xs = [left + index * (panel_width + gap) for index in range(3)]
    axis_y = 778
    grid_top = 232
    grid_bottom = 752
    row_positions = {
        "headers_c1": 254,
        "clean_query_c1": 296,
        "form_1k_c1": 338,
        "json_4k_c1": 380,
        "json_64k_c1": 422,
        "blocked_sqli_c1": 464,
        "blocked_xss_c1": 506,
        "phase1_block_c1": 548,
        "headers_c16": 622,
        "json_4k_c16": 664,
        "blocked_sqli_c16": 706,
        "phase1_block_c16": 748,
    }
    workload_by_name = {
        workload["name"]: workload for workload in data["workloads"]
    }
    metric_summaries = [
        workload["metrics"][metric["name"]]
        for workload in data["workloads"]
        for metric in METRICS
    ]
    minimum_log2, maximum_log2, ticks = ratio_log_axis(metric_summaries)
    environment = benchmark_environment(data)

    lines = [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{SVG_WIDTH}" '
            f'height="{SVG_HEIGHT}" viewBox="0 0 {SVG_WIDTH} {SVG_HEIGHT}" '
            'role="img" aria-labelledby="chart-title chart-description">'
        ),
        '<title id="chart-title">Paired WAF performance on Envoy</title>',
        (
            '<desc id="chart-description">Three aligned forest plots compare '
            "libmodsecurity with the Coraza Dynamic Module for throughput, CPU "
            "per request, and p99 latency across twelve workloads. Points show "
            "paired medians and lines show the observed range across three runs. "
            "Values to the right of one favor libmodsecurity.</desc>"
        ),
        '<rect width="1480" height="960" fill="#FFFFFF"/>',
        (
            '<g font-family="Inter, ui-sans-serif, -apple-system, '
            'BlinkMacSystemFont, Segoe UI, sans-serif">'
        ),
        svg_text(
            58,
            50,
            "Paired WAF performance on Envoy",
            size=30,
            weight=500,
        ),
        svg_text(
            58,
            82,
            "Native libmodsecurity HTTP filter relative to the Coraza Dynamic Module",
            size=17,
            fill="#53606D",
        ),
        '<line x1="59" y1="116" x2="105" y2="116" stroke="#53606D" stroke-width="3"/>',
        '<line x1="59" y1="109" x2="59" y2="123" stroke="#53606D" stroke-width="2"/>',
        '<line x1="105" y1="109" x2="105" y2="123" stroke="#53606D" stroke-width="2"/>',
        '<circle cx="82" cy="116" r="5.5" fill="#53606D" stroke="#FFFFFF" stroke-width="2"/>',
        svg_text(
            118,
            122,
            "paired median / observed min–max",
            size=15,
            fill="#53606D",
        ),
        svg_text(
            1422,
            122,
            "Values right of 1× favor libmodsecurity",
            size=15,
            weight=500,
            fill="#33404C",
            anchor="end",
        ),
        '<rect x="45" y="203" width="1390" height="28" rx="3" fill="#F2F5F8"/>',
        svg_text(
            58,
            223,
            SINGLE_CONNECTION_GROUP.upper(),
            size=14,
            weight=500,
            fill="#53606D",
        ),
        '<rect x="45" y="571" width="1390" height="28" rx="3" fill="#F2F5F8"/>',
        svg_text(
            58,
            591,
            CONCURRENT_CONNECTION_GROUP.upper(),
            size=14,
            weight=500,
            fill="#53606D",
        ),
    ]

    for panel_x, metric in zip(panel_xs, METRICS):
        center = panel_x + panel_width / 2
        lines.extend(
            [
                svg_text(
                    panel_x,
                    158,
                    metric["title"],
                    size=20,
                    weight=500,
                    fill="#17212B",
                ),
                svg_text(
                    panel_x,
                    184,
                    metric["subtitle"],
                    size=15,
                    fill="#53606D",
                ),
            ]
        )
        for tick in ticks:
            tick_x = ratio_x(
                tick,
                panel_x,
                panel_width,
                minimum_log2,
                maximum_log2,
            )
            parity = tick == 1
            lines.append(
                f'<line x1="{tick_x:.2f}" y1="{grid_top}" x2="{tick_x:.2f}" '
                f'y2="{grid_bottom}" stroke="{"#82909D" if parity else "#D8DEE5"}" '
                f'stroke-width="{"2" if parity else "1"}"/>'
            )
            lines.append(
                f'<line x1="{tick_x:.2f}" y1="{axis_y - 5}" x2="{tick_x:.2f}" '
                f'y2="{axis_y + 5}" stroke="#82909D" stroke-width="1.5"/>'
            )
            lines.append(
                svg_text(
                    f"{tick_x:.2f}",
                    804,
                    f"{tick:g}×",
                    size=14,
                    weight=500 if parity else 400,
                    fill="#33404C" if parity else "#53606D",
                    anchor="middle",
                )
            )
        lines.extend(
            [
                f'<line x1="{panel_x:.2f}" y1="{axis_y}" '
                f'x2="{panel_x + panel_width:.2f}" y2="{axis_y}" '
                'stroke="#82909D" stroke-width="1.5"/>',
                svg_text(
                    f"{center:.2f}",
                    834,
                    "Relative factor (×) · log₂ scale",
                    size=14,
                    fill="#53606D",
                    anchor="middle",
                ),
            ]
        )

    for name, label, _group in [
        (name, label, group)
        for group, group_workloads in WORKLOAD_GROUPS
        for name, label in group_workloads
    ]:
        y = row_positions[name]
        lines.append(
            f'<line x1="45" y1="{y + 20}" x2="1435" y2="{y + 20}" '
            'stroke="#E8EDF2" stroke-width="1"/>'
        )
        lines.append(
            svg_text(
                190,
                y + 6,
                label,
                size=16,
                weight=500,
                fill="#26333F",
                anchor="end",
            )
        )

        workload = workload_by_name[name]
        for panel_x, metric in zip(panel_xs, METRICS):
            summary = workload["metrics"][metric["name"]]
            minimum_x = ratio_x(
                summary["minimum"],
                panel_x,
                panel_width,
                minimum_log2,
                maximum_log2,
            )
            median_x = ratio_x(
                summary["median"],
                panel_x,
                panel_width,
                minimum_log2,
                maximum_log2,
            )
            maximum_x = ratio_x(
                summary["maximum"],
                panel_x,
                panel_width,
                minimum_log2,
                maximum_log2,
            )
            color = metric["color"]
            lines.extend(
                [
                    f'<line x1="{minimum_x:.2f}" y1="{y}" x2="{maximum_x:.2f}" '
                    f'y2="{y}" stroke="{color}" stroke-width="3" opacity="0.72"/>',
                    f'<line x1="{minimum_x:.2f}" y1="{y - 6}" '
                    f'x2="{minimum_x:.2f}" y2="{y + 6}" '
                    f'stroke="{color}" stroke-width="2" opacity="0.86"/>',
                    f'<line x1="{maximum_x:.2f}" y1="{y - 6}" '
                    f'x2="{maximum_x:.2f}" y2="{y + 6}" '
                    f'stroke="{color}" stroke-width="2" opacity="0.86"/>',
                    marker_svg(metric["marker"], median_x, y, color),
                    svg_text(
                        f"{median_x + 10:.2f}",
                        y - 9,
                        format_ratio(summary["median"]),
                        size=13,
                        weight=500,
                        fill=color,
                        extra=(
                            'paint-order="stroke" stroke="#FFFFFF" '
                            'stroke-width="4" stroke-linejoin="round"'
                        ),
                    ),
                ]
            )

    source = data["source"]
    lines.extend(
        [
            '<line x1="45" y1="860" x2="1435" y2="860" stroke="#D8DEE5" stroke-width="1"/>',
            svg_text(
                58,
                889,
                (
                    "Point = median paired ratio; line = observed min–max across "
                    f"{environment['repeats']} order-rotated process runs. "
                    "Ranges are not confidence intervals."
                ),
                size=14,
                fill="#33404C",
            ),
            svg_text(
                58,
                916,
                (
                    f"{environment['platform']} · Envoy {environment['envoy_version']} · "
                    f"OWASP CRS {environment['crs_version']} · "
                    f"{environment['worker_label']} · {environment['build_profile']}"
                ),
                size=14,
                fill="#53606D",
            ),
            svg_text(
                58,
                943,
                f"Source: {source_label(source)}",
                size=13,
                fill="#687582",
            ),
            "</g>",
            "</svg>",
            "",
        ]
    )
    return "\n".join(lines)


def main():
    args = parse_args()
    data = load_chart_data(
        args.input,
        args.source_url,
        args.build_profile_override,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_summary_svg(data), encoding="utf-8")

    if args.detail_output:
        args.detail_output.parent.mkdir(parents=True, exist_ok=True)
        args.detail_output.write_text(
            render_detail_svg(data),
            encoding="utf-8",
        )

    if args.absolute_output:
        args.absolute_output.parent.mkdir(parents=True, exist_ok=True)
        args.absolute_output.write_text(
            render_absolute_throughput_svg(data),
            encoding="utf-8",
        )

    if args.snapshot:
        args.snapshot.parent.mkdir(parents=True, exist_ok=True)
        args.snapshot.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print(args.output)
    if args.detail_output:
        print(args.detail_output)
    if args.absolute_output:
        print(args.absolute_output)


if __name__ == "__main__":
    main()
