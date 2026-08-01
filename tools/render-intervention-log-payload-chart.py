#!/usr/bin/env python3

"""Render a reader-friendly throughput chart from the Envoy A/B result."""

import argparse
import json
import math
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
SCHEMA = "intervention-log-payload-chart/v1"
WORKLOADS = (
    {
        "name": "phase1_block_c1",
        "panel": "primary",
        "label": "1 concurrent connection",
    },
    {
        "name": "phase1_block_c16",
        "panel": "primary",
        "label": "16 concurrent connections",
    },
    {
        "name": "blocked_sqli_c16",
        "panel": "checks",
        "label": "CRS SQLi block · 16 connections",
    },
    {
        "name": "headers_c16",
        "panel": "checks",
        "label": "Headers only · 16 connections",
    },
)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Raw intervention A/B benchmark JSON")
    parser.add_argument(
        "--output",
        action="append",
        type=Path,
        help=(
            "Destination .svg or .png path; may be repeated. Defaults to the "
            "README-ready SVG under docs/images."
        ),
    )
    parser.add_argument(
        "--snapshot",
        type=Path,
        help="Optional destination for normalized chart data",
    )
    parser.add_argument("--source-url", help="Benchmark run URL recorded in the snapshot")
    parser.add_argument(
        "--artifact-digest",
        help="Source Actions artifact digest recorded in the snapshot",
    )
    return parser.parse_args()


def finite_positive(value, context):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise ValueError(f"{context} must be finite and positive, got {value!r}")
    return number


def workload_summary(payload, workload):
    name = workload["name"]
    aggregate = payload["aggregate"]
    comparison = payload["comparisons"][name]["throughput_candidate_over_baseline"]
    interval = comparison["bootstrap_95_ci"]
    baseline = finite_positive(
        aggregate["baseline"]["workloads"][name]["throughput_rps"],
        f"{name}.baseline.throughput_rps",
    )
    candidate = finite_positive(
        aggregate["candidate"]["workloads"][name]["throughput_rps"],
        f"{name}.candidate.throughput_rps",
    )
    ratio = finite_positive(comparison["median"], f"{name}.paired.median")
    minimum = finite_positive(interval["minimum"], f"{name}.paired.minimum")
    maximum = finite_positive(interval["maximum"], f"{name}.paired.maximum")
    if not minimum <= ratio <= maximum:
        raise ValueError(f"{name} paired interval does not contain its median")
    return {
        **workload,
        "baseline": baseline,
        "candidate": candidate,
        "change": (ratio - 1.0) * 100.0,
        "change_minimum": (minimum - 1.0) * 100.0,
        "change_maximum": (maximum - 1.0) * 100.0,
        "wins": int(comparison["candidate_wins"]),
        "blocks": int(comparison["crossover_blocks"]),
    }


def validate_snapshot(payload):
    if payload.get("schema") != SCHEMA:
        raise ValueError(f"unsupported chart-data schema: {payload.get('schema')!r}")
    expected_names = [workload["name"] for workload in WORKLOADS]
    observed_names = [workload["name"] for workload in payload["workloads"]]
    if observed_names != expected_names:
        raise ValueError("snapshot workloads do not match the expected order")
    for workload in payload["workloads"]:
        for key in ("baseline", "candidate"):
            workload[key] = finite_positive(workload[key], f"{workload['name']}.{key}")
        if not workload["change_minimum"] <= workload["change"] <= workload["change_maximum"]:
            raise ValueError(f"{workload['name']} change interval does not contain its median")
    return payload


def load_chart_data(input_path, source_url=None, artifact_digest=None):
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    if payload.get("schema") == SCHEMA:
        snapshot = validate_snapshot(payload)
        if source_url:
            snapshot["source"]["run_url"] = source_url
        if artifact_digest:
            snapshot["source"]["artifact_digest"] = artifact_digest
        return snapshot
    summaries = [workload_summary(payload, workload) for workload in WORKLOADS]
    return {
        "schema": SCHEMA,
        "source": {
            "run_url": source_url or "",
            "artifact_digest": artifact_digest or "",
            "baseline_revision": payload["revisions"]["baseline"],
            "candidate_revision": payload["revisions"]["candidate"],
        },
        "generated_at": payload["generated_at"],
        "build_profile": payload["build_profile"],
        "repeats": int(payload["parameters"]["repeats"]),
        "crossover_blocks": summaries[0]["blocks"],
        "workloads": summaries,
    }


def effect_label(workload):
    change = workload["change"]
    lower = workload["change_minimum"]
    upper = workload["change_maximum"]
    prefix = "+" if change >= 0 else ""
    lower_prefix = "+" if lower >= 0 else ""
    upper_prefix = "+" if upper >= 0 else ""
    estimate = (
        f"{prefix}{change:.1f}% "
        f"[{lower_prefix}{lower:.1f}%, {upper_prefix}{upper:.1f}%]"
    )
    if lower > 0:
        interpretation = f"{workload['wins']}/{workload['blocks']} blocks improved"
    elif upper < 0:
        interpretation = f"{workload['wins']}/{workload['blocks']} blocks improved"
    else:
        interpretation = "no clear change"
    return estimate, interpretation


def render(data, outputs):
    try:
        import matplotlib.pyplot as plt
        from matplotlib.ticker import FuncFormatter
    except ImportError as error:
        raise SystemExit(
            "Matplotlib is required to render this chart; install matplotlib==3.10.5"
        ) from error

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10.5,
            "axes.titlesize": 12,
            "axes.titleweight": "semibold",
            "axes.labelsize": 10.5,
            "axes.edgecolor": "#5B6570",
            "axes.linewidth": 0.8,
            "xtick.color": "#3E4852",
            "ytick.color": "#202932",
            "text.color": "#202932",
            "svg.fonttype": "none",
            "svg.hashsalt": "envoy-modsecurity-intervention-log-payload-ab-v1",
        }
    )

    figure, axes = plt.subplots(2, 1, figsize=(13.6, 8.4))
    figure.patch.set_facecolor("white")
    figure.subplots_adjust(left=0.25, right=0.68, top=0.78, bottom=0.16, hspace=0.62)

    baseline_color = "#9AA3AB"
    candidate_color = "#0072B2"
    grid_color = "#D8DDE2"
    muted_color = "#626D77"
    panel_specs = (
        (
            axes[0],
            "primary",
            "Primary workload: immediate phase-1 deny",
            10_500,
            [0, 2_500, 5_000, 7_500, 10_000],
        ),
        (
            axes[1],
            "checks",
            "End-to-end checks (separate linear scale)",
            1_600,
            [0, 400, 800, 1_200, 1_600],
        ),
    )

    for axis, panel, title, maximum, ticks in panel_specs:
        rows = [workload for workload in data["workloads"] if workload["panel"] == panel]
        y_positions = list(reversed(range(len(rows))))
        bar_height = 0.30
        for index, (row, y_position) in enumerate(zip(rows, y_positions)):
            baseline_bar = axis.barh(
                y_position + bar_height / 1.8,
                row["baseline"],
                height=bar_height,
                color=baseline_color,
                label="Current behavior" if index == 0 and panel == "primary" else None,
                zorder=2,
            )
            candidate_bar = axis.barh(
                y_position - bar_height / 1.8,
                row["candidate"],
                height=bar_height,
                color=candidate_color,
                label=(
                    "Unused payload disabled via new API"
                    if index == 0 and panel == "primary"
                    else None
                ),
                zorder=2,
            )
            for bar, value in (
                (baseline_bar[0], row["baseline"]),
                (candidate_bar[0], row["candidate"]),
            ):
                axis.text(
                    bar.get_width() + maximum * 0.012,
                    bar.get_y() + bar.get_height() / 2,
                    f"{value:,.0f}",
                    ha="left",
                    va="center",
                    fontsize=9.5,
                    color="#303A44",
                    clip_on=False,
                )

            estimate, interpretation = effect_label(row)
            clear = row["change_minimum"] > 0 or row["change_maximum"] < 0
            axis.text(
                1.18,
                y_position + 0.08,
                estimate,
                transform=axis.get_yaxis_transform(),
                ha="left",
                va="center",
                fontsize=10.5,
                fontweight="semibold" if clear else "normal",
                color="#202932" if clear else muted_color,
                clip_on=False,
            )
            axis.text(
                1.18,
                y_position - 0.18,
                interpretation,
                transform=axis.get_yaxis_transform(),
                ha="left",
                va="center",
                fontsize=9.5,
                color=muted_color,
                clip_on=False,
            )

        axis.set_title(title, loc="left", pad=13)
        axis.set_xlim(0, maximum)
        axis.set_xticks(ticks)
        axis.xaxis.set_major_formatter(FuncFormatter(lambda value, _position: f"{value:,.0f}"))
        axis.set_xlabel("Median throughput (requests/s, linear scale)", labelpad=8)
        axis.set_yticks(y_positions, [row["label"] for row in rows])
        axis.tick_params(axis="y", length=0, pad=10)
        axis.grid(axis="x", color=grid_color, linewidth=0.8, zorder=0)
        axis.spines[["top", "right", "left"]].set_visible(False)
        axis.text(
            1.18,
            len(rows) - 0.53,
            "Paired throughput change\n[95% interval]",
            transform=axis.get_yaxis_transform(),
            ha="left",
            va="bottom",
            fontsize=9.5,
            color=muted_color,
            clip_on=False,
        )

    handles, labels = axes[0].get_legend_handles_labels()
    figure.legend(
        handles,
        labels,
        loc="upper left",
        bbox_to_anchor=(0.25, 0.845),
        ncol=2,
        frameon=False,
        handlelength=1.8,
        columnspacing=2.2,
    )
    figure.suptitle(
        "Disabling the unused intervention log payload improves phase-1 blocking throughput",
        x=0.06,
        y=0.955,
        ha="left",
        fontsize=17,
        fontweight="semibold",
    )
    figure.text(
        0.06,
        0.908,
        (
            "End-to-end Envoy A/B benchmark · Linux release ThinLTO · "
            f"{data['repeats']} alternating runs ({data['crossover_blocks']} crossover blocks)"
        ),
        ha="left",
        fontsize=10.5,
        color=muted_color,
    )
    figure.text(
        0.06,
        0.075,
        (
            "Bars show medians across runs. Paired estimates use crossover-block ratios and a "
            "deterministic 95% block-bootstrap interval. An interval crossing 0% is not conclusive."
        ),
        ha="left",
        fontsize=9.2,
        color=muted_color,
    )
    figure.text(
        0.06,
        0.045,
        (
            "One GitHub-hosted runner; intervals describe within-run block variation, not "
            "cross-host uncertainty. Higher throughput is better."
        ),
        ha="left",
        fontsize=9.2,
        color=muted_color,
    )

    for output in outputs:
        suffix = output.suffix.lower()
        if suffix not in {".svg", ".png"}:
            raise ValueError(f"unsupported chart output format: {output}")
        output.parent.mkdir(parents=True, exist_ok=True)
        figure.savefig(
            output,
            dpi=180 if suffix == ".png" else None,
            facecolor="white",
            bbox_inches="tight",
            metadata=(
                {
                    "Date": None,
                    "Creator": "Matplotlib 3.10.5",
                    "Title": "Intervention log payload Envoy A/B throughput",
                    "Description": (
                        "Grouped linear bars compare current behavior with disabling the "
                        "unused intervention log payload across four Envoy workloads."
                    ),
                }
                if suffix == ".svg"
                else {"Software": "Matplotlib 3.10.5"}
            ),
        )
    plt.close(figure)


def main():
    arguments = parse_args()
    outputs = arguments.output or [
        REPOSITORY / "docs/images/intervention-log-payload-ab-throughput.svg"
    ]
    data = load_chart_data(
        arguments.input,
        source_url=arguments.source_url,
        artifact_digest=arguments.artifact_digest,
    )
    if arguments.snapshot:
        arguments.snapshot.parent.mkdir(parents=True, exist_ok=True)
        arguments.snapshot.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    render(data, outputs)


if __name__ == "__main__":
    main()
