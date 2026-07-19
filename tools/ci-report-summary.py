#!/usr/bin/env python3

"""Build a GitHub Actions QA summary from the generated Markdown reports."""

import argparse
import json
from pathlib import Path
import shutil


REPORTS = {
    "crs": (
        "OWASP CRS compatibility",
        Path("crs-compatibility-linux-amd64/crs-compatibility-report.md"),
        "crs-compatibility-report.md",
    ),
    "qualification": (
        "Qualification benchmark",
        Path("qualification-benchmark/qualification-benchmark.md"),
        "qualification-benchmark-report.md",
    ),
    "body_pressure": (
        "Body-pressure stress",
        Path("body-pressure-stress/qualification-benchmark.md"),
        "body-pressure-stress-report.md",
    ),
}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts-directory", type=Path, default=Path("artifacts"))
    parser.add_argument(
        "--summary-output",
        type=Path,
        default=Path("artifacts/ci-report-summary/qa-summary.md"),
    )
    parser.add_argument(
        "--preview-directory",
        type=Path,
        default=Path("artifacts/ci-report-previews"),
    )
    return parser.parse_args()


def markdown_without_title(markdown):
    lines = markdown.splitlines()
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
        while lines and not lines[0].strip():
            lines.pop(0)
    return "\n".join(lines).rstrip()


def markdown_section(markdown, heading):
    lines = markdown.splitlines()
    selected = []
    in_section = False
    for line in lines:
        if line == heading:
            in_section = True
            continue
        if in_section and line.startswith("## "):
            break
        if in_section:
            selected.append(line)
    while selected and not selected[0].strip():
        selected.pop(0)
    return "\n".join(selected).rstrip()


def workflow_data(value):
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def workflow_property(value):
    return workflow_data(value).replace(":", "%3A").replace(",", "%2C")


def emit_annotation(level, title, message):
    print(
        f"::{level} title={workflow_property(title)}::{workflow_data(message)}",
        flush=True,
    )


def benchmark_annotations(json_path, title, level=None):
    if not json_path.is_file():
        return
    try:
        result = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        emit_annotation("warning", title, f"Unable to read benchmark JSON: {error}")
        return
    annotation_level = level or ("error" if result.get("enforced") else "warning")
    for violation in result.get("violations", []):
        emit_annotation(annotation_level, title, violation)


def qualification_markdown(artifacts_directory):
    qualification_directory = artifacts_directory / "qualification-benchmark"
    canonical_report = qualification_directory / "qualification-benchmark.md"
    attempt_directories = [
        qualification_directory / "attempt-1",
        qualification_directory / "attempt-2",
    ]

    if attempt_directories[1].is_dir():
        lines = []
        complete_attempts = 0
        for number, attempt_directory in enumerate(attempt_directories, start=1):
            report_path = attempt_directory / "qualification-benchmark.md"
            lines.extend([f"### Attempt {number}", ""])
            if report_path.is_file():
                complete_attempts += 1
                lines.extend(
                    [
                        markdown_without_title(
                            report_path.read_text(encoding="utf-8")
                        ),
                        "",
                    ]
                )
            else:
                lines.extend(
                    [
                        "> This attempt did not produce a report because it ended with a "
                        "functional or runtime error.",
                        "",
                    ]
                )
        rendered = "\n".join(lines).rstrip()
        preview = "# Qualification benchmark attempts\n\n" + rendered + "\n"
        status = (
            "Available (2 attempts)"
            if complete_attempts == 2
            else "Available (retry incomplete)"
        )
        return rendered, preview, status

    if canonical_report.is_file():
        markdown = canonical_report.read_text(encoding="utf-8")
        return markdown_without_title(markdown), markdown, "Available"

    first_attempt = attempt_directories[0] / "qualification-benchmark.md"
    if first_attempt.is_file():
        rendered = "### Attempt 1\n\n" + markdown_without_title(
            first_attempt.read_text(encoding="utf-8")
        )
        preview = "# Qualification benchmark attempts\n\n" + rendered + "\n"
        return rendered, preview, "Available (incomplete retry)"

    return None, None, "Not produced"


def qualification_annotations(artifacts_directory):
    qualification_directory = artifacts_directory / "qualification-benchmark"
    second_attempt = qualification_directory / "attempt-2"
    if second_attempt.is_dir():
        benchmark_annotations(
            qualification_directory / "attempt-1/qualification-benchmark.json",
            "Qualification benchmark attempt 1",
            level="warning",
        )
        benchmark_annotations(
            second_attempt / "qualification-benchmark.json",
            "Qualification benchmark attempt 2",
        )
        return
    benchmark_annotations(
        qualification_directory / "qualification-benchmark.json",
        "Qualification benchmark threshold",
    )


def build_summary(artifacts_directory, preview_directory):
    lines = [
        "# QA report preview",
        "",
        "Reports generated by the Linux QA job are rendered below. Full JSON and diagnostic "
        "output remain available as workflow artifacts.",
        "",
    ]
    availability = []
    preview_directory.mkdir(parents=True, exist_ok=True)

    for key, (title, relative_path, preview_name) in REPORTS.items():
        if key == "qualification":
            lines.extend([f"## {title}", ""])
            rendered, preview, status = qualification_markdown(artifacts_directory)
            if rendered is None:
                lines.extend(
                    [
                        "> This report was not produced. An earlier QA stage may have failed or "
                        "the stage may not have started.",
                        "",
                    ]
                )
            else:
                lines.extend([rendered, ""])
                (preview_directory / preview_name).write_text(
                    preview, encoding="utf-8"
                )
            availability.append((title, status))
            continue

        report_path = artifacts_directory / relative_path
        lines.extend([f"## {title}", ""])
        if not report_path.is_file():
            lines.extend(
                [
                    "> This report was not produced. An earlier QA stage may have failed or "
                    "the stage may not have started.",
                    "",
                ]
            )
            availability.append((title, "Not produced"))
            continue

        markdown = report_path.read_text(encoding="utf-8")
        if key == "crs":
            rendered = markdown_section(markdown, "## Summary")
        else:
            rendered = markdown_without_title(markdown)
        lines.extend([rendered or "> The report contained no renderable summary.", ""])
        shutil.copyfile(report_path, preview_directory / preview_name)
        availability.append((title, "Available"))

    lines.extend(
        [
            "## Report availability",
            "",
            "| Report | Status |",
            "| --- | --- |",
        ]
    )
    lines.extend(f"| {title} | {status} |" for title, status in availability)
    lines.append("")
    return "\n".join(lines)


def main():
    args = parse_args()
    summary = build_summary(args.artifacts_directory, args.preview_directory)
    args.summary_output.parent.mkdir(parents=True, exist_ok=True)
    args.summary_output.write_text(summary, encoding="utf-8")

    qualification_annotations(args.artifacts_directory)
    benchmark_annotations(
        args.artifacts_directory / "body-pressure-stress/qualification-benchmark.json",
        "Body-pressure diagnostic threshold",
    )


if __name__ == "__main__":
    main()
