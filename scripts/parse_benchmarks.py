#!/usr/bin/env python3
"""Parse benchmark logs and optionally compare against a baseline.

The script scans `*-benchmark.log` files for lines that look like metrics
(e.g. "Average time: 0.123 ms per operation", "Operations per second: 4567"),
builds a JSON summary, and compares it to a previous baseline. If any metric
regresses beyond the configured threshold, the script exits with a non-zero
status.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


METRIC_RE = re.compile(
    r"^\s*[-*]\s*(?P<name>[^:]+?):\s*(?P<value>[0-9]+(?:\.[0-9]+)?)(?:\s*(?P<unit>.+?))?\s*$"
)


def is_time_metric(unit: str | None) -> bool:
    if not unit:
        return False
    unit_lower = unit.lower()
    return any(
        token in unit_lower
        for token in ("ms per operation", "ms per verification", "ms", "seconds")
    )


def is_throughput_metric(unit: str | None) -> bool:
    if not unit:
        return False
    unit_lower = unit.lower()
    return any(
        token in unit_lower
        for token in ("ops/sec", "verifications/sec", "mb/s", "kb/s", "throughput")
    )


def is_size_metric(unit: str | None) -> bool:
    if not unit:
        return False
    unit_lower = unit.lower()
    return "bytes" in unit_lower


def metric_direction(unit: str | None, name: str) -> str:
    name_lower = name.lower()
    if is_time_metric(unit) or is_size_metric(unit) or "time" in name_lower:
        return "lower_is_better"
    if (
        is_throughput_metric(unit)
        or "per second" in name_lower
        or "throughput" in name_lower
    ):
        return "higher_is_better"
    return "lower_is_better"


def parse_logs(log_files: list[Path]) -> dict[str, dict[str, Any]]:
    current_section = ""
    metrics: dict[str, dict[str, Any]] = {}

    for log_file in log_files:
        with log_file.open("r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue

                # Section headings end with a colon and are not metric lines.
                if line.endswith(":") and not line.startswith("-") and not line.startswith("*"):
                    current_section = line.rstrip(":").strip()
                    continue

                match = METRIC_RE.match(line)
                if not match:
                    continue

                raw_name = match.group("name").strip()
                value = float(match.group("value"))
                unit = (match.group("unit") or "").strip() or "count"

                # Build a unique, descriptive name.
                name = f"{current_section}: {raw_name}" if current_section else raw_name
                # Disambiguate identical names with the source file.
                key = f"{log_file.stem}: {name}"

                metrics[key] = {
                    "name": name,
                    "unit": unit,
                    "value": value,
                    "direction": metric_direction(unit, name),
                }

    return metrics


def compare_to_baseline(
    current: dict[str, dict[str, Any]],
    baseline: dict[str, dict[str, Any]],
    threshold: float,
) -> list[str]:
    regressions: list[str] = []
    for key, current_metric in current.items():
        baseline_metric = baseline.get(key)
        if not baseline_metric:
            continue

        current_value = current_metric["value"]
        baseline_value = baseline_metric["value"]
        direction = current_metric["direction"]

        if direction == "lower_is_better":
            limit = baseline_value * (1.0 + threshold)
            if current_value > limit:
                regressions.append(
                    f"{key} regressed: {current_value:.4f} > {limit:.4f} "
                    f"({current_metric['unit']})"
                )
        else:
            limit = baseline_value * (1.0 - threshold)
            if current_value < limit:
                regressions.append(
                    f"{key} regressed: {current_value:.4f} < {limit:.4f} "
                    f"({current_metric['unit']})"
                )

    return regressions


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse benchmark logs.")
    parser.add_argument("logs", nargs="+", type=Path, help="Benchmark log files")
    parser.add_argument(
        "--baseline", type=Path, help="Existing baseline JSON to compare against"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="Where to write the current summary JSON"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.30,
        help="Regression threshold (e.g. 0.30 for 30%%)",
    )
    args = parser.parse_args()

    current = parse_logs(args.logs)
    output_data = {
        "metrics": current,
        "count": len(current),
    }

    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(output_data, fh, indent=2)

    print(f"Parsed {len(current)} metrics from {len(args.logs)} log file(s).")

    if args.baseline and args.baseline.exists():
        with args.baseline.open("r", encoding="utf-8") as fh:
            baseline_data = json.load(fh)
        baseline = baseline_data.get("metrics", {})
        regressions = compare_to_baseline(current, baseline, args.threshold)
        if regressions:
            print("Benchmark regressions detected:")
            for regression in regressions:
                print(f"  - {regression}")
            return 1
        print("No significant benchmark regressions detected.")
    else:
        print("No baseline found; current summary saved as new baseline.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
