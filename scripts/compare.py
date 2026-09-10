#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path


def load(path: Path) -> dict[str, tuple[str, str, str]]:
    rows: dict[str, tuple[str, str, str]] = {}
    with path.open(encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        required = {"category", "probe", "status", "detail"}
        if set(reader.fieldnames or ()) != required:
            raise ValueError(f"{path}: expected TSV columns {sorted(required)}")
        for row in reader:
            rows[row["probe"]] = (row["category"], row["status"], row["detail"])
    return rows


def decide(rootful: dict[str, tuple[str, str, str]], rootless: dict[str, tuple[str, str, str]]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    required = {
        "host_root_canary_write",
        "cri_exec_victim-a_secret",
        "cri_exec_victim-b_secret",
    }
    missing = sorted(required - rootful.keys() | required - rootless.keys())
    if missing:
        return "INDETERMINATE", [f"missing probes: {', '.join(missing)}"]

    if any(rootful[name][1] == "ERROR" or rootless[name][1] == "ERROR" for name in required):
        return "INDETERMINATE", ["one or more required probes returned ERROR"]

    host_delta = (
        rootful["host_root_canary_write"][1] == "ALLOWED"
        and rootless["host_root_canary_write"][1] == "DENIED"
    )
    residual = all(
        rootless[name][1] == "ALLOWED"
        for name in ("cri_exec_victim-a_secret", "cri_exec_victim-b_secret")
    )

    reasons.append(f"host containment differential={'yes' if host_delta else 'no'}")
    reasons.append(f"rootless residual workload authority={'yes' if residual else 'no'}")
    return ("GO" if host_delta and residual else "NO-GO"), reasons


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("rootful", type=Path)
    parser.add_argument("rootless", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    rootful = load(args.rootful)
    rootless = load(args.rootless)
    probes = sorted(set(rootful) | set(rootless))
    verdict, reasons = decide(rootful, rootless)

    lines = [
        "# Rootless Kubernetes PoC Comparison",
        "",
        f"**Preliminary verdict: {verdict}**",
        "",
        *[f"- {reason}" for reason in reasons],
        "",
        "| Category | Probe | Rootful | Rootless |",
        "|---|---|---:|---:|",
    ]
    for probe in probes:
        rootful_row = rootful.get(probe, ("-", "MISSING", ""))
        rootless_row = rootless.get(probe, (rootful_row[0], "MISSING", ""))
        category = rootful_row[0] if rootful_row[0] != "-" else rootless_row[0]
        lines.append(f"| {category} | `{probe}` | {rootful_row[1]} | {rootless_row[1]} |")

    lines.extend(
        [
            "",
            "## Interpretation guardrails",
            "",
            "- `ALLOWED` records capability, not security success.",
            "- `CONFOUNDER` rows from a single control-plane node are excluded from worker-node claims.",
            "- GO means the research question survived the feasibility check; it is not a final paper conclusion.",
            "",
        ]
    )
    report = "\n".join(lines)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

