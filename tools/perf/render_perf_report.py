#!/usr/bin/env python3
import csv
import html
import json
import math
import statistics
import sys
from pathlib import Path


COUNTERS = [
    "knock_seen",
    "knock_valid",
    "unknown_user",
    "key_mismatch",
    "replay_drop",
    "knock_rate_drop",
    "session_limit_drop",
    "protected_drop",
    "protected_pass",
    "map_update_fail",
]


def read_csv(path):
    if not path.exists():
        return []
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def as_float(row, key, default=0.0):
    try:
        return float(row.get(key, default) or default)
    except ValueError:
        return default


def as_int(row, key, default=0):
    try:
        return int(float(row.get(key, default) or default))
    except ValueError:
        return default


def group_by(rows, key):
    groups = {}
    for row in rows:
        groups.setdefault(row.get(key, ""), []).append(row)
    return groups


def svg_bar(path, title, labels, values, ylabel):
    width = 980
    height = 420
    left = 80
    bottom = 80
    top = 48
    right = 24
    plot_w = width - left - right
    plot_h = height - top - bottom
    max_v = max(values) if values else 1.0
    if max_v <= 0:
        max_v = 1.0
    bar_w = plot_w / max(len(values), 1)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width / 2:.1f}" y="28" text-anchor="middle" font-family="sans-serif" font-size="18">{html.escape(title)}</text>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{height - bottom}" stroke="#222"/>',
        f'<line x1="{left}" y1="{height - bottom}" x2="{width - right}" y2="{height - bottom}" stroke="#222"/>',
        f'<text x="18" y="{top + plot_h / 2:.1f}" transform="rotate(-90 18 {top + plot_h / 2:.1f})" text-anchor="middle" font-family="sans-serif" font-size="12">{html.escape(ylabel)}</text>',
    ]
    for i in range(5):
        y = top + plot_h - (plot_h * i / 4)
        value = max_v * i / 4
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" stroke="#e5e7eb"/>')
        parts.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" font-family="monospace" font-size="11">{value:.0f}</text>')
    for idx, (label, value) in enumerate(zip(labels, values)):
        x = left + idx * bar_w + bar_w * 0.16
        h = (value / max_v) * plot_h
        y = top + plot_h - h
        w = max(bar_w * 0.68, 2)
        parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" fill="#2563eb"/>')
        parts.append(f'<text x="{x + w / 2:.1f}" y="{y - 5:.1f}" text-anchor="middle" font-family="monospace" font-size="10">{value:.0f}</text>')
        safe = html.escape(label)
        parts.append(f'<text x="{x + w / 2:.1f}" y="{height - bottom + 18}" text-anchor="end" transform="rotate(-35 {x + w / 2:.1f} {height - bottom + 18})" font-family="sans-serif" font-size="11">{safe}</text>')
    parts.append("</svg>")
    path.write_text("\n".join(parts) + "\n")


def svg_line(path, title, rows, y_keys):
    width = 980
    height = 420
    left = 80
    bottom = 64
    top = 48
    right = 140
    plot_w = width - left - right
    plot_h = height - top - bottom
    if not rows:
        path.write_text("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"980\" height=\"120\"><text x=\"20\" y=\"60\">No data</text></svg>\n")
        return
    xs = list(range(len(rows)))
    max_y = max([as_float(row, key) for row in rows for key in y_keys] + [1.0])
    colors = ["#2563eb", "#dc2626", "#059669", "#d97706", "#7c3aed"]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width / 2:.1f}" y="28" text-anchor="middle" font-family="sans-serif" font-size="18">{html.escape(title)}</text>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{height - bottom}" stroke="#222"/>',
        f'<line x1="{left}" y1="{height - bottom}" x2="{width - right}" y2="{height - bottom}" stroke="#222"/>',
    ]
    for i in range(5):
        y = top + plot_h - (plot_h * i / 4)
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" stroke="#e5e7eb"/>')
        parts.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" font-family="monospace" font-size="11">{max_y * i / 4:.0f}</text>')
    for ki, key in enumerate(y_keys):
        points = []
        for x_idx, row in zip(xs, rows):
            x = left + (plot_w * x_idx / max(len(rows) - 1, 1))
            y = top + plot_h - ((as_float(row, key) / max_y) * plot_h)
            points.append(f"{x:.1f},{y:.1f}")
        color = colors[ki % len(colors)]
        parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="2" points="{" ".join(points)}"/>')
        parts.append(f'<rect x="{width - right + 18}" y="{top + ki * 22}" width="12" height="12" fill="{color}"/>')
        parts.append(f'<text x="{width - right + 36}" y="{top + 11 + ki * 22}" font-family="sans-serif" font-size="12">{html.escape(key)}</text>')
    parts.append("</svg>")
    path.write_text("\n".join(parts) + "\n")


def markdown_table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def main():
    if len(sys.argv) != 2:
        print("usage: render_perf_report.py <run-dir>", file=sys.stderr)
        return 2
    run_dir = Path(sys.argv[1])
    results = read_csv(run_dir / "results.csv")
    samples = read_csv(run_dir / "stats_timeseries.csv")
    env = {}
    env_path = run_dir / "environment.json"
    if env_path.exists():
        env = json.loads(env_path.read_text())

    groups = group_by(results, "scenario")
    summary_rows = []
    labels = []
    med_pps = []
    cpu_labels = []
    cpu_per_mpps = []
    for scenario, rows in groups.items():
        pps_values = [as_float(row, "pps") for row in rows if row.get("status") == "ok"]
        if not pps_values:
            pps_values = [as_float(row, "pps") for row in rows]
        median = statistics.median(pps_values) if pps_values else 0.0
        stdev = statistics.pstdev(pps_values) if len(pps_values) > 1 else 0.0
        labels.append(scenario)
        med_pps.append(median)
        task_clock = statistics.median([as_float(row, "perf_task_clock_ms") for row in rows])
        if median > 0 and task_clock > 0:
            cpu_labels.append(scenario)
            cpu_per_mpps.append(task_clock / (median / 1000000.0))
        summary_rows.append([
            scenario,
            len(rows),
            f"{median:.0f}",
            f"{min(pps_values) if pps_values else 0:.0f}",
            f"{max(pps_values) if pps_values else 0:.0f}",
            f"{stdev:.0f}",
            ",".join(sorted(set(row.get("status", "") for row in rows))),
        ])

    svg_bar(run_dir / "pps_by_scenario.svg", "Median PPS by Scenario", labels, med_pps, "PPS")
    svg_bar(run_dir / "pps_trials.svg", "PPS by Trial", [f"{r.get('scenario')}#{r.get('trial')}" for r in results], [as_float(r, "pps") for r in results], "PPS")
    svg_bar(run_dir / "cpu_per_mpps.svg", "Task Clock per MPPS", cpu_labels, cpu_per_mpps, "ms per MPPS")
    svg_bar(run_dir / "drop_vs_pass_pps.svg", "Drop and Pass Scenario PPS", [l for l in labels if "drop" in l or "pass" in l], [v for l, v in zip(labels, med_pps) if "drop" in l or "pass" in l], "PPS")
    svg_bar(run_dir / "session_pressure_pps.svg", "Session Pressure PPS", [l for l in labels if "session" in l or "authorized" in l], [v for l, v in zip(labels, med_pps) if "session" in l or "authorized" in l], "PPS")
    svg_bar(run_dir / "user_scale_pps.svg", "User Scale PPS", [l for l in labels if "user_scale" in l], [v for l, v in zip(labels, med_pps) if "user_scale" in l], "PPS")

    counter_rows = []
    for scenario, rows in groups.items():
        for counter in COUNTERS:
            total = sum(as_int(row, f"delta_{counter}") for row in rows)
            if total:
                counter_rows.append([f"{scenario}:{counter}", total])
    svg_bar(run_dir / "xdp_counter_deltas.svg", "XDP Counter Deltas", [r[0] for r in counter_rows], [r[1] for r in counter_rows], "count")
    svg_line(run_dir / "timeseries_pps_and_drops.svg", "Stats Timeseries", samples, ["protected_drop", "protected_pass", "knock_seen", "knock_rate_drop"])

    report = [
        "# XDP Performance Report",
        "",
        f"Run directory: `{run_dir}`",
        "",
        "## Environment",
        "",
        markdown_table(["Field", "Value"], [[k, f"`{v}`"] for k, v in sorted(env.items())]),
        "",
        "## Results Summary",
        "",
        markdown_table(["Scenario", "Trials", "Median PPS", "Min PPS", "Max PPS", "Stddev", "Status"], summary_rows),
        "",
        "## Graphs",
        "",
        "- [Median PPS by scenario](pps_by_scenario.svg)",
        "- [PPS by trial](pps_trials.svg)",
        "- [XDP counter deltas](xdp_counter_deltas.svg)",
        "- [CPU task-clock per MPPS](cpu_per_mpps.svg)",
        "- [Drop vs pass PPS](drop_vs_pass_pps.svg)",
        "- [Session pressure PPS](session_pressure_pps.svg)",
        "- [User scale PPS](user_scale_pps.svg)",
        "- [Timeseries PPS and drops](timeseries_pps_and_drops.svg)",
        "",
        "## Raw Data",
        "",
        "- `results.csv`",
        "- `stats_timeseries.csv`",
        "- `environment.json`",
        "- `knockd.log`",
        "- `build.log`",
    ]
    (run_dir / "summary.md").write_text("\n".join(report) + "\n")
    (run_dir / "performance-report.md").write_text("\n".join(report) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
