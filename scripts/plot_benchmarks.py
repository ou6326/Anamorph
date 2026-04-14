#!/usr/bin/env python3
"""
Post-process Criterion benchmark output into publication-quality figures.

Usage:
    python scripts/plot_benchmarks.py [target/criterion]

Produces PNG figures in resources/figures/.
"""

import json
import os
import sys
from pathlib import Path
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

# ── Style ────────────────────────────────────────────────────────────────

PALETTE = {
    "normal":      "#3B82F6",   # blue
    "prf_enc":     "#8B5CF6",   # violet
    "prf_dec":     "#A855F7",   # purple
    "xor_enc":     "#EF4444",   # red
    "xor_dec":     "#F97316",   # orange
    "ec24_prf":    "#10B981",   # emerald
    "ec24_xor":    "#14B8A6",   # teal
    "ratchet":     "#06B6D4",   # cyan
    "indicator":   "#F59E0B",   # amber
    "keygen":      "#6366F1",   # indigo
    "akeygen":     "#EC4899",   # pink
    "search":      "#78716C",   # stone
    "control":     "#9CA3AF",   # grey
    "keystream":   "#F472B6",   # pink-light
    "xor_op":      "#FB923C",   # orange-light
}

BG_DARK  = "#0F172A"
BG_CARD  = "#1E293B"
FG_TEXT  = "#E2E8F0"
GRID_CLR = "#334155"
ACCENT   = "#38BDF8"

plt.rcParams.update({
    "figure.facecolor":   BG_DARK,
    "axes.facecolor":     BG_CARD,
    "axes.edgecolor":     GRID_CLR,
    "axes.labelcolor":    FG_TEXT,
    "text.color":         FG_TEXT,
    "xtick.color":        FG_TEXT,
    "ytick.color":        FG_TEXT,
    "grid.color":         GRID_CLR,
    "grid.alpha":         0.4,
    "legend.facecolor":   BG_CARD,
    "legend.edgecolor":   GRID_CLR,
    "legend.labelcolor":  FG_TEXT,
    "font.family":        "sans-serif",
    "font.size":          11,
    "axes.titlesize":     14,
    "axes.titleweight":   "bold",
    "figure.dpi":         150,
    "savefig.dpi":        200,
    "savefig.bbox":       "tight",
    "savefig.facecolor":  BG_DARK,
})


# ── Criterion JSON Parsing ───────────────────────────────────────────────

def find_criterion_dir(start: str = "target/criterion") -> Path:
    p = Path(start)
    if not p.exists():
        print(f"⚠  Criterion output directory not found at '{p}'.")
        print("   Run 'cargo bench' first, then re-run this script.")
        sys.exit(1)
    return p


def parse_estimates(bench_dir: Path) -> dict | None:
    """Read the Criterion estimates.json for a single benchmark."""
    est = bench_dir / "new" / "estimates.json"
    if not est.exists():
        return None
    with open(est) as f:
        data = json.load(f)
    return {
        "mean_ns":   data["mean"]["point_estimate"],
        "median_ns": data.get("median", {}).get("point_estimate", data["mean"]["point_estimate"]),
        "stddev_ns": data["std_dev"]["point_estimate"],
    }


def collect_group_data(criterion_dir: Path, group_name: str) -> list[dict]:
    """Collect all parameter runs from a Criterion benchmark group."""
    group_dir = criterion_dir / group_name
    if not group_dir.exists():
        return []

    results = []
    for param_dir in sorted(group_dir.iterdir()):
        if not param_dir.is_dir() or param_dir.name == "report":
            continue
        est = parse_estimates(param_dir)
        if est is None:
            continue
        try:
            param = int(param_dir.name)
        except ValueError:
            param = param_dir.name
        est["param"] = param
        results.append(est)
    return sorted(results, key=lambda x: x["param"] if isinstance(x["param"], int) else 0)


def collect_baselines(criterion_dir: Path) -> dict:
    """Collect single-point (non-parameterised) benchmarks."""
    baselines = {}
    for entry in criterion_dir.iterdir():
        if not entry.is_dir():
            continue
        est = parse_estimates(entry)
        if est:
            baselines[entry.name] = est
    return baselines


# ── Figure Helpers ───────────────────────────────────────────────────────

def ns_to_us(ns: float) -> float:
    return ns / 1_000.0

def ns_to_ms(ns: float) -> float:
    return ns / 1_000_000.0

def bytes_label(n: int) -> str:
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f} MB"
    if n >= 1_024:
        return f"{n / 1_024:.0f} KB"
    return f"{n} B"


def save_fig(fig, name: str, out_dir: Path):
    path = out_dir / f"{name}.png"
    fig.savefig(path)
    plt.close(fig)
    print(f"  ✓ {path}")


def add_watermark(ax):
    ax.text(0.98, 0.02, "Project Anamorph", transform=ax.transAxes,
            fontsize=8, color=GRID_CLR, ha="right", va="bottom",
            fontstyle="italic", alpha=0.6)


# ── Figures ──────────────────────────────────────────────────────────────

def fig_overhead_comparison(baselines: dict, out_dir: Path):
    """Bar chart: Normal vs Anamorphic (PRF/XOR) baseline overhead."""
    labels = []
    values = []
    errors = []
    colors = []

    keys_map = [
        ("baseline/normal_encrypt_end_to_end",              "Normal Enc",       PALETTE["normal"]),
        ("baseline/normal_decrypt_end_to_end",              "Normal Dec",       PALETTE["normal"]),
        ("baseline/anamorphic_prf_encrypt_empty_payload",   "PRF Enc (ε=0)",    PALETTE["prf_enc"]),
        ("baseline/anamorphic_prf_decrypt_empty_payload",   "PRF Dec (ε=0)",    PALETTE["prf_dec"]),
        ("baseline/anamorphic_xor_encrypt_empty_payload",   "XOR Enc (ε=0)",    PALETTE["xor_enc"]),
        ("baseline/anamorphic_xor_decrypt_empty_payload",   "XOR Dec (ε=0)",    PALETTE["xor_dec"]),
    ]

    for key, label, color in keys_map:
        if key in baselines:
            b = baselines[key]
            labels.append(label)
            values.append(ns_to_us(b["mean_ns"]))
            errors.append(ns_to_us(b["stddev_ns"]))
            colors.append(color)

    if not values:
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(labels))
    bars = ax.bar(x, values, yerr=errors, capsize=4, color=colors,
                  edgecolor=[c + "BB" for c in colors], linewidth=0.8, alpha=0.9)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(values) * 0.02,
                f"{val:.1f}", ha="center", va="bottom", fontsize=9, color=FG_TEXT)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right", fontsize=10)
    ax.set_ylabel("Time (µs)")
    ax.set_title("Baseline Overhead: Normal vs Anamorphic (Empty Covert Payload)")
    ax.grid(axis="y", linestyle="--")
    add_watermark(ax)
    fig.tight_layout()
    save_fig(fig, "01_baseline_overhead", out_dir)


def fig_payload_scaling(criterion_dir: Path, out_dir: Path):
    """Line chart: Encrypt/decrypt cost vs covert payload size for PRF and XOR modes."""
    groups = [
        ("anamorphic_prf_total_cost",         "PRF Enc",  PALETTE["prf_enc"],  "-",  "o"),
        ("anamorphic_prf_decrypt_total_cost",  "PRF Dec",  PALETTE["prf_dec"],  "--", "s"),
        ("anamorphic_xor_encrypt_total_cost",  "XOR Enc",  PALETTE["xor_enc"],  "-",  "^"),
        ("anamorphic_xor_decrypt_total_cost",  "XOR Dec",  PALETTE["xor_dec"],  "--", "D"),
    ]

    fig, ax = plt.subplots(figsize=(10, 6))
    any_data = False

    for gname, label, color, ls, marker in groups:
        data = collect_group_data(criterion_dir, gname)
        if not data:
            continue
        any_data = True
        xs = [d["param"] for d in data]
        ys = [ns_to_us(d["mean_ns"]) for d in data]
        errs = [ns_to_us(d["stddev_ns"]) for d in data]
        ax.errorbar(xs, ys, yerr=errs, label=label, color=color,
                    linestyle=ls, marker=marker, markersize=6, capsize=3,
                    linewidth=2, alpha=0.9)

    if not any_data:
        plt.close(fig)
        return

    ax.set_xlabel("Covert Payload Size (bytes)")
    ax.set_ylabel("Time (µs)")
    ax.set_title("Anamorphic Overhead vs Covert Payload Size")
    ax.legend(loc="upper left", framealpha=0.9)
    ax.grid(True, linestyle="--")
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: bytes_label(int(x))))
    plt.xticks(rotation=30, ha="right")
    add_watermark(ax)
    fig.tight_layout()
    save_fig(fig, "02_payload_scaling", out_dir)


def fig_payload_scaling_large(criterion_dir: Path, out_dir: Path):
    """Line chart: Large-payload regime."""
    groups = [
        ("anamorphic_prf_total_cost_large",            "PRF Enc",  PALETTE["prf_enc"],  "-",  "o"),
        ("anamorphic_prf_decrypt_total_cost_large",    "PRF Dec",  PALETTE["prf_dec"],  "--", "s"),
        ("anamorphic_xor_encrypt_total_cost_large",    "XOR Enc",  PALETTE["xor_enc"],  "-",  "^"),
        ("anamorphic_xor_decrypt_total_cost_large",    "XOR Dec",  PALETTE["xor_dec"],  "--", "D"),
    ]

    fig, ax = plt.subplots(figsize=(10, 6))
    any_data = False

    for gname, label, color, ls, marker in groups:
        data = collect_group_data(criterion_dir, gname)
        if not data:
            continue
        any_data = True
        xs = [d["param"] for d in data]
        ys = [ns_to_us(d["mean_ns"]) for d in data]
        errs = [ns_to_us(d["stddev_ns"]) for d in data]
        ax.errorbar(xs, ys, yerr=errs, label=label, color=color,
                    linestyle=ls, marker=marker, markersize=6, capsize=3,
                    linewidth=2, alpha=0.9)

    if not any_data:
        plt.close(fig)
        return

    ax.set_xlabel("Covert Payload Size (bytes)")
    ax.set_ylabel("Time (µs)")
    ax.set_title("Large Payload Scaling (≥384 KB)")
    ax.legend(loc="upper left", framealpha=0.9)
    ax.grid(True, linestyle="--")
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: bytes_label(int(x))))
    plt.xticks(rotation=30, ha="right")
    add_watermark(ax)
    fig.tight_layout()
    save_fig(fig, "03_payload_scaling_large", out_dir)


def fig_ec24_vs_ec22(criterion_dir: Path, out_dir: Path):
    """Compare EC22 (plain) vs EC24 (ratcheted) encryption overhead."""
    groups = [
        ("anamorphic_prf_total_cost",     "EC22 PRF Enc",     PALETTE["prf_enc"],  "-",  "o"),
        ("ec24_prf_encrypt_total_cost",   "EC24 PRF Enc",     PALETTE["ec24_prf"], "-",  "P"),
        ("anamorphic_xor_encrypt_total_cost", "EC22 XOR Enc", PALETTE["xor_enc"],  "--", "^"),
        ("ec24_xor_encrypt_total_cost",   "EC24 XOR Enc",     PALETTE["ec24_xor"], "--", "X"),
    ]

    fig, ax = plt.subplots(figsize=(10, 6))
    any_data = False

    for gname, label, color, ls, marker in groups:
        data = collect_group_data(criterion_dir, gname)
        if not data:
            continue
        any_data = True
        xs = [d["param"] for d in data]
        ys = [ns_to_us(d["mean_ns"]) for d in data]
        errs = [ns_to_us(d["stddev_ns"]) for d in data]
        ax.errorbar(xs, ys, yerr=errs, label=label, color=color,
                    linestyle=ls, marker=marker, markersize=6, capsize=3,
                    linewidth=2, alpha=0.9)

    if not any_data:
        plt.close(fig)
        return

    ax.set_xlabel("Covert Payload Size (bytes)")
    ax.set_ylabel("Time (µs)")
    ax.set_title("EC22 vs EC24 Ratcheted Encryption Overhead")
    ax.legend(loc="upper left", framealpha=0.9)
    ax.grid(True, linestyle="--")
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: bytes_label(int(x))))
    plt.xticks(rotation=30, ha="right")
    add_watermark(ax)
    fig.tight_layout()
    save_fig(fig, "04_ec22_vs_ec24", out_dir)


def fig_xor_step_breakdown(criterion_dir: Path, out_dir: Path):
    """Stacked area: breakdown of XOR encryption steps."""
    steps = [
        ("keystream_derivation",         "Keystream Derivation",  PALETTE["keystream"]),
        ("payload_xor_with_alloc",       "XOR + Alloc",           PALETTE["xor_op"]),
    ]

    fig, ax = plt.subplots(figsize=(10, 6))
    any_data = False

    for step_name, label, color in steps:
        data = collect_group_data(criterion_dir, "xor_step_scaling")
        step_data = []
        for entry in sorted((criterion_dir / "xor_step_scaling").iterdir()) if (criterion_dir / "xor_step_scaling").exists() else []:
            if not entry.is_dir() or entry.name == "report":
                continue
            # within parameterised groups, Criterion nests as group/step_name/param
            for sub in sorted(entry.iterdir()):
                if sub.is_dir() and sub.name != "report":
                    est = parse_estimates(sub)
                    if est:
                        try:
                            est["param"] = int(sub.name)
                        except ValueError:
                            est["param"] = sub.name
                        est["step"] = entry.name
                        step_data.append(est)
        if not step_data:
            break
        # filter to this step
        filtered = [d for d in step_data if d["step"] == step_name]
        if filtered:
            any_data = True
            filtered.sort(key=lambda d: d["param"] if isinstance(d["param"], int) else 0)
            xs = [d["param"] for d in filtered]
            ys = [ns_to_us(d["mean_ns"]) for d in filtered]
            ax.plot(xs, ys, label=label, color=color, marker="o", linewidth=2, alpha=0.9)

    if not any_data:
        plt.close(fig)
        return

    ax.set_xlabel("Covert Payload Size (bytes)")
    ax.set_ylabel("Time (µs)")
    ax.set_title("XOR Encryption Step-Level Breakdown")
    ax.legend(loc="upper left", framealpha=0.9)
    ax.grid(True, linestyle="--")
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: bytes_label(int(x))))
    plt.xticks(rotation=30, ha="right")
    add_watermark(ax)
    fig.tight_layout()
    save_fig(fig, "05_xor_step_breakdown", out_dir)


def fig_ec24_primitives(baselines: dict, out_dir: Path):
    """Bar chart: EC24 primitive costs (ratchet step + indicator check)."""
    items = [
        ("ec24/ratchet_once",             "Ratchet (1 step)",    PALETTE["ratchet"]),
        ("ec24/verify_covert_indicator",  "Presence Indicator",  PALETTE["indicator"]),
    ]

    labels, values, errors, colors = [], [], [], []
    for key, label, color in items:
        if key in baselines:
            b = baselines[key]
            labels.append(label)
            values.append(ns_to_us(b["mean_ns"]))
            errors.append(ns_to_us(b["stddev_ns"]))
            colors.append(color)

    if not values:
        return

    fig, ax = plt.subplots(figsize=(7, 4))
    x = np.arange(len(labels))
    bars = ax.bar(x, values, yerr=errors, capsize=4, color=colors,
                  edgecolor=[c + "CC" for c in colors], linewidth=0.8, alpha=0.9,
                  width=0.5)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(values) * 0.03,
                f"{val:.1f} µs", ha="center", va="bottom", fontsize=10, color=FG_TEXT)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylabel("Time (µs)")
    ax.set_title("EC24 Primitive Costs")
    ax.grid(axis="y", linestyle="--")
    add_watermark(ax)
    fig.tight_layout()
    save_fig(fig, "06_ec24_primitives", out_dir)


def fig_keygen_comparison(criterion_dir: Path, out_dir: Path):
    """Bar chart: Gen vs aGen from-params cost."""
    data = collect_group_data(criterion_dir, "operation_keygen_from_params_total_cost")
    if not data:
        # try flat layout
        group_dir = criterion_dir / "operation_keygen_from_params_total_cost"
        if not group_dir.exists():
            return
        entries = []
        for sub in sorted(group_dir.iterdir()):
            if sub.is_dir() and sub.name != "report":
                est = parse_estimates(sub)
                if est:
                    est["name"] = sub.name
                    entries.append(est)
        if not entries:
            return

        labels = [e["name"].replace("_", " ") for e in entries]
        values = [ns_to_us(e["mean_ns"]) for e in entries]
        errors = [ns_to_us(e["stddev_ns"]) for e in entries]
        colors = [PALETTE["keygen"] if "Gen" in e["name"] else PALETTE["akeygen"] for e in entries]
    else:
        return  # parameterised groups handled differently

    fig, ax = plt.subplots(figsize=(7, 4))
    x = np.arange(len(labels))
    bars = ax.bar(x, values, yerr=errors, capsize=4, color=colors,
                  edgecolor=[c + "CC" for c in colors], width=0.45, alpha=0.9)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(values) * 0.03,
                f"{val:.1f}", ha="center", va="bottom", fontsize=10, color=FG_TEXT)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Time (µs)")
    ax.set_title("Key Generation Cost: Normal vs Anamorphic (from params)")
    ax.grid(axis="y", linestyle="--")
    add_watermark(ax)
    fig.tight_layout()
    save_fig(fig, "07_keygen_comparison", out_dir)


def fig_robustness_controls(baselines: dict, out_dir: Path):
    """Bar chart: robustness / negative-path timing."""
    items = [
        ("robustness/prf_adecrypt_on_normal_ciphertext",    "PRF aDec\non normal ct",     PALETTE["control"]),
        ("robustness/prf_adecrypt_wrong_candidate",         "PRF aDec\nwrong candidate",   PALETTE["search"]),
        ("robustness/ec24_indicator_on_normal_ciphertext",  "EC24 Indicator\non normal ct", PALETTE["indicator"]),
    ]

    labels, values, errors, colors = [], [], [], []
    for key, label, color in items:
        if key in baselines:
            b = baselines[key]
            labels.append(label)
            values.append(ns_to_us(b["mean_ns"]))
            errors.append(ns_to_us(b["stddev_ns"]))
            colors.append(color)

    if not values:
        return

    fig, ax = plt.subplots(figsize=(8, 4.5))
    x = np.arange(len(labels))
    bars = ax.bar(x, values, yerr=errors, capsize=4, color=colors,
                  edgecolor=[c + "CC" for c in colors], width=0.5, alpha=0.9)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(values) * 0.03,
                f"{val:.1f}", ha="center", va="bottom", fontsize=10, color=FG_TEXT)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Time (µs)")
    ax.set_title("Robustness Check Timing (Negative / Reject Paths)")
    ax.grid(axis="y", linestyle="--")
    add_watermark(ax)
    fig.tight_layout()
    save_fig(fig, "08_robustness_controls", out_dir)


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    criterion_path = sys.argv[1] if len(sys.argv) > 1 else "target/criterion"
    criterion_dir = find_criterion_dir(criterion_path)

    project_root = Path(__file__).resolve().parent.parent
    out_dir = project_root / "resources" / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Reading Criterion output from: {criterion_dir}")
    print(f"Saving figures to: {out_dir}\n")

    baselines = collect_baselines(criterion_dir)

    fig_overhead_comparison(baselines, out_dir)
    fig_payload_scaling(criterion_dir, out_dir)
    fig_payload_scaling_large(criterion_dir, out_dir)
    fig_ec24_vs_ec22(criterion_dir, out_dir)
    fig_xor_step_breakdown(criterion_dir, out_dir)
    fig_ec24_primitives(baselines, out_dir)
    fig_keygen_comparison(criterion_dir, out_dir)
    fig_robustness_controls(baselines, out_dir)

    print(f"\nDone. {len(list(out_dir.glob('*.png')))} figures generated.")


if __name__ == "__main__":
    main()
