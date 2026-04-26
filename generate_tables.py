#!/usr/bin/env python3
"""
SandBench: Generate tables from benchmark results.

Produces Markdown and LaTeX tables for all six charts:
  01 — Composite Score by Model × Mode (mean ± std)
  02 — Per-model multi-metric breakdown across modes
  03 — All metrics × all Model×Mode conditions (heatmap data)
  04 — LLM API calls and inference latency by mode
  05 — Improvement delta (Mode D − Mode A) per metric per model
  06 — Threat Verdict Accuracy by Model × Mode (mean ± std)

Usage:
    python generate_tables.py
    python generate_tables.py --results ./results/benchmark_results.json --output ./tables/
"""

import json
import os
import argparse
import numpy as np


MODEL_LABELS = {
    "meta-llama/Llama-3.1-8B-Instruct": "Llama-3.1-8B",
    "llama-3.1-8b": "Llama-3.1-8B",
    "gpt-oss-20b": "GPT-OSS-20B",
    "qwen3-8b": "Qwen3-8B",
}
MODE_LABELS = {
    "A": "Single-Shot",
    "B": "Judge-Refined",
    "C": "Agentic",
    "D": "Agentic+Judge",
}

HEATMAP_METRICS = [
    ("composite.composite_score",   "Composite Score"),
    ("ttp.ttp_f1",                  "TTP F1"),
    ("ttp.ttp_recall",              "TTP Recall"),
    ("verdict.verdict_score",       "Threat Verdict Acc."),
]

RADAR_METRICS = [
    ("ttp.ttp_f1",                  "TTP F1"),
    ("ttp.ttp_recall",              "TTP Recall"),
    ("verdict.verdict_score",       "Threat Verdict Acc."),
    ("composite.composite_score",   "Composite Score"),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_results(path):
    with open(path) as f:
        data = json.load(f)
    return data.get("results", [])


def get_val(r, path):
    val = r.get("evaluation", {})
    for p in path.split("."):
        val = val.get(p, 0) if isinstance(val, dict) else 0
    return float(val) if val is not None else 0.0


def model_label(key):
    return MODEL_LABELS.get(key, key.split("/")[-1])


def get_models_modes(results):
    return sorted(set(r["model_key"] for r in results)), sorted(set(r["mode"] for r in results))


def metric_stats(results, metric_path, model, mode):
    vals = [get_val(r, metric_path) for r in results
            if r["model_key"] == model and r["mode"] == mode]
    if not vals:
        return 0.0, 0.0
    return float(np.mean(vals)), float(np.std(vals))


def save(output_dir, stem, md, tex):
    with open(os.path.join(output_dir, f"{stem}.md"),  "w") as f:
        f.write(md)
    with open(os.path.join(output_dir, f"{stem}.tex"), "w") as f:
        f.write(tex)
    print(f"  Saved: {stem}.md + .tex")


# ── Table 01: Composite Score by Model × Mode ─────────────────────────────────

def build_table01(results):
    models, modes = get_models_modes(results)
    rows = []
    for model in models:
        row = {"model": model_label(model)}
        for mode in modes:
            mean, std = metric_stats(results, "composite.composite_score", model, mode)
            row[mode] = (mean, std)
        rows.append(row)
    return rows, modes


def table01_markdown(rows, modes):
    header  = "| Model | " + " | ".join(f"Mode {m} ({MODE_LABELS[m]})" for m in modes) + " |"
    divider = "| --- | " + " | ".join(["---:"] * len(modes)) + " |"
    lines   = [header, divider]
    for row in rows:
        cells = " | ".join(f"{row[m][0]:.4f} ± {row[m][1]:.4f}" for m in modes)
        lines.append(f"| {row['model']} | {cells} |")
    return "\n".join(lines)


def table01_latex(rows, modes):
    col_spec = "l" + "r" * len(modes)
    mode_header = " & ".join(f"Mode {m}" for m in modes)
    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        r"\caption{SandBench: Composite Score by Model and Evaluation Mode (mean $\pm$ std)}",
        r"\label{tab:composite_score}",
        r"\begin{tabular}{" + col_spec + r"}",
        r"\toprule",
        r"Model & " + mode_header + r" \\",
        r"\midrule",
    ]
    for row in rows:
        cells = " & ".join(
            r"$" + f"{row[m][0]:.4f}" + r" \pm " + f"{row[m][1]:.4f}" + r"$"
            for m in modes
        )
        lines.append(r"\textbf{" + row["model"] + r"} & " + cells + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines)


# ── Table 02: Per-model multi-metric breakdown ────────────────────────────────

def build_table02(results):
    models, modes = get_models_modes(results)
    rows = []
    for model in models:
        for metric_path, metric_label in RADAR_METRICS:
            vals_by_mode = {
                mode: metric_stats(results, metric_path, model, mode)[0]
                for mode in modes
            }
            rows.append((model_label(model), metric_label, vals_by_mode))
    return rows, modes


def table02_markdown(rows, modes):
    header  = "| Model | Metric | " + " | ".join(f"Mode {m} ({MODE_LABELS[m]})" for m in modes) + " |"
    divider = "| --- | --- | " + " | ".join(["---:"] * len(modes)) + " |"
    lines   = [header, divider]
    prev_model = None
    for model, metric, vals in rows:
        model_col  = model if model != prev_model else ""
        prev_model = model
        cells = " | ".join(f"{vals[m]:.4f}" for m in modes)
        lines.append(f"| {model_col} | {metric} | {cells} |")
    return "\n".join(lines)


def table02_latex(rows, modes):
    col_spec    = "ll" + "r" * len(modes)
    mode_header = " & ".join(f"Mode {m}" for m in modes)
    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        r"\caption{SandBench: Per-Model Metric Breakdown Across Evaluation Modes}",
        r"\label{tab:metric_breakdown}",
        r"\begin{tabular}{" + col_spec + r"}",
        r"\toprule",
        r"Model & Metric & " + mode_header + r" \\",
        r"\midrule",
    ]
    prev_model = None
    for i, (model, metric, vals) in enumerate(rows):
        model_col  = r"\textbf{" + model + r"}" if model != prev_model else ""
        if model_col and i > 0:
            lines.append(r"\midrule")
        prev_model = model
        cells = " & ".join(f"{vals[m]:.4f}" for m in modes)
        lines.append(f"{model_col} & {metric} & {cells} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines)


# ── Table 03: All metrics × all conditions ────────────────────────────────────

def build_table03(results):
    models, modes = get_models_modes(results)
    # columns: (model, mode) pairs
    columns = [(m, md) for m in models for md in modes]
    rows = []
    for metric_path, metric_label in HEATMAP_METRICS:
        vals = {
            (m, md): metric_stats(results, metric_path, m, md)[0]
            for m, md in columns
        }
        rows.append((metric_label, vals))
    return rows, columns, models, modes


def table03_markdown(rows, columns, models, modes):
    col_headers = " | ".join(
        f"{model_label(m)[:8]}/{MODE_LABELS[md][:6]}"
        for m, md in columns
    )
    header  = f"| Metric | {col_headers} |"
    divider = "| --- | " + " | ".join(["---:"] * len(columns)) + " |"
    lines   = [header, divider]
    for metric_label, vals in rows:
        cells = " | ".join(f"{vals[(m, md)]:.4f}" for m, md in columns)
        lines.append(f"| {metric_label} | {cells} |")
    return "\n".join(lines)


def table03_latex(rows, columns, models, modes):
    col_spec = "l" + "r" * len(columns)
    col_header = " & ".join(
        r"\shortstack{" + model_label(m)[:8] + r"\\" + MODE_LABELS[md][:6] + r"}"
        for m, md in columns
    )
    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        r"\caption{SandBench: All Metrics Across All Model $\times$ Mode Conditions}",
        r"\label{tab:all_conditions}",
        r"\begin{tabular}{" + col_spec + r"}",
        r"\toprule",
        r"Metric & " + col_header + r" \\",
        r"\midrule",
    ]
    for metric_label, vals in rows:
        cells = " & ".join(f"{vals[(m, md)]:.4f}" for m, md in columns)
        lines.append(f"{metric_label} & {cells} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines)


# ── Table 04: LLM calls & latency ────────────────────────────────────────────

def build_table04(results):
    models, modes = get_models_modes(results)
    rows = []
    for model in models:
        for mode in modes:
            subset      = [r for r in results if r["model_key"] == model and r["mode"] == mode]
            avg_calls   = float(np.mean([r["total_llm_calls"]       for r in subset])) if subset else 0.0
            avg_latency = float(np.mean([r["total_elapsed_seconds"] for r in subset])) if subset else 0.0
            rows.append((model_label(model), MODE_LABELS[mode], avg_calls, avg_latency))
    return rows


def table04_markdown(rows):
    header  = "| Model | Mode | Avg LLM Calls | Avg Latency (s) |"
    divider = "| --- | --- | ---: | ---: |"
    lines   = [header, divider]
    prev_model = None
    for model, mode, calls, latency in rows:
        model_col  = model if model != prev_model else ""
        prev_model = model
        lines.append(f"| {model_col} | {mode} | {calls:.2f} | {latency:.2f} |")
    return "\n".join(lines)


def table04_latex(rows):
    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        r"\caption{SandBench: Computational Cost and Latency by Evaluation Mode}",
        r"\label{tab:cost_latency}",
        r"\begin{tabular}{llrr}",
        r"\toprule",
        r"Model & Mode & Avg LLM Calls & Avg Latency (s) \\",
        r"\midrule",
    ]
    prev_model = None
    for i, (model, mode, calls, latency) in enumerate(rows):
        model_col = r"\textbf{" + model + r"}" if model != prev_model else ""
        if model_col and i > 0:
            lines.append(r"\midrule")
        prev_model = model
        lines.append(f"{model_col} & {mode} & {calls:.2f} & {latency:.2f} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines)


# ── Table 05: Improvement delta (Mode D − Mode A) ────────────────────────────

def build_table05(results):
    models, modes = get_models_modes(results)
    if "A" not in modes or "D" not in modes:
        return None, None
    rows = []
    for model in models:
        for metric_path, metric_label in HEATMAP_METRICS:
            a_mean, _ = metric_stats(results, metric_path, model, "A")
            d_mean, _ = metric_stats(results, metric_path, model, "D")
            rows.append((model_label(model), metric_label, a_mean, d_mean, d_mean - a_mean))
    return rows, models


def table05_markdown(rows):
    header  = "| Model | Metric | Mode A (Single-Shot) | Mode D (Agentic+Judge) | Δ (D − A) |"
    divider = "| --- | --- | ---: | ---: | ---: |"
    lines   = [header, divider]
    prev_model = None
    for model, metric, a_val, d_val, delta in rows:
        model_col  = model if model != prev_model else ""
        prev_model = model
        sign = "+" if delta >= 0 else ""
        lines.append(f"| {model_col} | {metric} | {a_val:.4f} | {d_val:.4f} | {sign}{delta:.4f} |")
    return "\n".join(lines)


def table05_latex(rows):
    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        r"\caption{SandBench: Improvement from Single-Shot (Mode A) to Agentic+Judge (Mode D)}",
        r"\label{tab:improvement_delta}",
        r"\begin{tabular}{llrrr}",
        r"\toprule",
        r"Model & Metric & Mode A & Mode D & $\Delta$ (D $-$ A) \\",
        r"\midrule",
    ]
    prev_model = None
    for i, (model, metric, a_val, d_val, delta) in enumerate(rows):
        model_col = r"\textbf{" + model + r"}" if model != prev_model else ""
        if model_col and i > 0:
            lines.append(r"\midrule")
        prev_model = model
        sign = "+" if delta >= 0 else ""
        lines.append(
            f"{model_col} & {metric} & {a_val:.4f} & {d_val:.4f} & {sign}{delta:.4f} \\\\"
        )
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines)


# ── Table 06: Threat Verdict Accuracy by Model × Mode ────────────────────────

def build_table06(results):
    models, modes = get_models_modes(results)
    rows = []
    for model in models:
        row = {"model": model_label(model)}
        for mode in modes:
            mean, std = metric_stats(results, "verdict.verdict_score", model, mode)
            row[mode] = (mean, std)
        rows.append(row)
    return rows, modes


def table06_markdown(rows, modes):
    header  = "| Model | " + " | ".join(f"Mode {m} ({MODE_LABELS[m]})" for m in modes) + " |"
    divider = "| --- | " + " | ".join(["---:"] * len(modes)) + " |"
    lines   = [header, divider]
    for row in rows:
        cells = " | ".join(f"{row[m][0]:.4f} ± {row[m][1]:.4f}" for m in modes)
        lines.append(f"| {row['model']} | {cells} |")
    return "\n".join(lines)


def table06_latex(rows, modes):
    col_spec    = "l" + "r" * len(modes)
    mode_header = " & ".join(f"Mode {m}" for m in modes)
    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        r"\caption{SandBench: Threat Verdict Accuracy by Model and Evaluation Mode (mean $\pm$ std)}",
        r"\label{tab:verdict_accuracy}",
        r"\begin{tabular}{" + col_spec + r"}",
        r"\toprule",
        r"Model & " + mode_header + r" \\",
        r"\midrule",
    ]
    for row in rows:
        cells = " & ".join(
            r"$" + f"{row[m][0]:.4f}" + r" \pm " + f"{row[m][1]:.4f}" + r"$"
            for m in modes
        )
        lines.append(r"\textbf{" + row["model"] + r"} & " + cells + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines)


# ── Table 07: Mode Summary (Composite / Token Cov. / Sig. F1 / MITRE / Score Err. / LLM Calls) ──

def build_table07(results):
    """
    Columns match the compact summary format:
      Mode | Composite | Token Cov. | Sig. F1 | MITRE | Score Err.↓ | LLM Calls

    Metric mapping from benchmark_results.json:
      Composite   = composite.composite_score
      Token Cov.  = ttp.ttp_recall          (fraction of GT TTPs recalled)
      Sig. F1     = ttp.ttp_f1              (TTP precision/recall F1)
      MITRE       = family.family_f1        (malware family classification F1)
      Score Err.↓ = avg hallucinated TTPs   (false-positive TTP count, lower is better)
      LLM Calls   = total_llm_calls
    """
    modes = sorted(set(r["mode"] for r in results))
    rows = []
    for mode in modes:
        sub = [r for r in results if r["mode"] == mode]

        def mean_metric(path):
            return metric_stats(results, path, sub[0]["model_key"], mode)[0] if sub else 0.0

        composite   = mean_metric("composite.composite_score")
        token_cov   = mean_metric("ttp.ttp_recall")
        sig_f1      = mean_metric("ttp.ttp_f1")
        mitre       = mean_metric("family.family_f1")
        score_err   = float(np.mean([
            len(r.get("evaluation", {}).get("ttp", {}).get("q3_hallucinated_ttps", []))
            for r in sub
        ]))
        llm_calls   = float(np.mean([r["total_llm_calls"] for r in sub]))

        rows.append({
            "mode":       MODE_LABELS.get(mode, mode),
            "composite":  composite,
            "token_cov":  token_cov,
            "sig_f1":     sig_f1,
            "mitre":      mitre,
            "score_err":  score_err,
            "llm_calls":  llm_calls,
        })
    return rows


def table07_markdown(rows):
    header  = "| Mode | Composite | Token Cov. | Sig. F1 | MITRE | Score Err. ↓ | LLM Calls |"
    divider = "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"
    lines   = [header, divider]
    for r in rows:
        lines.append(
            f"| {r['mode']} | {r['composite']:.3f} | {r['token_cov']:.3f} | "
            f"{r['sig_f1']:.3f} | {r['mitre']:.3f} | {r['score_err']:.3f} | {r['llm_calls']:.1f} |"
        )
    return "\n".join(lines)


def table07_latex(rows):
    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        r"\caption{SandBench: Mode Summary --- Composite, Token Coverage, Signature F1, MITRE Family F1, Score Error, and LLM Calls}",
        r"\label{tab:mode_summary}",
        r"\begin{tabular}{lrrrrrr}",
        r"\toprule",
        r"\textbf{Mode} & \textbf{Composite} & \textbf{Token Cov.} & \textbf{Sig.\ F1}"
        r" & \textbf{MITRE} & \textbf{Score Err.} $\downarrow$ & \textbf{LLM Calls} \\",
        r"\midrule",
    ]
    for r in rows:
        lines.append(
            f"{r['mode']:<14} & {r['composite']:.3f} & {r['token_cov']:.3f} & "
            f"{r['sig_f1']:.3f} & {r['mitre']:.3f} & {r['score_err']:.3f} & {r['llm_calls']:.1f} \\\\"
        )
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines)


# ── main ──────────────────────────────────────────────────────────────────────

TABLES = [
    ("01", "01_composite_score",    "Composite Score by Model × Mode"),
    ("02", "02_metric_breakdown",   "Per-Model Metric Breakdown Across Modes"),
    ("03", "03_all_conditions",     "All Metrics × All Conditions"),
    ("04", "04_cost_latency",       "LLM Calls & Latency by Mode"),
    ("05", "05_improvement_delta",  "Improvement Delta (Mode D − Mode A)"),
    ("06", "06_verdict_accuracy",   "Threat Verdict Accuracy by Model × Mode"),
    ("07", "07_mode_summary",       "Mode Summary (Composite / Token Cov. / Sig. F1 / MITRE / Score Err. / LLM Calls)"),
]


def main():
    parser = argparse.ArgumentParser(description="Generate SandBench result tables")
    parser.add_argument("--results", default="./results/benchmark_results.json")
    parser.add_argument("--output",  default="./tables")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    results = load_results(args.results)
    print(f"Loaded {len(results)} experiment results\n")

    # Table 01
    rows01, modes = build_table01(results)
    md01, tex01   = table01_markdown(rows01, modes), table01_latex(rows01, modes)
    save(args.output, "01_composite_score", md01, tex01)

    # Table 02
    rows02, modes = build_table02(results)
    md02, tex02   = table02_markdown(rows02, modes), table02_latex(rows02, modes)
    save(args.output, "02_metric_breakdown", md02, tex02)

    # Table 03
    rows03, columns, models, modes = build_table03(results)
    md03  = table03_markdown(rows03, columns, models, modes)
    tex03 = table03_latex(rows03, columns, models, modes)
    save(args.output, "03_all_conditions", md03, tex03)

    # Table 04
    rows04        = build_table04(results)
    md04, tex04   = table04_markdown(rows04), table04_latex(rows04)
    save(args.output, "04_cost_latency", md04, tex04)

    # Table 05
    rows05, _     = build_table05(results)
    if rows05 is None:
        print("  Skipping table 05 (need modes A and D)")
    else:
        md05, tex05 = table05_markdown(rows05), table05_latex(rows05)
        save(args.output, "05_improvement_delta", md05, tex05)

    # Table 06
    rows06, modes = build_table06(results)
    md06, tex06   = table06_markdown(rows06, modes), table06_latex(rows06, modes)
    save(args.output, "06_verdict_accuracy", md06, tex06)

    # Table 07
    rows07      = build_table07(results)
    md07, tex07 = table07_markdown(rows07), table07_latex(rows07)
    save(args.output, "07_mode_summary", md07, tex07)

    # Print all to stdout
    for num, stem, title in TABLES:
        md_path = os.path.join(args.output, f"{stem}.md")
        if not os.path.exists(md_path):
            continue
        with open(md_path) as f:
            content = f.read()
        print(f"\n{'='*60}")
        print(f"TABLE {num} — {title}")
        print("="*60)
        print(content)


if __name__ == "__main__":
    main()
