#!/usr/bin/env bash
# reproduce.sh — CyFER-Bench end-to-end reproducibility script
#
# Runs all three modules on the 10 included sample files.
# For full-dataset reproduction, download the complete dataset first
# (see README.md) and remove the --max-samples flags.
#
# Prerequisites:
#   conda activate cyfer
#   Set OPENAI_API_KEY in malware_analysis/.env  (or export it)
#
# Usage:
#   bash reproduce.sh               # all modules
#   bash reproduce.sh malware       # malware analysis only
#   bash reproduce.sh intent        # attacker intent only
#   bash reproduce.sh vuln          # vulnerability explanation only

set -euo pipefail

TARGET="${1:-all}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo "  CyFER-Bench Reproducibility Script"
echo "============================================================"
echo ""

# ── Helper ────────────────────────────────────────────────────────────────────
header() { echo ""; echo "──────────────────────────────────────────"; echo "  $1"; echo "──────────────────────────────────────────"; }

# ── Module 1: Malware Analysis (Tasks 1, 2, 3, 6) ─────────────────────────────
run_malware() {
    header "Malware Analysis — Tasks 1, 2, 3, 6"
    cd "$SCRIPT_DIR/malware_analysis"

    echo "[1/3] Preprocessing sample data..."
    python preprocess.py --config config.json

    echo "[2/3] Running benchmark (all modes, sample data)..."
    python run_benchmark.py \
        --max-samples 10 \
        --modes A B C D \
        --config config.json

    echo "[3/3] Generating charts and tables..."
    python generate_graphs.py
    python generate_extended_charts.py
    python generate_tables.py

    echo "  Results  → malware_analysis/results/benchmark_results.json"
    echo "  Charts   → malware_analysis/charts/"
    echo "  Tables   → malware_analysis/tables/"
}

# ── Module 2: Attacker Intent (Task 7) ────────────────────────────────────────
run_intent() {
    header "Attacker Intent Attribution — Task 7"
    cd "$SCRIPT_DIR/attacker_intent"

    echo "[1/1] Running attacker intent evaluation..."
    python eval.py --config config.json

    echo "  Results  → attacker_intent/results/all_results.json"
}

# ── Module 3: Vulnerability Explanation (Tasks 4, 5) ──────────────────────────
run_vuln() {
    header "Vulnerability Explanation — Tasks 4, 5"
    cd "$SCRIPT_DIR/vuln_explanation"

    echo "[1/3] Building dataset..."
    python build_dataset.py \
        --dataset dataset \
        --output dataset/dataset.json \
        --context 10

    echo "[2/3] Generating LLM explanations (zero-shot)..."
    python generate_explanations.py \
        --dataset dataset/dataset.json \
        --model gpt-4o \
        --api-key "${OPENAI_API_KEY:-}" \
        --prompt-mode zero_shot \
        --output-dir explanations

    echo "[3/3] Evaluating explanations..."
    python evaluate.py \
        --results explanations/gpt-4o/zero_shot/results.json \
        --output  explanations/gpt-4o/zero_shot/scores.json \
        --judge-model gpt-4o \
        --api-key "${OPENAI_API_KEY:-}"

    echo "  Scores   → vuln_explanation/explanations/gpt-4o/zero_shot/scores.json"
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
case "$TARGET" in
    malware) run_malware ;;
    intent)  run_intent ;;
    vuln)    run_vuln ;;
    all)
        run_malware
        run_intent
        run_vuln
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Usage: bash reproduce.sh [all|malware|intent|vuln]"
        exit 1
        ;;
esac

echo ""
echo "============================================================"
echo "  CyFER-Bench: All selected modules completed."
echo "============================================================"
