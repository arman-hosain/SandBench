#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# SandBench: Run benchmark against ALREADY RUNNING vLLM
# Use this when you've started vLLM yourself.
#
# Usage:
#   # First, start vLLM yourself in another terminal:
#   python -m vllm.entrypoints.openai.api_server \
#       --model openai/gpt-oss-20b --port 8001
#
#   # Then run:
#   ./run_manual.sh gpt-oss-20b              # all modes
#   ./run_manual.sh gpt-oss-20b --modes A B  # specific modes
#   ./run_manual.sh gpt-oss-20b --max-samples 5  # quick test
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: ./run_manual.sh <model-key> [--modes A B C D] [--max-samples N]"
    echo ""
    echo "Model keys: llama-3.1-8b | gpt-oss-20b | qwen3-8b"
    echo ""
    echo "Make sure vLLM is already running on port ${SANDBENCH_VLLM_PORT:-8001}!"
    exit 1
fi

MODEL_KEY="$1"
shift

# GPU selection (only GPU 2 available on djarin)
export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-1,2}"

# Paths
export SANDBENCH_DATASET_DIR="${SANDBENCH_DATASET_DIR:-/mnt/ahossain4/data/cuckoo/dataset}"
export SANDBENCH_EXTRACTED_DIR="${SANDBENCH_EXTRACTED_DIR:-/mnt/ahossain4/data/cuckoo/extracted_data}"
export SANDBENCH_VLLM_PORT="${SANDBENCH_VLLM_PORT:-8001}"
export SANDBENCH_VLLM_URL="http://localhost:${SANDBENCH_VLLM_PORT}/v1"

mkdir -p results logs charts

echo "═══════════════════════════════════════════"
echo "  SandBench: Manual Run"
echo "═══════════════════════════════════════════"
echo "  Model:     $MODEL_KEY"
echo "  vLLM:      $SANDBENCH_VLLM_URL"
echo "  Dataset:   $SANDBENCH_DATASET_DIR"
echo "  Extracted: $SANDBENCH_EXTRACTED_DIR"
echo ""

# Check vLLM is up
echo "Checking vLLM connection..."
if ! curl -s "http://localhost:${SANDBENCH_VLLM_PORT}/v1/models" > /dev/null 2>&1; then
    echo "ERROR: vLLM is not running on port $SANDBENCH_VLLM_PORT"
    echo ""
    echo "Start it first:"
    echo "  python -m vllm.entrypoints.openai.api_server \\"
    echo "      --model <HF_MODEL_NAME> --port $SANDBENCH_VLLM_PORT"
    exit 1
fi

echo "vLLM is up. Available models:"
curl -s "http://localhost:${SANDBENCH_VLLM_PORT}/v1/models" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for m in data.get('data', []):
    print(f'  - {m[\"id\"]}')
" 2>/dev/null
echo ""

# Run benchmark
python run_benchmark.py \
    --models "$MODEL_KEY" \
    --dataset-dir "$SANDBENCH_DATASET_DIR" \
    --extracted-dir "$SANDBENCH_EXTRACTED_DIR" \
    --output-dir ./results \
    --log-dir ./logs \
    --vllm-url "$SANDBENCH_VLLM_URL" \
    "$@"

echo ""
echo "Done! Generating charts..."
python generate_graphs.py --results ./results/benchmark_results.json --output ./charts 2>/dev/null || true
python generate_extended_charts.py --results ./results/benchmark_results.json --output ./charts 2>/dev/null || true
python generate_log_viewer.py --results ./results/benchmark_results.json --log-dir ./logs --output ./charts/log_viewer.html 2>/dev/null || true

echo ""
echo "Results: ./results/benchmark_results.json"
echo "Charts:  ./charts/"
echo "Logs:    ./logs/"
echo "Viewer:  ./charts/log_viewer.html"
