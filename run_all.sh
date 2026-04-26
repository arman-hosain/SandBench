#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# SandBench: Parallel Benchmark Runner
# Two vLLM servers, one per GPU, models dispatched in parallel
#
# GPU layout (djarin):
#   CUDA 0 = nvidia-smi GPU 1 (RTX 6000 Ada, 48GB)  → port 8001
#   CUDA 1 = nvidia-smi GPU 2 (RTX 6000 Ada, 48GB)  → port 8002
#
# Execution plan:
#   Round 1 (parallel): llama-3.1-8b on GPU0 + qwen3-8b on GPU1
#   Round 2 (serial):   gpt-oss-20b on GPU0  (both GPUs if needed)
#
# Usage:
#   ./run_all.sh                        # full run
#   ./run_all.sh --max-samples=10       # quick test
#   ./run_all.sh --modes=A,B,C,D        # specific modes
#   ./run_all.sh --dry-run              # print plan only
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ── CONFIGURATION ──────────────────────────────────────────────
export SANDBENCH_DATASET_DIR="${SANDBENCH_DATASET_DIR:-/mnt/ahossain4/data/cuckoo/dataset}"
export SANDBENCH_EXTRACTED_DIR="${SANDBENCH_EXTRACTED_DIR:-/mnt/ahossain4/data/cuckoo/sandbench_extracted}"
export SANDBENCH_RESULTS_DIR="${SANDBENCH_RESULTS_DIR:-./results}"
export SANDBENCH_LOG_DIR="${SANDBENCH_LOG_DIR:-./logs}"
export SANDBENCH_CHARTS_DIR="${SANDBENCH_CHARTS_DIR:-./charts}"

# Two vLLM servers, one per GPU
PORT_GPU0=8001
PORT_GPU1=8002
VLLM_GPU_UTIL=0.80
VLLM_WAIT_TIMEOUT=600   # 10 min max for model load
GPU_DRAIN_TIMEOUT=120   # 2 min max for VRAM to release
GPU_DRAIN_POLL=5

# CUDA device indices (as seen by CUDA, not nvidia-smi)
CUDA_IDX_GPU0=1  # nvidia-smi GPU 1
CUDA_IDX_GPU1=2   # nvidia-smi GPU 2

# nvidia-smi physical indices (for memory polling)
NVSMI_IDX_GPU0=1
NVSMI_IDX_GPU1=2

# Model assignments
#   GPU0: llama-3.1-8b (round 1), gpt-oss-20b (round 2)
#   GPU1: qwen3-8b     (round 1), idle          (round 2)
declare -A MODEL_HF=(
    ["llama-3.1-8b"]="meta-llama/Llama-3.1-8B"
    ["gpt-oss-20b"]="openai/gpt-oss-20b"
    ["qwen3-8b"]="Qwen/Qwen3-8B-Base"
)

# ── Argument parsing ───────────────────────────────────────────
MAX_SAMPLES=""
DRY_RUN=false
MODES="A B C D"

for arg in "$@"; do
    case "$arg" in
        --max-samples=*) MAX_SAMPLES="${arg#*=}" ;;
        --dry-run)       DRY_RUN=true ;;
        --modes=*)
            raw="${arg#*=}"
            MODES="${raw//,/ }"
            ;;
    esac
done

SAMPLE_FLAG=""
[ -n "$MAX_SAMPLES" ] && SAMPLE_FLAG="--max-samples $MAX_SAMPLES"

# ── Logging ────────────────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_LOG="./sandbench_run_${TIMESTAMP}.log"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$RUN_LOG"
}
log_section() {
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "  $1"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ── GPU helpers ────────────────────────────────────────────────
gpu_used_mib() {
    local nvsmi_idx="$1"
    nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits \
        --id="$nvsmi_idx" 2>/dev/null | head -1 | tr -d ' ' || echo "99999"
}

wait_gpu_drain() {
    local nvsmi_idx="$1"
    local label="$2"
    local elapsed=0
    log "  Waiting for $label (nvidia-smi GPU $nvsmi_idx) to drain..."
    while [ $elapsed -lt $GPU_DRAIN_TIMEOUT ]; do
        local used
        used=$(gpu_used_mib "$nvsmi_idx")
        if [ "$used" -lt 500 ] 2>/dev/null; then
            log "  $label clear: ${used} MiB (${elapsed}s)"
            return 0
        fi
        if [ $((elapsed % 20)) -eq 0 ] && [ $elapsed -gt 0 ]; then
            log "  $label draining: ${used} MiB (${elapsed}s)"
        fi
        sleep $GPU_DRAIN_POLL
        elapsed=$((elapsed + GPU_DRAIN_POLL))
    done
    log "  WARNING: $label did not drain after ${GPU_DRAIN_TIMEOUT}s — proceeding"
}

show_gpu_status() {
    log "  GPU status:"
    local u0; u0=$(gpu_used_mib "$NVSMI_IDX_GPU0")
    local u1; u1=$(gpu_used_mib "$NVSMI_IDX_GPU1")
    log "    GPU0 (nvidia-smi $NVSMI_IDX_GPU0): ${u0} MiB used"
    log "    GPU1 (nvidia-smi $NVSMI_IDX_GPU1): ${u1} MiB used"
}

# ── vLLM lifecycle ─────────────────────────────────────────────
PID_GPU0=""
PID_GPU1=""

kill_vllm_on_port() {
    local port="$1"
    local pid_var="$2"      # name of the PID variable (PID_GPU0 or PID_GPU1)
    local nvsmi_idx="$3"
    local label="$4"

    local pid="${!pid_var}"

    log "  Stopping vLLM on $label (port $port)..."

    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        local waited=0
        while kill -0 "$pid" 2>/dev/null && [ $waited -lt 15 ]; do
            sleep 1; waited=$((waited+1))
        done
        if kill -0 "$pid" 2>/dev/null; then
            log "  SIGKILL → PID $pid"
            kill -KILL "$pid" 2>/dev/null || true
            sleep 2
        fi
        # Clear the variable by name
        printf -v "$pid_var" ""
    fi

    pkill -f "vllm.*--port ${port}" 2>/dev/null || true
    fuser -k "${port}/tcp" 2>/dev/null || true
    sleep 2
    wait_gpu_drain "$nvsmi_idx" "$label"
}

kill_all_vllm() {
    log "Stopping all vLLM servers..."
    # Kill both in parallel, then wait for both GPUs to drain
    if [ -n "$PID_GPU0" ] && kill -0 "$PID_GPU0" 2>/dev/null; then
        kill -TERM "$PID_GPU0" 2>/dev/null || true
    fi
    if [ -n "$PID_GPU1" ] && kill -0 "$PID_GPU1" 2>/dev/null; then
        kill -TERM "$PID_GPU1" 2>/dev/null || true
    fi
    sleep 5
    pkill -f "vllm.*--port ${PORT_GPU0}" 2>/dev/null || true
    pkill -f "vllm.*--port ${PORT_GPU1}" 2>/dev/null || true
    fuser -k "${PORT_GPU0}/tcp" 2>/dev/null || true
    fuser -k "${PORT_GPU1}/tcp" 2>/dev/null || true
    PID_GPU0=""
    PID_GPU1=""
    sleep 2
    wait_gpu_drain "$NVSMI_IDX_GPU0" "GPU0"
    wait_gpu_drain "$NVSMI_IDX_GPU1" "GPU1"
}

start_vllm_on_gpu() {
    local model_hf="$1"
    local model_key="$2"
    local cuda_idx="$3"     # CUDA device index
    local port="$4"
    local pid_var="$5"      # name of variable to store PID
    local label="$6"

    local vllm_log="${SANDBENCH_LOG_DIR}/vllm_${model_key}_${TIMESTAMP}.log"
    log "  Starting vLLM on $label: $model_hf"
    log "    CUDA_VISIBLE_DEVICES=$cuda_idx  port=$port  log=$vllm_log"

    CUDA_VISIBLE_DEVICES="$cuda_idx" \
    python -m vllm.entrypoints.openai.api_server \
        --model "$model_hf" \
        --port "$port" \
        --max-model-len 8192 \
        --gpu-memory-utilization "$VLLM_GPU_UTIL" \
        --trust-remote-code \
        --disable-log-requests \
        > "$vllm_log" 2>&1 &

    local pid=$!
    printf -v "$pid_var" "%d" "$pid"
    log "    PID: $pid"

    # Wait for health
    local elapsed=0
    while [ $elapsed -lt $VLLM_WAIT_TIMEOUT ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            log "  ERROR: vLLM on $label died during startup"
            tail -20 "$vllm_log" | while IFS= read -r line; do log "  | $line"; done
            printf -v "$pid_var" ""
            return 1
        fi
        if curl -sf "http://localhost:${port}/health" > /dev/null 2>&1; then
            log "  $label ready (${elapsed}s)"
            return 0
        fi
        sleep 5; elapsed=$((elapsed+5))
        if [ $((elapsed % 30)) -eq 0 ]; then
            local last; last=$(tail -1 "$vllm_log" 2>/dev/null || echo "")
            log "  $label waiting ${elapsed}s — ${last:0:100}"
        fi
    done

    log "  ERROR: $label not healthy after ${VLLM_WAIT_TIMEOUT}s"
    tail -20 "$vllm_log" | while IFS= read -r line; do log "  | $line"; done
    return 1
}

# ── Benchmark runner ───────────────────────────────────────────
run_benchmark_for_model() {
    local model_key="$1"
    local port="$2"
    local label="$3"
    local vllm_url="http://localhost:${port}/v1"

    log "  [$label] Running benchmark: $model_key  modes=$MODES"
    python run_benchmark.py \
        --models "$model_key" \
        --modes $MODES \
        --vllm-url "$vllm_url" \
        --dataset-dir "$SANDBENCH_DATASET_DIR" \
        --extracted-dir "$SANDBENCH_EXTRACTED_DIR" \
        --output-dir "$SANDBENCH_RESULTS_DIR" \
        --log-dir "$SANDBENCH_LOG_DIR" \
        $SAMPLE_FLAG \
        2>&1 | tee -a "$RUN_LOG"
}

# ── Trap ───────────────────────────────────────────────────────
trap 'log "Interrupted — cleaning up"; kill_all_vllm; exit 1' INT TERM

# ── Preflight ──────────────────────────────────────────────────
mkdir -p "$SANDBENCH_RESULTS_DIR" "$SANDBENCH_LOG_DIR" "$SANDBENCH_CHARTS_DIR"

log "═══════════════════════════════════════════════════════"
log "  SandBench Parallel Benchmark"
log "═══════════════════════════════════════════════════════"
log "  GPU0: CUDA $CUDA_IDX_GPU0 (nvidia-smi $NVSMI_IDX_GPU0) → port $PORT_GPU0"
log "  GPU1: CUDA $CUDA_IDX_GPU1 (nvidia-smi $NVSMI_IDX_GPU1) → port $PORT_GPU1"
log "  Modes:       $MODES"
log "  Max samples: ${MAX_SAMPLES:-all}"
log "  Dry run:     $DRY_RUN"
log "  Run log:     $RUN_LOG"
log ""
show_gpu_status
log ""

if [ "$DRY_RUN" = true ]; then
    log "DRY RUN — execution plan:"
    log ""
    log "  Round 1 (parallel):"
    log "    GPU0 port $PORT_GPU0 → llama-3.1-8b"
    log "    GPU1 port $PORT_GPU1 → qwen3-8b"
    log "    Both benchmarks run simultaneously"
    log ""
    log "  Round 2 (serial, GPU0 only):"
    log "    GPU0 port $PORT_GPU0 → gpt-oss-20b"
    log "    (GPU1 idle — 20B model may need both GPUs)"
    log ""
    log "  → merge → graphs → log viewer"
    exit 0
fi

# Kill any lingering vLLM from previous runs
kill_all_vllm

TOTAL_START=$(date +%s)
FAILED_MODELS=()

# ══════════════════════════════════════════════════════════════
# ROUND 1: llama-3.1-8b (GPU0) + qwen3-8b (GPU1) in parallel
# ══════════════════════════════════════════════════════════════
log_section "Round 1: parallel  [llama-3.1-8b @ GPU0] + [qwen3-8b @ GPU1]"

# Start both vLLM servers
started_gpu0=false
started_gpu1=false

if start_vllm_on_gpu \
    "${MODEL_HF[llama-3.1-8b]}" "llama-3.1-8b" \
    "$CUDA_IDX_GPU0" "$PORT_GPU0" "PID_GPU0" "GPU0"; then
    started_gpu0=true
else
    log "WARNING: GPU0 vLLM failed — llama-3.1-8b will be skipped"
    FAILED_MODELS+=("llama-3.1-8b")
fi

if start_vllm_on_gpu \
    "${MODEL_HF[qwen3-8b]}" "qwen3-8b" \
    "$CUDA_IDX_GPU1" "$PORT_GPU1" "PID_GPU1" "GPU1"; then
    started_gpu1=true
else
    log "WARNING: GPU1 vLLM failed — qwen3-8b will be skipped"
    FAILED_MODELS+=("qwen3-8b")
fi

show_gpu_status

# Launch both benchmarks in parallel using background jobs
BENCH_PID_GPU0=""
BENCH_PID_GPU1=""

if [ "$started_gpu0" = true ]; then
    run_benchmark_for_model "llama-3.1-8b" "$PORT_GPU0" "GPU0" &
    BENCH_PID_GPU0=$!
    log "  GPU0 benchmark PID: $BENCH_PID_GPU0"
fi

if [ "$started_gpu1" = true ]; then
    run_benchmark_for_model "qwen3-8b" "$PORT_GPU1" "GPU1" &
    BENCH_PID_GPU1=$!
    log "  GPU1 benchmark PID: $BENCH_PID_GPU1"
fi

# Wait for both benchmarks to finish
log "  Waiting for Round 1 benchmarks to complete..."
R1_START=$(date +%s)

if [ -n "$BENCH_PID_GPU0" ]; then
    if wait "$BENCH_PID_GPU0"; then
        log "  GPU0 (llama-3.1-8b) benchmark done"
    else
        log "  WARNING: GPU0 benchmark non-zero exit"
        FAILED_MODELS+=("llama-3.1-8b-benchmark")
    fi
fi

if [ -n "$BENCH_PID_GPU1" ]; then
    if wait "$BENCH_PID_GPU1"; then
        log "  GPU1 (qwen3-8b) benchmark done"
    else
        log "  WARNING: GPU1 benchmark non-zero exit"
        FAILED_MODELS+=("qwen3-8b-benchmark")
    fi
fi

R1_END=$(date +%s)
log "  Round 1 done in $(( (R1_END-R1_START)/60 ))m $(( (R1_END-R1_START)%60 ))s"

# Shut down both vLLM servers and drain both GPUs
log_section "Round 1 teardown — draining both GPUs"
kill_all_vllm
show_gpu_status

# ══════════════════════════════════════════════════════════════
# ROUND 2: gpt-oss-20b — try GPU0 first, fall back to both GPUs
# ══════════════════════════════════════════════════════════════
log_section "Round 2: gpt-oss-20b"

R2_START=$(date +%s)

# Try single-GPU first (GPU0 only)
log "  Attempting single-GPU load (CUDA 0)..."
started_r2=false

if start_vllm_on_gpu \
    "${MODEL_HF[gpt-oss-20b]}" "gpt-oss-20b" \
    "$CUDA_IDX_GPU0" "$PORT_GPU0" "PID_GPU0" "GPU0"; then
    started_r2=true
else
    # Single GPU failed — retry with tensor parallelism across both GPUs
    log "  Single-GPU failed — retrying with tensor_parallel_size=2 (both GPUs)"
    kill_vllm_on_port "$PORT_GPU0" "PID_GPU0" "$NVSMI_IDX_GPU0" "GPU0"

    local vllm_log="${SANDBENCH_LOG_DIR}/vllm_gpt-oss-20b_tp2_${TIMESTAMP}.log"
    log "  Starting vLLM with --tensor-parallel-size 2"
    log "    CUDA_VISIBLE_DEVICES=0,1  port=$PORT_GPU0  log=$vllm_log"

    CUDA_VISIBLE_DEVICES="0,1" \
    python -m vllm.entrypoints.openai.api_server \
        --model "${MODEL_HF[gpt-oss-20b]}" \
        --port "$PORT_GPU0" \
        --max-model-len 8192 \
        --gpu-memory-utilization "$VLLM_GPU_UTIL" \
        --tensor-parallel-size 2 \
        --trust-remote-code \
        --disable-log-requests \
        > "$vllm_log" 2>&1 &

    PID_GPU0=$!
    log "  PID: $PID_GPU0"

    elapsed=0
    while [ $elapsed -lt $VLLM_WAIT_TIMEOUT ]; do
        if ! kill -0 "$PID_GPU0" 2>/dev/null; then
            log "  ERROR: vLLM (tp2) died during startup"
            tail -20 "$vllm_log" | while IFS= read -r line; do log "  | $line"; done
            break
        fi
        if curl -sf "http://localhost:${PORT_GPU0}/health" > /dev/null 2>&1; then
            log "  gpt-oss-20b (tp2) ready (${elapsed}s)"
            started_r2=true
            break
        fi
        sleep 5; elapsed=$((elapsed+5))
        if [ $((elapsed % 30)) -eq 0 ]; then
            local last; last=$(tail -1 "$vllm_log" 2>/dev/null || echo "")
            log "  Waiting ${elapsed}s — ${last:0:100}"
        fi
    done
fi

if [ "$started_r2" = true ]; then
    show_gpu_status
    run_benchmark_for_model "gpt-oss-20b" "$PORT_GPU0" "GPU0" || {
        log "WARNING: gpt-oss-20b benchmark non-zero exit"
        FAILED_MODELS+=("gpt-oss-20b-benchmark")
    }
    R2_END=$(date +%s)
    log "  Round 2 done in $(( (R2_END-R2_START)/60 ))m $(( (R2_END-R2_START)%60 ))s"
else
    log "SKIPPING gpt-oss-20b — could not start vLLM on single or dual GPU"
    FAILED_MODELS+=("gpt-oss-20b")
fi

# Final teardown
kill_all_vllm

# ── Merge results ──────────────────────────────────────────────
log_section "Merging results"
python3 << 'MERGE_SCRIPT'
import json, glob, os, time

results_dir = os.environ.get("SANDBENCH_RESULTS_DIR", "./results")
all_results, seen = [], set()

for f in sorted(glob.glob(os.path.join(results_dir, "benchmark_results*.json"))):
    with open(f) as fh:
        data = json.load(fh)
    for r in data.get("results", []):
        key = (r["sample_id"], r["model_key"], r["mode"])
        if key not in seen:
            seen.add(key); all_results.append(r)

merged = {
    "benchmark": "SandBench",
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    "config": {
        "models":            sorted(set(r["model_key"] for r in all_results)),
        "modes":             sorted(set(r["mode"]      for r in all_results)),
        "num_samples":       len(set(r["sample_id"]   for r in all_results)),
        "total_experiments": len(all_results),
    },
    "results": all_results,
}

out_path = os.path.join(results_dir, "benchmark_results.json")
with open(out_path, "w") as f:
    json.dump(merged, f, indent=2)
print(f"  Merged {len(all_results)} results → {out_path}")
MERGE_SCRIPT

# ── Charts ─────────────────────────────────────────────────────
log_section "Generating charts"
python generate_graphs.py \
    --results "$SANDBENCH_RESULTS_DIR/benchmark_results.json" \
    --output  "$SANDBENCH_CHARTS_DIR" 2>&1 | tee -a "$RUN_LOG"

python generate_extended_charts.py \
    --results "$SANDBENCH_RESULTS_DIR/benchmark_results.json" \
    --output  "$SANDBENCH_CHARTS_DIR" 2>&1 | tee -a "$RUN_LOG"

python generate_log_viewer.py \
    --results  "$SANDBENCH_RESULTS_DIR/benchmark_results.json" \
    --log-dir  "$SANDBENCH_LOG_DIR" \
    --output   "$SANDBENCH_CHARTS_DIR/log_viewer.html" 2>&1 | tee -a "$RUN_LOG"

# ── Final summary ──────────────────────────────────────────────
TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$((TOTAL_END - TOTAL_START))

log ""
log "═══════════════════════════════════════════════════════"
log "  BENCHMARK COMPLETE"
log "═══════════════════════════════════════════════════════"
log "  Total time:  $(( TOTAL_ELAPSED/3600 ))h $(( (TOTAL_ELAPSED%3600)/60 ))m"
log "  Results:     $SANDBENCH_RESULTS_DIR/benchmark_results.json"
log "  Charts:      $SANDBENCH_CHARTS_DIR/"
log "  Log viewer:  $SANDBENCH_CHARTS_DIR/log_viewer.html"
log "  Run log:     $RUN_LOG"

if [ ${#FAILED_MODELS[@]} -gt 0 ]; then
    log ""
    log "  FAILURES:"
    for m in "${FAILED_MODELS[@]}"; do log "    - $m"; done
fi

log ""
log "  scp djarin:$(pwd)/$SANDBENCH_CHARTS_DIR/log_viewer.html . && open log_viewer.html"