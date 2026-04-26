"""
SandBench: LLM Malware Analysis Benchmark
Configuration and shared constants.

4 Evaluation Modes × 3 LLMs = 12 experimental conditions

All paths can be overridden via environment variables:
    export SANDBENCH_DATASET_DIR=/path/to/dataset
    export SANDBENCH_EXTRACTED_DIR=/path/to/extracted_data
    export SANDBENCH_VLLM_URL=http://localhost:8001/v1
"""

import os

# ── LLM Models to benchmark ──
# When running one-at-a-time on vLLM, the "name" is what vLLM serves as model ID.
# You may need to adjust "name" to match what vLLM reports in /v1/models.
MODELS = {
    "llama-3.1-8b": {
        "name": "meta-llama/Llama-3.1-8B",
        "short": "Llama-3.1-8B",
        "color": "#1E88E5",  # blue
        "vllm_args": "--model meta-llama/Llama-3.1-8B --max-model-len 8192 --gpu-memory-utilization 0.90",
    },
    "gpt-oss-20b": {
        "name": "openai/gpt-oss-20b",
        "short": "GPT-OSS-20B",
        "color": "#43A047",  # green
        "vllm_args": "--model openai/gpt-oss-20b --max-model-len 8192 --gpu-memory-utilization 0.90",
    },
    "qwen3-8b": {
        "name": "Qwen/Qwen3-8B-Base",
        "short": "Qwen3-8B",
        "color": "#E53935",  # red
        "vllm_args": "--model Qwen/Qwen3-8B-Base --max-model-len 8192 --gpu-memory-utilization 0.90",
    },
}

# ── Evaluation Modes ──
MODES = {
    "A": {
        "name": "Single-Shot",
        "description": "Single prompt → analysis. No judge, no agents.",
        "judge": False,
        "agentic": False,
    },
    "B": {
        "name": "Judge-Refined",
        "description": "Single prompt → judge feedback loop (up to 5 iterations).",
        "judge": True,
        "agentic": False,
    },
    "C": {
        "name": "Agentic",
        "description": "Multi-step investigation (orient→hypothesize→investigate→refine). No judge.",
        "judge": False,
        "agentic": True,
    },
    "D": {
        "name": "Agentic + Judge",
        "description": "Multi-step investigation + judge feedback after each cycle.",
        "judge": True,
        "agentic": True,
    },
}

# ── vLLM Configuration ──
VLLM_BASE_URL = os.environ.get("SANDBENCH_VLLM_URL", "http://localhost:8001/v1")
VLLM_API_KEY = os.environ.get("SANDBENCH_VLLM_KEY", "EMPTY")
VLLM_PORT = int(os.environ.get("SANDBENCH_VLLM_PORT", "8001"))
MAX_TOKENS = 2048
TEMPERATURE = 0.3

# ── Agentic Mode Config ──
AGENT_BUDGET = 50           # max tool calls per investigation

# ── Judge Config ──
JUDGE_MAX_ITERATIONS = 5

# ── File Paths (override with env vars or --flags) ──
#
# Defaults set for djarin.cs.utep.edu:
#
DATASET_DIR = os.environ.get("SANDBENCH_DATASET_DIR", "/mnt/ahossain4/data/cuckoo/dataset")
EXTRACTED_DIR = os.environ.get("SANDBENCH_EXTRACTED_DIR", "/mnt/ahossain4/data/cuckoo/extracted_data")
RESULTS_BASE_DIR = os.environ.get("SANDBENCH_RESULTS_DIR", "./results")
LOG_DIR = os.environ.get("SANDBENCH_LOG_DIR", "./logs")
CHARTS_DIR = os.environ.get("SANDBENCH_CHARTS_DIR", "./charts")
