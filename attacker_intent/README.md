# CyFER-Bench — Attacker Intent Attribution

**Module**: Attacker Intent Prediction  
**Task**: Given a pentesting tool execution log, predict the attacker's intent in a single natural-language sentence.

---

## Overview

This module evaluates language models on their ability to infer attacker intent from real penetration-test session logs.
Each sample contains a tool execution record (tool name, arguments, command output) and a ground-truth intent sentence written by a human expert following the pattern:

> `<Action> <Technique> on <Target>`
>
> e.g., *"Brute-force SNMP community strings on 10.0.2.2:161"*

### Evaluation Modes

| Mode | Description |
|------|-------------|
| **Zero-shot** | Model receives the tool log and outputs one intent sentence directly. |
| **Judge-refined** | GPT-4o generates one probing question (with access to ground truth) that targets the most wrong component of the zero-shot prediction (action / technique / target). The model then revises its answer. Both predictions are scored side-by-side. |

### Metrics

| Metric | Description |
|--------|-------------|
| **BERTScore F1** | Semantic similarity between prediction and ground truth using `distilbert-base-uncased`. |
| **LLM-as-Judge** | GPT-4o scores each prediction `0.0` (wrong), `0.5` (partial), or `1.0` (fully correct) based on operational correctness. |

Both metrics are reported for zero-shot and judge-refined predictions independently.

---

## Dataset

- **Location**: `dataset/` folder — all `*.xlsx` files are loaded automatically.
- **Format**: Each xlsx contains one session of pentesting logs with the following columns:

| Column | Description |
|--------|-------------|
| `#` | Row index |
| `Time` | Timestamp within session |
| `Step in Task` | Step number in the pentest task |
| `Tool` | Tool invoked (`msf_run`, `shell`, `nmap`, etc.) |
| `Arguments` | CLI arguments or module options |
| `Output Summary` | Short human-written summary of tool output |
| `Full Tool Input` | Raw full execution log (command + output) |
| `Ground Truth (User Intent)` | Expert-annotated intent sentence |

Multiple xlsx files in `dataset/` represent different pentesting sessions and are evaluated independently.

---

## Directory Structure

```
attacker_intent/
├── eval.py              # Main evaluation script
├── config.json          # Runtime configuration
├── dataset/
│   └── *.xlsx           # One or more session files
└── results/
    ├── cache.json        # Prediction cache (zero-shot + judge-refined)
    ├── run.log           # Full execution log
    ├── all_results.json  # Combined summary across all sessions and models
    ├── <session>__<model>_results.json   # Per-session/model summary + per_sample list
    └── logs/
        └── <session>__<model>/
            └── row_<N>_<tool>.json       # Per-sample detailed log
```

### Per-sample log format (`logs/<session>__<model>/row_NNN_<tool>.json`)

```json
{
  "row": 3,
  "tool": "msf_run",
  "output_summary": "...",
  "full_log": "...",
  "ground_truth": "Brute-force SNMP community strings on 10.0.2.2:161",
  "zero_shot": {
    "prediction": "Scanning SNMP service on 10.0.2.2",
    "bertscore_f1": 0.8821,
    "judge_score": 0.5,
    "judge_reason": "Correct target but misses brute-force action."
  },
  "judge_refined": {
    "question": "What specific operation is the tool performing against the SNMP service?",
    "prediction": "Brute-force SNMP community strings on 10.0.2.2:161",
    "bertscore_f1": 0.9743,
    "judge_score": 1.0,
    "judge_reason": "Fully correct — action, technique, and target all match."
  }
}
```

---

## Configuration (`config.json`)

```json
{
  "dataset": {
    "path": "./dataset",
    "input_columns": ["Output Summary", "Full Tool Input"],
    "ground_truth_column": "Ground Truth\n(User Intent)"
  },
  "models": [
    {
      "key": "llama3-8b",
      "model_string": "meta-llama/Meta-Llama-3-8B-Instruct",
      "host": "http://localhost:8001/v1",
      "enabled": true
    }
  ],
  "judge": {
    "model": "gpt-4o",
    "api_key": "",
    "temperature": 0
  },
  "judge_refined": {
    "enabled": true,
    "model": "gpt-4o",
    "api_key": ""
  },
  "output": {
    "results_dir": "./results",
    "log_file": "./results/run.log"
  }
}
```

**Key fields:**

| Field | Description |
|-------|-------------|
| `dataset.path` | Folder path (all `*.xlsx` inside are used) or path to a single xlsx file |
| `models[].host` | Base URL of a vLLM-compatible OpenAI API server |
| `models[].enabled` | Set `false` to skip a model without removing it |
| `judge.api_key` | OpenAI API key for LLM-as-Judge scoring (or set `OPENAI_API_KEY` env var) |
| `judge_refined.enabled` | Toggle judge-refined evaluation on/off |
| `judge_refined.model` | GPT model used to generate the probing question |
| `judge_refined.api_key` | Optional override key for the question-generation model |

> **Tip**: Leave `api_key` fields empty and export `OPENAI_API_KEY` instead to keep credentials out of the config file.

---

## Running

```bash
cd attacker_intent/

# Default config
python eval.py

# Custom config
python eval.py --config config.json
```

**Dependencies** (install once from repo root):
```bash
pip install -r requirements.txt
```

Key packages: `openai`, `bert-score`, `pandas`, `openpyxl`, `python-dotenv`

---

## Caching

All model predictions are cached in `results/cache.json` after each API call.
Re-running the script skips already-computed predictions (zero-shot and judge-refined separately).
Cache keys follow the pattern:

| Prediction type | Cache key |
|-----------------|-----------|
| Zero-shot | `<xlsx_stem>__<model_key>__zs__<row_index>` |
| Judge question | `<xlsx_stem>__<model_key>__jr_q__<row_index>` |
| Refined prediction | `<xlsx_stem>__<model_key>__jr_p__<row_index>` |

This ensures predictions from different sessions and models never collide.

---

## Output

After a run, `results/` contains:

- **`all_results.json`** — high-level summary across all sessions and models
- **`<session>__<model>_results.json`** — full summary + per-sample array for one run
- **`logs/<session>__<model>/row_NNN_<tool>.json`** — detailed per-sample breakdown

Summary JSON structure:

```json
{
  "model": "llama3-8b",
  "total_samples": 46,
  "valid_predictions": 46,
  "parse_rate": 1.0,
  "zero_shot": {
    "bertscore_f1": 0.8512,
    "judge_score": 0.6087
  },
  "judge_refined": {
    "bertscore_f1": 0.9134,
    "judge_score": 0.8261
  },
  "per_tool": {
    "msf_run": {
      "n": 20,
      "zero_shot":     {"bertscore_f1": 0.862, "judge_score": 0.625},
      "judge_refined": {"bertscore_f1": 0.921, "judge_score": 0.850}
    }
  }
}
```
