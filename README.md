# CyFER-Bench

**CyFER-Bench: A Multi-Hop Reasoning Benchmark for LLM Agents in Security Operations**

> Large language models (LLMs) are increasingly deployed as autonomous agents in security operations centers (SOC), where they reason over alerts, logs, and threat reports to guide investigation and response. Existing benchmarks evaluate only static knowledge retrieval or single-step tasks in isolation. However, effective threat analysis demands chaining multiple inferential steps. We ask: *can LLMs operationalize multi-hop reasoning across heterogeneous security artifacts and translate it into correct, executable actions?* To this end, we present **CyFER-Bench**, a novel suite of datasets and benchmark tasks that evaluates LLM capabilities across seven coupled reasoning tasks spanning the full threat analysis pipeline.

---

## Overview

CyFER-Bench covers **seven coupled reasoning tasks** across the full threat analysis pipeline, organized into three sub-modules:

| # | Task | Module |
|---|------|--------|
| 1 | Malware Binary Analysis | `malware_analysis/` |
| 2 | TTP Extraction | `malware_analysis/` |
| 3 | TTP-to-CWE Mapping | `malware_analysis/` |
| 4 | Weakness Identification | `vuln_explanation/` |
| 5 | Vulnerable Code Localization and Exploit Inference | `vuln_explanation/` |
| 6 | Attacker Action Sequencing | `malware_analysis/` |
| 7 | Attacker Intent Attribution | `attacker_intent/` |

The benchmark spans both **attacker and defender** perspectives of the SOC pipeline, enabling evaluation of:
- Knowledge extraction from heterogeneous security artifacts (VT sandbox reports, static analysis output, pentest logs)
- Single-step reasoning over structured and unstructured inputs
- Mapping of defensive actions and exploitation strategies to justifications
- Error propagation across the full inference chain under four agentic configurations

---

## Repository Structure

```
cyfer-bench/
├── README.md                    ← this file
├── requirements.txt             ← unified dependencies
├── .gitignore
├── reproduce.sh                 ← end-to-end reproducibility script
│
├── malware_analysis/            ← Tasks 1, 2, 3, 6
│   ├── README.md
│   ├── config.json
│   ├── preprocess.py
│   ├── run_benchmark.py
│   ├── modes/                   ← mode_a.py … mode_d.py
│   ├── tools/                   ← vt_environment.py, llm_utils.py
│   ├── eval/                    ← vt_metrics.py
│   ├── dataset/                 ← 10 sample VT reports included
│   ├── results/
│   ├── charts/
│   └── tables/
│
├── attacker_intent/             ← Task 7
│   ├── README.md
│   ├── config.json
│   ├── eval.py
│   └── dataset/
│
└── vuln_explanation/            ← Tasks 4, 5
    ├── README.md
    ├── build_dataset.py
    ├── generate_explanations.py
    ├── evaluate.py
    └── dataset/
```

---

## Setup

### 1. Create the environment

```bash
conda create -n cyfer python=3.13 -y
conda activate cyfer
pip install -r requirements.txt
```

### 2. Set API keys

```bash
cd malware_analysis
cp .env.example .env   # fill in OPENAI_API_KEY
```

The key is needed only for models with `"client": "openai"` in `config.json`. Leave blank if running local vLLM models only.

### 3. (Optional) Start local vLLM servers

Each local model needs its own vLLM server. Example for one model on port 8002:

```bash
CUDA_VISIBLE_DEVICES=0 python -m vllm.entrypoints.openai.api_server \
  --model meta-llama/Llama-3.1-8B-Instruct \
  --port 8002 --max-model-len 81920
```

---

## Quick Start

### Malware Analysis (Tasks 1–3)

```bash
cd malware_analysis
python preprocess.py --max 10          # preprocess sample data
python run_benchmark.py --max-samples 10 --modes A --models gpt-4o
python generate_graphs.py
```

### Attacker Intent (Task 7)

```bash
cd attacker_intent
python eval.py --config config.json
```

### Vulnerability Explanation (Tasks 4–5)

```bash
cd vuln_explanation
python build_dataset.py --dataset dataset --output dataset/dataset.json
python generate_explanations.py --model gpt-4o --api-key $OPENAI_API_KEY \
       --prompt-mode zero_shot
python evaluate.py --results explanations/gpt-4o/zero_shot/results.json \
       --judge-model gpt-4o --api-key $OPENAI_API_KEY
```

For a full end-to-end run:

```bash
bash reproduce.sh
```

---

## Agentic Configurations

All three modules support evaluation under four configurations:

| Mode | Name | Description |
|------|------|-------------|
| A | Single-Shot | One prompt, one response. Baseline. |
| B | Judge-Refined | Output fed into a deterministic judge loop (up to N iterations). |
| C | Agentic | ReAct loop — model calls tools to investigate step by step. |
| D | Agentic + Judge | Mode C followed by Mode B refinement. |

---

## Dataset

The repository includes **10 samples per module** for quick validation and reproducibility checks. The full dataset used in the paper is available for download separately:

> Full dataset download: [instructions will be provided upon publication]

The `.gitignore` excludes bulk dataset files. To work with the full dataset, place raw files in the appropriate `dataset/` subdirectories and re-run the preprocessing scripts.

---

## Evaluation Metrics

### Malware Analysis Module

| Metric | Description |
|--------|-------------|
| TTP F1 | Set-level F1 between predicted and CAPA-extracted MITRE ATT&CK technique IDs |
| IOC Recall | Per-type recall over IPs, domains, files, registry keys, mutexes |
| Family Accuracy | Exact match (with alias handling) on malware family name |
| Evidence Grounding | Fraction of agent-cited IOCs that exist in ground truth (Modes C/D) |
| Composite Score | Weighted combination of all applicable metrics |

### Attacker Intent Module

| Metric | Description |
|--------|-------------|
| BERTScore F1 | Semantic similarity between prediction and ground truth |
| LLM-as-Judge | GPT-4o holistic correctness score: 0.0 / 0.5 / 1.0 |

### Vulnerability Explanation Module

| Axis | Weight | Method |
|------|--------|--------|
| CWE Alignment | 25% | Rules-based keyword match |
| Construct Match | 20% | Rules-based exact/partial |
| Completeness | 25% | LLM-as-judge |
| Severity Calibration | 15% | LLM-as-judge |
| No Hallucination | 15% | LLM-as-judge (inverted) |

---

## Key Finding

While models succeed on isolated subtasks, **performance degrades sharply with chain length**. This reveals a fundamental gap in current agentic reasoning: the ability to understand does not imply the ability to act.

---

## Requirements

See `requirements.txt` for the full dependency list. Key packages:

- `openai>=1.30.0` — OpenAI-compatible client (also used for local vLLM)
- `vllm==0.19.1` — Local model server
- `bert-score>=0.3.13` — Semantic similarity metric
- `numpy`, `matplotlib` — Evaluation and charting
- `pandas`, `openpyxl` — Dataset loading

---

## Citation

```bibtex
@article{cyferbench2025,
  title   = {CyFER-Bench: A Multi-Hop Reasoning Benchmark for LLM Agents in Security Operations},
  year    = {2025},
}
```
