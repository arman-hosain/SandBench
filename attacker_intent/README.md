# CyFER-Bench — Attacker Intent Module

**CyFER-Bench Task covered:** (7) Attacker Intent Attribution

Evaluates LLMs on predicting attacker intent from pentesting tool execution logs. Given tool execution logs and an output summary, the model must predict what the attacker was trying to do. Scored with BERTScore F1 and GPT-4o-as-judge.

---

## Project Structure

```
attacker_intent/
├── config.json          # Runtime settings: dataset path, models, judge config
├── eval.py              # Main evaluation script
└── dataset/
    └── pentest_dataset_expanded.xlsx   # Labeled pentesting session dataset
```

---

## Task

**Input to LLM:** Tool execution log (column: Full Tool Input) + output summary (column: Output Summary)

**Prediction target:** What was the attacker trying to do? (column: Ground Truth User Intent)

**Tools covered:** nmap, Metasploit (`msf_run`, `msf_search`), shell, proxychains, SSH

---

## Setup

```bash
conda activate cyfer
pip install -r ../requirements.txt
```

Start one vLLM server per model to evaluate:

```bash
CUDA_VISIBLE_DEVICES=0 python -m vllm.entrypoints.openai.api_server \
  --model meta-llama/Meta-Llama-3-8B-Instruct \
  --port 8001 --max-model-len 8192
```

---

## Configuration (`config.json`)

```json
{
  "dataset": {
    "path": "./dataset/pentest_dataset_expanded.xlsx",
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
  "output": {
    "results_dir": "./results",
    "log_file": "./results/run.log"
  }
}
```

Set `"enabled": false` to skip a model without deleting its config entry. Leave `api_key` blank to skip the LLM judge (BERTScore F1 still runs).

---

## Run

```bash
python eval.py --config config.json
```

The script is fully resumable — predictions are cached in `results/cache.json`. Re-run the same command after an interruption to continue from where it stopped.

To re-run from scratch (e.g. after changing the prompt):

```bash
rm results/cache.json
python eval.py --config config.json
```

---

## Output

| File | Description |
|------|-------------|
| `results/cache.json` | Cached LLM predictions per row |
| `results/<model_key>_results.json` | Per-sample predictions and scores for one model |
| `results/all_results.json` | Summary across all models |
| `results/run.log` | Full timestamped log (appends on every run) |

---

## Metrics

**BERTScore F1** — semantic similarity between prediction and ground truth using BERT embeddings. Handles paraphrasing. Range: 0.0–1.0.

**LLM-as-Judge Score** — GPT-4o reads prediction and ground truth and assigns:
- `1.0` = fully correct (right action, technique, and target)
- `0.5` = partially correct (right action or technique, wrong/missing target)
- `0.0` = wrong
