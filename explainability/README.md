# CWE Explanation Evaluation Pipeline

A benchmark pipeline for evaluating how well LLMs can explain C/C++ vulnerabilities
flagged by static analysis tools (Flawfinder), using the NIST Juliet Test Suite.

---

## Dataset Structure Expected

```
dataset/
  CWE78/
    code/    ← .cpp files (Juliet test cases)
    report/  ← Flawfinder report files (one per .cpp, any extension)
  CWE134/
    code/
    report/
  CWE190/
    code/
    report/
  CWE121/
    code/
    report/
```

---

## Pipeline Steps

### Step 1: Build the dataset JSON

```bash
python build_dataset.py \
  --dataset dataset \
  --output dataset/dataset.json \
  --context 10          # lines before/after flagged line
```

This parses each Flawfinder report, extracts only the CWE-matching findings,
then pulls a ±10 line code window around the flagged line.

Output fields per entry:
- `ground_truth`  : Flawfinder rationale (Tier 1 GT — never shown to LLM)
- `code_window`   : annotated code lines around the flagged line
- `full_function` : full enclosing function (optional, for broader context)
- `severity`      : Flawfinder severity 1-4
- `construct`     : dangerous function flagged (e.g. execl, strcpy)
- `cwe_id`        : CWE being evaluated

### Step 2: Generate LLM explanations

```bash
# Zero-shot (recommended baseline)
python generate_explanations.py \
  --dataset dataset/dataset.json \
  --model gpt-4o \
  --api-key $OPENAI_API_KEY \
  --prompt-mode zero_shot \
  --output-dir explanations

# Few-shot
python generate_explanations.py \
  --prompt-mode few_shot ...

# Ablation: give CWE ID as hint
python generate_explanations.py \
  --prompt-mode hint ...

# vLLM-hosted model (e.g. on djarin)
python generate_explanations.py \
  --model meta-llama/Llama-3.1-70B-Instruct \
  --api-base http://localhost:8001/v1 \
  --api-key EMPTY \
  --prompt-mode zero_shot ...

# Use full enclosing function instead of ±N window
python generate_explanations.py \
  --use-full-function ...
```

### Step 3: Evaluate explanations

```bash
python evaluate.py \
  --results explanations/gpt-4o/zero_shot/results.json \
  --output  explanations/gpt-4o/zero_shot/scores.json \
  --judge-model gpt-4o \
  --api-key $OPENAI_API_KEY
```

---

## Evaluation Axes

| Axis | Method | Weight |
|---|---|---|
| CWE Alignment | Rules-based keyword match | 25% |
| Construct Match | Rules-based exact/partial | 20% |
| Completeness | LLM-as-judge (root cause + impact + fix) | 25% |
| Severity Calibration | LLM-as-judge (urgency language vs. score 1-4) | 15% |
| No Hallucination | LLM-as-judge (inverted hallucination score) | 15% |

Final score = weighted average over all 5 axes (0.0 - 1.0).

---

## LLM Input vs Ground Truth Split

**LLM receives:**
- Code snippet (±N lines around flagged line, with line numbers)
- Flagged line number (marked with >>>>)
- NO CWE ID, NO Flawfinder rationale (zero_shot / few_shot modes)

**Ground truth (never shown to LLM):**
- Flawfinder rationale string
- CWE ID and severity
- Dangerous construct name

---

## Supported Models (tested)

- GPT-4o (OpenAI API)
- Claude Sonnet (via OpenAI-compat proxy)
- Llama-3.1-70B-Instruct (vLLM)
- CodeLlama-34B (vLLM)
- Mistral-7B-Instruct (vLLM)

---

## Notes

- The fuzzy matcher handles Juliet variant mismatches (e.g. execl_33 vs execlp_33 report/code pairs).
- Flawfinder sometimes flags `#define` lines rather than call sites; the full_function field
  captures the actual dangerous call context in those cases.
- Run with `--context 15` or `--use-full-function` for CWE-78 where source and sink are far apart.
