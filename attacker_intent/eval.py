"""
eval.py — CyFER-Bench Attacker Intent Evaluation
Evaluates LLMs on predicting attacker intent from pentesting tool execution logs.

Metrics:
  1. BERTScore F1    — semantic similarity (Zhang et al. 2020)
  2. LLM-as-Judge   — holistic correctness scored by GPT-4o (Zheng et al. 2023)

Modes:
  Zero-shot       — single-shot prediction from tool log
  Judge-refined   — GPT-4o asks one probing question → model revises prediction

Run:
    python eval.py --config config.json
"""

import argparse, json, os, re, time, logging, glob
import pandas as pd
from dotenv import load_dotenv
from openai import OpenAI
from bert_score import score as bert_score_fn

load_dotenv()

# -----------------------------------------------------------------------
# Prompts
# -----------------------------------------------------------------------
INTENT_PROMPT = """You are a cybersecurity analyst reviewing a penetration test session.

Given the tool execution log and its output summary below, write ONE sentence describing what the attacker was trying to do.

Be specific — include:
- The action (e.g. enumerate, brute-force, exploit, read, scan)
- The technique or tool used
- The target (IP address, port, file, or service) if visible

Output Summary:
{output_summary}

Full Tool Execution Log:
{full_log}

Respond with only the intent sentence. Nothing else."""

JUDGE_QUESTION_PROMPT = """You are a cybersecurity expert reviewing an AI analyst's prediction.

Tool execution log: {tool_log}

AI prediction: {prediction}

Correct intent: {ground_truth}

The prediction misses something. Ask ONE short, specific question that guides the analyst toward the correct intent WITHOUT giving away the answer. Target whichever is most wrong: the action (what the attacker did), the technique (how), or the target (what/where).

Output only the question. Nothing else."""

REFINE_PROMPT = """You analyzed a pentesting log and predicted the attacker's intent as: "{prediction}"

A reviewer asks: {question}

Re-read the log and revise your prediction.

Output Summary: {output_summary}

Full Tool Execution Log: {tool_log}

Respond with only the revised intent sentence. Nothing else."""

JUDGE_PROMPT = """You are a senior cybersecurity expert evaluating an AI analyst's prediction.

Ground truth attacker intent:
{ground_truth}

AI prediction:
{prediction}

Score the prediction:
1.0 = Fully correct (right action, technique, and target)
0.5 = Partially correct (right action or technique, but missing/wrong target or specifics)
0.0 = Wrong (wrong action or completely off)

Focus only on operational correctness. Ignore wording differences.

Respond with only JSON: {{"score": <0.0|0.5|1.0>, "reason": "<one sentence>"}}"""

# -----------------------------------------------------------------------
# Logger
# -----------------------------------------------------------------------
def setup_logger(log_file: str) -> logging.Logger:
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logger = logging.getLogger("pentest_eval")
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

# -----------------------------------------------------------------------
# Load config + dataset
# -----------------------------------------------------------------------
def load_config(path: str) -> dict:
    with open(path) as f:
        return json.load(f)

def load_datasets(cfg: dict, logger: logging.Logger):
    """
    Returns a list of (xlsx_stem, df, input_cols, gt_col) tuples.
    cfg["dataset"]["path"] may be a folder (glob *.xlsx) or a single file.
    """
    dataset_path = cfg["dataset"]["path"]
    input_cols   = cfg["dataset"]["input_columns"]
    gt_col       = cfg["dataset"]["ground_truth_column"]

    # Resolve xlsx files
    if os.path.isdir(dataset_path):
        xlsx_files = sorted(glob.glob(os.path.join(dataset_path, "*.xlsx")))
    elif os.path.isfile(dataset_path):
        xlsx_files = [dataset_path]
    else:
        raise FileNotFoundError(f"Dataset path not found: {dataset_path}")

    if not xlsx_files:
        raise FileNotFoundError(f"No .xlsx files found in: {dataset_path}")

    datasets = []
    for xlsx_path in xlsx_files:
        stem = os.path.splitext(os.path.basename(xlsx_path))[0]
        df = pd.read_excel(xlsx_path)
        df.columns = [c.replace("\n", " ").strip() for c in df.columns]
        norm_input = [c.replace("\n", " ").strip() for c in input_cols]
        norm_gt    = gt_col.replace("\n", " ").strip()

        for col in norm_input + [norm_gt]:
            if col not in df.columns:
                raise ValueError(
                    f"[{stem}] Column '{col}' not found. Available: {list(df.columns)}"
                )

        df = df.dropna(subset=[norm_gt])
        logger.info(f"  [{stem}] Loaded {len(df)} samples")
        datasets.append((stem, df, norm_input, norm_gt))

    return datasets

# -----------------------------------------------------------------------
# Step 1a: Zero-shot predictions
# -----------------------------------------------------------------------
def run_model(xlsx_stem, df, input_cols, gt_col, model_cfg, cache, logger):
    key    = model_cfg["key"]
    model  = model_cfg["model_string"]
    host   = model_cfg["host"]
    client = OpenAI(base_url=host, api_key="dummy")
    results = []

    logger.info(f"  Model: {key} @ {host}")

    for i, row in df.iterrows():
        output_summary = str(row.get(input_cols[0], "N/A")) if len(input_cols) > 0 else "N/A"
        full_log       = str(row.get(input_cols[1], "N/A")) if len(input_cols) > 1 else "N/A"
        ground_truth   = str(row[gt_col])
        cache_key      = f"{xlsx_stem}__{key}__zs__{i}"

        if cache_key in cache:
            prediction = cache[cache_key]
            logger.debug(f"  Row {i+1}: [CACHED]")
        else:
            try:
                resp = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": INTENT_PROMPT.format(
                        output_summary=output_summary[:500],
                        full_log=full_log[:2500]
                    )}],
                    temperature=0,
                    max_tokens=150
                )
                content    = resp.choices[0].message.content
                prediction = content.strip() if content else ""
                cache[cache_key] = prediction
                logger.info(f"  Row {i+1}: {prediction[:80]}")
                logger.debug(f"  GT:   {ground_truth}")
            except Exception as e:
                prediction = ""
                logger.error(f"  Row {i+1} ERROR: {e}")

        results.append({
            "row":            i + 1,
            "tool":           str(row.get("Tool", "")),
            "output_summary": output_summary[:200],
            "full_log":       full_log[:300],
            "ground_truth":   ground_truth,
            "zero_shot":      {"prediction": prediction},
        })
        time.sleep(0.3)

    return results

# -----------------------------------------------------------------------
# Step 1b: Judge-refined predictions
# -----------------------------------------------------------------------
def run_judge_refined(xlsx_stem, results, input_cols, gt_col, model_cfg,
                      judge_cfg, cache, logger):
    """
    For each sample:
      1. GPT-4o generates ONE probing question (has access to GT).
      2. Target model revises its zero-shot prediction.
    Cache keys: __jr_q__ (question), __jr_p__ (revised prediction).
    """
    key      = model_cfg["key"]
    model    = model_cfg["model_string"]
    host     = model_cfg["host"]
    api_key  = judge_cfg.get("api_key") or os.environ.get("OPENAI_API_KEY", "")
    jmodel   = judge_cfg["model"]
    temp_j   = judge_cfg.get("temperature", 0)

    if not api_key or api_key == "YOUR_OPENAI_KEY_HERE":
        logger.warning("  Judge-refined skipped — no api_key for judge model")
        for r in results:
            r["judge_refined"] = {"question": None, "prediction": None}
        return results

    judge_client  = OpenAI(api_key=api_key)
    target_client = OpenAI(base_url=host, api_key="dummy")

    logger.info(f"  Judge-refined with {jmodel} → {key}")

    for r in results:
        i         = r["row"] - 1          # original df index offset
        zs_pred   = r["zero_shot"]["prediction"]
        gt        = r["ground_truth"]
        tool_log  = r["full_log"]         # already truncated to 300 in results
        out_sum   = r["output_summary"]   # already truncated to 200

        q_cache_key = f"{xlsx_stem}__{key}__jr_q__{i}"
        p_cache_key = f"{xlsx_stem}__{key}__jr_p__{i}"

        # --- 1. Generate probing question ---
        if q_cache_key in cache:
            question = cache[q_cache_key]
            logger.debug(f"  Row {r['row']}: question [CACHED]")
        else:
            if not zs_pred.strip():
                question = "What is the attacker specifically trying to do here?"
            else:
                try:
                    resp = judge_client.chat.completions.create(
                        model=jmodel,
                        messages=[{"role": "user", "content": JUDGE_QUESTION_PROMPT.format(
                            tool_log=tool_log,
                            prediction=zs_pred,
                            ground_truth=gt
                        )}],
                        temperature=temp_j,
                        max_tokens=100
                    )
                    content  = resp.choices[0].message.content
                    question = content.strip() if content else ""
                    logger.info(f"  Row {r['row']} Q: {question[:80]}")
                except Exception as e:
                    question = ""
                    logger.error(f"  Row {r['row']} question ERROR: {e}")
            cache[q_cache_key] = question
            time.sleep(0.3)

        # --- 2. Model refines prediction ---
        if p_cache_key in cache:
            refined_pred = cache[p_cache_key]
            logger.debug(f"  Row {r['row']}: refined [CACHED]")
        else:
            if not question.strip():
                refined_pred = zs_pred
            else:
                try:
                    resp = target_client.chat.completions.create(
                        model=model,
                        messages=[{"role": "user", "content": REFINE_PROMPT.format(
                            prediction=zs_pred,
                            question=question,
                            output_summary=out_sum,
                            tool_log=tool_log
                        )}],
                        temperature=0,
                        max_tokens=150
                    )
                    content      = resp.choices[0].message.content
                    refined_pred = content.strip() if content else ""
                    logger.info(f"  Row {r['row']} refined: {refined_pred[:80]}")
                except Exception as e:
                    refined_pred = zs_pred
                    logger.error(f"  Row {r['row']} refine ERROR: {e}")
            cache[p_cache_key] = refined_pred
            time.sleep(0.3)

        r["judge_refined"] = {"question": question, "prediction": refined_pred}

    return results

# -----------------------------------------------------------------------
# Step 2: BERTScore F1  (runs on a list of (pred, ref) pairs)
# -----------------------------------------------------------------------
def _run_bertscore(preds, refs, logger):
    """Returns list of float scores aligned with input lists."""
    valid = [(i, p, r) for i, (p, r) in enumerate(zip(preds, refs)) if p.strip()]
    scores = [0.0] * len(preds)
    if not valid:
        return scores
    idx, vp, vr = zip(*valid)
    logger.info(f"    BERTScore on {len(vp)} samples...")
    _, _, F1 = bert_score_fn(list(vp), list(vr),
                              lang="en",
                              model_type="distilbert-base-uncased",
                              verbose=False)
    for i, f in zip(idx, F1):
        scores[i] = round(float(f), 4)
    return scores

def compute_bertscore(results, jr_enabled, logger):
    logger.info("  BERTScore F1 (zero-shot)...")
    zs_scores = _run_bertscore(
        [r["zero_shot"]["prediction"] for r in results],
        [r["ground_truth"] for r in results],
        logger
    )
    for r, s in zip(results, zs_scores):
        r["zero_shot"]["bertscore_f1"] = s

    if jr_enabled:
        logger.info("  BERTScore F1 (judge-refined)...")
        jr_scores = _run_bertscore(
            [r["judge_refined"]["prediction"] or "" for r in results],
            [r["ground_truth"] for r in results],
            logger
        )
        for r, s in zip(results, jr_scores):
            r["judge_refined"]["bertscore_f1"] = s

    return results

# -----------------------------------------------------------------------
# Step 3: LLM-as-Judge  (runs on a list of result dicts)
# -----------------------------------------------------------------------
def _judge_one(client, model, temp, ground_truth, prediction, logger, row_id, tag):
    if not prediction or not prediction.strip():
        return 0.0, "empty prediction"
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": JUDGE_PROMPT.format(
                ground_truth=ground_truth,
                prediction=prediction
            )}],
            temperature=temp,
            max_tokens=100
        )
        content = resp.choices[0].message.content or ""
        match   = re.search(r'\{.*\}', content, re.DOTALL)
        if match:
            obj    = json.loads(match.group())
            score  = float(obj.get("score", 0.0))
            reason = obj.get("reason", "")
        else:
            score  = 0.0
            reason = f"parse error: {content[:80]}"
        logger.debug(f"  Row {row_id} [{tag}] judge={score}: {reason}")
        return score, reason
    except Exception as e:
        logger.error(f"  Row {row_id} [{tag}] judge error: {e}")
        return 0.0, str(e)

def compute_llm_judge(results, judge_cfg, jr_enabled, logger):
    api_key = judge_cfg.get("api_key") or os.environ.get("OPENAI_API_KEY", "")
    model   = judge_cfg["model"]
    temp    = judge_cfg.get("temperature", 0)

    if not api_key or api_key == "YOUR_OPENAI_KEY_HERE":
        logger.warning("Judge skipped — set api_key in config judge section")
        for r in results:
            r["zero_shot"]["judge_score"]  = None
            r["zero_shot"]["judge_reason"] = "no api key"
            if jr_enabled:
                r["judge_refined"]["judge_score"]  = None
                r["judge_refined"]["judge_reason"] = "no api key"
        return results

    client = OpenAI(api_key=api_key)
    logger.info(f"  LLM judge ({model}) on {len(results)} samples (zero-shot)...")

    for r in results:
        score, reason = _judge_one(
            client, model, temp,
            r["ground_truth"], r["zero_shot"]["prediction"],
            logger, r["row"], "zs"
        )
        r["zero_shot"]["judge_score"]  = score
        r["zero_shot"]["judge_reason"] = reason
        time.sleep(0.5)

    if jr_enabled:
        logger.info(f"  LLM judge ({model}) on {len(results)} samples (judge-refined)...")
        for r in results:
            score, reason = _judge_one(
                client, model, temp,
                r["ground_truth"], r["judge_refined"]["prediction"],
                logger, r["row"], "jr"
            )
            r["judge_refined"]["judge_score"]  = score
            r["judge_refined"]["judge_reason"] = reason
            time.sleep(0.5)

    return results

# -----------------------------------------------------------------------
# Step 4: Per-sample logs
# -----------------------------------------------------------------------
def write_sample_logs(results, session_name, results_dir, logger):
    log_dir = os.path.join(results_dir, "logs", session_name)
    os.makedirs(log_dir, exist_ok=True)
    for r in results:
        fname = f"row_{r['row']:03d}_{r['tool']}.json"
        path  = os.path.join(log_dir, fname)
        with open(path, "w") as f:
            json.dump(r, f, indent=2)
    logger.info(f"  Per-sample logs → {log_dir}/")

# -----------------------------------------------------------------------
# Step 5: Aggregate
# -----------------------------------------------------------------------
def _mean(vals):
    vals = [v for v in vals if v is not None]
    return round(sum(vals) / len(vals), 4) if vals else 0.0

def aggregate(results, model_key, jr_enabled):
    valid_zs = [r for r in results if r["zero_shot"].get("prediction", "").strip()]
    n, nv    = len(results), len(valid_zs)

    summary = {
        "model":             model_key,
        "total_samples":     n,
        "valid_predictions": nv,
        "parse_rate":        round(nv / n, 3) if n else 0.0,
        "zero_shot": {
            "bertscore_f1": _mean([r["zero_shot"].get("bertscore_f1") for r in valid_zs]),
            "judge_score":  _mean([r["zero_shot"].get("judge_score")  for r in valid_zs]),
        },
    }

    if jr_enabled:
        valid_jr = [r for r in results
                    if r.get("judge_refined", {}).get("prediction", "")]
        summary["judge_refined"] = {
            "bertscore_f1": _mean([r["judge_refined"].get("bertscore_f1") for r in valid_jr]),
            "judge_score":  _mean([r["judge_refined"].get("judge_score")  for r in valid_jr]),
        }

    # Per-tool breakdown
    tools = sorted(set(r["tool"] for r in valid_zs))
    summary["per_tool"] = {}
    for tool in tools:
        tp = [r for r in valid_zs if r["tool"] == tool]
        entry = {
            "n": len(tp),
            "zero_shot": {
                "bertscore_f1": _mean([r["zero_shot"].get("bertscore_f1") for r in tp]),
                "judge_score":  _mean([r["zero_shot"].get("judge_score")  for r in tp]),
            },
        }
        if jr_enabled:
            tp_jr = [r for r in tp if r.get("judge_refined", {}).get("prediction", "")]
            entry["judge_refined"] = {
                "bertscore_f1": _mean([r["judge_refined"].get("bertscore_f1") for r in tp_jr]),
                "judge_score":  _mean([r["judge_refined"].get("judge_score")  for r in tp_jr]),
            }
        summary["per_tool"][tool] = entry

    return summary

# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="CyFER-Bench: Attacker Intent Evaluation"
    )
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    cfg         = load_config(args.config)
    logger      = setup_logger(cfg["output"]["log_file"])
    logger.info("=== CyFER-Bench: Attacker Intent Prediction Eval ===")
    logger.info(f"Config: {args.config}")

    results_dir = cfg["output"]["results_dir"]
    os.makedirs(results_dir, exist_ok=True)
    cache_path  = os.path.join(results_dir, "cache.json")
    cache       = json.load(open(cache_path)) if os.path.exists(cache_path) else {}

    judge_cfg   = cfg["judge"]
    jr_cfg      = cfg.get("judge_refined", {})
    jr_enabled  = jr_cfg.get("enabled", False)

    # Override judge model/key for judge-refined if specified
    if jr_enabled and "model" in jr_cfg:
        jr_judge_cfg = {**judge_cfg, "model": jr_cfg["model"]}
        if "api_key" in jr_cfg and jr_cfg["api_key"]:
            jr_judge_cfg["api_key"] = jr_cfg["api_key"]
    else:
        jr_judge_cfg = judge_cfg

    logger.info(f"Judge-refined mode: {'ON' if jr_enabled else 'OFF'}")

    # Load all xlsx files
    logger.info("\n[0] Loading datasets...")
    datasets = load_datasets(cfg, logger)

    all_summaries = {}

    for xlsx_stem, df, input_cols, gt_col in datasets:
        logger.info(f"\n{'#'*60}")
        logger.info(f"SESSION: {xlsx_stem}  ({len(df)} samples)")
        logger.info(f"{'#'*60}")

        for model_cfg in cfg["models"]:
            if not model_cfg.get("enabled", True):
                logger.info(f"[SKIP] {model_cfg['key']} (disabled)")
                continue

            key = model_cfg["key"]
            logger.info(f"\n{'='*55}")
            logger.info(f"MODEL: {key}")
            logger.info(f"{'='*55}")

            # Step 1a: Zero-shot predictions
            logger.info("\n[1a] Zero-shot predictions...")
            results = run_model(xlsx_stem, df, input_cols, gt_col,
                                model_cfg, cache, logger)
            with open(cache_path, "w") as f:
                json.dump(cache, f)

            # Step 1b: Judge-refined predictions
            if jr_enabled:
                logger.info("\n[1b] Judge-refined predictions...")
                results = run_judge_refined(xlsx_stem, results, input_cols, gt_col,
                                            model_cfg, jr_judge_cfg, cache, logger)
                with open(cache_path, "w") as f:
                    json.dump(cache, f)

            # Step 2: BERTScore F1
            logger.info("\n[2] BERTScore F1...")
            results = compute_bertscore(results, jr_enabled, logger)

            # Step 3: LLM-as-Judge
            logger.info("\n[3] LLM-as-Judge...")
            results = compute_llm_judge(results, judge_cfg, jr_enabled, logger)

            # Step 4: Per-sample logs
            session_tag = f"{xlsx_stem}__{key}"
            write_sample_logs(results, session_tag, results_dir, logger)

            # Step 5: Aggregate
            summary = aggregate(results, key, jr_enabled)
            run_key  = f"{xlsx_stem}__{key}"
            all_summaries[run_key] = summary

            # Print summary
            logger.info(f"\n--- {key} | {xlsx_stem} Results ---")
            logger.info(f"  Samples:       {summary['total_samples']}")
            logger.info(f"  Valid:         {summary['valid_predictions']} "
                        f"({summary['parse_rate']*100:.0f}%)")
            zs = summary["zero_shot"]
            logger.info(f"  Zero-shot   BERTScore F1: {zs['bertscore_f1']:.4f} | "
                        f"Judge: {zs['judge_score']:.4f}")
            if jr_enabled and "judge_refined" in summary:
                jr = summary["judge_refined"]
                logger.info(f"  Judge-refined BERTScore F1: {jr['bertscore_f1']:.4f} | "
                            f"Judge: {jr['judge_score']:.4f}")
            logger.info(f"\n  Per-tool:")
            for tool, s in summary["per_tool"].items():
                zst = s["zero_shot"]
                line = (f"    {tool:<15} n={s['n']:>3} | "
                        f"ZS BERT={zst['bertscore_f1']:.3f} "
                        f"ZS Judge={zst['judge_score']:.3f}")
                if jr_enabled and "judge_refined" in s:
                    jrt = s["judge_refined"]
                    line += (f" | JR BERT={jrt['bertscore_f1']:.3f} "
                             f"JR Judge={jrt['judge_score']:.3f}")
                logger.info(line)

            # Save per-model/session results
            out_path = os.path.join(results_dir, f"{run_key}_results.json")
            with open(out_path, "w") as f:
                json.dump({"summary": summary, "per_sample": results}, f, indent=2)
            logger.info(f"\n  Saved: {out_path}")

    # Save combined summary
    combined = os.path.join(results_dir, "all_results.json")
    with open(combined, "w") as f:
        json.dump(all_summaries, f, indent=2)
    logger.info(f"\nAll results: {combined}")
    logger.info(f"Log file:    {cfg['output']['log_file']}")

if __name__ == "__main__":
    main()
