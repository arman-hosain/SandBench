"""
SandBench Mode B: Judge-Refined Analysis (VT Edition)

Mode A output -> evidence feedback -> analyst refinement, up to N iterations.
Judge checks whether predicted TTPs align with ground truth,
then sends evidence-only behavior feedback without revealing TTP IDs.
"""

import json
import time
import re
from tools.llm_utils import safe_llm_call
from modes.mode_a import run_mode_a

REFINE_SYSTEM = """You are an expert malware analyst. A senior reviewer identified gaps in your previous analysis.

Output the COMPLETE updated analysis as a single valid JSON object. Re-answer all three questions incorporating the reviewer's feedback. No text before or after the JSON.

Required schema:
{
  "q1": {
    "verdict": "MALICIOUS | SUSPICIOUS | BENIGN",
    "explanation": "<updated reasoning>"
  },
  "q2": {
    "family": ["<one or more from: Ransomware, Trojan, Adware, Dropper, Spyware, Worm, PUA, Backdoor, Unknown>"],
    "explanation": "<updated reasoning>"
  },
  "q3": {
    "ttps": [
      {"id": "T1027", "name": "<technique name>"}
    ]
  }
}

Reviewer feedback may identify behavior phrases evidenced in the report, but it will not provide ATT&CK IDs.
Map those behavior phrases to real MITRE ATT&CK Enterprise technique IDs only when you know the exact mapping.
If you are unsure of the exact ID, omit it rather than inventing one.
Do NOT use placeholder IDs such as T1234."""


def _count_ttps_in_output(output):
    try:
        data = json.loads(output)
        return set(
            t["id"].split(".")[0].upper()
            for t in data.get("q3", {}).get("ttps", [])
            if isinstance(t, dict) and t.get("id")
        )
    except Exception:
        return set(t.split(".")[0].upper() for t in re.findall(r"T\d{4}(?:\.\d{3})?", output))


def _is_structured(output):
    try:
        data = json.loads(output.strip())
        return "q1" in data and "q3" in data
    except Exception:
        return False


def _gt_ttp_map(gt):
    result = {}
    for t in gt.get("ttps", []):
        tid = (t["id"] if isinstance(t, dict) else str(t)).split(".")[0].upper()
        desc = t.get("signature_description", "") if isinstance(t, dict) else ""
        result[tid] = desc.strip()
    return result


def _score_ttp_prediction(output, gt):
    gt_set = set(_gt_ttp_map(gt))
    pred_set = _count_ttps_in_output(output)
    tp = len(gt_set & pred_set)
    fp = len(pred_set - gt_set)
    fn = len(gt_set - pred_set)
    precision = tp / len(pred_set) if pred_set else 0.0
    recall = tp / len(gt_set) if gt_set else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if precision + recall > 0 else 0.0)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "f1": round(f1, 4),
        "pred_ttps": sorted(pred_set),
        "missing_ttps": sorted(gt_set - pred_set),
        "hallucinated_ttps": sorted(pred_set - gt_set),
    }


def _score_rank(score):
    return (score["tp"], -score["fp"], score["f1"])


def _judge_needs_more(output, gt):
    """
    Returns (needs_more, gap_summary, missed_behaviors).
    TTP IDs are used internally only; feedback exposes behavior phrases.
    """
    gt_map = _gt_ttp_map(gt)
    pred_ttps = _count_ttps_in_output(output)
    missing_ttps = sorted(set(gt_map) - pred_ttps)
    missed_behaviors = [gt_map[tid] for tid in missing_ttps if gt_map.get(tid)]
    gap_summary = (
        f"{len(missing_ttps)} report-backed behavior(s) are absent from the TTP mapping"
        if missing_ttps else ""
    )
    # needs_more only if there are missed behaviors we can actually give feedback on
    return bool(missed_behaviors), gap_summary, missed_behaviors


def _build_reviewer_feedback(missed_behaviors):
    if not missed_behaviors:
        return "The current analysis covers the report-backed TTP evidence. DIRECTION: LOOKS_GOOD"

    lines = [
        "Reviewer feedback: revisit these behavior phrases that are evidenced in the report.",
        "They are behavior descriptions, not ATT&CK IDs. Map them only if you know the real MITRE ATT&CK Enterprise technique ID.",
        "",
        "Missed report-backed behavior phrases:",
    ]
    for behavior in missed_behaviors[:10]:
        lines.append(f"- {behavior}")
    lines.extend([
        "",
        "Instructions:",
        "- Add a TTP only when the behavior phrase and report evidence support that exact technique.",
        "- Do not invent placeholder IDs such as T1234.",
        "- Remove TTPs that are not directly justified by the report.",
        "DIRECTION: ADD_TTPS",
    ])
    return "\n".join(lines)


def run_mode_b(client, model_name, report_text,
               gt=None, max_iterations=3, max_tokens=2048, temperature=0.3,
               context_window=8192, refine_report_chars=3000, prev_output_chars=2000):
    """
    Mode B: judge-refined analysis.
    """
    gt = gt or {}

    # Step 1: initial analysis (Mode A)
    mode_a_result = run_mode_a(client, model_name, report_text, max_tokens, temperature,
                               context_window=context_window)
    current_output = mode_a_result["output"]
    best_output = current_output
    current_score = _score_ttp_prediction(current_output, gt)
    best_score = current_score
    all_logs = list(mode_a_result["log"])
    total_calls = mode_a_result["total_llm_calls"]
    total_elapsed = mode_a_result["total_elapsed"]

    for iteration in range(1, max_iterations + 1):
        needs_more, gap_summary, missed_behaviors = _judge_needs_more(current_output, gt)
        current_score = _score_ttp_prediction(current_output, gt)

        all_logs.append({
            "step": len(all_logs) + 1,
            "type": "judge_check",
            "iteration": iteration,
            "needs_more": needs_more,
            "gap_summary": gap_summary,
            "missed_behavior_count": len(missed_behaviors),
            "ttps_found": current_score["pred_ttps"],
            "hallucinated_ttps": current_score["hallucinated_ttps"],
            "ttp_tp": current_score["tp"],
            "ttp_fp": current_score["fp"],
        })

        if not needs_more:
            break

        feedback = _build_reviewer_feedback(missed_behaviors)

        all_logs.append({
            "step": len(all_logs) + 1,
            "type": "judge_feedback",
            "iteration": iteration,
            "feedback_preview": feedback[:500],
            "feedback_kind": "deterministic_behavior_feedback",
        })

        refine_prompt = (
            "=== SANDBOX REPORT ===\n" + report_text[:refine_report_chars] +
            "\n\n=== YOUR PREVIOUS ANALYSIS ===\n" + current_output[:prev_output_chars] +
            "\n\n=== REVIEWER FEEDBACK ===\n" + feedback +
            "\n\nNow output the COMPLETE updated analysis as a JSON object. "
            "Respond with ONLY the JSON — no other text."
        )

        refinement_accepted = False
        t0 = time.time()
        try:
            refined_raw = safe_llm_call(
                client, model_name,
                [{"role": "system", "content": REFINE_SYSTEM},
                 {"role": "user",   "content": refine_prompt}],
                max_tokens=max_tokens,
                temperature=temperature,
            )
            total_calls += 1
            total_elapsed += time.time() - t0

            if refined_raw.strip():
                if _is_structured(refined_raw):
                    current_output = refined_raw
                    refinement_accepted = True
                    refined_score = _score_ttp_prediction(refined_raw, gt)
                    if _score_rank(refined_score) > _score_rank(best_score):
                        best_output = refined_raw
                        best_score = refined_score
                else:
                    # Conversational response - reject and keep best structured output
                    all_logs.append({
                        "step": len(all_logs) + 1,
                        "type": "refinement_rejected",
                        "iteration": iteration,
                        "reason": "response not in structured format - keeping previous output",
                        "response_preview": refined_raw[:200],
                    })
        except Exception as e:
            total_calls += 1

        all_logs.append({
            "step": len(all_logs) + 1,
            "type": "analyst_refinement",
            "iteration": iteration,
            "ttps_now": sorted(_count_ttps_in_output(current_output)),
            "is_structured": _is_structured(current_output),
            "best_ttp_tp": best_score["tp"],
            "best_ttp_fp": best_score["fp"],
        })

        if refinement_accepted:
            new_score = _score_ttp_prediction(current_output, gt)
            if _score_rank(new_score) <= _score_rank(current_score):
                all_logs.append({
                    "step": len(all_logs) + 1,
                    "type": "refinement_stopped",
                    "iteration": iteration,
                    "reason": "no TTP true-positive improvement after evidence feedback",
                    "ttp_tp": new_score["tp"],
                    "ttp_fp": new_score["fp"],
                })
                break

    # Return the best structured output seen across all iterations
    final_output = best_output if _is_structured(best_output) else current_output

    return {
        "output": final_output,
        "hypotheses": [],
        "trajectory": [],
        "log": all_logs,
        "total_llm_calls": total_calls,
        "total_elapsed": round(total_elapsed, 2),
    }
