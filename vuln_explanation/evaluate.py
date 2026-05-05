"""
evaluate.py
-----------
Scores LLM-generated vulnerability explanations against ground truth.

Evaluation axes:
  1. CWE Alignment       - Does the LLM identify the right vulnerability class?
  2. Construct Match     - Does it name the correct dangerous function/construct?
  3. Completeness        - Does it cover: root cause, impact, remediation?
  4. Severity Calibration- Does its urgency language match the Flawfinder severity?
  5. Hallucination Rate  - Does it introduce CWEs/issues not in the ground truth?

Scoring: each axis 0.0 - 1.0, final score = weighted average.

Judge: GPT-4o-as-judge for axes 3, 4, 5.
Rules-based:            for axes 1, 2 (more reproducible).
"""

import os
import re
import json
import argparse
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

# ── CWE keyword maps ──────────────────────────────────────────────────────────
# Maps CWE ID → keywords that should appear in a correct explanation
CWE_KEYWORDS = {
    "CWE-78":  ["command injection", "os command", "shell", "execl", "execlp",
                 "system(", "popen", "arbitrary command", "untrusted input"],
    "CWE-134": ["format string", "printf", "sprintf", "fprintf", "%n", "%x",
                 "format specifier", "externally controlled"],
    "CWE-121": ["buffer overflow", "stack overflow", "stack-based", "strcpy",
                 "gets(", "fixed-size", "bounds check", "overwrite"],
    "CWE-190": ["integer overflow", "wraparound", "arithmetic overflow",
                 "integer wrap", "signed overflow", "unsigned overflow"],
}

# Severity → urgency descriptors for calibration check
SEVERITY_LEVEL = {
    4: ["critical", "severe", "high severity", "dangerous", "easily exploited",
        "arbitrary command", "arbitrary code"],
    3: ["moderate", "significant", "security risk", "not sufficiently random",
        "cryptographic", "weak randomness"],
    2: ["potential", "possible overflow", "could lead", "risk is low",
        "bounds checking"],
    1: ["minor", "low risk", "edge case", "if unprotected"],
}


# ── Rules-based scorers ───────────────────────────────────────────────────────

def score_cwe_alignment(explanation: str, cwe_id: str) -> tuple[float, str]:
    """Check if explanation mentions keywords for the correct CWE."""
    keywords = CWE_KEYWORDS.get(cwe_id, [])
    if not keywords:
        return 0.5, "No keyword list for this CWE"

    explanation_lower = explanation.lower()
    hits = [kw for kw in keywords if kw.lower() in explanation_lower]

    if len(hits) >= 3:
        score = 1.0
    elif len(hits) == 2:
        score = 0.75
    elif len(hits) == 1:
        score = 0.5
    else:
        score = 0.0

    reason = f"Matched keywords: {hits}" if hits else "No matching keywords found"
    return score, reason


def score_construct_match(explanation: str, construct: str) -> tuple[float, str]:
    """Check if the explanation names the specific dangerous construct."""
    if construct.lower() in explanation.lower():
        return 1.0, f"Construct '{construct}' mentioned"
    # Partial: close variants
    variants = {
        "execl": ["execl", "exec(", "execve", "execlp"],
        "execlp": ["execlp", "execl", "exec("],
        "strcpy": ["strcpy", "string copy"],
        "strcat": ["strcat", "string concat"],
        "printf": ["printf", "format string"],
        "srand":  ["srand", "rand(", "random"],
        "strlen": ["strlen", "string length"],
    }
    close = variants.get(construct.lower(), [])
    for v in close:
        if v in explanation.lower():
            return 0.5, f"Partial match via variant '{v}'"
    return 0.0, f"Construct '{construct}' not mentioned"


# ── LLM-as-judge scorers ─────────────────────────────────────────────────────

COMPLETENESS_PROMPT = """You are evaluating a security vulnerability explanation.

GROUND TRUTH (from a static analysis tool):
{ground_truth}

LLM EXPLANATION:
{explanation}

Score the LLM explanation on COMPLETENESS (0.0 to 1.0) based on whether it covers:
- Root cause of the vulnerability
- Potential impact or attack scenario
- Suggested remediation or fix

Return ONLY a JSON object like:
{{"score": 0.85, "root_cause_covered": true, "impact_covered": true, "remediation_covered": false, "reason": "brief explanation"}}"""

HALLUCINATION_PROMPT = """You are checking for hallucinations in a security vulnerability explanation.

GROUND TRUTH FINDING (from static analysis tool):
Construct flagged: {construct}
CWE: {cwe_id}
Tool rationale: {ground_truth}

LLM EXPLANATION:
{explanation}

Check: Does the LLM explanation introduce security issues, CWEs, or vulnerability types that are NOT supported by the ground truth finding?

Return ONLY a JSON object like:
{{"hallucination_score": 0.0, "hallucinated_claims": ["list any unsupported claims"], "reason": "brief explanation"}}

hallucination_score: 0.0 = no hallucinations, 1.0 = severe/numerous hallucinations"""

SEVERITY_PROMPT = """You are checking if a vulnerability explanation correctly conveys the severity level.

The static analysis tool assigned severity level {severity}/4 (where 4 is most severe, 1 is least).
Severity {severity} typically implies: {severity_desc}

LLM EXPLANATION:
{explanation}

Does the explanation's language match this severity level?
Return ONLY a JSON object like:
{{"calibration_score": 0.8, "perceived_severity": "high/medium/low", "reason": "brief explanation"}}

calibration_score: 1.0 = perfect match, 0.0 = completely wrong severity framing"""


def judge_completeness(client, model, entry) -> tuple[float, dict]:
    prompt = COMPLETENESS_PROMPT.format(
        ground_truth=entry["ground_truth"],
        explanation=entry["explanation"],
    )
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
            temperature=0.0,
        )
        raw = resp.choices[0].message.content.strip()
        raw = re.sub(r"```json|```", "", raw).strip()
        data = json.loads(raw)
        return data.get("score", 0.0), data
    except Exception as e:
        return 0.0, {"error": str(e)}


def judge_hallucination(client, model, entry) -> tuple[float, dict]:
    prompt = HALLUCINATION_PROMPT.format(
        construct=entry["construct"],
        cwe_id=entry["cwe_id"],
        ground_truth=entry["ground_truth"],
        explanation=entry["explanation"],
    )
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
            temperature=0.0,
        )
        raw = resp.choices[0].message.content.strip()
        raw = re.sub(r"```json|```", "", raw).strip()
        data = json.loads(raw)
        # Invert: high hallucination → low score
        hall_score = data.get("hallucination_score", 0.0)
        return 1.0 - hall_score, data
    except Exception as e:
        return 0.5, {"error": str(e)}


def judge_severity_calibration(client, model, entry) -> tuple[float, dict]:
    sev = entry["severity"]
    sev_desc = ", ".join(SEVERITY_LEVEL.get(sev, ["unspecified"]))
    prompt = SEVERITY_PROMPT.format(
        severity=sev,
        severity_desc=sev_desc,
        explanation=entry["explanation"],
    )
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            temperature=0.0,
        )
        raw = resp.choices[0].message.content.strip()
        raw = re.sub(r"```json|```", "", raw).strip()
        data = json.loads(raw)
        return data.get("calibration_score", 0.5), data
    except Exception as e:
        return 0.5, {"error": str(e)}


# ── Weighted final score ──────────────────────────────────────────────────────

WEIGHTS = {
    "cwe_alignment":       0.25,
    "construct_match":     0.20,
    "completeness":        0.25,
    "severity_calibration":0.15,
    "no_hallucination":    0.15,
}

def compute_final(scores: dict) -> float:
    return sum(WEIGHTS[k] * scores[k] for k in WEIGHTS)


# ── Main evaluator ────────────────────────────────────────────────────────────

def evaluate(results_path: str, output_path: str, judge_model: str,
             api_base: str, api_key: str):

    entries = json.loads(Path(results_path).read_text())
    client  = OpenAI(api_key=api_key, base_url=api_base)

    evaluated = []
    for entry in entries:
        if entry.get("status") != "ok" or not entry.get("explanation"):
            continue

        eid = entry["id"]
        print(f"  [id={eid}] evaluating {entry['filename']}:{entry['flagged_line']}")

        # Rules-based
        cwe_score,  cwe_reason  = score_cwe_alignment(entry["explanation"], entry["cwe_id"])
        cons_score, cons_reason = score_construct_match(entry["explanation"], entry["construct"])

        # LLM-as-judge
        comp_score,  comp_detail  = judge_completeness(client, judge_model, entry)
        hall_score,  hall_detail  = judge_hallucination(client, judge_model, entry)
        sev_score,   sev_detail   = judge_severity_calibration(client, judge_model, entry)

        scores = {
            "cwe_alignment":        cwe_score,
            "construct_match":      cons_score,
            "completeness":         comp_score,
            "severity_calibration": sev_score,
            "no_hallucination":     hall_score,
        }
        final = compute_final(scores)

        evaluated.append({
            **entry,
            "scores": scores,
            "final_score": round(final, 4),
            "details": {
                "cwe_alignment":        cwe_reason,
                "construct_match":      cons_reason,
                "completeness":         comp_detail,
                "hallucination":        hall_detail,
                "severity_calibration": sev_detail,
            }
        })

        print(f"    → final={final:.3f} | cwe={cwe_score:.2f} | "
              f"construct={cons_score:.2f} | completeness={comp_score:.2f} | "
              f"hallucination={hall_score:.2f} | severity={sev_score:.2f}")

    Path(output_path).write_text(json.dumps(evaluated, indent=2))
    print(f"\nEvaluation done. {len(evaluated)} entries → {output_path}")

    # Summary
    if evaluated:
        avg_final = sum(e["final_score"] for e in evaluated) / len(evaluated)
        print(f"\nAggregate final score: {avg_final:.4f}")
        for axis in WEIGHTS:
            avg = sum(e["scores"][axis] for e in evaluated) / len(evaluated)
            print(f"  {axis:25s}: {avg:.4f}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results",    required=True,
                        help="Path to results.json from generate_explanations.py")
    parser.add_argument("--output",     default="evaluation_scores.json")
    parser.add_argument("--judge-model",default="gpt-4o")
    parser.add_argument("--api-base",   default="https://api.openai.com/v1")
    parser.add_argument("--api-key",    default=os.getenv("OPENAI_API_KEY", ""))
    args = parser.parse_args()

    evaluate(
        results_path=args.results,
        output_path=args.output,
        judge_model=args.judge_model,
        api_base=args.api_base,
        api_key=args.api_key,
    )

if __name__ == "__main__":
    main()
