"""
SandBench Mode A: Single-Shot Analysis (VT Edition)

One prompt → LLM analysis. No judge, no tools.
The LLM receives the cleaned VT report text and must produce:
  - MITRE ATT&CK technique IDs
  - IOCs (IPs, domains, dropped files, registry persistence)
  - Malware family if identifiable
  - Overall threat summary
"""

import time
from typing import Any
from tools.llm_utils import safe_llm_call

SYSTEM_PROMPT = """You are an expert malware analyst. You will receive a sandbox behavior report from VirusTotal.
Answer three questions about the sample. Respond with ONLY a single valid JSON object — no text before or after the JSON.

Required schema:
{
  "q1": {
    "verdict": "MALICIOUS | SUSPICIOUS | BENIGN",
    "explanation": "<reasoning>"
  },
  "q2": {
    "family": ["<one or more values from the fixed vocabulary>"],
    "explanation": "<reasoning>"
  },
  "q3": {
    "ttps": [
      {"id": "T1027", "name": "<technique name>"}
    ]
  }
}

Q1 — Verdict
Look at the totality of the report: network behavior, process behavior, capabilities, file drops.
The "verdict" field must be exactly one of: MALICIOUS, SUSPICIOUS, BENIGN.

Q2 — Family Classification
Look at the behavioral pattern: what does this sample do, what is its purpose, who benefits from its execution.
The "family" list must contain only values from this fixed vocabulary:
Ransomware, Trojan, Adware, Dropper, Spyware, Worm, PUA, Backdoor, Unknown

Q3 — MITRE TTPs
Reason from the behavioral evidence in the report: network activity, execution chain, CAPA rule matches, artifacts, and file identity.
Map each observed behavior to its MITRE ATT&CK technique. Each entry must have "id" (e.g. "T1027") and "name" (e.g. "Obfuscated Files or Information").
Only output real MITRE ATT&CK Enterprise technique IDs.
If you are unsure of the exact ID, omit the technique rather than inventing one.
Do NOT use placeholder IDs such as T1234.
Do NOT list TTPs you cannot directly justify from evidence in this report."""


def run_mode_a(client: Any, model_name: str, report_text: str,
               max_tokens: int = 2048, temperature: float = 0.3,
               context_window: int = 8192) -> dict:
    """
    Mode A: single-shot analysis.

    Args:
        client:         OpenAI-compatible client
        model_name:     model id string
        report_text:    cleaned VT report text (from preprocess.py)
        max_tokens:     per-call token limit
        temperature:    sampling temperature
        context_window: model's total token context limit (from config llm.context_window
                        or per-model context_window override)

    Returns:
        Standard result dict with 'output' (str), 'log', 'total_llm_calls'.
    """
    user_prompt = f"Analyze the following sandbox behavior report:\n\n{report_text}"

    # Truncate if needed (rough char limit: ~3 chars per token, leave room for response)
    max_input_chars = (context_window - max_tokens - len(SYSTEM_PROMPT) // 3) * 3
    if len(user_prompt) > max_input_chars:
        user_prompt = user_prompt[:max_input_chars] + "\n\n[report truncated]"

    t0 = time.time()
    try:
        raw = safe_llm_call(
            client, model_name,
            [{"role": "system", "content": SYSTEM_PROMPT},
             {"role": "user",   "content": user_prompt}],
            max_tokens=max_tokens,
            temperature=temperature,
        )
    except Exception as e:
        return {
            "output": f"[ERROR] {e}",
            "hypotheses": [],
            "trajectory": [],
            "log": [{"step": 1, "type": "error", "error": str(e)}],
            "total_llm_calls": 0,
            "total_elapsed": 0.0,
        }

    elapsed = time.time() - t0

    return {
        "output": raw,
        "hypotheses": [],
        "trajectory": [],
        "log": [{
            "step": 1,
            "type": "single_shot",
            "model": model_name,
            "prompt_chars": len(user_prompt),
            "response_chars": len(raw),
            "response_preview": raw[:400],
            "elapsed_seconds": round(elapsed, 2),
        }],
        "total_llm_calls": 1,
        "total_elapsed": round(elapsed, 2),
    }
