"""
generate_explanations.py
------------------------
Takes dataset.json and queries one or more LLMs for vulnerability explanations.
The LLM receives ONLY the code snippet and the flagged line number.
NO CWE ID, NO Flawfinder rationale is given.

Supports:
  - OpenAI-compatible APIs (GPT-4o, vLLM-hosted models)
  - Configurable prompt modes: zero_shot, few_shot, hint (CWE ID given as ablation)

Output: explanations/<model_name>/results.json
"""

import os
import re
import json
import time
import argparse
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# ── Prompt templates ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a software security expert analyzing C/C++ code for vulnerabilities."""

ZERO_SHOT_TEMPLATE = """Look at the following C/C++ code. The line marked with >>>> has been flagged by a static analysis tool.

{code_window}

Answer these three questions:
1. What CWE (vulnerability type) is this?
2. Which line is the problem and what exactly is wrong with it?
"""

FEW_SHOT_PREFIX = """Here is an example:

CODE:
    42 | char buf[64];
>>>> 43 | strcpy(buf, user_input);
    44 | printf("Hello %s", buf);

ANSWER:
1. CWE-121 (Stack-based Buffer Overflow)
2. Line 43 — strcpy() copies user_input into a 64-byte buffer with no length check, so input longer than 63 bytes overflows the stack.
3. An attacker can overwrite the return address to redirect execution, leading to arbitrary code execution.

Now look at this code:

"""

FEW_SHOT_TEMPLATE = FEW_SHOT_PREFIX + """{code_window}

Answer the same three questions:
1. What CWE (vulnerability type) is this?
2. Which line is the problem and what exactly is wrong with it?
"""

HINT_TEMPLATE = """Look at the following C/C++ code. The line marked with >>>> has been flagged as a {cwe_id} vulnerability.

{code_window}

Answer these three questions:
1. What CWE (vulnerability type) is this?
2. Which line is the problem and what exactly is wrong with it?
"""


PROMPT_MODES = {
    "zero_shot": ZERO_SHOT_TEMPLATE,
    "few_shot":  FEW_SHOT_TEMPLATE,
    "hint":      HINT_TEMPLATE,   # ablation: CWE ID is provided
}

# ── Prompt sanitization ──────────────────────────────────────────────────────

LABEL_PATTERNS = [
    # Juliet identifiers often encode the answer, e.g.
    # CWE78_OS_Command_Injection__char_connect_socket_execl_33.
    (re.compile(r"\bCWE\d+_[A-Za-z0-9_]+\b"), "JULIET_TEST_CASE"),
    (re.compile(r"\bCWE[-_ ]?\d+\b", re.IGNORECASE), "CWE_REDACTED"),
    (re.compile(r"\bOS[_ -]+Command[_ -]+Injection\b", re.IGNORECASE), "VULN_LABEL"),
    (re.compile(r"\bUncontrolled[_ -]+Format[_ -]+String\b", re.IGNORECASE), "VULN_LABEL"),
    (re.compile(r"\bInteger[_ -]+Overflow\b", re.IGNORECASE), "VULN_LABEL"),
    (re.compile(r"\bStack[_ -]+Based[_ -]+Buffer[_ -]+Overflow\b", re.IGNORECASE), "VULN_LABEL"),
    (re.compile(r"\bBuffer[_ -]+Overflow\b", re.IGNORECASE), "VULN_LABEL"),
]


def sanitize_label_leakage(code_snippet: str) -> str:
    """Mask Juliet benchmark labels that reveal the target CWE/class."""
    sanitized = code_snippet
    for pattern, replacement in LABEL_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


# ── LLM caller ────────────────────────────────────────────────────────────────

def call_llm(client: OpenAI, model: str, system: str, user: str,
             max_tokens: int = 800, temperature: float = 0.0) -> tuple[str, dict]:
    """Returns (response_text, usage_dict)."""
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system",  "content": system},
            {"role": "user",    "content": user},
        ],
        max_tokens=max_tokens,
        temperature=temperature,
    )
    text  = response.choices[0].message.content
    usage = {
        "prompt_tokens":     response.usage.prompt_tokens,
        "completion_tokens": response.usage.completion_tokens,
    }
    return text, usage


# ── Main generator ────────────────────────────────────────────────────────────

def generate(dataset_path: str, output_dir: str, model: str,
             api_base: str, api_key: str,
             prompt_mode: str, use_full_function: bool,
             delay: float, limit: int, sanitize_labels: bool):

    entries = json.loads(Path(dataset_path).read_text())
    if limit > 0:
        entries = entries[:limit]

    if OpenAI is None:
        raise SystemExit("Missing dependency: install the openai package with `pip install openai`.")

    client = OpenAI(api_key=api_key, base_url=api_base)

    template = PROMPT_MODES[prompt_mode]
    model_slug = model.replace("/", "_").replace(":", "_")
    out_dir = Path(output_dir) / model_slug / prompt_mode
    out_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for entry in entries:
        eid = entry["id"]

        # Choose code window
        code_snippet = (
            entry.get("full_function") or entry["code_window"]
            if use_full_function
            else entry["code_window"]
        )
        if sanitize_labels:
            code_snippet = sanitize_label_leakage(code_snippet)

        # Build prompt
        if prompt_mode == "hint":
            user_prompt = template.format(
                code_window=code_snippet,
                cwe_id=entry["cwe_id"]
            )
        else:
            user_prompt = template.format(code_window=code_snippet)

        print(f"  [id={eid}] {entry['filename']}:{entry['flagged_line']} ({model}, {prompt_mode})")

        try:
            explanation, usage = call_llm(client, model, SYSTEM_PROMPT, user_prompt)
            status = "ok"
            error  = None
        except Exception as e:
            explanation = ""
            usage  = {}
            status = "error"
            error  = str(e)
            print(f"    ERROR: {e}")

        result = {
            "id":            eid,
            "cwe_id":        entry["cwe_id"],
            "filename":      entry["filename"],
            "flagged_line":  entry["flagged_line"],
            "severity":      entry["severity"],
            "construct":     entry["construct"],
            "ground_truth":  entry["ground_truth"],   # for evaluator
            "code_window":   code_snippet,
            "label_sanitized": sanitize_labels,
            "prompt_mode":   prompt_mode,
            "model":         model,
            "explanation":   explanation,
            "usage":         usage,
            "status":        status,
            "error":         error,
        }
        results.append(result)

        if delay > 0:
            time.sleep(delay)

    out_path = out_dir / "results.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nSaved {len(results)} results → {out_path}")
    return results


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset",          default="dataset/dataset.json")
    parser.add_argument("--output-dir",       default="explanations")
    parser.add_argument("--model",            default="gpt-4o",
                        help="Model name, or vLLM model path")
    parser.add_argument("--api-base",         default="https://api.openai.com/v1")
    parser.add_argument("--api-key",          default=os.getenv("OPENAI_API_KEY", ""))
    parser.add_argument("--prompt-mode",      default="zero_shot",
                        choices=["zero_shot", "few_shot", "hint"])
    parser.add_argument("--use-full-function", action="store_true",
                        help="Use full enclosing function instead of ±N window")
    parser.add_argument("--delay",  type=float, default=0.5,
                        help="Seconds between API calls (rate limiting)")
    parser.add_argument("--limit",  type=int,   default=0,
                        help="Process only first N entries (0 = all)")
    parser.add_argument("--no-sanitize-labels", action="store_true",
                        help="Do not mask Juliet CWE/vulnerability labels in snippets")
    args = parser.parse_args()

    print(f"Model      : {args.model}")
    print(f"Prompt mode: {args.prompt_mode}")
    print(f"Dataset    : {args.dataset}\n")

    generate(
        dataset_path=args.dataset,
        output_dir=args.output_dir,
        model=args.model,
        api_base=args.api_base,
        api_key=args.api_key,
        prompt_mode=args.prompt_mode,
        use_full_function=args.use_full_function,
        delay=args.delay,
        limit=args.limit,
        sanitize_labels=not args.no_sanitize_labels,
    )


if __name__ == "__main__":
    main()
