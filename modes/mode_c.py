"""
SandBench Mode C: ReAct Agentic Investigation (VT Edition)
"""
import json, time, re
from tools.llm_utils import parse_json_response, safe_llm_call
from tools.vt_environment import VALID_TOOLS

AGENT_SYSTEM = """You are an expert malware analyst autonomously investigating a VirusTotal sandbox report.

Use the available tools to gather evidence, form hypotheses, and build a complete threat assessment.

At EVERY step respond with ONLY valid JSON (no other text before or after):
{
    "thought": "<reasoning about what you found and what to investigate next>",
    "action":  "<tool_name OR 'finish'>",
    "args":    {},
    "hypothesis": null
}

RULES:
- Call get_sample_overview FIRST (free, no budget cost).
- Call get_all_ioc_types early to see what data is available.
- Use tools before forming hypotheses.
- Set action to 'finish' when done.
- Respond ONLY with the JSON object. No markdown fences, no explanatory text.
- When proposing TTPs in hypotheses, use only real MITRE ATT&CK Enterprise IDs.
- If you are unsure of an exact ATT&CK ID, leave the hypothesis TTP null rather than inventing one.

AVAILABLE TOOLS:
  get_sample_overview()              cost:0  -> file type, tags, sandboxes available
  get_all_ioc_types()                cost:1  -> counts of IPs, domains, files, registry, mutexes
  get_capa_behaviors()               cost:1  -> CAPA capability rules (MBC behaviors, no MITRE IDs)
  get_network_activity()             cost:1  -> IPs, DNS, HTTP (all sandboxes merged)
  get_registry_changes()             cost:1  -> registry keys set, persistence keys
  get_dropped_files()                cost:1  -> files written to disk
  get_process_activity()             cost:1  -> processes spawned, mutexes, modules
  get_sandbox_summary(sandbox_name)  cost:1  -> field counts for one sandbox
  finish                                     -> end investigation"""

SYNTHESIS_SYSTEM = """You are an expert malware analyst. You just completed a tool-based investigation.
Write the final threat assessment as a single valid JSON object. No text before or after the JSON.

Required schema:
{
  "q1": {
    "verdict": "MALICIOUS | SUSPICIOUS | BENIGN",
    "explanation": "<reasoning based on everything you investigated>"
  },
  "q2": {
    "family": ["<one or more from: Ransomware, Trojan, Adware, Dropper, Spyware, Worm, PUA, Backdoor, Unknown>"],
    "explanation": "<what the sample does, its purpose, who benefits>"
  },
  "q3": {
    "ttps": [
      {"id": "T1027", "name": "<technique name>"}
    ]
  }
}

Q1: verdict must be exactly MALICIOUS, SUSPICIOUS, or BENIGN.
Q2: family values must come only from the fixed vocabulary above.
Q3: map observed behaviors to MITRE ATT&CK techniques — reason from evidence, do not copy IDs from memory.
Only output real MITRE ATT&CK Enterprise technique IDs.
If you are unsure of the exact ID, omit the technique rather than inventing one.
Do NOT use placeholder IDs such as T1234."""

MAX_PARSE_ERRORS = 3


def _build_synthesis_prompt(trajectory, hypotheses, report_text, synthesis_report_chars=1500):
    """
    Build a clean synthesis prompt summarising what the agent found.
    Using a fresh prompt (not the full JSON history) prevents the model
    from continuing to produce JSON format in the synthesis call.
    """
    lines = ["=== INITIAL REPORT SUMMARY ===", report_text[:synthesis_report_chars]]

    tool_results = [t for t in trajectory if t.get("type") == "tool_call"]
    if tool_results:
        lines.append("\n=== TOOLS CALLED AND KEY FINDINGS ===")
        for tr in tool_results:
            lines.append("Tool: " + tr["tool"])
            summary = tr.get("result_summary", "")
            if summary:
                lines.append("  Result: " + summary[:400])

    if hypotheses:
        lines.append("\n=== HYPOTHESES FORMED ===")
        for h in hypotheses[:10]:
            ttp = h.get("ttp", "?")
            behavior = h.get("behavior", "")
            conf = h.get("confidence", 0)
            evidence = [e.get("value", "") for e in h.get("evidence", [])[:3]]
            lines.append("- [" + str(ttp) + "] " + behavior +
                         " (conf=" + str(round(conf, 1)) + ")" +
                         " | evidence: " + ", ".join(evidence))

    lines.append("\n=== TASK ===")
    lines.append("Investigation complete. Produce the final structured threat assessment.")
    return "\n".join(lines)


def run_mode_c(client, model_name, report_text, tool_env=None,
               budget=15, max_tokens=2048, temperature=0.3,
               seed_report_chars=3000, observation_chars=3000, synthesis_report_chars=1500):
    if tool_env is None:
        return _error("Mode C requires tool_env=VTToolEnv(...)")

    seed_report = report_text[:seed_report_chars]
    if len(report_text) > seed_report_chars:
        seed_report += "\n\n[truncated - use tools to query specific data]"

    history = [{"role": "user", "content":
                "Initial report overview:\n\n" + seed_report +
                "\n\nBegin. Call get_sample_overview first."}]

    hypotheses, trajectory, log_entries = [], [], []
    llm_calls = 0
    budget_remaining = budget
    step = 0
    total_elapsed = 0.0
    parse_errors = 0

    while budget_remaining > 0:
        step += 1
        t0 = time.time()
        try:
            raw = safe_llm_call(client, model_name,
                                [{"role": "system", "content": AGENT_SYSTEM}] + history,
                                max_tokens=max_tokens, temperature=temperature)
        except Exception as e:
            log_entries.append({"step": step, "type": "llm_error", "error": str(e)})
            break
        elapsed = time.time() - t0
        total_elapsed += elapsed
        llm_calls += 1

        parsed = parse_json_response(raw)
        if parsed.get("parse_error"):
            parse_errors += 1
            log_entries.append({"step": step, "type": "parse_error",
                                "error_count": parse_errors, "raw_preview": raw[:300]})
            if parse_errors >= MAX_PARSE_ERRORS:
                log_entries.append({"step": step, "type": "parse_error_limit",
                                   "note": "Too many parse errors - proceeding to synthesis"})
                break
            # Don't break immediately - send a correction and retry
            history.append({"role": "assistant", "content": raw})
            history.append({"role": "user", "content":
                            "ERROR: Your response was not valid JSON. "
                            "Respond ONLY with a JSON object starting with '{' and ending with '}'. "
                            "No markdown, no explanatory text."})
            continue

        parse_errors = 0
        thought = parsed.get("thought", "")
        action  = (parsed.get("action") or "finish").strip()
        args    = parsed.get("args") or {}
        hyp     = parsed.get("hypothesis")

        if hyp and isinstance(hyp, dict) and hyp.get("behavior"):
            hyp_rec = dict(hyp)
            hyp_rec["step"] = step
            hypotheses.append(hyp_rec)
            trajectory.append({
                "type": "hypothesis", "step": step,
                "behavior": hyp.get("behavior", ""),
                "confidence": hyp.get("confidence", 0),
                "ttp": hyp.get("ttp"),
                "evidence_count": len(hyp.get("evidence", [])),
            })

        history.append({"role": "assistant", "content": raw})
        log_entries.append({
            "step": step, "type": "agent_step",
            "thought_preview": thought[:200], "action": action,
            "args": args, "hypothesis_emitted": hyp is not None,
            "elapsed_seconds": round(elapsed, 2),
        })

        if action == "finish":
            break

        if action not in VALID_TOOLS:
            history.append({"role": "user", "content": json.dumps(
                {"error": "Unknown tool '" + action + "'. Valid: " + str(sorted(VALID_TOOLS))})})
            continue

        t0 = time.time()
        obs = tool_env.execute(action, args)
        cost = obs.get("cost", 1)
        budget_remaining -= cost
        result_payload = obs.get("result", obs.get("error", {}))
        obs_text = json.dumps(result_payload, indent=1)
        if len(obs_text) > observation_chars:
            obs_text = obs_text[:observation_chars] + "\n...[truncated]"

        trajectory.append({
            "type": "tool_call", "step": step, "tool": action, "args": args,
            "cost": cost, "budget_remaining": budget_remaining,
            "result_summary": obs_text[:400], "elapsed_seconds": round(time.time() - t0, 2),
        })
        log_entries.append({
            "step": step, "type": "tool_result", "tool": action,
            "cost": cost, "budget_remaining": budget_remaining,
            "result_preview": obs_text[:300],
        })
        history.append({"role": "user",
                        "content": "Observation (tool=" + action +
                                   ", budget_remaining=" + str(budget_remaining) + "):\n" + obs_text})

        if budget_remaining <= 0:
            history.append({"role": "user", "content": "Budget exhausted. Call finish now."})
            break

    # ── Final synthesis: use a CLEAN prompt, not the full JSON conversation ──
    synthesis_prompt = _build_synthesis_prompt(trajectory, hypotheses, report_text,
                                               synthesis_report_chars=synthesis_report_chars)

    t0 = time.time()
    try:
        final_raw = safe_llm_call(
            client, model_name,
            [{"role": "system", "content": SYNTHESIS_SYSTEM},
             {"role": "user",   "content": synthesis_prompt}],
            max_tokens=max_tokens,
            temperature=temperature,
        )
    except Exception as e:
        final_raw = "[SYNTHESIS ERROR] " + str(e)
    total_elapsed += time.time() - t0
    llm_calls += 1

    tool_call_count = sum(1 for t in trajectory if t["type"] == "tool_call")
    log_entries.append({
        "step": step + 1, "type": "final_synthesis",
        "total_tool_calls": tool_call_count,
        "total_hypotheses": len(hypotheses),
        "total_llm_calls": llm_calls,
        "synthesis_preview": final_raw[:300],
    })

    return {
        "output": final_raw,
        "hypotheses": hypotheses,
        "trajectory": trajectory,
        "log": log_entries,
        "total_llm_calls": llm_calls,
        "total_elapsed": round(total_elapsed, 2),
    }


def _error(msg):
    return {
        "output": "[ERROR] " + msg,
        "hypotheses": [], "trajectory": [],
        "log": [{"step": 0, "type": "error", "error": msg}],
        "total_llm_calls": 0, "total_elapsed": 0.0,
    }
