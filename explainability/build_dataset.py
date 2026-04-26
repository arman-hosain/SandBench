"""
build_dataset.py
----------------
Parses Flawfinder reports + matching .cpp files to produce a structured
JSON dataset for LLM explanation evaluation.

Dataset structure expected:
    dataset/
        CWE78/
            code/    ← .cpp files
            report/  ← flawfinder .txt/.report files (one per .cpp)
        CWE134/
            ...

Output: dataset/dataset.json
"""

import os
import re
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional

# ── CWE filter config ────────────────────────────────────────────────────────
# Maps folder name → the CWE ID string we require to appear in the finding msg.
# Add more CWEs here as you expand the dataset.
CWE_FILTER = {
    "CWE78":  "CWE-78",
    "CWE134": "CWE-134",
    "CWE190": "CWE-190",
    "CWE121": "CWE-121",
}

CONTEXT_LINES = 10   # lines before and after the flagged line (configurable)

# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class Finding:
    cwe_folder: str          # e.g. "CWE78"
    cwe_id: str              # e.g. "CWE-78"
    filename: str            # e.g. "CWE78_OS_Command_Injection__...cpp"
    flagged_line: int        # line number from report
    severity: int            # 1-4 from Flawfinder
    category: str            # e.g. "shell", "buffer"
    construct: str           # e.g. "execl", "strcat"
    rationale: str           # Flawfinder explanation text (ground truth tier 1)
    code_window: str         # extracted lines from .cpp
    window_start: int        # first line number of window
    window_end: int          # last line number of window
    full_function: Optional[str] = None  # full enclosing function if extracted


# ── Report parser ────────────────────────────────────────────────────────────

# Matches lines like:
# /path/to/File.cpp:60:  [4] (shell) execl:
FINDING_HEADER = re.compile(
    r'^(.+\.cpp):(\d+):\s+\[(\d+)\]\s+\((\w+)\)\s+(\w+):'
)

def parse_report(report_path: Path, target_cwe: str) -> list[dict]:
    """
    Parse a single Flawfinder report file.
    Returns only findings whose rationale text mentions target_cwe (e.g. 'CWE-78').
    """
    findings = []
    text = report_path.read_text(errors="replace")
    lines = text.splitlines()

    i = 0
    while i < len(lines):
        m = FINDING_HEADER.match(lines[i])
        if m:
            filepath, lineno, severity, category, construct = m.groups()
            # Collect the multi-line rationale (indented lines after the header)
            rationale_lines = []
            j = i + 1
            while j < len(lines) and (lines[j].startswith("  ") or lines[j].startswith("\t")):
                rationale_lines.append(lines[j].strip())
                j += 1
            rationale = " ".join(rationale_lines)

            # Only keep findings that mention the target CWE
            if target_cwe in rationale:
                findings.append({
                    "source_path": filepath,
                    "filename": Path(filepath).name,
                    "flagged_line": int(lineno),
                    "severity": int(severity),
                    "category": category,
                    "construct": construct,
                    "rationale": rationale,
                })
            i = j
        else:
            i += 1

    return findings


# ── Code extractor ───────────────────────────────────────────────────────────

def extract_window(code_lines: list[str], center: int, n: int) -> tuple[str, int, int]:
    """
    Extract n lines before and after center (1-indexed line number).
    Returns (window_text, start_line, end_line).
    Lines in the output are annotated with their original line numbers,
    and the flagged line is marked with >>>>.
    """
    total = len(code_lines)
    start = max(0, center - 1 - n)      # convert to 0-indexed
    end   = min(total, center - 1 + n + 1)

    annotated = []
    for idx in range(start, end):
        lineno = idx + 1
        prefix = ">>>>" if lineno == center else "    "
        annotated.append(f"{prefix} {lineno:4d} | {code_lines[idx].rstrip()}")

    return "\n".join(annotated), start + 1, end


def extract_enclosing_function(code_lines: list[str], center: int) -> Optional[str]:
    """
    Walk backwards from center to find the opening of the enclosing function,
    then walk forwards to find the closing brace. Returns the full function text.
    Heuristic: looks for a line ending in '{' that is not indented (top-level).
    """
    # Walk back to find function start
    func_start = None
    brace_depth = 0
    for i in range(center - 1, -1, -1):
        line = code_lines[i]
        brace_depth += line.count('}') - line.count('{')
        # A line at depth 0 that opens a brace is likely the function header
        if brace_depth <= 0 and '{' in line:
            func_start = i
            break

    if func_start is None:
        return None

    # Walk forward to find matching closing brace
    depth = 0
    func_end = None
    for i in range(func_start, len(code_lines)):
        depth += code_lines[i].count('{') - code_lines[i].count('}')
        if depth <= 0:
            func_end = i
            break

    if func_end is None:
        return None

    annotated = []
    for idx in range(func_start, func_end + 1):
        lineno = idx + 1
        prefix = ">>>>" if lineno == center else "    "
        annotated.append(f"{prefix} {lineno:4d} | {code_lines[idx].rstrip()}")

    return "\n".join(annotated)


# ── Main builder ─────────────────────────────────────────────────────────────

def build_dataset(dataset_root: str, context_lines: int = CONTEXT_LINES) -> list[dict]:
    root = Path(dataset_root)
    all_entries = []
    entry_id = 0

    for cwe_folder, target_cwe in CWE_FILTER.items():
        cwe_dir = root / cwe_folder
        if not cwe_dir.exists():
            print(f"  [skip] {cwe_folder} not found at {cwe_dir}")
            continue

        code_dir   = cwe_dir / "code"
        report_dir = cwe_dir / "report"

        if not code_dir.exists() or not report_dir.exists():
            print(f"  [skip] {cwe_folder}: missing code/ or report/ subdirectory")
            continue

        # Build a lookup: stem → .cpp path
        cpp_files = {f.stem: f for f in code_dir.glob("*.cpp")}

        report_files = list(report_dir.iterdir())
        print(f"\n[{cwe_folder}] Found {len(cpp_files)} cpp files, {len(report_files)} report files")

        for report_path in sorted(report_files):
            if report_path.suffix in (".py", ".json"):
                continue  # skip any stray files

            findings = parse_report(report_path, target_cwe)

            if not findings:
                print(f"  [skip] {report_path.name}: no {target_cwe} findings")
                continue

            for f in findings:
                fname = f["filename"]
                stem  = Path(fname).stem

                # Match report filename to code file
                # Strategy: exact stem match, then fuzzy (report name often
                # matches cpp name without extension)
                cpp_path = cpp_files.get(stem)
                if cpp_path is None:
                    # Try matching by report stem (report file may lack .cpp ext)
                    report_stem = report_path.stem
                    cpp_path = cpp_files.get(report_stem)
                if cpp_path is None:
                    # Fuzzy fallback: find best prefix overlap in available cpp files
                    # Handles execl vs execlp variant mismatches
                    best, best_len = None, 0
                    for avail_stem, avail_path in cpp_files.items():
                        common = 0
                        for a, b in zip(stem, avail_stem):
                            if a == b:
                                common += 1
                            else:
                                break
                        if common > best_len:
                            best_len = common
                            best = avail_path
                    # Accept fuzzy match only if >80% of stem characters match
                    if best and best_len > 0.8 * max(len(stem), 1):
                        print(f"  [fuzzy] '{stem}' matched to '{best.stem}'")
                        cpp_path = best

                if cpp_path is None:
                    print(f"  [warn] No .cpp found for '{stem}' (report: {report_path.name})")
                    continue

                code_lines = cpp_path.read_text(errors="replace").splitlines()
                center     = f["flagged_line"]

                window_text, w_start, w_end = extract_window(
                    code_lines, center, context_lines
                )
                full_func = extract_enclosing_function(code_lines, center)

                entry = {
                    "id":            entry_id,
                    "cwe_folder":    cwe_folder,
                    "cwe_id":        target_cwe,
                    "filename":      fname,
                    "flagged_line":  center,
                    "severity":      f["severity"],
                    "category":      f["category"],
                    "construct":     f["construct"],
                    # ── Ground Truth (Tier 1) ──────────────────────────────
                    "ground_truth":  f["rationale"],
                    # ── LLM Input (no CWE, no rationale) ──────────────────
                    "code_window":      window_text,
                    "window_start_line": w_start,
                    "window_end_line":   w_end,
                    "full_function":     full_func,
                    # ── Metadata ───────────────────────────────────────────
                    "source_cpp_path":  str(cpp_path),
                }

                all_entries.append(entry)
                entry_id += 1
                print(f"  [ok] id={entry_id-1} {fname}:{center} [{f['severity']}] {f['construct']}")

    return all_entries


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Build CWE explanation dataset")
    parser.add_argument("--dataset",  default="dataset", help="Path to dataset/ root")
    parser.add_argument("--output",   default="dataset/dataset.json")
    parser.add_argument("--context",  type=int, default=CONTEXT_LINES,
                        help="Lines of context before/after flagged line (default 10)")
    args = parser.parse_args()

    print(f"Building dataset from: {args.dataset}")
    print(f"Context window: ±{args.context} lines\n")

    entries = build_dataset(args.dataset, args.context)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(entries, indent=2))

    print(f"\nDone. {len(entries)} entries written to {args.output}")

    # Print summary stats
    from collections import Counter
    cwe_counts  = Counter(e["cwe_id"]   for e in entries)
    sev_counts  = Counter(e["severity"] for e in entries)
    cons_counts = Counter(e["construct"] for e in entries)
    print("\n── Dataset Summary ──────────────────────────────")
    print(f"Total entries : {len(entries)}")
    print(f"By CWE        : {dict(cwe_counts)}")
    print(f"By severity   : {dict(sorted(sev_counts.items()))}")
    print(f"Top constructs: {cons_counts.most_common(10)}")


if __name__ == "__main__":
    main()
