#!/usr/bin/env python3
"""
preprocess.py — SandBench VT Dataset Preprocessor

Reads raw VirusTotal JSON files from dataset_dir and produces:
  1. dataset/preprocessed/<hash>.json  — clean LLM input per sample
  2. dataset/ground_truth.json         — all ground truth labels

Usage:
    python preprocess.py                     # process all samples
    python preprocess.py --max 100           # first 100 only
    python preprocess.py --hash <sha256>     # single sample
    python preprocess.py --stats             # just print dataset stats
"""

import json
import os
import glob
import argparse
import re
from collections import defaultdict


# ── Load config ──────────────────────────────────────────────────────────────

def load_config(path="config.json"):
    with open(path) as f:
        return json.load(f)


# ── Internal/noise filters ────────────────────────────────────────────────────

INTERNAL_IP_PREFIXES = ["110.110.110.", "127.0.0.", "0.0.0.0", "192.168.", "10.0.", "172.16."]
NOISE_DOMAINS = {"wpad", "localhost", "broadcasthost"}
NOISE_REGISTRY_PREFIXES = [
    "HKLM\\SOFTWARE\\Microsoft\\Tracing",
    "HKCU\\Software\\Microsoft\\Tracing",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
]

def is_internal_ip(ip):
    return any(ip.startswith(p) for p in INTERNAL_IP_PREFIXES)

def is_noise_domain(domain):
    return domain.lower() in NOISE_DOMAINS or domain.lower().endswith(".local")

def is_noise_registry(key):
    return any(key.upper().startswith(p.upper()) for p in NOISE_REGISTRY_PREFIXES)

def is_persistence_registry(key):
    """Return True if registry key looks like a persistence mechanism."""
    patterns = [
        "CurrentVersion\\Run",
        "CurrentVersion\\RunOnce",
        "Winlogon",
        "Explorer\\Shell",
        "Image File Execution",
        "AppInit_DLLs",
        "Policies\\Explorer\\Run",
        "Services\\",
    ]
    return any(p.lower() in key.lower() for p in patterns)


# ── Extract ground truth from one VT sample ──────────────────────────────────

def extract_ground_truth(d, cfg):
    """
    Returns a dict with:
      family, suggested_label, ttps, ips, domains, urls,
      registry_keys_set, files_dropped, mutexes, processes
    """
    top_level_only = cfg["eval"].get("ttp_top_level_only", True)

    meta_attrs = d["metadata"]["attributes"]

    # Verdict from AV detection rate
    stats = meta_attrs.get("last_analysis_stats", {})
    malicious_count = int(stats.get("malicious", 0))
    undetected      = int(stats.get("undetected", 0))
    total           = malicious_count + undetected
    detection_rate  = round(malicious_count / total, 4) if total > 0 else 0.0
    if detection_rate >= 0.15:
        verdict = "MALICIOUS"
    elif detection_rate >= 0.05:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    # Popular threat classification
    ptc = meta_attrs.get("popular_threat_classification", {})
    popular_threat_category = []
    popular_threat_name = []
    suggested_label = None
    if ptc:
        popular_threat_category = [{"value": e.get("value"), "count": e.get("count")}
                                   for e in ptc.get("popular_threat_category", [])]
        popular_threat_name = [{"value": e.get("value"), "count": e.get("count")}
                               for e in ptc.get("popular_threat_name", [])]
        suggested_label = ptc.get("suggested_threat_label")

    # AV majority vote family (fallback when ptc missing)
    av_families = defaultdict(int)
    for eng, res in meta_attrs.get("last_analysis_results", {}).items():
        if res.get("category") == "malicious" and res.get("result"):
            result_str = res["result"].lower()
            # Try to extract a family name after common prefixes
            for prefix in ["trojan.", "worm.", "backdoor.", "ransomware.", "spyware.", "adware.", "pua."]:
                if prefix in result_str:
                    parts = result_str.split(prefix)
                    if len(parts) > 1:
                        candidate = parts[1].split(".")[0].split("/")[0].strip()
                        if len(candidate) > 2:
                            av_families[candidate] += 1
    av_family_vote = max(av_families, key=av_families.get) if av_families else None

    # MITRE TTPs from CAPA (most reliable source)
    ttps = {}
    for b in d.get("behavior", []):
        if b["attributes"].get("sandbox_name") == "CAPA":
            for t in b["attributes"].get("mitre_attack_techniques", []):
                tid = t["id"]
                if top_level_only:
                    tid = tid.split(".")[0]
                if tid not in ttps:
                    ttps[tid] = t.get("signature_description", "")

    # Signature match names from CAPA
    capa_sig_names = []
    for b in d.get("behavior", []):
        if b["attributes"].get("sandbox_name") == "CAPA":
            for sm in b["attributes"].get("signature_matches", []):
                name = sm.get("name", "")
                if name:
                    capa_sig_names.append(name)
            break

    # IOCs — aggregate across all sandboxes, deduplicate
    ips = set()
    domains = set()
    urls = set()
    registry_persistence = set()
    registry_all = set()
    files_dropped = set()
    mutexes = set()
    processes = set()

    for b in d.get("behavior", []):
        attrs = b["attributes"]

        for item in attrs.get("ip_traffic", []):
            ip = item.get("destination_ip", "")
            if ip and not is_internal_ip(ip):
                ips.add(ip)

        for item in attrs.get("dns_lookups", []):
            h = item.get("hostname", "")
            if h and not is_noise_domain(h):
                domains.add(h.lower())

        for item in attrs.get("http_conversations", []):
            u = item.get("url", "")
            if u:
                urls.add(u)

        for item in attrs.get("registry_keys_set", []):
            key = item.get("key", "")
            if key and not is_noise_registry(key):
                registry_all.add(key)
                if is_persistence_registry(key):
                    registry_persistence.add(key)

        for item in attrs.get("files_dropped", []):
            path = item.get("path", "")
            if path:
                # Normalise placeholder usernames
                path = re.sub(r"C:\\Users\\[^\\]+", r"C:\\Users\\<USER>", path)
                files_dropped.add(path)

        for item in attrs.get("mutexes_created", []):
            if isinstance(item, str) and item:
                mutexes.add(item)
            elif isinstance(item, dict) and item.get("name"):
                mutexes.add(item["name"])

        for p in attrs.get("processes_created", []):
            if isinstance(p, str) and p:
                processes.add(p)

    return {
        "hash": d["hash"],
        "verdict": verdict,
        "detection_rate": detection_rate,
        "malicious_count": malicious_count,
        "popular_threat_category": popular_threat_category,
        "popular_threat_name": popular_threat_name,
        "suggested_label": suggested_label,
        "av_family_vote": av_family_vote,
        "has_family_label": bool(popular_threat_name),
        "ttps": [{"id": k, "signature_description": v} for k, v in sorted(ttps.items())],
        "capa_sig_names": capa_sig_names,
        "iocs": {
            "ips": sorted(ips),
            "domains": sorted(domains),
            "urls": sorted(urls),
            "registry_persistence": sorted(registry_persistence),
            "registry_all_count": len(registry_all),
            "files_dropped": sorted(files_dropped),
            "mutexes": sorted(mutexes),
            "processes": sorted(processes),
        },
    }


# ── Process-tree helpers ─────────────────────────────────────────────────────

def _count_tree_nodes(tree):
    count = 0
    for node in tree:
        count += 1 + _count_tree_nodes(node.get("children", []))
    return count


def _render_tree(tree, depth, out, counter, cap):
    for node in tree:
        if counter[0] >= cap:
            return
        name = node.get("name", node.get("process_name", "?"))
        out.append("  " + "  " * depth + name)
        counter[0] += 1
        _render_tree(node.get("children", []), depth + 1, out, counter, cap)


# ── Build clean LLM input text from one VT sample ────────────────────────────

SANDBOX_PRIORITY = [
    "VirusTotal Cuckoofork",
    "VirusTotal Jujubox",
    "Lastline",
    "Tencent HABO",
    "SNDBOX",
    "VenusEye Sandbox",
    "Microsoft Sysinternals",
    "Zenbox",
    "Yomi Hunter",
    "Dr.Web vxCube",
    "ReaQta-Hive",
    "CAPE Sandbox",
]


def build_llm_input(d, cfg, gt):
    """
    Produces a clean text report for the LLM.
    Does NOT include AV labels (would reveal family).
    Merges across sandboxes, deduplicates.
    """
    lines = []
    meta_attrs = d["metadata"]["attributes"]
    max_files = cfg["preprocess"].get("max_dropped_files", 30)

    SYSTEM_MUTEXES = {
        "ShimCacheMutex", "WininetStartupMutex", "WininetConnectionMutex",
        "WininetProxyRegistryMutex", "RasPbFile", "_SHuassist.mtx",
    }
    DANGEROUS_IMPORTS = {
        "VirtualAlloc", "VirtualProtect", "VirtualAllocEx", "WriteProcessMemory",
        "CreateProcessW", "CreateProcessA", "AdjustTokenPrivileges", "LookupPrivilegeValue",
        "OpenProcessToken", "GetProcAddress", "LoadLibraryW", "LoadLibraryExW",
        "CreateRemoteThread", "NtAllocateVirtualMemory", "ShellExecute", "WinExec",
    }

    # Build ordered non-CAPA sandbox list
    sandbox_map = {b["attributes"].get("sandbox_name", ""): b for b in d.get("behavior", [])}
    ordered = [sandbox_map[s] for s in SANDBOX_PRIORITY if s in sandbox_map]
    ordered += [b for b in d.get("behavior", [])
                if b not in ordered and b["attributes"].get("sandbox_name") != "CAPA"]

    # ── Accumulators ─────────────────────────────────────────────────────────
    all_http = []
    all_http_seen = set()
    all_dns = set()
    all_ips = set()
    all_services = set()

    best_tree = None
    best_tree_size = 0
    all_cmds = []
    all_cmds_seen = set()
    all_procs_flat = set()

    all_highlighted = []
    all_highlighted_seen = set()

    all_files_dropped = []
    all_files_dropped_paths = set()
    all_files_written = set()
    all_reg_persistence = set()
    all_reg_other = []
    all_reg_other_seen = set()
    all_mutexes_created = set()
    all_mutexes_opened = set()

    # ── Collect across non-CAPA sandboxes ─────────────────────────────────────
    for b in ordered:
        attrs = b["attributes"]

        for item in attrs.get("http_conversations", []):
            u = item.get("url", "")
            if not u:
                continue
            method = item.get("request_method", "GET")
            headers = item.get("request_headers", {})
            ua = headers.get("User-Agent", headers.get("user-agent", "")) if isinstance(headers, dict) else ""
            entry = f"{method} {u}"
            if ua:
                entry += f"  UA: {ua}"
            if entry not in all_http_seen:
                all_http_seen.add(entry)
                all_http.append(entry)

        for item in attrs.get("dns_lookups", []):
            h = item.get("hostname", "")
            resolved = item.get("resolved_ips", [])
            if h and not is_noise_domain(h):
                entry = h
                if resolved:
                    entry += f" → {', '.join(resolved[:2])}"
                all_dns.add(entry)

        for item in attrs.get("ip_traffic", []):
            ip = item.get("destination_ip", "")
            port = item.get("destination_port", "")
            proto = item.get("transport_layer_protocol", "")
            if ip and not is_internal_ip(ip):
                all_ips.add(f"{ip}:{port} ({proto})" if port else ip)

        for item in attrs.get("services_opened", []):
            name = item.get("name", "") if isinstance(item, dict) else str(item)
            if name:
                all_services.add(name)

        tree = attrs.get("processes_tree", [])
        if tree:
            size = _count_tree_nodes(tree)
            if size > best_tree_size:
                best_tree_size = size
                best_tree = tree

        for p in attrs.get("processes_created", []):
            if isinstance(p, str) and p:
                all_procs_flat.add(p[:200])

        for item in attrs.get("command_executions", []):
            cmd = item if isinstance(item, str) else item.get("command", "")
            if cmd and cmd not in all_cmds_seen:
                all_cmds_seen.add(cmd)
                all_cmds.append(cmd)

        for item in attrs.get("calls_highlighted", []):
            call_str = item if isinstance(item, str) else str(item)
            if call_str and call_str not in all_highlighted_seen:
                all_highlighted_seen.add(call_str)
                all_highlighted.append(call_str)

        for item in attrs.get("files_dropped", []):
            path = item.get("path", "")
            sha = item.get("sha256", "")
            if path and len(all_files_dropped) < max_files:
                path = re.sub(r"C:\\Users\\[^\\]+", r"C:\\Users\\<USER>", path)
                if path not in all_files_dropped_paths:
                    all_files_dropped_paths.add(path)
                    entry = path + (f"  [sha256: {sha[:16]}...]" if sha else "")
                    all_files_dropped.append(entry)

        for item in attrs.get("files_written", []):
            path = item.get("path", "") if isinstance(item, dict) else str(item)
            if path and len(all_files_written) < max_files:
                path = re.sub(r"C:\\Users\\[^\\]+", r"C:\\Users\\<USER>", path)
                if path not in all_files_dropped_paths:
                    all_files_written.add(path)

        for item in attrs.get("registry_keys_set", []):
            key = item.get("key", "")
            val = item.get("value", "")
            if not key or is_noise_registry(key):
                continue
            if is_persistence_registry(key):
                entry = key + (f" = {val[:100]}" if val and len(val) < 200 else "")
                all_reg_persistence.add(entry)
            elif key not in all_reg_other_seen and len(all_reg_other) < 10:
                all_reg_other_seen.add(key)
                all_reg_other.append(key[:120])

        for item in attrs.get("mutexes_created", []):
            name = item if isinstance(item, str) else item.get("name", "")
            if name:
                all_mutexes_created.add(name)

        for item in attrs.get("mutexes_opened", []):
            name = item if isinstance(item, str) else item.get("name", "")
            if name and name not in SYSTEM_MUTEXES:
                all_mutexes_opened.add(name)

    all_mutexes_opened -= all_mutexes_created

    # ── CAPA ─────────────────────────────────────────────────────────────────
    capa_triggers = []   # refs[].value from mitre_attack_techniques (no T-IDs)
    capa_sigs = []
    _capa_seen = set()
    for b in d.get("behavior", []):
        if b["attributes"].get("sandbox_name") == "CAPA":
            _trigger_seen = set()
            for t in b["attributes"].get("mitre_attack_techniques", []):
                for ref in t.get("refs", []):
                    val = ref.get("value", "").strip()
                    if val and val not in _trigger_seen:
                        _trigger_seen.add(val)
                        capa_triggers.append(f"  - {val}")
            for sm in b["attributes"].get("signature_matches", []):
                if len(capa_sigs) >= 25:
                    break
                src = sm.get("rule_src", "")
                name_m = re.search(r'name:\s*(.+)', src)
                rule_name = name_m.group(1).strip() if name_m else ""

                # Extract MBC behavior entries
                mbc_entries = []
                in_mbc = False
                for line in src.splitlines():
                    stripped = line.strip()
                    if re.match(r'^mbc\s*:', stripped):
                        in_mbc = True
                        continue
                    if in_mbc:
                        if stripped.startswith("- "):
                            mbc_entries.append(stripped[2:].strip())
                        elif stripped == "":
                            continue
                        elif not stripped.startswith("-"):
                            break

                # Prefer MBC entries; fall back to rule name
                if mbc_entries:
                    for entry in mbc_entries:
                        if entry not in _capa_seen and len(capa_sigs) < 25:
                            _capa_seen.add(entry)
                            capa_sigs.append(f"  - {entry}")
                elif rule_name and rule_name not in _capa_seen:
                    _capa_seen.add(rule_name)
                    capa_sigs.append(f"  - {rule_name}")
            break

    # ── Section 1: Network Activity ───────────────────────────────────────────
    net = []
    if all_http:
        net.append(f"\nHTTP CONVERSATIONS ({len(all_http)}):")
        for x in all_http[:15]:
            net.append(f"  {x}")
    if all_dns:
        net.append(f"\nDNS LOOKUPS ({len(all_dns)}):")
        for x in sorted(all_dns)[:20]:
            net.append(f"  {x}")
    if all_ips:
        net.append(f"\nIP TRAFFIC ({len(all_ips)}):")
        for x in sorted(all_ips)[:20]:
            net.append(f"  {x}")
    if all_services:
        net.append(f"\nSERVICES OPENED ({len(all_services)}):")
        for x in sorted(all_services)[:10]:
            net.append(f"  {x}")
    if net:
        lines.append("--- NETWORK ACTIVITY ---")
        lines.extend(net)
        lines.append("")

    # ── Section 2: Execution Chain ────────────────────────────────────────────
    exe = []
    if best_tree:
        exe.append("\nPROCESS TREE:")
        counter = [0]
        _render_tree(best_tree, 0, exe, counter, 15)
    elif all_procs_flat:
        exe.append("\nPROCESS TREE (flat):")
        for p in sorted(all_procs_flat)[:15]:
            exe.append(f"  {p}")
    if all_cmds:
        exe.append(f"\nCOMMAND EXECUTIONS ({len(all_cmds)}):")
        for x in all_cmds[:15]:
            exe.append(f"  {x}")
    if exe:
        lines.append("--- EXECUTION CHAIN ---")
        lines.extend(exe)
        lines.append("")

    # ── Section 3: Capabilities (CAPA) ────────────────────────────────────────
    cap = []
    if capa_triggers:
        cap.append(f"\nTECHNIQUE TRIGGERS ({len(capa_triggers)}):")
        cap.extend(capa_triggers)
    if capa_sigs:
        cap.append("\nCAPA RULE MATCHES (MBC):")
        cap.extend(capa_sigs)
    if all_highlighted:
        cap.append("\nHIGHLIGHTED CALLS:")
        for x in all_highlighted:
            cap.append(f"  {x}")
    if cap:
        lines.append("--- CAPABILITIES (CAPA) ---")
        lines.extend(cap)
        lines.append("")

    # ── Section 4: Artifacts ──────────────────────────────────────────────────
    art = []
    if all_files_dropped:
        art.append(f"\nFILES DROPPED ({len(all_files_dropped)}):")
        for x in all_files_dropped[:20]:
            art.append(f"  {x}")
    if all_files_written:
        art.append(f"\nFILES WRITTEN ({len(all_files_written)}):")
        for x in sorted(all_files_written)[:20]:
            art.append(f"  {x}")
    if all_reg_persistence:
        art.append(f"\nPERSISTENCE REGISTRY KEYS ({len(all_reg_persistence)}):")
        for x in sorted(all_reg_persistence)[:15]:
            art.append(f"  {x}")
    if all_reg_other:
        art.append(f"\nOTHER REGISTRY KEYS SET ({len(all_reg_other)}):")
        for x in all_reg_other[:10]:
            art.append(f"  {x}")
    if all_mutexes_created:
        art.append(f"\nMUTEXES CREATED ({len(all_mutexes_created)}):")
        for x in sorted(all_mutexes_created)[:10]:
            art.append(f"  {x}")
    if all_mutexes_opened:
        art.append(f"\nMUTEXES OPENED ({len(all_mutexes_opened)}):")
        for x in sorted(all_mutexes_opened)[:10]:
            art.append(f"  {x}")
    if all_procs_flat:
        art.append(f"\nPROCESSES CREATED ({len(all_procs_flat)}):")
        for x in sorted(all_procs_flat)[:10]:
            art.append(f"  {x}")
    if art:
        lines.append("--- ARTIFACTS ---")
        lines.extend(art)
        lines.append("")

    # ── Section 5: File Identity ──────────────────────────────────────────────
    pe_info = meta_attrs.get("pe_info", {})
    ident = []

    dangerous_found = []
    for lib_entry in pe_info.get("import_list", []):
        lib_name = lib_entry.get("library_name", "")
        funcs = [f for f in lib_entry.get("imported_functions", []) if f in DANGEROUS_IMPORTS]
        if funcs:
            dangerous_found.append(f"  {lib_name}: {', '.join(funcs)}")
    if dangerous_found:
        ident.append("\nPE IMPORTS (DANGEROUS):")
        ident.extend(dangerous_found)

    sig_info = meta_attrs.get("signature_info", {})
    if sig_info:
        signer = sig_info.get("signers", "")
        details = sig_info.get("signers_details", [])
        det = details[0] if details else {}
        ident.append("\nCERTIFICATE INFO:")
        if signer:
            ident.append(f"  Signer: {signer}")
        if det.get("status"):
            ident.append(f"  Status: {det['status']}")
        if det.get("valid_from") or det.get("valid_to"):
            ident.append(f"  Valid:  {det.get('valid_from', '')} → {det.get('valid_to', '')}")
        if det.get("cert_issuer"):
            ident.append(f"  Issuer: {det['cert_issuer']}")

    die = meta_attrs.get("detectiteasy", {})
    die_values = die.get("values", [])
    packers = meta_attrs.get("packers", [])
    if die_values or packers:
        ident.append("\nCOMPILER AND PACKER:")
        for v in die_values:
            t, n = v.get("type", ""), v.get("name", "")
            if t and n:
                ident.append(f"  [{t}] {n}")
        if packers:
            ident.append(f"  Packers: {', '.join(packers) if isinstance(packers, list) else packers}")

    sections = pe_info.get("sections", [])
    overlay = pe_info.get("overlay", {})
    if sections or overlay:
        ident.append("\nPE SECTIONS (entropy):")
        for sec in sections:
            name = sec.get("name", "")
            if name:
                ident.append(f"  {name:<12} entropy={sec.get('entropy', '')}")
        if overlay:
            ident.append(f"  [overlay]    entropy={overlay.get('entropy', '')}  size={overlay.get('size', '')}")

    if ident:
        lines.append("--- FILE IDENTITY ---")
        lines.extend(ident)
        lines.append("")

    return "\n".join(lines)


# ── Process one file ──────────────────────────────────────────────────────────

def process_file(fpath, cfg, out_dir):
    with open(fpath) as f:
        d = json.load(f)

    sha256 = d["hash"]
    gt = extract_ground_truth(d, cfg)
    report_text = build_llm_input(d, cfg, gt)

    out = {
        "hash": sha256,
        "report_text": report_text,
        "ground_truth": gt,
        "num_sandboxes": len(d.get("behavior", [])),
        "sandbox_names": [b["attributes"].get("sandbox_name", "") for b in d.get("behavior", [])],
    }

    out_path = os.path.join(out_dir, f"{sha256}.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    return gt


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SandBench VT Preprocessor")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--max", type=int, default=None, help="Max samples to process")
    parser.add_argument("--hash", type=str, default=None, help="Process single hash")
    parser.add_argument("--stats", action="store_true", help="Print dataset stats and exit")
    args = parser.parse_args()

    cfg = load_config(args.config)
    data_dir = cfg["dataset_dir"]
    out_dir = cfg["preprocessed_dir"]
    gt_file = cfg["ground_truth_file"]

    os.makedirs(out_dir, exist_ok=True)

    if args.hash:
        files = [os.path.join(data_dir, f"{args.hash}.json")]
    else:
        files = sorted(glob.glob(os.path.join(data_dir, "*.json")))

    if args.max:
        files = files[:args.max]

    print(f"Found {len(files)} samples in {data_dir}")

    if args.stats:
        # Quick stats pass
        stats = {"total": 0, "has_ttps": 0, "has_family": 0, "has_network": 0,
                 "has_registry": 0, "has_dropped": 0, "sandbox_counts": defaultdict(int)}
        for fpath in files[:500]:
            try:
                with open(fpath) as f:
                    d = json.load(f)
                stats["total"] += 1
                gt = extract_ground_truth(d, cfg)
                if gt["ttps"]: stats["has_ttps"] += 1
                if gt["has_family_label"]: stats["has_family"] += 1
                if gt["iocs"]["ips"] or gt["iocs"]["domains"]: stats["has_network"] += 1
                if gt["iocs"]["registry_persistence"]: stats["has_registry"] += 1
                if gt["iocs"]["files_dropped"]: stats["has_dropped"] += 1
                for b in d.get("behavior", []):
                    sn = b["attributes"].get("sandbox_name", "?")
                    stats["sandbox_counts"][sn] += 1
            except Exception as e:
                pass
        n = stats["total"]
        print(f"\n=== Dataset Stats (sampled {n} files) ===")
        print(f"  Has MITRE TTPs:        {stats['has_ttps']} ({100*stats['has_ttps']//n}%)")
        print(f"  Has family label:      {stats['has_family']} ({100*stats['has_family']//n}%)")
        print(f"  Has network IOCs:      {stats['has_network']} ({100*stats['has_network']//n}%)")
        print(f"  Has persistence reg:   {stats['has_registry']} ({100*stats['has_registry']//n}%)")
        print(f"  Has files dropped:     {stats['has_dropped']} ({100*stats['has_dropped']//n}%)")
        print(f"  Sandbox breakdown:     {dict(sorted(stats['sandbox_counts'].items(), key=lambda x:-x[1]))}")
        return

    # Full preprocessing pass
    all_ground_truth = {}
    done = 0
    errors = 0

    for i, fpath in enumerate(files):
        try:
            gt = process_file(fpath, cfg, out_dir)
            all_ground_truth[gt["hash"]] = gt
            done += 1
            if done % 100 == 0:
                print(f"  [{done}/{len(files)}] processed...")
        except Exception as e:
            errors += 1
            print(f"  [ERROR] {os.path.basename(fpath)}: {e}")

    # Save ground truth index
    with open(gt_file, "w") as f:
        json.dump(all_ground_truth, f, indent=2)

    print(f"\nDone. Processed={done}, Errors={errors}")
    print(f"Ground truth saved → {gt_file}")
    print(f"Preprocessed inputs → {out_dir}/")

    # Summary stats
    has_ttps = sum(1 for v in all_ground_truth.values() if v["ttps"])
    has_fam = sum(1 for v in all_ground_truth.values() if v["has_family_label"])
    has_net = sum(1 for v in all_ground_truth.values() if v["iocs"]["ips"] or v["iocs"]["domains"])
    has_reg = sum(1 for v in all_ground_truth.values() if v["iocs"]["registry_persistence"])
    print(f"\n  Has TTPs:             {has_ttps}/{done} ({100*has_ttps//done}%)")
    print(f"  Has family label:     {has_fam}/{done} ({100*has_fam//done}%)")
    print(f"  Has network IOCs:     {has_net}/{done} ({100*has_net//done}%)")
    print(f"  Has persistence reg:  {has_reg}/{done} ({100*has_reg//done}%)")


if __name__ == "__main__":
    main()
