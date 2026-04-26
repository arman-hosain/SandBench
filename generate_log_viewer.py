#!/usr/bin/env python3
"""
SandBench: Log Viewer Dashboard Generator
Creates a self-contained HTML file that lets you inspect agent traces,
judge feedback, tool calls, and hypotheses for every experiment.
"""

import json
import os
import glob
import argparse
import html


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def escape(s):
    return html.escape(str(s)) if s else ""


def generate_log_viewer(results_path, log_dir, output_path):
    results_data = load_json(results_path)
    results = results_data.get("results", [])

    # Load all log files
    log_files = {}
    for f in glob.glob(os.path.join(log_dir, "*.log.json")):
        log_files[os.path.basename(f)] = load_json(f)

    # Build HTML
    experiments_json = json.dumps(results, indent=2)
    logs_json = json.dumps(log_files, indent=2)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SandBench — Log Viewer</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;600;700&display=swap');

  :root {{
    --bg: #0d1117;
    --surface: #161b22;
    --surface2: #1c2333;
    --border: #30363d;
    --text: #e6edf3;
    --text2: #8b949e;
    --accent: #58a6ff;
    --green: #3fb950;
    --red: #f85149;
    --orange: #d29922;
    --purple: #bc8cff;
    --cyan: #39d2c0;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'Inter', sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }}

  .header {{
    background: linear-gradient(135deg, #1a1e2e 0%, #0d1117 100%);
    border-bottom: 1px solid var(--border);
    padding: 20px 32px;
    display: flex;
    align-items: center;
    gap: 16px;
  }}
  .header h1 {{
    font-size: 22px;
    font-weight: 700;
    background: linear-gradient(90deg, var(--accent), var(--cyan));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }}
  .header .stats {{
    font-size: 13px;
    color: var(--text2);
    margin-left: auto;
  }}

  .layout {{
    display: grid;
    grid-template-columns: 320px 1fr;
    height: calc(100vh - 70px);
  }}

  /* Sidebar */
  .sidebar {{
    background: var(--surface);
    border-right: 1px solid var(--border);
    overflow-y: auto;
    padding: 12px;
  }}

  .filter-bar {{
    display: flex;
    gap: 6px;
    margin-bottom: 12px;
    flex-wrap: wrap;
  }}
  .filter-btn {{
    padding: 4px 10px;
    border-radius: 12px;
    border: 1px solid var(--border);
    background: transparent;
    color: var(--text2);
    font-size: 11px;
    cursor: pointer;
    font-family: 'Inter', sans-serif;
    transition: all 0.15s;
  }}
  .filter-btn:hover {{ border-color: var(--accent); color: var(--text); }}
  .filter-btn.active {{
    background: var(--accent);
    color: #000;
    border-color: var(--accent);
    font-weight: 600;
  }}

  .exp-item {{
    padding: 10px 12px;
    border-radius: 8px;
    cursor: pointer;
    margin-bottom: 4px;
    border: 1px solid transparent;
    transition: all 0.15s;
  }}
  .exp-item:hover {{ background: var(--surface2); border-color: var(--border); }}
  .exp-item.selected {{ background: var(--surface2); border-color: var(--accent); }}

  .exp-item .top {{ display: flex; justify-content: space-between; align-items: center; }}
  .exp-item .sample-id {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; font-weight: 600; }}
  .exp-item .mode-badge {{
    font-size: 10px;
    padding: 2px 8px;
    border-radius: 10px;
    font-weight: 600;
  }}
  .mode-A {{ background: #1e3a5f; color: var(--accent); }}
  .mode-B {{ background: #2d3a1f; color: var(--green); }}
  .mode-C {{ background: #3a2a1f; color: var(--orange); }}
  .mode-D {{ background: #2a1f3a; color: var(--purple); }}

  .exp-item .bottom {{ font-size: 11px; color: var(--text2); margin-top: 4px; }}
  .exp-item .score {{ font-weight: 600; }}
  .score-good {{ color: var(--green); }}
  .score-mid {{ color: var(--orange); }}
  .score-bad {{ color: var(--red); }}

  /* Main panel */
  .main {{
    overflow-y: auto;
    padding: 24px 32px;
  }}

  .detail-header {{
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 24px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }}
  .detail-header h2 {{ font-size: 18px; }}

  .metrics-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
  }}
  .metric-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
  }}
  .metric-card .label {{ font-size: 11px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.5px; }}
  .metric-card .value {{ font-size: 24px; font-weight: 700; font-family: 'JetBrains Mono', monospace; margin-top: 4px; }}

  /* Timeline */
  .timeline {{ margin-top: 24px; }}
  .timeline h3 {{ font-size: 15px; margin-bottom: 12px; color: var(--accent); }}

  .timeline-entry {{
    display: grid;
    grid-template-columns: 50px 24px 1fr;
    gap: 0 12px;
    margin-bottom: 2px;
    font-size: 13px;
  }}
  .timeline-step {{
    text-align: right;
    color: var(--text2);
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    padding-top: 8px;
  }}
  .timeline-dot {{
    display: flex;
    flex-direction: column;
    align-items: center;
    padding-top: 8px;
  }}
  .timeline-dot .dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
  }}
  .timeline-dot .line {{
    width: 2px;
    flex-grow: 1;
    background: var(--border);
    margin-top: 2px;
  }}
  .dot-tool {{ background: var(--accent); }}
  .dot-hypothesis {{ background: var(--green); }}
  .dot-judge {{ background: var(--orange); }}
  .dot-end {{ background: var(--purple); }}
  .dot-error {{ background: var(--red); }}

  .timeline-content {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 14px;
    margin-bottom: 8px;
  }}
  .timeline-content .type-label {{
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-weight: 700;
    margin-bottom: 4px;
  }}
  .type-tool_call {{ color: var(--accent); }}
  .type-hypothesis {{ color: var(--green); }}
  .type-judge_feedback {{ color: var(--orange); }}
  .type-judge_check {{ color: var(--orange); }}
  .type-end {{ color: var(--purple); }}
  .type-error {{ color: var(--red); }}
  .type-single_shot {{ color: var(--cyan); }}
  .type-analyst_refinement {{ color: var(--cyan); }}
  .type-agentic_round {{ color: var(--purple); }}

  .timeline-content pre {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--text2);
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow-y: auto;
    margin-top: 6px;
    padding: 8px;
    background: var(--bg);
    border-radius: 4px;
  }}

  .empty-state {{
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--text2);
    font-size: 15px;
  }}

  .search-box {{
    width: 100%;
    padding: 8px 12px;
    border-radius: 6px;
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', sans-serif;
    font-size: 13px;
    margin-bottom: 12px;
    outline: none;
  }}
  .search-box:focus {{ border-color: var(--accent); }}
</style>
</head>
<body>

<div class="header">
  <h1>SandBench Log Viewer</h1>
  <div class="stats" id="statsBar"></div>
</div>

<div class="layout">
  <div class="sidebar">
    <input type="text" class="search-box" id="searchBox" placeholder="Search sample ID...">
    <div class="filter-bar" id="filterBar"></div>
    <div id="expList"></div>
  </div>
  <div class="main" id="mainPanel">
    <div class="empty-state">Select an experiment from the sidebar</div>
  </div>
</div>

<script>
const experiments = {experiments_json};
const logFiles = {logs_json};

// State
let activeFilters = {{ model: null, mode: null }};
let selectedIdx = null;

// ── Render sidebar ──
function renderFilters() {{
  const bar = document.getElementById('filterBar');
  const models = [...new Set(experiments.map(e => e.model_key))];
  const modes = [...new Set(experiments.map(e => e.mode))];

  let html = '';
  modes.forEach(m => {{
    const cls = activeFilters.mode === m ? 'active' : '';
    html += `<button class="filter-btn mode-${{m}} ${{cls}}" onclick="toggleFilter('mode','${{m}}')">${{m}}</button>`;
  }});
  models.forEach(m => {{
    const cls = activeFilters.model === m ? 'active' : '';
    html += `<button class="filter-btn ${{cls}}" onclick="toggleFilter('model','${{m}}')">${{m}}</button>`;
  }});
  bar.innerHTML = html;
}}

function toggleFilter(type, val) {{
  activeFilters[type] = activeFilters[type] === val ? null : val;
  renderFilters();
  renderList();
}}

function getFiltered() {{
  const q = document.getElementById('searchBox').value.toLowerCase();
  return experiments.filter(e => {{
    if (activeFilters.model && e.model_key !== activeFilters.model) return false;
    if (activeFilters.mode && e.mode !== activeFilters.mode) return false;
    if (q && !sampleId(e).toLowerCase().includes(q)) return false;
    return true;
  }});
}}

function scoreClass(val) {{
  if (val >= 0.6) return 'score-good';
  if (val >= 0.3) return 'score-mid';
  return 'score-bad';
}}

function sampleId(e) {{
  return e.hash || e.sample_id || '?';
}}

function shortSampleId(e) {{
  const id = sampleId(e);
  return id.length > 16 ? id.slice(0, 16) + '...' : id;
}}

function renderList() {{
  const list = document.getElementById('expList');
  const filtered = getFiltered();
  const statsBar = document.getElementById('statsBar');
  statsBar.textContent = `${{filtered.length}} / ${{experiments.length}} experiments`;

  list.innerHTML = filtered.map((e, i) => {{
    const origIdx = experiments.indexOf(e);
    const comp = e.evaluation?.composite?.composite_score || 0;
    const sc = scoreClass(comp);
    const sel = origIdx === selectedIdx ? 'selected' : '';
    return `<div class="exp-item ${{sel}}" onclick="selectExp(${{origIdx}})">
      <div class="top">
        <span class="sample-id">#${{shortSampleId(e)}}</span>
        <span class="mode-badge mode-${{e.mode}}">Mode ${{e.mode}}</span>
      </div>
      <div class="bottom">
        ${{e.model_key}} &middot;
        <span class="score ${{sc}}">${{comp.toFixed(3)}}</span> &middot;
        ${{e.total_llm_calls}} calls &middot;
        ${{e.total_elapsed_seconds?.toFixed(1) || '?'}}s
      </div>
    </div>`;
  }}).join('');
}}

// ── Render detail panel ──
function selectExp(idx) {{
  selectedIdx = idx;
  renderList();

  const e = experiments[idx];
  const panel = document.getElementById('mainPanel');
  const ev = e.evaluation || {{}};
  const comp = ev.composite?.composite_score || 0;
  const ttpF1 = ev.ttp?.ttp_f1 || 0;
  const ttpRecall = ev.ttp?.ttp_recall || 0;
  const iocRecall = ev.ioc?.overall?.recall || 0;
  const eg = ev.evidence_grounding?.grounding_score;

  // Find log file
  const logKey = e.log_file || '';
  const logData = logFiles[logKey] || {{}};
  const logEntries = logData.log_entries || logData.trajectory || [];
  const hypotheses = logData.hypotheses || [];

  let metricsHtml = `
    <div class="metric-card"><div class="label">Composite</div><div class="value ${{scoreClass(comp)}}">${{comp.toFixed(3)}}</div></div>
    <div class="metric-card"><div class="label">TTP F1</div><div class="value ${{scoreClass(ttpF1)}}">${{ttpF1.toFixed(3)}}</div></div>
    <div class="metric-card"><div class="label">TTP Recall</div><div class="value ${{scoreClass(ttpRecall)}}">${{ttpRecall.toFixed(3)}}</div></div>
    <div class="metric-card"><div class="label">IOC Recall</div><div class="value ${{scoreClass(iocRecall)}}">${{iocRecall.toFixed(3)}}</div></div>
    <div class="metric-card"><div class="label">LLM Calls</div><div class="value">${{e.total_llm_calls}}</div></div>
    <div class="metric-card"><div class="label">Time</div><div class="value">${{e.total_elapsed_seconds?.toFixed(1) || '?'}}s</div></div>
  `;

  if (eg !== undefined && eg !== null) {{
    metricsHtml += `<div class="metric-card"><div class="label">Evidence Grounding</div><div class="value ${{scoreClass(eg)}}">${{eg.toFixed(3)}}</div></div>`;
  }}

  // Timeline
  let timelineHtml = '';
  if (logEntries.length > 0) {{
    timelineHtml = logEntries.map(entry => {{
      const t = entry.type || 'unknown';
      const dotClass = t.includes('tool') ? 'dot-tool' :
                        t.includes('hypo') ? 'dot-hypothesis' :
                        t.includes('judge') ? 'dot-judge' :
                        t.includes('end') ? 'dot-end' :
                        t.includes('error') ? 'dot-error' : 'dot-tool';

      // Build detail text
      let detail = '';
      if (t === 'tool_call') {{
        detail = `Tool: ${{entry.tool || '?'}}`;
        if (entry.args && Object.keys(entry.args).length > 0) detail += `\\nArgs: ${{JSON.stringify(entry.args)}}`;
        if (entry.result_preview) detail += `\\nResult: ${{entry.result_preview}}`;
        if (entry.budget_remaining !== undefined) detail += `\\nBudget: ${{entry.budget_remaining}}`;
      }} else if (t === 'hypothesis') {{
        detail = `Behavior: ${{entry.behavior || '?'}}`;
        if (entry.evidence_count) detail += `\\nEvidence items: ${{entry.evidence_count}}`;
      }} else if (t === 'judge_feedback') {{
        detail = entry.feedback_preview || '(no preview)';
      }} else if (t === 'judge_check') {{
        detail = entry.gap_summary || (entry.gaps ? entry.gaps.join('; ') : JSON.stringify(entry, null, 2));
      }} else if (t === 'analyst_refinement') {{
        detail = entry.ttps_now ? `TTPs now: ${{entry.ttps_now.join(', ')}}` : JSON.stringify(entry, null, 2);
      }} else if (t === 'single_shot') {{
        detail = `Prompt: ${{entry.prompt_chars || entry.prompt_length || '?'}} chars  Response: ${{entry.response_chars || entry.response_length || '?'}} chars`;
      }} else if (t === 'end') {{
        detail = entry.summary || JSON.stringify(entry, null, 2);
      }} else if (t === 'agentic_round') {{
        detail = `Round ${{entry.judge_round}}  Hypotheses: ${{entry.hypotheses_this_round}}  Tool calls: ${{entry.tool_calls_this_round}}`;
      }} else {{
        detail = JSON.stringify(entry, null, 2);
      }}

      const elapsed = entry.elapsed_seconds ? ` (${{entry.elapsed_seconds}}s)` : '';

      return `<div class="timeline-entry">
        <div class="timeline-step">#${{entry.step || '?'}}</div>
        <div class="timeline-dot"><div class="dot ${{dotClass}}"></div><div class="line"></div></div>
        <div class="timeline-content">
          <div class="type-label type-${{t}}">${{t}}${{elapsed}}</div>
          <pre>${{detail}}</pre>
        </div>
      </div>`;
    }}).join('');
  }}

  // Hypotheses section
  let hypHtml = '';
  if (hypotheses && hypotheses.length > 0) {{
    hypHtml = `<div class="timeline" style="margin-top:32px">
      <h3>Submitted Hypotheses (${{hypotheses.length}})</h3>
      ${{hypotheses.map((h, i) => `<div class="timeline-content" style="margin-bottom:8px">
        <div class="type-label type-hypothesis">Hypothesis #${{i+1}} (confidence: ${{h.confidence || '?'}})</div>
        <pre>Behavior: ${{h.behavior || '?'}}
MITRE: ${{h.ttp || h.mitre_ttp || 'none'}}
Evidence: ${{JSON.stringify(h.evidence || [], null, 2)}}</pre>
      </div>`).join('')}}
    </div>`;
  }}

  // Missed VT evidence
  let missedHtml = '';
  const missedTtps = ev.ttp?.fn ? ev.ttp.gt_ttps.filter(t => !ev.ttp.pred_ttps.includes(t)) : [];
  const missedIocs = [];
  for (const [kind, data] of Object.entries(ev.ioc || {{}})) {{
    if (data && Array.isArray(data.missed) && data.missed.length > 0) {{
      missedIocs.push(`${{kind}}: ${{data.missed.join(', ')}}`);
    }}
  }}
  const missed = missedTtps.length || missedIocs.length;
  if (missed) {{
    missedHtml = `<div style="margin-top:24px;padding:14px;background:var(--surface);border:1px solid var(--border);border-radius:8px">
      <div style="font-size:13px;font-weight:600;color:var(--red);margin-bottom:8px">Missed Evidence</div>
      <pre style="font-size:11px;color:var(--text2)">TTPs: ${{missedTtps.join(', ') || 'none'}}\\n${{missedIocs.join('\\n') || 'IOCs: none'}}</pre>
    </div>`;
  }}

  panel.innerHTML = `
    <div class="detail-header">
      <h2>Sample #${{shortSampleId(e)}}</h2>
      <span class="mode-badge mode-${{e.mode}}">Mode ${{e.mode}}: ${{e.mode_name}}</span>
      <span style="color:var(--text2);font-size:13px">${{e.model_key}}</span>
      <span style="color:var(--text2);font-size:13px;margin-left:auto">${{e.model_key}}</span>
    </div>
    <div class="metrics-grid">${{metricsHtml}}</div>
    ${{missedHtml}}
    <div class="timeline">
      <h3>Execution Timeline (${{logEntries.length}} entries)</h3>
      ${{timelineHtml || '<div style="color:var(--text2);padding:20px">No detailed log available for this experiment</div>'}}
    </div>
    ${{hypHtml}}
  `;
}}

// Init
document.getElementById('searchBox').addEventListener('input', renderList);
renderFilters();
renderList();
</script>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"  Log viewer saved: {output_path}")
    print(f"  Embedded {len(results)} experiments, {len(log_files)} log files")


def main():
    parser = argparse.ArgumentParser(description="Generate SandBench log viewer dashboard")
    parser.add_argument("--results", default="./results/benchmark_results.json")
    parser.add_argument("--log-dir", default="./logs")
    parser.add_argument("--output", default="./charts/log_viewer.html")
    args = parser.parse_args()

    print("Generating SandBench Log Viewer...")
    generate_log_viewer(args.results, args.log_dir, args.output)


if __name__ == "__main__":
    main()
