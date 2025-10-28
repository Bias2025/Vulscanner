import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List

import streamlit as st

# Your toolkit (from the uploaded file)
from garak_scanner_toolkit import (
    GarakScanner,
    GarakAnalyzer,
    ScanConfig,
    ScanCategory,
)

# ----------- UI → toolkit category mapping -----------
UI_TO_CATEGORY = {
    "DAN / TAP / DRA (jailbreaks)": ScanCategory.JAILBREAKS,
    "Prompt Injection": ScanCategory.PROMPT_INJECTION,
    "Toxicity / Harmful Output": ScanCategory.TOXICITY,
    "Data Leakage": ScanCategory.DATA_LEAKAGE,
    "Malware Generation": ScanCategory.MALWARE,
    "Package Hallucination": ScanCategory.HALLUCINATION,
}

st.set_page_config(page_title="LLM Vulnerability Scanner (Garak)", layout="wide")

# ---------- Sidebar: config ----------
st.sidebar.header("Model Configuration")
model_type = st.sidebar.selectbox("Model Type", ["openai", "anthropic", "huggingface", "ollama", "cohere", "replicate"])
model_name = st.sidebar.text_input("Model Name (e.g., gpt-4o, claude-3-5, meta-llama/Meta-Llama-3-70B-Instruct)", value="gpt-4o")

st.sidebar.header("Vulnerability Categories")
categories = st.sidebar.multiselect(
    "Choose one or more",
    list(UI_TO_CATEGORY.keys()),
    default=["Prompt Injection", "Malware Generation", "DAN / TAP / DRA (jailbreaks)"],
)

st.sidebar.header("Limits & Timeouts")
max_generations = st.sidebar.number_input("Max Generations per Probe", 1, 200, 10)
timeout = st.sidebar.number_input("Timeout (seconds)", 30, 24 * 3600, 3600)

st.sidebar.header("API Keys (optional)")
openai_key = st.sidebar.text_input("OPENAI_API_KEY", type="password")
anthropic_key = st.sidebar.text_input("ANTHROPIC_API_KEY", type="password")

# ---------- Session state ----------
if "scan_running" not in st.session_state:
    st.session_state.scan_running = False
if "progress" not in st.session_state:
    st.session_state.progress = 0
if "results_payload" not in st.session_state:
    st.session_state.results_payload = None
if "scan_dir" not in st.session_state:
    st.session_state.scan_dir = None

st.title("🛡️ LLM Vulnerability Scanner — Streamlit + Garak")
st.caption("Runs real Garak probes and aggregates results into an executive-friendly summary.")

# ---------- Build ScanConfig ----------
def build_config() -> ScanConfig:
    api_keys = {}
    if openai_key:
        api_keys["OPENAI_API_KEY"] = openai_key
    if anthropic_key:
        api_keys["ANTHROPIC_API_KEY"] = anthropic_key

    chosen = [UI_TO_CATEGORY[c] for c in categories] or [ScanCategory.COMPREHENSIVE]
    scan_id = str(int(time.time() * 1000))
    out_dir = os.path.abspath(f"./garak_results/streamlit_{scan_id}")
    os.makedirs(out_dir, exist_ok=True)
    st.session_state.scan_dir = out_dir

    return ScanConfig(
        target_model=model_name,
        model_type=model_type,
        scan_categories=chosen,
        output_dir=out_dir,
        report_prefix="scan",
        max_generations=int(max_generations),
        timeout=int(timeout),
        parallel_probes=1,
        api_keys=api_keys or None,
    )

# ---------- Run scan in a worker thread ----------
EXECUTOR = ThreadPoolExecutor(max_workers=1)

def run_scan_and_analyze(cfg: ScanConfig) -> Dict:
    scanner = GarakScanner(cfg)
    start = time.time()
    results_meta = scanner.run_comprehensive_scan()  # blocking; toolkit handles garak CLI/lib

    analyzer = GarakAnalyzer(cfg.output_dir)
    analysis = analyzer.analyze_jsonl_reports()  # returns dict with severity_breakdown, probe_results, etc.

    # Build the same shape your web dashboard expects
    sev = analysis.get("severity_breakdown", {}) if isinstance(analysis, dict) else {}
    critical = int(sev.get("critical", 0))
    high = int(sev.get("high", 0))
    medium = int(sev.get("medium", 0))
    low = int(sev.get("low", 0))
    total = critical + high + medium + low

    probes_rows = []
    cat_stats: Dict[str, int] = {}
    for probe_name, pdata in (analysis.get("probe_results", {}) or {}).items():
        failed = int(pdata.get("failed_attempts", 0))
        total_attempts = int(pdata.get("total_attempts", max_generations))
        success_rate = round((max(total_attempts - failed, 0) / max(total_attempts, 1)) * 100, 1)
        category = probe_name.split(".")[0]  # heuristic bucket
        severity = "critical" if category in {"tap", "malwaregen"} else ("high" if failed > 0 else "medium")
        probes_rows.append(
            {
                "name": probe_name,
                "category": category,
                "severity": severity,
                "totalAttempts": total_attempts,
                "failed": failed,
                "successRate": success_rate,
            }
        )
        cat_stats[category] = cat_stats.get(category, 0) + failed

    payload = {
        "timestamp": results_meta.get("end_time"),
        "model": f"{model_type}:{model_name}",
        "duration": int(results_meta.get("total_duration", time.time() - start)),
        "summary": {"critical": critical, "high": high, "medium": medium, "low": low, "total": total},
        "probes": probes_rows,
        "categoryStats": cat_stats,
    }
    return payload

# ---------- UI: Start / progress ----------
col_left, col_right = st.columns([1, 1])
with col_left:
    start_btn = st.button("▶️ Start Vulnerability Scan", disabled=st.session_state.scan_running)
with col_right:
    stop_btn = st.button("🛑 Stop (UI only)", disabled=not st.session_state.scan_running)

progress_bar = st.progress(st.session_state.progress)

if start_btn and not st.session_state.scan_running:
    st.session_state.scan_running = True
    st.session_state.progress = 0
    st.session_state.results_payload = None

    cfg = build_config()

    # Kick off background work
    future = EXECUTOR.submit(run_scan_and_analyze, cfg)

    # Animate progress while the worker runs
    while future.running():
        if st.session_state.progress < 95:
            st.session_state.progress += 1
            progress_bar.progress(st.session_state.progress)
        time.sleep(0.5)

    # Finish & collect
    st.session_state.results_payload = future.result()
    st.session_state.progress = 100
    progress_bar.progress(100)
    st.session_state.scan_running = False
    st.success("Scan completed.")

if stop_btn and st.session_state.scan_running:
    # We don't forcibly kill the worker; we just stop animating the UI.
    st.session_state.scan_running = False
    st.warning("Stopped the UI loop. The background thread may still finish this run.")

# ---------- Results ----------
results = st.session_state.results_payload
if results:
    st.subheader("Results Summary")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Critical", results["summary"]["critical"])
    m2.metric("High", results["summary"]["high"])
    m3.metric("Medium", results["summary"]["medium"])
    m4.metric("Low", results["summary"]["low"])
    m5.metric("Total", results["summary"]["total"])

    st.write(f"**Model:** {results['model']}  |  **Duration:** {results['duration']}s  |  **Timestamp:** {results['timestamp']}")

    st.subheader("Vulnerability Distribution by Category")
    if results["categoryStats"]:
        # Streamlit bar chart accepts dicts or dataframes
        st.bar_chart(results["categoryStats"])
    else:
        st.info("No category stats available.")

    st.subheader("Probe Results")
    if results["probes"]:
        # Nicely sortable
        import pandas as pd
        df = pd.DataFrame(results["probes"])
        st.dataframe(df, use_container_width=True)
        # Export helpers
        c1, c2 = st.columns(2)
        with c1:
            st.download_button("Export JSON", data=str(results).encode(), file_name="vulnerability_results.json", mime="application/json")
        with c2:
            csv = df.to_csv(index=False)
            st.download_button("Export CSV", data=csv, file_name="vulnerability_results.csv", mime="text/csv")
    else:
        st.info("No probe rows were parsed.")
else:
    st.info("No results yet. Configure and click Start.")
