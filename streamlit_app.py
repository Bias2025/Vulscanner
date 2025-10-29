# ── Streamlit + Garak: production-ready app ───────────────────────────────────
# Features:
# - Robust preflight (env, keys, output dir, optional toolkit validation)
# - Clean background execution with progress animation + UI "stop"
# - Tight exception handling with detailed diagnostics (no hard crashes)
# - File watcher disabled for Streamlit Cloud to avoid inotify limit

import os
os.environ["STREAMLIT_WATCHDOG"] = "false"  # avoid inotify watch limit on Streamlit Cloud

import time
from typing import Dict, List, Optional
import json
import re

import streamlit as st

# Import your toolkit (ship this file alongside the app)
try:
    from garak_scanner_toolkit import (
        GarakScanner,
        GarakAnalyzer,
        ScanConfig,
        ScanCategory,
    )
    TOOLKIT_OK = True
    TOOLKIT_ERR = None
except Exception as e:
    TOOLKIT_OK = False
    TOOLKIT_ERR = e

# ── Page setup ────────────────────────────────────────────────────────────────
st.set_page_config(page_title="LLM Vulnerability Scanner (Garak)", layout="wide")
st.title("🛡️ LLM Vulnerability Scanner — Streamlit + Garak")
st.caption("Runs real Garak probes, with preflight + production-safe error handling.")

# Read secrets into env (non-destructive: secrets only set if not already in env)
for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
    try:
        val = st.secrets.get(key, "")
    except Exception:
        val = ""
    if val and not os.environ.get(key):
        os.environ[key] = val

# ── Sidebar: configuration ───────────────────────────────────────────────────
st.sidebar.header("Model Configuration")
model_type = st.sidebar.selectbox(
    "Model Type",
    ["openai", "anthropic", "huggingface", "ollama", "cohere", "replicate"],
    index=0,
)
model_name = st.sidebar.text_input(
    "Model Name (e.g., gpt-4o, claude-3-5, meta-llama/Meta-Llama-3-70B-Instruct)",
    value="gpt-4o",
)

st.sidebar.header("Vulnerability Categories")
UI_TO_CATEGORY = {
    "DAN / TAP / DRA (jailbreaks)": ScanCategory.JAILBREAKS if TOOLKIT_OK else "JAILBREAKS",
    "Prompt Injection":             ScanCategory.PROMPT_INJECTION if TOOLKIT_OK else "PROMPT_INJECTION",
    "Toxicity / Harmful Output":    ScanCategory.TOXICITY if TOOLKIT_OK else "TOXICITY",
    "Data Leakage":                 ScanCategory.DATA_LEAKAGE if TOOLKIT_OK else "DATA_LEAKAGE",
    "Malware Generation":           ScanCategory.MALWARE if TOOLKIT_OK else "MALWARE",
    "Package Hallucination":        ScanCategory.HALLUCINATION if TOOLKIT_OK else "HALLUCINATION",
}
categories_ui = st.sidebar.multiselect(
    "Choose one or more",
    list(UI_TO_CATEGORY.keys()),
    default=["Prompt Injection", "Malware Generation", "DAN / TAP / DRA (jailbreaks)"],
)

st.sidebar.header("Limits & Timeouts")
max_generations = st.sidebar.number_input("Max Generations per Probe", 1, 200, 10)
timeout = st.sidebar.number_input("Timeout (seconds)", 30, 24 * 3600, 3600)

st.sidebar.header("API Keys (override)")
openai_key = st.sidebar.text_input("OPENAI_API_KEY", type="password")
anthropic_key = st.sidebar.text_input("ANTHROPIC_API_KEY", type="password")

# ── Diagnostics ──────────────────────────────────────────────────────────────
with st.expander("🔧 Diagnostics"):
    st.write("Python:", os.sys.version)
    st.write("OPENAI_API_KEY set:", bool(os.environ.get("OPENAI_API_KEY") or openai_key))
    st.write("ANTHROPIC_API_KEY set:", bool(os.environ.get("ANTHROPIC_API_KEY") or anthropic_key))
    if TOOLKIT_OK:
        try:
            import garak  # noqa: F401
            ver = getattr(garak, "__version__", "unknown")
            st.write("garak importable ✓  version:", ver)
        except Exception as e:
            st.error(f"'garak' import failed: {e}")
    else:
        st.error(f"Toolkit import failed: {TOOLKIT_ERR}")

# ── Session state ────────────────────────────────────────────────────────────
st.session_state.setdefault("scan_running", False)
st.session_state.setdefault("progress", 0)
st.session_state.setdefault("results_payload", None)
st.session_state.setdefault("scan_dir", None)
st.session_state.setdefault("future", None)
if "EXECUTOR" not in st.session_state:
    from concurrent.futures import ThreadPoolExecutor
    st.session_state.EXECUTOR = ThreadPoolExecutor(max_workers=1)

# ── Helpers ──────────────────────────────────────────────────────────────────
def build_config() -> ScanConfig:
    merged_keys: Dict[str, str] = {}
    if os.environ.get("OPENAI_API_KEY") or openai_key:
        merged_keys["OPENAI_API_KEY"] = openai_key or os.environ.get("OPENAI_API_KEY", "")
    if os.environ.get("ANTHROPIC_API_KEY") or anthropic_key:
        merged_keys["ANTHROPIC_API_KEY"] = anthropic_key or os.environ.get("ANTHROPIC_API_KEY", "")

    chosen = [UI_TO_CATEGORY[c] for c in categories_ui] or [ScanCategory.COMPREHENSIVE]

    scan_id = str(int(time.time() * 1000))
    out_dir = os.path.abspath(f"./garak_results/streamlit_{scan_id}")
    os.makedirs(out_dir, exist_ok=True)
    st.session_state.scan_dir = out_dir

    return ScanConfig(
        target_model=model_name.strip(),
        model_type=model_type,
        scan_categories=chosen,
        output_dir=out_dir,
        report_prefix="scan",
        max_generations=int(max_generations),
        timeout=int(timeout),
        parallel_probes=1,
        api_keys=merged_keys or None,
    )

def preflight(cfg: ScanConfig):
    """Return (ok: bool, report: dict)."""
    report: Dict[str, object] = {"checks": []}

    if not TOOLKIT_OK:
        report["checks"].append({"name": "toolkit_import", "ok": False, "detail": str(TOOLKIT_ERR)})
        return False, report
    report["checks"].append({"name": "toolkit_import", "ok": True})

    # output dir writeability
    try:
        os.makedirs(cfg.output_dir, exist_ok=True)
        probe = os.path.join(cfg.output_dir, ".write_test")
        with open(probe, "w") as f:
            f.write("ok")
        os.remove(probe)
        report["checks"].append({"name": "output_dir", "ok": True, "path": cfg.output_dir})
    except Exception as e:
        report["checks"].append({"name": "output_dir", "ok": False, "detail": str(e), "path": cfg.output_dir})
        return False, report

    # model string
    if not cfg.target_model:
        report["checks"].append({"name": "model_name", "ok": False, "detail": "Empty model name"})
        return False, report
    report["checks"].append({"name": "model_name", "ok": True, "value": cfg.target_model})

    # provider keys heuristic
    need_openai = cfg.model_type.lower() == "openai"
    need_anthropic = cfg.model_type.lower() == "anthropic"
    if need_openai and not (cfg.api_keys and cfg.api_keys.get("OPENAI_API_KEY")):
        report["checks"].append({"name": "OPENAI_API_KEY", "ok": False, "detail": "Missing for OpenAI model"})
        return False, report
    if need_anthropic and not (cfg.api_keys and cfg.api_keys.get("ANTHROPIC_API_KEY")):
        report["checks"].append({"name": "ANTHROPIC_API_KEY", "ok": False, "detail": "Missing for Anthropic model"})
        return False, report
    if need_openai:    report["checks"].append({"name": "OPENAI_API_KEY", "ok": True})
    if need_anthropic: report["checks"].append({"name": "ANTHROPIC_API_KEY", "ok": True})

    # Optional: toolkit-level quick validation
    try:
        scanner = GarakScanner(cfg)
        if hasattr(scanner, "validate_environment"):
            ok, details = scanner.validate_environment(return_report=True)  # type: ignore[attr-defined]
            report["checks"].append({"name": "toolkit_validate_environment", "ok": bool(ok), "detail": details})
            if not ok:
                return False, report
        else:
            report["checks"].append({"name": "toolkit_validate_environment", "ok": True, "detail": "not exposed; skipped"})
    except Exception as e:
        report["checks"].append({"name": "toolkit_validate_environment", "ok": False, "detail": str(e)})
        return False, report

    return True, report

def run_scan_and_analyze(cfg: ScanConfig) -> Dict:
    """Run the scan (blocking) and return a UI-friendly payload."""
    scanner = GarakScanner(cfg)
    start = time.time()
    meta = scanner.run_comprehensive_scan()  # may raise; toolkit saves validation_report.json on failure
    analyzer = GarakAnalyzer(cfg.output_dir)
    analysis = analyzer.analyze_jsonl_reports()

    sev = analysis.get("severity_breakdown", {}) if isinstance(analysis, dict) else {}
    critical = int(sev.get("critical", 0)); high = int(sev.get("high", 0))
    medium   = int(sev.get("medium", 0));   low  = int(sev.get("low", 0))
    total = critical + high + medium + low

    probes_rows = []
    cat_stats: Dict[str, int] = {}
    for probe_name, pdata in (analysis.get("probe_results", {}) or {}).items():
        failed = int(pdata.get("failed_attempts", 0))
        total_attempts = int(pdata.get("total_attempts", max_generations))
        success_rate = round((max(total_attempts - failed, 0) / max(total_attempts, 1)) * 100, 1)
        category = probe_name.split(".")[0]
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
        "timestamp": meta.get("end_time"),
        "model": f"{cfg.model_type}:{cfg.target_model}",
        "duration": int(meta.get("total_duration", time.time() - start)),
        "summary": {"critical": critical, "high": high, "medium": medium, "low": low, "total": total},
        "probes": probes_rows,
        "categoryStats": cat_stats,
    }
    return payload

# ── UI controls (robust) ─────────────────────────────────────────────────────
left, right = st.columns([1, 1])
start_btn = left.button("▶️ Start Vulnerability Scan", disabled=st.session_state.scan_running)
stop_btn  = right.button("🛑 Stop (UI only)", disabled=not st.session_state.scan_running)

progress_bar = st.progress(st.session_state.progress)

# Start scan
if start_btn and not st.session_state.scan_running:
    if not TOOLKIT_OK:
        st.error("Cannot start: toolkit import failed.")
        st.exception(TOOLKIT_ERR)
        st.stop()

    # UI overrides env for provider keys
    if openai_key:
        os.environ["OPENAI_API_KEY"] = openai_key
    if anthropic_key:
        os.environ["ANTHROPIC_API_KEY"] = anthropic_key

    cfg = build_config()
    ok, preflight_report = preflight(cfg)
    with st.expander("📋 Preflight report", expanded=not ok):
        st.json(preflight_report)

    if not ok:
        st.error("Preflight failed. Fix the issues above and try again.")
        st.stop()

    st.session_state.scan_running = True
    st.session_state.progress = 0
    progress_bar.progress(0)
    st.session_state.results_payload = None
    st.session_state.future = st.session_state.EXECUTOR.submit(run_scan_and_analyze, cfg)

# UI-only stop (does not kill worker)
if stop_btn and st.session_state.scan_running:
    st.session_state.scan_running = False
    st.warning("Stopped the UI loop. The background thread may still finish in the background.")

# Animate progress while running
if st.session_state.scan_running and st.session_state.future is not None:
    while st.session_state.future.running() and st.session_state.scan_running:
        if st.session_state.progress < 95:
            st.session_state.progress += 1
            progress_bar.progress(st.session_state.progress)
        time.sleep(0.5)

# Collect results if future is done
if st.session_state.future is not None and st.session_state.future.done():
    try:
        st.session_state.results_payload = st.session_state.future.result()
        st.session_state.progress = 100
        progress_bar.progress(100)
        st.session_state.scan_running = False
        st.success("Scan completed.")
    except Exception as e:
        # Reset UI state safely
        st.session_state.scan_running = False
        st.session_state.progress = 0
        progress_bar.progress(0)
        st.error("Scan failed during execution.")

        # Try to parse JSON details embedded in the exception (…details={...})
        msg = str(e)
        details_obj = None
        m = re.search(r"details=(\{.*\})", msg, re.DOTALL)
        if m:
            try:
                details_obj = json.loads(m.group(1))
            except Exception:
                pass

        if details_obj:
            with st.expander("🔎 Validation details (from exception)"):
                st.json(details_obj)
        else:
            st.exception(e)

        # Also surface validation_report.json if the toolkit saved it
        if st.session_state.get("scan_dir"):
            candidate = os.path.join(st.session_state["scan_dir"], "validation_report.json")
            if os.path.exists(candidate):
                data = open(candidate, "rb").read()
                with st.expander("📄 validation_report.json (saved by toolkit)"):
                    try:
                        st.json(json.loads(data))
                    except Exception:
                        st.code(data.decode("utf-8", errors="ignore"), language="json")
                st.download_button("Download validation_report.json", data=data,
                                   file_name="validation_report.json", mime="application/json")
        # Clear future so we don't re-handle this on next rerun
        st.session_state.future = None

# ── Results ──────────────────────────────────────────────────────────────────
results = st.session_state.results_payload
if results:
    st.subheader("Results Summary")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Critical", results["summary"]["critical"])
    m2.metric("High",     results["summary"]["high"])
    m3.metric("Medium",   results["summary"]["medium"])
    m4.metric("Low",      results["summary"]["low"])
    m5.metric("Total",    results["summary"]["total"])

    st.write(
        f"**Model:** {results['model']}  |  **Duration:** {results['duration']}s  |  **Timestamp:** {results['timestamp']}"
    )

    st.subheader("Vulnerability Distribution by Category")
    if results["categoryStats"]:
        st.bar_chart(results["categoryStats"])
    else:
        st.info("No category stats available.")

    st.subheader("Probe Results")
    if results["probes"]:
        import pandas as pd
        df = pd.DataFrame(results["probes"])
        st.dataframe(df, use_container_width=True)
        c1, c2 = st.columns(2)
        with c1:
            st.download_button(
                "Export JSON",
                data=json.dumps(results, indent=2).encode(),
                file_name="vulnerability_results.json",
                mime="application/json",
            )
        with c2:
            csv = df.to_csv(index=False)
            st.download_button("Export CSV", data=csv, file_name="vulnerability_results.csv", mime="text/csv")
    else:
        st.info("No probe rows were parsed.")
else:
    st.info("No results yet. Configure and click Start.")
