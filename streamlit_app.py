# streamlit_app.py
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict

import streamlit as st

# --- Try to import your toolkit early so we can surface import errors nicely
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

# ---------- Streamlit page config ----------
st.set_page_config(page_title="LLM Vulnerability Scanner (Garak)", layout="wide")
st.title("🛡️ LLM Vulnerability Scanner — Streamlit + Garak")
st.caption("Runs real Garak probes and shows a friendly summary. Now with preflight + safe error handling.")

# ---------- Read secrets into env (non-destructive defaults) ----------
# This lets Garak and underlying SDKs find keys if provided via Streamlit Secrets.
for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
    try:
        val = st.secrets.get(key, "")
    except Exception:
        val = ""
    if val and not os.environ.get(key):
        os.environ[key] = val

# ---------- Sidebar config ----------
st.sidebar.header("Model Configuration")
model_type = st.sidebar.selectbox(
    "Model Type",
    ["openai", "anthropic", "huggingface", "ollama", "cohere", "replicate"],
)
model_name = st.sidebar.text_input(
    "Model Name (e.g., gpt-4o, claude-3-5, meta-llama/Meta-Llama-3-70B-Instruct)",
    value="gpt-4o",
)

st.sidebar.header("Vulnerability Categories")
UI_TO_CATEGORY = {
    "DAN / TAP / DRA (jailbreaks)": ScanCategory.JAILBREAKS if TOOLKIT_OK else "JAILBREAKS",
    "Prompt Injection": ScanCategory.PROMPT_INJECTION if TOOLKIT_OK else "PROMPT_INJECTION",
    "Toxicity / Harmful Output": ScanCategory.TOXICITY if TOOLKIT_OK else "TOXICITY",
    "Data Leakage": ScanCategory.DATA_LEAKAGE if TOOLKIT_OK else "DATA_LEAKAGE",
    "Malware Generation": ScanCategory.MALWARE if TOOLKIT_OK else "MALWARE",
    "Package Hallucination": ScanCategory.HALLUCINATION if TOOLKIT_OK else "HALLUCINATION",
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

# ---------- Diagnostics panel ----------
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

# ---------- Session state ----------
if "scan_running" not in st.session_state:
    st.session_state.scan_running = False
if "progress" not in st.session_state:
    st.session_state.progress = 0
if "results_payload" not in st.session_state:
    st.session_state.results_payload = None
if "scan_dir" not in st.session_state:
    st.session_state.scan_dir = None

# ---------- Helpers ----------
def build_config() -> ScanConfig:
    # Merge sidebar overrides (UI wins over env)
    merged_keys = {}
    if os.environ.get("OPENAI_API_KEY") or openai_key:
        merged_keys["OPENAI_API_KEY"] = openai_key or os.environ.get("OPENAI_API_KEY")
    if os.environ.get("ANTHROPIC_API_KEY") or anthropic_key:
        merged_keys["ANTHROPIC_API_KEY"] = anthropic_key or os.environ.get("ANTHROPIC_API_KEY")

    chosen = [UI_TO_CATEGORY[c] for c in categories_ui]
    if not chosen:
        chosen = [ScanCategory.COMPREHENSIVE]

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
    """
    Run lightweight checks and return (ok: bool, report: dict).
    Goal: explain *why* a scan would fail: missing keys, invalid model, garak not importable, etc.
    """
    report: Dict[str, object] = {"checks": []}

    # 0) Toolkit import
    if not TOOLKIT_OK:
        report["checks"].append({"name": "toolkit_import", "ok": False, "detail": str(TOOLKIT_ERR)})
        return False, report
    report["checks"].append({"name": "toolkit_import", "ok": True})

    # 1) Output dir writeability
    try:
        test_path = os.path.join(cfg.output_dir, ".write_test")
        os.makedirs(cfg.output_dir, exist_ok=True)
        with open(test_path, "w") as f:
            f.write("ok")
        os.remove(test_path)
        report["checks"].append({"name": "output_dir", "ok": True, "path": cfg.output_dir})
    except Exception as e:
        report["checks"].append({"name": "output_dir", "ok": False, "detail": str(e), "path": cfg.output_dir})
        return False, report

    # 2) Model string sanity
    if not cfg.target_model:
        report["checks"].append({"name": "model_name", "ok": False, "detail": "Empty model name"})
        return False, report
    report["checks"].append({"name": "model_name", "ok": True, "value": cfg.target_model})

    # 3) Backend API keys expectation (heuristics)
    need_openai = cfg.model_type.lower() == "openai"
    need_anthropic = cfg.model_type.lower() == "anthropic"
    if need_openai and not (cfg.api_keys and cfg.api_keys.get("OPENAI_API_KEY")):
        report["checks"].append({"name": "OPENAI_API_KEY", "ok": False, "detail": "Missing for OpenAI model"})
        return False, report
    if need_anthropic and not (cfg.api_keys and cfg.api_keys.get("ANTHROPIC_API_KEY")):
        report["checks"].append({"name": "ANTHROPIC_API_KEY", "ok": False, "detail": "Missing for Anthropic model"})
        return False, report
    if need_openai:
        report["checks"].append({"name": "OPENAI_API_KEY", "ok": True})
    if need_anthropic:
        report["checks"].append({"name": "ANTHROPIC_API_KEY", "ok": True})

    # 4) Optional: Toolkit-provided validation (if available)
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

# Long-running worker
def run_scan_and_analyze(cfg: ScanConfig) -> Dict:
    scanner = GarakScanner(cfg)
    start = time.time()
    meta = scanner.run_comprehensive_scan()  # blocks; may raise
    analyzer = GarakAnalyzer(cfg.output_dir)
    analysis = analyzer.analyze_jsonl_reports()  # returns dict

    sev = analysis.get("severity_breakdown", {}) if isinstance(analysis, dict) else {}
    critical = int(sev.get("critical", 0)); high = int(sev.get("high", 0))
    medium = int(sev.get("medium", 0)); low = int(sev.get("low", 0))
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

# ---------- UI controls ----------
left, right = st.columns([1, 1])
start_btn = left.button("▶️ Start Vulnerability Scan", disabled=st.session_state.scan_running)
stop_btn = right.button("🛑 Stop (UI only)", disabled=not st.session_state.scan_running)
progress_bar = st.progress(st.session_state.progress)

EXECUTOR = ThreadPoolExecutor(max_workers=1)

if start_btn and not st.session_state.scan_running:
    if not TOOLKIT_OK:
        st.error("Cannot start: toolkit import failed.")
        st.exception(TOOLKIT_ERR)
        st.stop()

    # Merge sidebar overrides into env for the run
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
    st.session_state.results_payload = None

    future = EXECUTOR.submit(run_scan_and_analyze, cfg)

    # Animate progress while worker runs
    while future.running():
        if st.session_state.progress < 95:
            st.session_state.progress += 1
            progress_bar.progress(st.session_state.progress)
        time.sleep(0.5)

    # Collect results with safety net
    try:
        st.session_state.results_payload = future.result()
        st.session_state.progress = 100
        progress_bar.progress(100)
        st.session_state.scan_running = False
        st.success("Scan completed.")
    except Exception as e:
        st.session_state.scan_running = False
        st.session_state.progress = 0
        progress_bar.progress(0)
        st.error("Scan failed during execution. See details below.")
        st.exception(e)
        st.stop()

if stop_btn and st.session_state.scan_running:
    # UI stop only: we don't kill the thread, but stop animating.
    st.session_state.scan_running = False
    st.warning("Stopped the UI loop. The background thread may still finish in the background.")

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
                data=str(results).encode(),
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
