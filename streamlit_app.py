# --- unchanged imports and setup above ---

def preflight(cfg: ScanConfig):
    report = {"checks": []}

    # toolkit import
    if not TOOLKIT_OK:
        report["checks"].append({"name": "toolkit_import", "ok": False, "detail": str(TOOLKIT_ERR)})
        return False, report
    report["checks"].append({"name": "toolkit_import", "ok": True})

    # output dir
    try:
        os.makedirs(cfg.output_dir, exist_ok=True)
        with open(os.path.join(cfg.output_dir, ".write_test"), "w") as f:
            f.write("ok")
        os.remove(os.path.join(cfg.output_dir, ".write_test"))
        report["checks"].append({"name": "output_dir", "ok": True, "path": cfg.output_dir})
    except Exception as e:
        report["checks"].append({"name": "output_dir", "ok": False, "detail": str(e), "path": cfg.output_dir})
        return False, report

    # model name
    if not cfg.target_model:
        report["checks"].append({"name": "model_name", "ok": False, "detail": "Empty model name"})
        return False, report
    report["checks"].append({"name": "model_name", "ok": True, "value": cfg.target_model})

    # API keys
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

    # optional toolkit validation (fast)
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
    # unchanged: runs the scan and builds the payload
    scanner = GarakScanner(cfg)
    start = time.time()
    meta = scanner.run_comprehensive_scan()  # may raise *with JSON details now*
    analyzer = GarakAnalyzer(cfg.output_dir)
    analysis = analyzer.analyze_jsonl_reports()
    # ... build payload (same as your current version) ...
    # return payload

# --- UI control section where we collect future.result() ---

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
    st.error("Scan failed during execution.")

    # Try to parse JSON details from the exception message
    import json, re
    msg = str(e)
    details_obj = None
    if "details=" in msg:
        # grab the JSON-ish tail after 'details='
        m = re.search(r"details=(\\{.*\\})", msg, re.DOTALL)
        if m:
            try:
                details_obj = json.loads(m.group(1))
            except Exception:
                pass

    # Show inline details
    if details_obj:
        with st.expander("🔎 Validation details (from exception)"):
            st.json(details_obj)
    else:
        st.exception(e)

    # Also look for validation_report.json in the output dir
    if st.session_state.get("scan_dir"):
        candidate = os.path.join(st.session_state["scan_dir"], "validation_report.json")
        if os.path.exists(candidate):
            with open(candidate, "r") as f:
                try:
                    report_disk = json.load(f)
                except Exception:
                    report_disk = f.read()
            with st.expander("📄 validation_report.json (saved by toolkit)"):
                if isinstance(report_disk, dict):
                    st.json(report_disk)
                else:
                    st.code(report_disk, language="json")
            st.download_button("Download validation_report.json", data=open(candidate, "rb").read(),
                               file_name="validation_report.json", mime="application/json")
    st.stop()
