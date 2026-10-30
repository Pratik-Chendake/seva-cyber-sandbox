"""
Seva Cyber Sandbox: Malicious APK & Vernacular Phishing Detector for WhatsApp
Main Streamlit Web Application (app.py)

Hackathon: Seva First Innovation Challenge 2026
Sub-Theme: Responsible AI, Deepfake Detection, Cyber Resilience and Digital Trust
"""

import json
import os
from typing import Any, Dict, List

import streamlit as st

import create_sample_apks
from src.apk_analyzer import MAX_APK_UPLOAD_BYTES, analyze_apk_bytes
from src.audio_alert import (
    generate_alert_wav_bytes,
    get_spoken_script,
    inspect_installed_tts_voices,
    speak_offline_windows_tts,
)
from src.ml_classifier import predict_with_local_ml, train_and_evaluate_local_model
from src.phishing_detector import analyze_message_text
from src.risk_scorer import score_apk_analysis, score_message_analysis
from src.scheme_verifier import load_official_sources, verify_scheme_claim
from src.url_analyzer import analyze_url
from src.whatsapp_handler import (
    clear_simulated_outbox,
    get_simulated_outbox_entries,
    load_whatsapp_config,
    process_incoming_webhook_event,
)
from src.hybrid_decision_engine import evaluate_message_hybrid
from src.model_registry import get_default_model_registry
from src.case_manager import (
    SessionCaseStore,
    create_apk_case,
    create_message_case,
    create_scheme_case,
    create_url_case,
    generate_evidence_report,
)
try:
    from evaluation.evaluate_phishing import get_cached_evaluation_report
except Exception:
    get_cached_evaluation_report = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_MESSAGES_PATH = os.path.join(BASE_DIR, "data", "sample_messages.json")
SAMPLE_APKS_DIR = os.path.join(BASE_DIR, "sample_apks")


def ensure_sample_apks_exist() -> List[str]:
    """Ensures the 5 safe test files exist in sample_apks/ before rendering the selector."""
    if not os.path.exists(SAMPLE_APKS_DIR) or not os.listdir(SAMPLE_APKS_DIR):
        try:
            create_sample_apks.main()
        except Exception:
            pass
    if not os.path.exists(SAMPLE_APKS_DIR):
        return []
    return sorted(f for f in os.listdir(SAMPLE_APKS_DIR) if f.endswith(".apk"))


def load_sample_messages() -> List[Dict[str, Any]]:
    """Safely loads the sample messages dataset from data/sample_messages.json."""
    if not os.path.exists(SAMPLE_MESSAGES_PATH):
        return []
    try:
        with open(SAMPLE_MESSAGES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def render_risk_assessment_panel(
    scored: Dict[str, Any], enable_audio: bool, key_prefix: str
) -> None:
    """Renders the unified risk level, score, bilingual summaries, evidence, next steps, and audio alert."""
    color = scored.get("badge_color", "gray")
    icon = {"red": "🚨", "orange": "⚠️", "green": "ℹ️"}.get(color, "🔎")

    st.markdown("---")
    st.subheader(f"{icon} {scored.get('analysis_type', 'Security Assessment')} Result")

    col_status, col_metric = st.columns([2, 1])
    with col_status:
        if color == "red":
            st.error(f"**Assessment Label:** {scored['risk_level']}")
        elif color == "orange":
            st.warning(f"**Assessment Label:** {scored['risk_level']}")
        else:
            st.info(f"**Assessment Label:** {scored['risk_level']}")
    with col_metric:
        st.metric(
            "Heuristic Risk Index (0–100)",
            f"{scored['score']} / 100",
            help="Weighted checklist index of detected risk indicators (not a probability of maliciousness).",
        )

    st.markdown(f"**English Explanation:** {scored['summary_en']}")
    st.markdown(f"**मराठी स्पष्टीकरण (Marathi Explanation):** {scored['summary_mr']}")

    st.markdown("#### 🔍 Matched Evidence & Warning Indicators")
    for ev in scored.get("evidence", []):
        st.markdown(f"- {ev}")

    if scored.get("observed_facts"):
        with st.expander("📋 Confirmed Structural Observations vs. Heuristic Inferences", expanded=False):
            st.markdown("**Confirmed Static Facts (Ground Truth Observations):**")
            for fact in scored.get("observed_facts", []):
                st.markdown(f"- `{fact}`")
            if scored.get("heuristic_inferences"):
                st.markdown("**Heuristic Inferences (Expert Rule Deductions & Severity Weights):**")
                for inf in scored.get("heuristic_inferences", []):
                    st.markdown(f"- *{inf}*")

    col_en, col_mr = st.columns(2)
    with col_en:
        st.markdown("#### 🛡️ Suggested Safe Next Steps (English)")
        for idx, step in enumerate(scored.get("safe_next_steps_en", []), start=1):
            st.markdown(f"{idx}. {step}")
    with col_mr:
        st.markdown("#### 🛡️ सुरक्षित पुढील पावले (Marathi)")
        for idx, step in enumerate(scored.get("safe_next_steps_mr", []), start=1):
            st.markdown(f"{idx}. {step}")

    if enable_audio:
        st.markdown("#### 🔊 Audio Warning & Accessibility Fallback")
        spoken_en, written_mr = get_spoken_script(color, scored["analysis_type"])
        wav_bytes = generate_alert_wav_bytes(color)
        st.audio(wav_bytes, format="audio/wav")
        st.info(written_mr)

        if st.button(
            "🗣️ Speak Warning Aloud (Windows Offline SAPI5 TTS)",
            key=f"{key_prefix}_tts_btn",
        ):
            ok, msg = speak_offline_windows_tts(spoken_en)
            if ok:
                st.success(msg)
            else:
                st.warning(msg)

    st.caption(f"⚖️ **Limitations & Uncertainty Disclosure:** {scored.get('limitations', '')}")


def main() -> None:
    st.set_page_config(
        page_title="Seva Cyber Sandbox — APK & Vernacular Phishing Detector",
        page_icon="🛡️",
        layout="wide",
    )

    if "case_store" not in st.session_state:
        st.session_state.case_store = SessionCaseStore()

    st.title("🛡️ Seva Cyber Sandbox: Malicious APK & Vernacular Phishing Detector for WhatsApp")
    st.markdown(
        "**Seva First Innovation Challenge 2026** | "
        "**Sub-Theme:** *Responsible AI, Deepfake Detection, Cyber Resilience and Digital Trust*"
    )

    st.info(
        "**Defensive Sandbox & Simulation Disclosure:** "
        "This application performs **real static inspection** of Android `.apk` archives and "
        "**real rule-based + educational ML analysis** of Marathi (Devanagari), Romanized Marathi, Mixed, and English messages. "
        "**Simulated Workflow:** Pasting messages or uploading files in this web dashboard simulates forwarding content to a WhatsApp helpline bot. "
        "This sandbox **never** installs APKs, **never** executes code, **never** visits extracted URLs, and **never** claims a file or message is 100% safe."
    )

    with st.sidebar:
        st.header("⚙️ Sandbox Settings")
        enable_audio = st.checkbox("Enable Audio Alert & TTS Controls", value=True)
        show_ml_panel = st.checkbox(
            "Show Experimental Local ML Baseline Comparison", value=True
        )

        if st.button("🔍 Check Installed Windows TTS Voices"):
            v_info = inspect_installed_tts_voices()
            if v_info["tts_available"]:
                st.success(f"Detected {len(v_info['voices'])} offline system voice(s).")
                st.write("Voices:", v_info["voices"])
                if not v_info["has_marathi_or_hindi_voice"]:
                    st.caption(
                        "Note: No native offline Marathi voice pack detected on this PC; "
                        "spoken TTS uses English while Marathi is displayed on screen."
                    )
            else:
                st.warning(
                    "Offline OS speech driver not detected. The built-in browser WAV player remains active."
                )

        st.markdown("---")
        st.markdown("### 🔒 Privacy & Hosting Disclosure")
        st.markdown(
            "- **When Running Locally (`localhost:8501`):** All files and messages are processed strictly in your laptop's RAM and never leave your machine.\n"
            "- **When Using a Public Cloud Demo URL:** Uploaded files travel over HTTPS to the cloud application server's memory for analysis. **Never upload private personal chats, real banking documents, or confidential files to a public demo server.**\n"
            "- **No Permanent Storage:** Neither local nor cloud mode writes uploaded APKs or pasted messages to a database.\n"
            "- **Emergency Helpline:** Report real financial cyber fraud immediately to **1930** or `https://cybercrime.gov.in`."
        )

    tab_phishing, tab_apk, tab_url, tab_scheme, tab_cases, tab_eval, tab_review = st.tabs(
        [
            "💬 1. Marathi & Mixed-Language Phishing Detector",
            "📦 2. Android .APK Static Security Analyzer",
            "🌐 3. Safe Suspicious URL Analyzer",
            "🏛️ 4. Maharashtra Scheme & Announcement Verifier",
            "📋 5. Threat Case Dashboard & Evidence Export",
            "📊 6. Optional ML Baseline & Responsible AI Disclosures",
            "🛡️ 7. Human Review Desk & Model Registry",
        ]
    )

    # =========================================================================
    # TAB 1: VERNACULAR PHISHING DETECTOR
    # =========================================================================
    with tab_phishing:
        st.subheader("💬 WhatsApp Vernacular Phishing Detector (Marathi, Romanized Marathi, Mixed & English)")
        st.caption(
            "Simulates a citizen forwarding a suspicious WhatsApp message for instant indicator inspection."
        )

        samples = load_sample_messages()
        options = ["-- Custom Input (Type or Paste Below) --"] + [
            f"{item['id'].upper()} [{item['label'].upper()}]: {item['title']} ({item['language']})"
            for item in samples
        ]
        chosen_sample = st.selectbox(
            "Choose a Safe Fictional Test Message or Select Custom Input:", options
        )

        initial_text = ""
        ground_truth = None
        if chosen_sample != "-- Custom Input (Type or Paste Below) --":
            sample_idx = options.index(chosen_sample) - 1
            initial_text = samples[sample_idx]["text"]
            ground_truth = samples[sample_idx]["label"]

        message_input = st.text_area(
            "WhatsApp Message Text to Analyze:",
            value=initial_text,
            height=130,
            placeholder="Paste a Marathi (Devanagari), Romanized Marathi, or English message here...",
        )

        training_consent_opt_in = st.checkbox(
            "🔒 Opt-in: Allow anonymous Machine Learning feature extraction for future model improvement",
            value=False,
            help=(
                "OPT-IN ONLY (Default: Off). If checked, the system computes and retains an abstract 1024-dimensional "
                "numerical feature representation from sanitized text for local model improvement. "
                "The original message text is NOT stored. Derived features are retained strictly on this local device "
                "and are not guaranteed anonymous."
            ),
            key="training_consent_checkbox",
        )

        if st.button("🔍 Analyze WhatsApp Message", type="primary", key="run_msg_btn"):
            msg_res = analyze_message_text(message_input)
            if msg_res["is_empty"]:
                st.warning("Please enter or select a non-empty message to analyze.")
            else:
                scored_msg = score_message_analysis(msg_res)
                st.markdown(f"**Detected Script Format:** `{msg_res['script_detected']}`")
                if ground_truth:
                    st.caption(f"Sample Dataset Ground-Truth Category: **{ground_truth.upper()}**")

                if msg_res.get("context_only_suppressed"):
                    st.success(
                        "✅ **Context Safeguard Active:** This message mentions a utility or bank (such as MSEDCL or SBI), "
                        "but contains **no** suspicious links, `.apk` files, urgency threats, or credential requests. "
                        "It was therefore not flagged."
                    )
                if msg_res.get("protective_advisory_detected"):
                    st.success(
                        "✅ **Protective Negation Safeguard Active:** Detected security awareness phrasing "
                        "(e.g., advising users *never* to share OTPs or download unknown APKs)."
                    )

                render_risk_assessment_panel(
                    scored_msg, enable_audio=enable_audio, key_prefix="msg"
                )
                msg_case = create_message_case(msg_res, scored_msg)
                msg_case_id = st.session_state.case_store.add_case(msg_case)
                st.caption(f"📋 **Case Logged to Session Dashboard:** `{msg_case_id}` (Inspect in Tab 5)")

                # Phase 6.1: Opt-in Derived Feature Capture
                if training_consent_opt_in:
                    feat_capture = st.session_state.case_store.capture_training_features(
                        case_id=msg_case_id,
                        message_text=message_input,
                        consent_given=True,
                    )
                    if feat_capture.get("captured"):
                        st.caption(
                            f"🔒 **Derived Training Features Captured (Opt-In Active):** "
                            f"Record `{feat_capture.get('feature_record_id')}` ({feat_capture.get('feature_dim')} dimensions, zero raw text stored)"
                        )
                    else:
                        st.caption(f"ℹ️ Training feature capture skipped: {feat_capture.get('reason')}")

                # -------------------------------------------------------------
                # Hybrid Decision Engine Diagnostics (Phase 4)
                # -------------------------------------------------------------
                hybrid_eval = evaluate_message_hybrid(
                    message_text=message_input,
                    rule_analysis=msg_res,
                )
                with st.expander("🛡️ Hybrid Decision Engine & Guardrails Diagnostics", expanded=False):
                    c_h1, c_h2, c_h3 = st.columns(3)
                    c_h1.metric("Engine Mode", hybrid_eval["operating_mode"].upper(), help="Configured via HYBRID_ENGINE_MODE (Default: shadow)")
                    c_h2.metric("Rule Score (Authoritative)", f"{hybrid_eval['final_decision']['final_risk_score']} / 100")
                    conc_status = hybrid_eval["concordance"]["status"]
                    c_h3.metric(
                        "Model-Rule Concordance",
                        conc_status,
                        delta="Agreed" if conc_status == "AGREEMENT" else ("Disagreed" if conc_status == "DISAGREEMENT" else "N/A"),
                        delta_color="normal" if conc_status == "AGREEMENT" else "inverse",
                    )

                    st.markdown("##### 🔬 Evidence Decomposition")
                    st.write(f"- **Authoritative Rule Verdict:** `{hybrid_eval['rule_based_evidence']['rule_label']}` (Findings: {hybrid_eval['rule_based_evidence']['findings_count']})")
                    exp_m = hybrid_eval["experimental_model"]
                    if exp_m.get("is_available"):
                        st.write(
                            f"- **Experimental Custom Neural Model:** `{exp_m.get('predicted_label')}` "
                            f"(Uncalibrated Confidence: `{exp_m.get('confidence', 0.0):.2%}`, Version: `{exp_m.get('model_version')}`)"
                        )
                        st.caption(f"⚠️ *{exp_m.get('confidence_warning')}*")
                    else:
                        st.write(f"- **Experimental Neural Model:** Unavailable ({exp_m.get('fallback_reason')})")

                    st.markdown("##### 🛡️ Active Safety Guardrails")
                    for gd in hybrid_eval["final_decision"]["guardrails_applied"]:
                        st.markdown(f"- `{gd}`")

                if msg_res["findings"]:
                    st.markdown("#### 📋 Detailed Warning Indicators Table")
                    st.table(
                        [
                            {
                                "Category": f["category"],
                                "Severity": f["severity"],
                                "Matched Phrase": f["matched_text"],
                                "Why It Matters (English)": f["why_it_matters_en"],
                                "मराठी स्पष्टीकरण": f["why_it_matters_mr"],
                            }
                            for f in msg_res["findings"]
                        ]
                    )

                if msg_res["extracted_urls"]:
                    st.markdown("#### 🌐 Extracted URLs from Message (Safe Offline Inspection)")
                    for e_url in msg_res["extracted_urls"]:
                        u_res = analyze_url(e_url)
                        u_color = u_res["badge_color"]
                        u_icon = "🚨" if u_color == "red" else ("⚠️" if u_color == "orange" else "ℹ️")
                        with st.expander(f"{u_icon} {e_url} — {u_res['risk_level']} (Score: {u_res['score']}/100)"):
                            st.markdown(f"**English:** {u_res['summary_en']}")
                            st.markdown(f"**मराठी:** {u_res['summary_mr']}")
                            st.markdown("**Evidence & Findings:**")
                            for ev in u_res["evidence"]:
                                st.markdown(f"- {ev}")
                            st.error("**⚠️ CITIZEN SAFETY RULE:** Never enter OTPs, bank passwords, or UPI PINs into unverified web links.")

                if show_ml_panel:
                    st.markdown("#### 🧪 Experimental Local ML Baseline Comparison")
                    ml_out = predict_with_local_ml(message_input)
                    if ml_out["is_available"]:
                        st.info(
                            f"**Experimental TF-IDF + Logistic Regression Output:** `{ml_out['ml_flag']}` "
                            f"(Experimental Score: `{ml_out['experimental_ml_confidence']}%`)\n\n"
                            f"*{ml_out['evaluation_summary'].get('methodology_note', '')}*"
                        )
                    else:
                        st.warning(f"Optional ML baseline unavailable: {ml_out.get('error')}")

        st.markdown("---")
        with st.expander("📱 WhatsApp Business Platform (Cloud API) Integration & Webhook Simulator", expanded=False):
            wa_cfg = load_whatsapp_config()
            st.markdown(f"##### ⚙️ Webhook Status: `{'LIVE META CLOUD API' if wa_cfg['mode'] == 'live' else 'STANDBY / SIMULATION MODE'}`")
            st.caption(
                "Allows citizens to forward suspicious WhatsApp messages directly to a verified WhatsApp Business helpline bot. "
                "Runs in offline simulation mode until real Meta credentials are provided in `.env`."
            )
            c_w1, c_w2 = st.columns(2)
            c_w1.write(f"**Verify Token Configured:** `{wa_cfg['verify_token']}`")
            c_w1.write(f"**Live Meta Credentials Found?:** `{'Yes' if wa_cfg['has_live_credentials'] else 'No (Using Simulation Outbox)'}`")
            c_w2.write("**Local Webhook URL:** `http://localhost:8000/webhook`")
            c_w2.write("**CLI Server Runner:** `python src/whatsapp_webhook.py --port 8000`")

            st.markdown("###### 🧪 Test Incoming WhatsApp Webhook Callback (Simulated Ingress):")
            sim_text = st.text_input(
                "Simulated Inbound WhatsApp Message:",
                value="प्रिय ग्राहक, तुमचे महावितरण वीज बिल अपडेट झालेले नाही. तात्काळ MSEDCL_Bill.apk डाउनलोड करा किंवा OTP सांगा.",
                key="sim_wa_msg_input",
            )
            if st.button("📲 Simulate WhatsApp Webhook Ingress Event", key="btn_sim_wa"):
                import json as _json
                import time as _time
                mock_payload = _json.dumps({
                    "object": "whatsapp_business_account",
                    "entry": [
                        {
                            "changes": [
                                {
                                    "value": {
                                        "messages": [
                                            {
                                                "from": "919822000000",
                                                "id": "wamid.sim_" + str(int(_time.time() * 1000)),
                                                "type": "text",
                                                "text": {"body": sim_text},
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    ],
                }).encode("utf-8")

                wa_res = process_incoming_webhook_event(mock_payload, case_store=st.session_state.case_store)
                st.success("✅ Inbound Webhook Callback Processed (HTTP 200 OK — Idempotent)")

                outbox = get_simulated_outbox_entries()
                if outbox:
                    latest_reply = outbox[-1]
                    st.markdown("**Outbound WhatsApp Reply (Dispatched to Citizen's Phone Screen):**")
                    st.code(latest_reply["message_text"])

    # =========================================================================
    # TAB 2: APK STATIC SECURITY ANALYZER
    # =========================================================================
    with tab_apk:
        st.subheader("📦 Safe Android .APK Static Security Analyzer")
        st.caption(
            f"Inspects `.apk` archives up to {MAX_APK_UPLOAD_BYTES // (1024 * 1024)} MB in memory without installing or executing code."
        )

        apk_source_mode = st.radio(
            "Select APK Source:",
            [
                "Use Pre-Generated Safe Test Files (Synthetic Fixtures & Binary AXML Sample)",
                "Upload an .APK File from Computer",
            ],
            horizontal=True,
        )

        apk_bytes = None
        apk_filename = ""

        if apk_source_mode.startswith("Use Pre-Generated"):
            sample_files = ensure_sample_apks_exist()
            if not sample_files:
                st.error("No files found in `sample_apks/`. Run `python create_sample_apks.py`.")
            else:
                selected_apk_name = st.selectbox(
                    "Select a Safe Test File from `sample_apks/`:", sample_files
                )
                sample_path = os.path.join(SAMPLE_APKS_DIR, selected_apk_name)
                with open(sample_path, "rb") as f:
                    apk_bytes = f.read()
                apk_filename = selected_apk_name
        else:
            uploaded_file = st.file_uploader(
                "Upload an .apk file for static inspection (Max 15 MB)",
                type=["apk", "zip", "txt"],
            )
            if uploaded_file is not None:
                apk_bytes = uploaded_file.getvalue()
                apk_filename = uploaded_file.name

        if apk_bytes is not None and st.button(
            "🔬 Inspect APK Package Statically", type="primary", key="run_apk_btn"
        ):
            apk_res = analyze_apk_bytes(apk_bytes, apk_filename)
            scored_apk = score_apk_analysis(apk_res)

            if apk_res["is_valid_apk"]:
                if apk_res["is_synthetic_fixture"]:
                    st.warning(
                        "🧪 **Synthetic Test Fixture Detected:** This file uses a plain-text XML manifest or non-executable stub "
                        "created for safe testing. It is **not** a compiled, installable Android application."
                    )
                else:
                    st.success(
                        "📦 **Compiled Binary AXML Package Detected:** Verified Android Binary XML (`0x00080003`) manifest header "
                        "and Dalvik (`dex\\n03x`) bytecode signature."
                    )

            render_risk_assessment_panel(
                scored_apk, enable_audio=enable_audio, key_prefix="apk"
            )
            apk_case = create_apk_case(apk_res, scored_apk)
            apk_case_id = st.session_state.case_store.add_case(apk_case)
            st.caption(f"📋 **Case Logged to Session Dashboard:** `{apk_case_id}` (Inspect in Tab 5)")

            if apk_res["is_valid_apk"]:
                st.markdown("#### 🗂️ Package Metadata & Confirmed Structural Observations")
                c1, c2, c3 = st.columns(3)
                c1.metric("Declared Package Name", apk_res["package_name"])
                c2.metric("Manifest Format", apk_res["manifest_format"].split("(")[0].strip())
                c3.metric("File Size", f"{apk_res['file_size_bytes']:,} bytes")

                st.code(
                    f"Filename:           {apk_res['filename']}\n"
                    f"SHA-256 Hash:       {apk_res['sha256_hash']}\n"
                    f"Parser Used:        {apk_res['parser_used']}\n"
                    f"Manifest Format:    {apk_res['manifest_format']}\n"
                    f"DEX Bytecode:       {apk_res['dex_format']}\n"
                    f"Synthetic Fixture?: {apk_res['is_synthetic_fixture']}"
                )

                st.markdown("#### 🔐 Sensitive Permissions Found in `AndroidManifest.xml`")
                if apk_res["permissions_found"]:
                    st.table(
                        [
                            {
                                "Permission": p["short_name"],
                                "Capability Family": p["family"],
                                "Severity": p["severity"],
                                "Weight": p["weight"],
                                "Why It Warrants Attention (English)": p["reason_en"],
                                "मराठी स्पष्टीकरण": p["reason_mr"],
                            }
                            for p in apk_res["permissions_found"]
                        ]
                    )
                else:
                    st.info(
                        "No sensitive permissions from the watch catalog were declared in this manifest."
                    )

                with st.expander("View All Raw Permissions, Passive URLs & Archive Entries"):
                    st.write("**Confirmed Observations:**", apk_res["confirmed_observations"])
                    st.write("**All Declared Permissions:**", apk_res["all_raw_permissions"])
                    st.write(
                        "**Passively Extracted URLs (Inert text — never visited):**",
                        apk_res["passive_urls"],
                    )
                    if apk_res["passive_urls"]:
                        st.markdown("##### 🔬 URL Analyzer Inspection for Embedded Package Links:")
                        for p_url in apk_res["passive_urls"]:
                            pu_eval = analyze_url(p_url)
                            pu_icon = "🚨" if pu_eval["badge_color"] == "red" else ("⚠️" if pu_eval["badge_color"] == "orange" else "ℹ️")
                            st.markdown(
                                f"- {pu_icon} `{p_url}` — **{pu_eval['risk_level']}** (Score: {pu_eval['score']}/100)  \n"
                                f"  *Summary:* {pu_eval['summary_en']}"
                            )
                    st.write("**ZIP Archive File Listing (First 30):**", apk_res["files_inside_zip"])

    # =========================================================================
    # TAB 3: SAFE SUSPICIOUS URL & DOMAIN ANALYZER
    # =========================================================================
    with tab_url:
        st.subheader("🌐 Safe Suspicious URL & Domain Analyzer")
        st.caption(
            "Defensively inspects suspicious web links, brand lookalikes, URL shorteners, punycode homoglyphs, "
            "and IP addresses 100% offline without ever opening or contacting the target server."
        )

        st.markdown("##### 📌 Test with a Real-World Scam Scenario or Enter Custom URL:")
        sample_urls = [
            "-- Enter Custom URL Below --",
            "MSEDCL Lookalike Phishing Link: http://msedcl-bill-update-maharashtra.xyz/quick-pay",
            "Bank KYC Expiry Lure: http://sbi-kyc-maharashtra-update.top/login?action=verify-otp",
            "Masked URL Shortener: https://bit.ly/3xY8zMsedclPay",
            "Internal Network Target / SSRF Probe: http://192.168.1.1/admin/router-setup",
            "Punycode Homoglyph Domain: http://xn--sbi-8ka.com/netbanking",
            "Direct APK File Download Link: http://utility-update-host.com/files/MSEDCL_Bill_Helper.apk",
            "Official Maharashtra Government Portal: https://ladakibahin.maharashtra.gov.in/",
        ]
        chosen_sample_url = st.selectbox(
            "Choose a Safe Pre-Set URL Fixture or Select Custom Input:",
            sample_urls,
            key="url_sample_selector",
        )

        initial_url_val = ""
        if "MSEDCL Lookalike" in chosen_sample_url:
            initial_url_val = "http://msedcl-bill-update-maharashtra.xyz/quick-pay"
        elif "Bank KYC Expiry" in chosen_sample_url:
            initial_url_val = "http://sbi-kyc-maharashtra-update.top/login?action=verify-otp"
        elif "Masked URL Shortener" in chosen_sample_url:
            initial_url_val = "https://bit.ly/3xY8zMsedclPay"
        elif "Internal Network" in chosen_sample_url:
            initial_url_val = "http://192.168.1.1/admin/router-setup"
        elif "Punycode Homoglyph" in chosen_sample_url:
            initial_url_val = "http://xn--sbi-8ka.com/netbanking"
        elif "Direct APK File" in chosen_sample_url:
            initial_url_val = "http://utility-update-host.com/files/MSEDCL_Bill_Helper.apk"
        elif "Official Maharashtra" in chosen_sample_url:
            initial_url_val = "https://ladakibahin.maharashtra.gov.in/"

        url_input_text = st.text_input(
            "Enter or Paste Suspicious URL to Inspect:",
            value=initial_url_val,
            placeholder="e.g., http://msedcl-bill-online.xyz/pay or https://bit.ly/3example",
            key="url_analyzer_input",
            help="STRICT SECURITY: The sandbox analyzes domain and protocol structure passively and NEVER connects to user URLs.",
        )

        if st.button("🔬 Analyze URL Statically", type="primary", key="run_url_btn"):
            if not url_input_text.strip():
                st.warning("Please enter or select a URL to inspect.")
            else:
                url_eval = analyze_url(url_input_text)
                url_case = create_url_case(url_eval)
                url_case_id = st.session_state.case_store.add_case(url_case)
                color = url_eval["badge_color"]
                icon = {"red": "🚨", "orange": "⚠️", "green": "ℹ️"}.get(color, "🔎")

                st.markdown("---")
                st.subheader(f"{icon} Link Security Assessment Result")

                col_u_stat, col_u_metric = st.columns([2, 1])
                with col_u_stat:
                    if color == "red":
                        st.error(f"**Assessment Label:** {url_eval['risk_level']}")
                    elif color == "orange":
                        st.warning(f"**Assessment Label:** {url_eval['risk_level']}")
                    else:
                        st.info(f"**Assessment Label:** {url_eval['risk_level']}")
                with col_u_metric:
                    st.metric(
                        "Heuristic URL Risk Index (0–100)",
                        f"{url_eval['score']} / 100",
                        help="Transparent score based on domain lookalikes, TLD risk, encoding, and protocol security.",
                    )

                # Urgent Citizen Safeguard Banner
                if color in ("red", "orange"):
                    st.error(
                        "🛑 **CRITICAL CITIZEN PROTECTION WARNING:**\n"
                        "**NEVER enter your Bank OTP, Netbanking Password, ATM PIN, or UPI PIN into this page.** "
                        "Legitimate banks, government portals, and MSEDCL never ask you to enter a UPI PIN to receive money."
                    )

                st.markdown(f"**English Explanation:** {url_eval['summary_en']}")
                st.markdown(f"**मराठी स्पष्टीकरण (Marathi Explanation):** {url_eval['summary_mr']}")

                st.markdown("#### 🔍 Matched Evidence & Threat Indicators")
                for ev in url_eval["evidence"]:
                    st.markdown(f"- {ev}")

                # Observable Characteristics Table
                st.markdown("#### 🗂️ Observable URL Characteristics (Passive Extraction)")
                obs = url_eval["observable_characteristics"]
                c_o1, c_o2, c_o3 = st.columns(3)
                c_o1.write(f"**Protocol / Scheme:** `{url_eval['scheme'].upper() or 'None'}`")
                c_o2.write(f"**Target Hostname:** `{url_eval['hostname'] or 'N/A'}`")
                c_o3.write(f"**Port:** `{obs.get('port') or 'Default (80/443)'}`")

                c_o4, c_o5, c_o6 = st.columns(3)
                c_o4.write(f"**Official Allowlisted?:** `{'Yes (.gov.in / allowlisted)' if obs.get('is_official_allowlisted') else 'NO'}`")
                c_o5.write(f"**URL Shortener?:** `{'Yes (' + str(obs.get('is_shortener')) + ')' if obs.get('is_shortener') else 'No'}`")
                c_o6.write(f"**Brand Lookalike?:** `{'Yes (' + str(obs.get('lookalike_brand')) + ')' if obs.get('is_lookalike') else 'No'}`")

                c_o7, c_o8, c_o9 = st.columns(3)
                c_o7.write(f"**IP Address Target?:** `{obs.get('ip_type') if obs.get('is_ip_address') else 'No'}`")
                c_o8.write(f"**Punycode / Homoglyph?:** `{'Yes' if obs.get('is_punycode_or_homoglyph') else 'No'}`")
                c_o9.write(f"**Direct APK Target?:** `{'Yes (.apk)' if obs.get('has_apk_download') else 'No'}`")

                if enable_audio:
                    st.markdown("#### 🔊 Audio Alert Chime")
                    u_wav = generate_alert_wav_bytes(color)
                    st.audio(u_wav, format="audio/wav")

                # Recommended Next Steps
                col_u_en, col_u_mr = st.columns(2)
                with col_u_en:
                    st.markdown("#### 🛡️ Safe Next Steps (English)")
                    for idx, step in enumerate(url_eval["safe_next_steps_en"], start=1):
                        st.markdown(f"{idx}. {step}")
                with col_u_mr:
                    st.markdown("#### 🛡️ सुरक्षित पुढील पावले (Marathi)")
                    for idx, step in enumerate(url_eval["safe_next_steps_mr"], start=1):
                        st.markdown(f"{idx}. {step}")

                st.caption(f"⚖️ **Limitations & Transparency:** {url_eval['limitations']}")

    # =========================================================================
    # TAB 4: MAHARASHTRA GOVERNMENT SCHEME & ANNOUNCEMENT VERIFIER
    # =========================================================================
    with tab_scheme:
        st.subheader("🏛️ Maharashtra Government Scheme & Announcement Verifier")
        st.caption(
            "Verifies claims and forwarded WhatsApp promises against official Government Resolutions (GRs) "
            "and allowlisted state portals (.gov.in, .maharashtra.gov.in, .mahadiscom.in)."
        )

        scheme_registry = load_official_sources()
        if not scheme_registry.get("is_valid"):
            st.error(f"Official registry notice: {scheme_registry.get('error')}")

        st.markdown("##### 📌 Quick-Fill Test Scenarios:")
        sample_claims = [
            "-- Enter Custom Scheme Claim Below --",
            "Scam Lure: 'Register through this WhatsApp link to receive ₹3,000 under Mukhyamantri Majhi Ladki Bahin Yojana' (Amount mismatch & fake link)",
            "Official Notice: 'मुख्यमंत्री माझी लाडकी बहीण योजनेअंतर्गत दरमहा ₹१,५०० चा थेट लाभ अधिकृत पोर्टल ladakibahin.maharashtra.gov.in वर मिळतो' (Genuine)",
            "Scam Lure: 'Namo Shetkari Yojana ₹10,000 release fee - pay ₹500 advance to receive money' (Fraudulent fee demand)",
            "Unverified Claim: 'Maharashtra Free Laptop Yojana 2026: All college students get a free laptop via registration' (Unindexed / Insufficient evidence)",
        ]
        selected_scheme_sample = st.selectbox(
            "Choose a Safe Fictional Test Scenario or Enter Custom Text:",
            sample_claims,
            key="scheme_sample_selector",
        )

        preset_claim = ""
        preset_url = ""
        if "Ladki Bahin Yojana' (Amount mismatch" in selected_scheme_sample:
            preset_claim = "Register through this WhatsApp link to receive ₹3,000 under Mukhyamantri Majhi Ladki Bahin Yojana."
            preset_url = "http://ladki-bahin-apply-fast.xyz/register"
        elif "लाडकी बहीण योजनेअंतर्गत दरमहा ₹१,५००" in selected_scheme_sample:
            preset_claim = "मुख्यमंत्री माझी लाडकी बहीण योजनेअंतर्गत पात्र महिलांना दरमहा ₹१,५०० चा थेट लाभ अधिकृत पोर्टलद्वारे दिला जातो."
            preset_url = "https://ladakibahin.maharashtra.gov.in/"
        elif "Namo Shetkari Yojana ₹10,000" in selected_scheme_sample:
            preset_claim = "नमो शेतकरी महासन्मान निधी योजनेचे ₹१०,००० तात्काळ मिळवण्यासाठी ₹५०० रजिस्ट्रेशन फी भरा."
            preset_url = "http://namo-shetkari-advance.top"
        elif "Free Laptop Yojana" in selected_scheme_sample:
            preset_claim = "Maharashtra Golden Citizen Free Laptop Yojana 2026: All college students get a free laptop."
            preset_url = ""

        c_claim, c_url = st.columns([2, 1])
        with c_claim:
            scheme_claim_input = st.text_area(
                "Paste Suspicious Scheme Claim or WhatsApp Announcement:",
                value=preset_claim,
                height=110,
                placeholder="e.g., Register through this WhatsApp link to receive ₹3,000 under a Maharashtra government scheme...",
                key="scheme_claim_area",
            )
        with c_url:
            scheme_url_input = st.text_input(
                "Optional Suspicious Link (Analyzed PASSIVELY without opening):",
                value=preset_url,
                placeholder="e.g., http://ladki-bahin-update.xyz/apply",
                key="scheme_url_field",
                help="STRICT SECURITY: The sandbox analyzes domain and protocol structure passively and NEVER connects to user URLs.",
            )
            live_probe_toggle = st.checkbox(
                "Probe Official Portal Health (Only for allowlisted .gov.in domains)",
                value=False,
                help="Checks whether the official government website is currently responding, bounded by a 3.0s timeout.",
            )

        if st.button("🏛️ Analyze Claim with Official Sources", type="primary", key="run_scheme_btn"):
            if not scheme_claim_input.strip():
                st.warning("Please enter or select a scheme claim text to verify.")
            else:
                with st.spinner("Comparing against verified Government of Maharashtra Resolutions..."):
                    verification_res = verify_scheme_claim(
                        claim_text=scheme_claim_input,
                        suspicious_url=scheme_url_input,
                        check_live_portal=live_probe_toggle,
                    )
                    scheme_case = create_scheme_case(verification_res)
                    scheme_case_id = st.session_state.case_store.add_case(scheme_case)

                classification = verification_res["classification"]

                st.markdown("---")
                if classification == "SUPPORTED BY OFFICIAL SOURCE":
                    st.success(f"### ✅ Official Verification: {classification}")
                elif classification == "CONFLICTING EVIDENCE FOUND":
                    st.error(f"### 🚨 Official Verification: {classification}")
                elif classification == "NOT ENOUGH EVIDENCE":
                    st.warning(f"### ⚠️ Official Verification: {classification}")
                else:
                    st.info(f"### ℹ️ Official Verification: {classification}")

                if verification_res.get("matched_scheme_title"):
                    st.markdown(f"**Identified Official Scheme:** `{verification_res['matched_scheme_title']}`")

                col_exp_en, col_exp_mr = st.columns(2)
                with col_exp_en:
                    st.markdown(f"**English Summary:**\n{verification_res['summary_en']}")
                with col_exp_mr:
                    st.markdown(f"**मराठी स्पष्टीकरण (Marathi Summary):**\n{verification_res['summary_mr']}")

                st.markdown("#### 🔍 Evidence & Discrepancy Breakdown")
                c_supp, c_conf = st.columns(2)
                with c_supp:
                    st.markdown("**✅ Supporting Evidence (Official Ground Truth):**")
                    if verification_res["supporting_evidence"]:
                        for sup in verification_res["supporting_evidence"]:
                            st.markdown(f"- {sup}")
                    else:
                        st.write("No matching parameters confirmed by official records.")

                with c_conf:
                    st.markdown("**⚠️ Conflicting Evidence / Red Flags:**")
                    if verification_res["conflicting_evidence"]:
                        for conf in verification_res["conflicting_evidence"]:
                            st.markdown(f"- {conf}")
                    else:
                        st.write("No direct contradictions detected with official guidelines.")

                if verification_res["url_assessment"]["has_url"]:
                    st.markdown("#### 🌐 Passive Link Safety Analysis")
                    u_info = verification_res["url_assessment"]
                    col_u1, col_u2 = st.columns(2)
                    col_u1.write(f"**Evaluated Hostname:** `{u_info['hostname']}`")
                    col_u2.write(f"**Official Allowlisted Domain?:** `{'Yes (Allowlisted)' if u_info['is_official_domain'] else 'NO (Third-Party / Unofficial)'}`")
                    if u_info["warnings_en"]:
                        for idx, w in enumerate(u_info["warnings_en"]):
                            st.warning(f"⚠️ {w} — *{u_info['warnings_mr'][idx]}*")
                    elif u_info["is_official_domain"]:
                        st.success("✅ This link points to a verified official government domain (.gov.in / .maharashtra.gov.in / .mahadiscom.in).")

                if verification_res["official_sources"]:
                    st.markdown("#### 📄 Official Sources & Government Resolutions (GR)")
                    for src in verification_res["official_sources"]:
                        with st.container():
                            st.markdown(
                                f"**{src['title']} ({src['title_mr']})**  \n"
                                f"- **Department:** {src['department']}  \n"
                                f"- **Government Resolution (GR) No:** `{src['gr_number']}` (Published: `{src['publication_date']}`)  \n"
                                f"- **Official Portal Link:** [{src['portal_url']}]({src['portal_url']})"
                            )

                meta = verification_res["retrieval_metadata"]
                st.markdown("---")
                c_m1, c_m2, c_m3 = st.columns(3)
                c_m1.caption(f"🕒 **Retrieval Timestamp:** {meta['retrieval_timestamp']}")
                c_m2.caption(f"📅 **Source Freshness:** {meta['source_freshness']}")
                c_m3.caption(f"⚙️ **Mode:** {meta['mode']}")

                if meta.get("live_health"):
                    lh = meta["live_health"]
                    if lh["is_reachable"]:
                        st.caption(f"🟢 **Live Portal Probe:** Reached in {lh['latency_ms']} ms (HTTP {lh['status_code']})")
                    else:
                        st.caption(f"🔴 **Live Portal Probe:** Unreachable ({lh.get('error')})")

                col_steps_en, col_steps_mr = st.columns(2)
                with col_steps_en:
                    st.markdown("#### 🛡️ Citizen Guidance (English)")
                    for idx, step in enumerate(verification_res["safe_next_steps_en"], start=1):
                        st.markdown(f"{idx}. {step}")
                with col_steps_mr:
                    st.markdown("#### 🛡️ नागरिकांसाठी सुरक्षित पावले (Marathi)")
                    for idx, step in enumerate(verification_res["safe_next_steps_mr"], start=1):
                        st.markdown(f"{idx}. {step}")

                st.caption(f"⚖️ **Limitations & Verification Scope:** {verification_res['limitations']}")

    # =========================================================================
    # TAB 5: THREAT CASE DASHBOARD & INCIDENT EVIDENCE EXPORT
    # =========================================================================
    with tab_cases:
        st.subheader("📋 Threat Case Dashboard & Incident Evidence Export")
        st.caption(
            "Session-scoped incident management desk for citizen facilitation counters and cyber-awareness volunteers. "
            "Cases are securely persisted in SQLite with privacy-preserving redaction and automatic retention."
        )

        store: SessionCaseStore = st.session_state.case_store
        cases_list = store.list_cases()

        # Summary Metric Cards
        col_m1, col_m2, col_m3, col_m4 = st.columns(4)
        total_cnt = store.count()
        red_cnt = sum(1 for c in cases_list if c.get("badge_color") == "red" or c.get("risk_score", 0) >= 50)
        orange_cnt = sum(1 for c in cases_list if c.get("badge_color") == "orange" or (20 <= c.get("risk_score", 0) < 50))
        green_cnt = sum(1 for c in cases_list if c.get("badge_color") == "green" or c.get("risk_score", 0) < 20)

        col_m1.metric("Total Cases (This Session)", f"{total_cnt}")
        col_m2.metric("High-Risk Cases (Red)", f"{red_cnt}")
        col_m3.metric("Notice / Review Cases (Orange)", f"{orange_cnt}")
        col_m4.metric("Cleared / Supported (Green)", f"{green_cnt}")

        st.markdown("---")
        st.markdown("#### 🗂️ Active Session Threat Cases")

        if not cases_list:
            st.info(
                "No cases have been logged in this session yet. "
                "Analyze a WhatsApp message, APK file, suspicious URL, or scheme claim in the preceding tabs "
                "to automatically register cases here."
            )
        else:
            # Structured table matching required specifications
            table_rows = store.export_summary_table_rows()
            st.dataframe(table_rows, use_container_width=True)

            # Export Action Controls
            col_exp_csv, col_exp_json, col_clear = st.columns([1, 1, 1])
            with col_exp_csv:
                csv_data = store.export_csv()
                st.download_button(
                    label="📥 Download Cases Summary (CSV)",
                    data=csv_data,
                    file_name="seva_cyber_cases_summary.csv",
                    mime="text/csv",
                    key="download_cases_csv",
                )
            with col_exp_json:
                json_data = store.export_json()
                st.download_button(
                    label="📥 Download Full Cases Registry (JSON)",
                    data=json_data,
                    file_name="seva_cyber_cases_registry.json",
                    mime="application/json",
                    key="download_cases_json",
                )
            with col_clear:
                if st.button("🗑️ Clear Session Cases", key="clear_cases_btn"):
                    store.clear()
                    st.rerun()

            st.markdown("---")
            st.markdown("#### 📄 Case Detail & Official Evidence Report Generator")
            case_options = [f"{c['case_id']} — {c.get('analysis_type')} (Score: {c.get('risk_score')}/100)" for c in cases_list]
            selected_case_label = st.selectbox(
                "Select a Case to Inspect & Generate Formal Summary:",
                case_options,
                key="selected_case_box",
            )

            if selected_case_label:
                sel_id = selected_case_label.split(" — ")[0].strip()
                sel_case = store.get_case(sel_id)

                if sel_case:
                    report_text = generate_evidence_report(sel_case)
                    c_det1, c_det2 = st.columns([2, 1])
                    with c_det1:
                        st.text_area(
                            "Preview of Cybersecurity Analysis Summary (Ready for Citizen Advisory):",
                            value=report_text,
                            height=260,
                            key="report_preview_area",
                        )
                    with c_det2:
                        st.markdown("**Evidence Report Actions:**")
                        st.download_button(
                            label=f"📄 Download Report ({sel_id}.txt)",
                            data=report_text,
                            file_name=f"{sel_id}_Evidence_Report.txt",
                            mime="text/plain",
                            key=f"dl_rep_{sel_id}",
                        )
                        st.info(
                            "**Mandatory Legal Disclaimer:**\n"
                            "This report is labeled *'Cybersecurity Analysis Summary — Not an Official Forensic Certification'*. "
                            "It provides technical decision-support and does not constitute a certified certificate under Section 65B of the Indian Evidence Act."
                        )

        st.markdown("---")
        st.markdown("#### 🔒 Privacy Boundaries & Official Cyber Reporting")
        st.markdown(
            "1. **Session-Scoped Storage:** Cases are kept strictly in this browser tab's RAM. Closing the tab permanently deletes all session cases.\n"
            "2. **Zero Raw Payload Retention:** Original `.apk` binaries and raw message texts are not stored by default. Only derived structural indicators, hashes, and observation notes are kept.\n"
            "3. **No Automatic External Transmission:** This sandbox **never** contacts IP addresses, uploads records to external servers, or transmits data to law enforcement. If fraud has occurred, citizens must report directly to official channels below:\n"
            "   - **National Cyber Crime Helpline:** Call **1930** immediately to freeze unauthorized bank transactions.\n"
            "   - **Official Cyber Reporting Portal:** File a formal cyber complaint at `https://cybercrime.gov.in`.\n"
            "   - **Maharashtra State Official Portal:** `https://maharashtra.gov.in`."
        )

    # =========================================================================
    # TAB 6: PHISHING EVALUATION, DATASET QUALITY & RESPONSIBLE AI
    # =========================================================================
    with tab_eval:
        st.subheader("📊 Phishing Detection Evaluation, Dataset Quality & Responsible AI")
        st.caption(
            "Rigorous, reproducible evaluation metrics comparing the semantic rule engine with the experimental ML baseline "
            "on a group-aware, leak-free partition across 39 documented records."
        )

        # ---------------------------------------------------------------------
        # SECTION 1: BENCHMARK DATASET METADATA & PROVENANCE
        # ---------------------------------------------------------------------
        eval_report = None
        if get_cached_evaluation_report:
            try:
                eval_report = get_cached_evaluation_report(force_rerun=st.session_state.get("rerun_eval", False))
                st.session_state["rerun_eval"] = False
            except Exception as e_err:
                st.error(f"Failed to load evaluation benchmark: {e_err}")

        if eval_report:
            meta = eval_report.get("dataset_metadata", {})
            if eval_report.get("sample_size_warning"):
                st.warning(f"⚠️ **Small-Sample Quality Notice:** {eval_report['sample_size_warning']}")

            col_d1, col_d2, col_d3, col_d4 = st.columns(4)
            col_d1.metric("Evaluation Dataset", f"{meta.get('total_records', 0)} Records")
            col_d2.metric("Unique Campaigns", f"{meta.get('unique_campaigns_count', 0)} Groups")
            labels_d = meta.get("label_distribution", {})
            col_d3.metric("Phishing / Legitimate", f"{labels_d.get('phishing', 0)} / {labels_d.get('legitimate', 0)}")
            col_d4.metric("Advisories / Ambiguous", f"{labels_d.get('protective_advisory', 0)} / {labels_d.get('ambiguous_needs_review', 0)}")

            with st.expander("📁 Dataset Provenance & Taxonomy Breakdown", expanded=False):
                col_p1, col_p2 = st.columns(2)
                with col_p1:
                    st.markdown("**Data Provenance Categories:**")
                    for k, v in meta.get("provenance_distribution", {}).items():
                        st.markdown(f"- `{k}`: **{v}** records")
                with col_p2:
                    st.markdown("**Language & Script Coverage:**")
                    for k, v in meta.get("language_distribution", {}).items():
                        st.markdown(f"- `{k}`: **{v}** records")

            st.markdown("---")

            # -----------------------------------------------------------------
            # SECTION 2: COMPARATIVE PERFORMANCE SUMMARY
            # -----------------------------------------------------------------
            st.markdown("#### ⚖️ Side-by-Side Model Evaluation (Leak-Free Group Split)")

            rb_eval = eval_report.get("rule_based_evaluation", {})
            rb_m = rb_eval.get("overall_binary_metrics", {})

            ml_eval = eval_report.get("ml_baseline_evaluation", {})
            ml_m = ml_eval.get("overall_binary_metrics", {}) if ml_eval.get("is_available") else {}

            comp = eval_report.get("model_comparison", {})

            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown("##### 🛡️ Rule-Based Detector")
                st.markdown(f"- **Accuracy:** `{rb_m.get('accuracy_pct', 0)}%` ({rb_m.get('true_positives', 0) + rb_m.get('true_negatives', 0)}/{rb_m.get('total_samples', 0)})")
                st.markdown(f"- **Precision:** `{rb_m.get('precision_pct', 0)}%`")
                st.markdown(f"- **Recall (Sensitivity):** `{rb_m.get('recall_pct', 0)}%`")
                st.markdown(f"- **Specificity:** `{rb_m.get('specificity_pct', 0)}%`")
                st.markdown(f"- **F1 Score:** `{rb_m.get('f1_score_pct', 0)}%`")
                adv_rb = rb_eval.get("protective_advisory_evaluation", {})
                st.markdown(f"- **Protective Negation Rate:** `{adv_rb.get('safeguard_success_pct', 0)}%` ({adv_rb.get('correctly_cleared_count', 0)}/{adv_rb.get('total_advisories', 0)})")

            with c2:
                st.markdown("##### 🧪 Experimental ML Baseline")
                if ml_eval.get("is_available"):
                    st.markdown(f"- **Holdout Accuracy:** `{ml_m.get('accuracy_pct', 0)}%` ({ml_m.get('true_positives', 0) + ml_m.get('true_negatives', 0)}/{ml_m.get('total_samples', 0)})")
                    st.markdown(f"- **Precision:** `{ml_m.get('precision_pct', 0)}%`")
                    st.markdown(f"- **Recall:** `{ml_m.get('recall_pct', 0)}%`")
                    st.markdown(f"- **Specificity:** `{ml_m.get('specificity_pct', 0)}%`")
                    st.markdown(f"- **F1 Score:** `{ml_m.get('f1_score_pct', 0)}%`")
                    adv_ml = ml_eval.get("protective_advisory_evaluation", {})
                    st.markdown(f"- **Advisories Falsely Flagged:** `{adv_ml.get('advisory_false_alarm_rate_pct', 0)}%` ({adv_ml.get('falsely_flagged_by_ml', 0)}/{adv_ml.get('total_advisories', 0)})")
                else:
                    st.warning(f"ML baseline unavailable: {ml_eval.get('error')}")

            with c3:
                st.markdown("##### 🤝 Agreement & Concordance")
                if comp.get("comparison_available"):
                    st.markdown(f"- **Samples Compared:** `{comp.get('test_samples_compared', 0)}`")
                    st.markdown(f"- **Concordance Rate:** `{comp.get('concordance_rate_pct', 0)}%`")
                    st.markdown(f"- **Agreements:** `{comp.get('agreements_count', 0)}`")
                    st.markdown(f"- **Disagreements:** `{comp.get('disagreements_count', 0)}`")
                    st.caption(f"ℹ️ {comp.get('architectural_distinction', '')}")

            if st.button("🔄 Re-run Evaluation Benchmark", key="btn_rerun_eval"):
                st.session_state["rerun_eval"] = True
                st.rerun()

            st.markdown("---")

        # ---------------------------------------------------------------------
        # SECTION 3: LEGACY 20-SAMPLE DEMONSTRATION BASELINE
        # ---------------------------------------------------------------------
        st.markdown("#### 🧪 Legacy 20-Sample Educational Baseline (data/sample_messages.json)")
        eval_bundle = train_and_evaluate_local_model()

        if not eval_bundle.get("is_available"):
            st.warning(f"Legacy demonstration baseline status: {eval_bundle.get('error')}")
        else:
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Demo Corpus", f"{eval_bundle['total_samples']} samples")
            m2.metric("5-Fold CV Accuracy", f"{eval_bundle.get('cross_validation_accuracy_pct', 'N/A')}%")
            m3.metric("5-Fold CV F1", f"{eval_bundle.get('cross_validation_f1_pct', 'N/A')}%")
            m4.metric("Holdout Test Accuracy", f"{eval_bundle['test_accuracy_pct']}%")

            st.table(
                [
                    {"Metric": "True Positives (Phishing Correctly Flagged)", "Count": eval_bundle["true_positives"]},
                    {"Metric": "True Negatives (Legitimate Correctly Cleared)", "Count": eval_bundle["true_negatives"]},
                    {"Metric": "False Positives (Legitimate Wrongly Flagged)", "Count": eval_bundle["false_positives"]},
                    {"Metric": "False Negatives (Phishing Missed)", "Count": eval_bundle["false_negatives"]},
                ]
            )

        st.markdown("---")
        st.markdown("#### 🛡️ Summary of Responsible AI & Security Boundaries")
        st.markdown(
            "1. **Static vs. Dynamic Boundary:** Static manifest inspection identifies declared capabilities (`READ_SMS`, `BIND_ACCESSIBILITY_SERVICE`), not runtime behavior. A legitimate banking app may request SMS permissions, and a sophisticated malicious app may hide code in encrypted assets.\n"
            "2. **Synthetic Fixture Transparency:** Test files generated by `create_sample_apks.py` are explicitly flagged in the UI so synthetic test fixtures are never misrepresented as real malware.\n"
            "3. **Language Coverage:** The vernacular detector targets common Marathi (Devanagari), Romanized Marathi, and English scam templates in Maharashtra (such as MSEDCL bill disconnection, KYC expiry, and RTO challan lures). It does not cover all regional dialects."
        )

    # =========================================================================
    # TAB 7: HUMAN REVIEW DESK & MODEL VERSION REGISTRY
    # =========================================================================
    with tab_review:
        st.subheader("🛡️ Human Review Desk & Model Version Registry")
        st.caption(
            "Local operator adjudication desk for ambiguous detections, accompanied by the "
            "cryptographically verified neural model version registry and atomic rollback controls."
        )

        st.warning(
            "🔒 **OPERATOR PRIVACY & SECURITY BOUNDARIES:**\n"
            "- **Zero PII & Zero Raw Content:** The review desk operates strictly on sanitized features, "
            "structural indicators, and anonymized diagnostic fingerprints. Raw chat text is never displayed or stored.\n"
            "- **Strict Model Isolation:** Operator review adjudication NEVER automatically triggers model retraining or modifies "
            "production threat scores. Production scoring is permanently governed by deterministic rules.\n"
            "- **Unauthenticated Local Desk:** Review attribution is an unauthenticated local label for development and testing. "
            "Do not treat local audit trails as non-repudiable forensic proof."
        )

        subtab_desk, subtab_registry, subtab_discovery = st.tabs(
            [
                "📝 Section A: Human Review Desk",
                "⚙️ Section B: Model Version Registry & Rollback",
                "🔬 Section C: Fraud Pattern Discovery",
            ]
        )

        # ---------------------------------------------------------------------
        # SECTION A: HUMAN REVIEW DESK
        # ---------------------------------------------------------------------
        with subtab_desk:
            store: SessionCaseStore = st.session_state.case_store
            stats = store.get_review_stats()

            col_r1, col_r2, col_r3, col_r4 = st.columns(4)
            col_r1.metric("Pending Reviews", stats.get("pending", 0))
            col_r2.metric("Under Review", stats.get("under_review", 0))
            col_r3.metric("Completed Reviews", stats.get("completed", 0))
            col_r4.metric("Inconclusive", stats.get("inconclusive", 0))

            st.markdown("---")
            st.markdown("#### 📥 Review Queue & Case Adjudication")

            session_cases = store.list_cases()
            if not session_cases:
                st.info(
                    "No cases have been logged in this session yet. "
                    "Analyze a message, APK, URL, or scheme claim in preceding tabs to generate cases for review."
                )
            else:
                case_select_options = [
                    f"{c['case_id']} — {c.get('analysis_type')} (Score: {c.get('risk_score')}/100, Cat: {c.get('risk_category')})"
                    for c in session_cases
                ]
                selected_case_entry = st.selectbox(
                    "Select a Threat Case to Review or Re-adjudicate:",
                    case_select_options,
                    key="review_case_selector",
                )

                if selected_case_entry:
                    selected_case_id = selected_case_entry.split(" — ")[0].strip()
                    case_data = store.get_case(selected_case_id)
                    existing_rev = store.get_review(selected_case_id)

                    st.markdown("##### 🔍 Sanitized Case Metadata (Zero Raw Text Displayed)")
                    c_meta1, c_meta2 = st.columns(2)
                    with c_meta1:
                        st.markdown(f"- **Case ID:** `{case_data.get('case_id')}`")
                        st.markdown(f"- **Target Identifier (Sanitized):** `{case_data.get('target_identifier', 'N/A')}`")
                        st.markdown(f"- **Analysis Type:** `{case_data.get('analysis_type', 'N/A')}`")
                        st.markdown(f"- **Risk Category:** `{case_data.get('risk_category', 'N/A')}`")
                        st.markdown(f"- **Deterministic Risk Score:** `{case_data.get('risk_score', 0)} / 100`")
                    with c_meta2:
                        st.markdown(f"- **Created At (UTC):** `{case_data.get('timestamp_utc', 'N/A')}`")
                        st.markdown(f"- **Analysis Status:** `{case_data.get('analysis_status', 'N/A')}`")
                        st.markdown(f"- **Recommended Action:** `{case_data.get('recommended_action', 'N/A')}`")
                        st.markdown(f"- **Active Review State:** `{existing_rev.get('review_state', 'pending') if existing_rev else 'pending'}`")
                        if existing_rev and existing_rev.get("outcome_category"):
                            st.markdown(f"- **Recorded Adjudication:** `{existing_rev.get('outcome_category')}` (Confidence: `{existing_rev.get('confidence_rating')}`)")

                    with st.expander("🔬 Structural Observations & Heuristic Inferences", expanded=False):
                        st.write("**Observed Evidence:**", case_data.get("observed_evidence", []))
                        st.write("**Heuristic Inferences:**", case_data.get("heuristic_inferences", []))
                        if case_data.get("extracted_urls"):
                            st.write("**Passively Extracted URLs:**", case_data.get("extracted_urls"))

                    st.markdown("---")
                    st.markdown("##### ✍️ Operator Review Input Form")
                    with st.form(key=f"form_review_{selected_case_id}"):
                        f_outcome = st.selectbox(
                            "Adjudicated Classification:",
                            ["phishing", "legitimate", "protective_advisory", "insufficient_evidence"],
                            index=0 if not existing_rev or not existing_rev.get("outcome_category") else
                                  ["phishing", "legitimate", "protective_advisory", "insufficient_evidence"].index(existing_rev.get("outcome_category")),
                            help="Adjudicate the threat class based on sanitized structural traits."
                        )
                        f_conf = st.radio(
                            "Operator Confidence Level:",
                            ["high", "medium", "low"],
                            index=1,
                            horizontal=True,
                        )
                        f_notes = st.text_area(
                            "Operator Rationale / Notes (Max 1000 characters — No PII allowed):",
                            value=existing_rev.get("notes", "") if existing_rev else "",
                            max_chars=1000,
                            placeholder="State objective rationale for this adjudication...",
                        )
                        f_reviewer = st.text_input(
                            "Reviewer Identifier (Local Unauthenticated Attribution):",
                            value="operator_local",
                            max_chars=64,
                        )

                        submit_rev_btn = st.form_submit_button("💾 Submit Adjudication Review", type="primary")

                        if submit_rev_btn:
                            try:
                                rev_res = store.submit_review(
                                    case_id=selected_case_id,
                                    outcome_category=f_outcome,
                                    notes=f_notes,
                                    confidence_rating=f_conf,
                                    reviewer_label=f_reviewer,
                                )
                                st.success(f"Review successfully recorded! Review ID: `{rev_res['review_id']}` (State: `{rev_res['review_state']}`)")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed to record review: {e}")

                st.markdown("---")
                st.markdown("#### 📜 Review Desk Audit Trail")
                with st.expander("View Recent Review Desk Actions (review_audit_log)", expanded=False):
                    audit_logs = store.list_review_audit_logs(limit=25)
                    if audit_logs:
                        st.dataframe(audit_logs, use_container_width=True)
                    else:
                        st.info("No review audit events logged yet.")

                st.markdown("---")
                st.markdown("#### 📤 Privacy-Preserving Human Reviews Export")
                st.caption(
                    "Export adjudicated cases as a de-identified research corpus (JSONL). "
                    "Conforms strictly to privacy guidelines: contains zero raw text and zero citizen PII."
                )
                export_corpus_jsonl = store.export_human_reviews_corpus()
                st.download_button(
                    label="📥 Download Reviewed Corpus (JSONL)",
                    data=export_corpus_jsonl,
                    file_name="human_reviewed_cases_corpus.jsonl",
                    mime="application/x-jsonlines",
                    key="dl_human_reviews_corpus",
                )

                st.markdown("---")
                st.markdown("#### 🧪 Curated Feature Dataset & Quality Report (Phase 6.1)")
                st.caption(
                    "Export cryptographically deduplicated, privacy-preserving 1024-dimensional feature vectors "
                    "from opted-in, completed reviews for future offline model training. Contains zero raw text, "
                    "zero reviewer notes, and zero PII."
                )

                try:
                    curation_report = store.generate_curation_report()
                    c_col1, c_col2, c_col3 = st.columns(3)
                    c_col1.metric("Features Stored", curation_report.get("total_feature_records_evaluated", 0))
                    c_col2.metric("Eligible for Training", curation_report.get("eligible_training_examples_count", 0))
                    c_col3.metric("Data Quality Status", curation_report.get("data_quality_status", "UNKNOWN"))

                    curated_features = store.export_curated_training_features()
                    curated_jsonl = "\n".join(json.dumps(r, ensure_ascii=False) for r in curated_features)
                    report_json = json.dumps(curation_report, indent=2, ensure_ascii=False)

                    dl_f_col, dl_r_col = st.columns(2)
                    with dl_f_col:
                        st.download_button(
                            label="📥 Download Curated Features (JSONL)",
                            data=curated_jsonl,
                            file_name="curated_training_features.jsonl",
                            mime="application/x-jsonlines",
                            key="dl_curated_features",
                        )
                    with dl_r_col:
                        st.download_button(
                            label="📊 Download Curation Report (JSON)",
                            data=report_json,
                            file_name="curation_quality_report.json",
                            mime="application/json",
                            key="dl_curation_report",
                        )
                except Exception as c_err:
                    st.info(f"Feature curation requires configured HMAC key: {c_err}")

            # -----------------------------------------------------------------
            # SECTION B: MODEL VERSION REGISTRY & ROLLBACK
            # -----------------------------------------------------------------
            with subtab_registry:
                registry = get_default_model_registry()
                active_cfg = registry.get_active_model_config()
                active_ver = active_cfg.get("active_model_version")

                st.markdown("#### 📌 Current Active Diagnostic Configuration")
                c_cfg1, c_cfg2, c_cfg3 = st.columns(3)
                with c_cfg1:
                    st.metric("Active Model Version", active_ver or "None (Fallback)")
                    st.caption(f"Operating Mode: `{active_cfg.get('operating_mode', 'shadow').upper()}` (Score Delta = 0)")
                with c_cfg2:
                    st.metric("Last Known-Good Version", active_cfg.get("last_known_good_version") or "None")
                    st.caption(f"Activated By: `{active_cfg.get('activated_by', 'system')}`")
                with c_cfg3:
                    st.metric("Preprocessing Version", active_cfg.get("preprocessing_version", "None"))
                    st.caption(f"Activated At (UTC): `{active_cfg.get('activated_at_utc', 'N/A')}`")

                # Checkpoint integrity badge
                if active_ver:
                    is_valid, v_msg = registry.verify_checkpoint_integrity(active_ver)
                    if is_valid:
                        st.success(f"✅ **Cryptographic Integrity Verified:** {v_msg}")
                    else:
                        st.error(f"🚨 **Cryptographic Integrity FAILED:** {v_msg}")

                st.markdown("---")
                st.markdown("#### 📚 Registered Neural Models in Local Catalog")
                models_list = registry.list_models()
                if models_list:
                    table_models = []
                    for m in models_list:
                        hparams = m.get("hyperparameters", {})
                        metrics = m.get("validation_metrics", {})
                        table_models.append({
                            "Version ID": m.get("model_version"),
                            "Lifecycle State": m.get("lifecycle_state"),
                            "Architecture": m.get("architecture_version"),
                            "Hidden Layers": f"{hparams.get('hidden_dim1')} -> {hparams.get('hidden_dim2')}",
                            "Val Accuracy": f"{metrics.get('accuracy', 0):.2%}" if isinstance(metrics.get("accuracy"), (int, float)) else "N/A",
                            "Weights SHA-256": m.get("weights_sha256", "")[:16] + "...",
                            "Preprocessing": m.get("preprocessing_version"),
                            "Registered At": m.get("registered_at_utc", "")[:10],
                        })
                    st.dataframe(table_models, use_container_width=True)
                else:
                    st.info("No neural models registered in model_registry.json.")

                st.markdown("---")
                st.markdown("#### 🔀 Shadow Diagnostics Model Activation")
                st.caption(
                    "Select an approved registered model version to evaluate in shadow mode alongside deterministic rules. "
                    "Activation performs cryptographic SHA-256 verification before updating the active diagnostic configuration."
                )

                eligible_models = [
                    m["model_version"]
                    for m in models_list
                    if m.get("lifecycle_state") in ("approved_for_shadow", "experimental")
                ]

                if eligible_models:
                    c_sw1, c_sw2 = st.columns([2, 1])
                    with c_sw1:
                        chosen_ver = st.selectbox(
                            "Select Registered Model Version to Activate:",
                            eligible_models,
                            index=eligible_models.index(active_ver) if active_ver in eligible_models else 0,
                            key="model_version_switcher",
                        )
                        act_reason = st.text_input(
                            "Activation Reason / Operator Note:",
                            value="Evaluation in shadow mode",
                            max_chars=200,
                            key="act_reason_input",
                        )
                    with c_sw2:
                        st.write("")
                        st.write("")
                        if st.button("🚀 Activate for Shadow Diagnostics", type="primary", key="btn_activate_model"):
                            try:
                                new_cfg = registry.activate_model(
                                    model_version=chosen_ver,
                                    operator_label="operator_local",
                                    reason=act_reason,
                                )
                                st.success(f"Model `{chosen_ver}` successfully activated for shadow diagnostics!")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Activation failed: {e}")

                st.markdown("---")
                st.markdown("#### ⏪ Emergency Diagnostic Rollback")
                st.caption(
                    "Atomically restores the active configuration to the last known-good registered version. "
                    "Has ZERO effect on production risk scores or citizen guidance."
                )
                lkg_ver = active_cfg.get("last_known_good_version")
                if lkg_ver and lkg_ver != active_ver:
                    st.warning(f"⚠️ Last Known-Good Version Available for Rollback: **`{lkg_ver}`**")
                    col_rb1, col_rb2 = st.columns([2, 1])
                    with col_rb1:
                        rollback_reason = st.text_input(
                            "Reason for Rollback:",
                            value="Operator initiated rollback to prior verified configuration",
                            key="rb_reason_input",
                        )
                    with col_rb2:
                        st.write("")
                        st.write("")
                        if st.button("⏪ Execute Emergency Rollback", type="secondary", key="btn_rollback_model"):
                            try:
                                rb_cfg = registry.rollback_model(
                                    operator_label="operator_local",
                                    reason=rollback_reason,
                                )
                                st.success(f"Rollback successful! Active model is now `{rb_cfg['active_model_version']}`.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Rollback failed: {e}")
                else:
                    st.info("No distinct last known-good version recorded for rollback.")

                st.markdown("---")
                st.markdown("#### 📜 Model Registry Audit Trail")
                with st.expander("View Model Registry Lifecycle & Activation Events", expanded=False):
                    reg_audit = registry.get_audit_log(limit=25)
                    if reg_audit:
                        st.dataframe(reg_audit, use_container_width=True)
                    else:
                        st.info("No registry audit events logged yet.")

        # ---------------------------------------------------------------------
        # SECTION C: FRAUD PATTERN DISCOVERY & CATALOGUE (Phase 6.2)
        # ---------------------------------------------------------------------
        with subtab_discovery:
            st.markdown("#### 🔬 Offline Autonomous Fraud Pattern Discovery Engine")
            st.caption(
                "Mines statistical character n-gram and structural URL associations from eligible, consented, "
                "human-reviewed case records. Candidate patterns are hypotheses for human analyst triage "
                "and NEVER alter active detection rules or production threat scores."
            )

            st.warning(
                "🔒 **DISCOVERY PRIVACY & SAFETY BOUNDARIES:**\n"
                "- **Non-Reversible Feature Indices:** Feature vectors are 1024-dimensional character n-gram hashes. "
                "Original text words cannot be reconstructed from hashed feature buckets.\n"
                "- **Zero Raw URL Retention:** Structural URL flags are extracted passively in memory and immediately discarded. "
                "Raw URLs are never saved into pattern catalogues.\n"
                "- **Explicit Approval Separation:** Candidates start in `draft` or `needs_more_evidence`. "
                "Approving a hypothesis records an operator review and does NOT activate any automated rule."
            )

            from src.pattern_discovery import PatternCatalogManager, PatternDiscoveryEngine

            cat_mgr = PatternCatalogManager()
            disc_col1, disc_col2 = st.columns(2)
            with disc_col1:
                st.markdown("##### 🚀 Run Offline Pattern Mining")
                min_supp = st.slider(
                    "Minimum Supporting Examples (Threshold):",
                    min_value=2,
                    max_value=20,
                    value=3,
                    key="slider_disc_supp",
                )
                if st.button("🔎 Mine Eligible Local Reviewed Features", type="primary", key="btn_run_disc"):
                    try:
                        store: SessionCaseStore = st.session_state.case_store
                        disc_res = store.discover_patterns(min_support=min_supp, catalog_manager=cat_mgr)
                        candidates = disc_res.get("candidates", [])
                        st.info(f"Discovery Run Finished: {len(candidates)} candidate pattern(s) identified.")
                        if candidates:
                            saved_path = cat_mgr.save_catalog(candidates, provenance_filter="local_curated_feedback")
                            st.success(f"Saved new candidate catalogue version at `{saved_path}`.")
                    except Exception as disc_err:
                        st.error(f"Pattern discovery failed: {disc_err}")

            with disc_col2:
                st.markdown("##### 📚 Available Pattern Catalogues")
                catalogs = cat_mgr.list_catalogs()
                if catalogs:
                    st.write(f"Catalogues on disk: {len(catalogs)}")
                    selected_cat = st.selectbox("Select Catalogue Version:", catalogs, key="sel_cat_version")
                else:
                    selected_cat = None
                    st.info("No pattern catalogues saved on disk yet. Run discovery above.")

            if selected_cat:
                cat_data = cat_mgr.load_catalog(catalog_path=os.path.join(cat_mgr.catalog_dir, selected_cat))
                st.markdown(f"##### 📋 Catalogue: `{cat_data.get('catalog_version')}` (Candidates: {cat_data.get('candidate_count')})")
                cand_list = cat_data.get("candidate_patterns", [])
                if cand_list:
                    cand_summary = []
                    for c in cand_list:
                        cand_summary.append({
                            "Candidate ID": c.get("candidate_id"),
                            "Type": c.get("candidate_pattern_type"),
                            "Target Class": c.get("target_class"),
                            "Support": c.get("supporting_example_count"),
                            "State": c.get("lifecycle_state"),
                            "Features": ", ".join(c.get("opaque_feature_identifiers", [])),
                            "Wilson Lower Bound": c.get("statistical_evidence", {}).get("wilson_lower_bound", 0.0),
                            "Lift": c.get("statistical_evidence", {}).get("lift", 0.0),
                        })
                    st.dataframe(cand_summary, use_container_width=True)

                    st.markdown("##### ✍️ Operator Candidate Pattern Adjudication")
                    cand_ids = [c["Candidate ID"] for c in cand_summary]
                    chosen_cid = st.selectbox("Select Candidate to Review:", cand_ids, key="sel_cand_review")
                    if chosen_cid:
                        full_cand = next(c for c in cand_list if c["candidate_id"] == chosen_cid)
                        st.json(full_cand)

                        col_act1, col_act2, col_act3 = st.columns(3)
                        with col_act1:
                            rev_action = st.selectbox(
                                "Review Action:",
                                ["ready_for_human_review", "approved_by_human", "rejected", "needs_more_evidence"],
                                key="sel_rev_action",
                            )
                        with col_act2:
                            rev_reason = st.text_input(
                                "Reviewer Justification / Reason:",
                                value="Analyst verified correlation with observed campaign telemetry",
                                key="input_rev_reason",
                            )
                        with col_act3:
                            st.write("")
                            st.write("")
                            if st.button("Submit Pattern Decision", key="btn_submit_pattern_review"):
                                try:
                                    cat_mgr.review_candidate_pattern(
                                        candidate_id=chosen_cid,
                                        new_state=rev_action,
                                        reason=rev_reason,
                                        catalog_path=os.path.join(cat_mgr.catalog_dir, selected_cat),
                                    )
                                    st.success(f"Candidate `{chosen_cid}` updated to `{rev_action}`.")
                                    st.rerun()
                                except Exception as rev_err:
                                    st.error(f"Review action failed: {rev_err}")

            st.markdown("---")
            st.markdown("#### 📜 Pattern Review Audit Trail")
            with st.expander("View Append-Only Pattern Review Audit Events", expanded=False):
                audit_logs = cat_mgr.list_review_audit_logs(limit=25)
                if audit_logs:
                    st.dataframe(audit_logs, use_container_width=True)
                else:
                    st.info("No pattern review decisions recorded yet.")


if __name__ == "__main__":
    main()