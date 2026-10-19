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

    tab_phishing, tab_apk, tab_eval = st.tabs(
        [
            "💬 1. Marathi & Mixed-Language Phishing Detector",
            "📦 2. Android .APK Static Security Analyzer",
            "📊 3. Optional ML Baseline & Responsible AI Disclosures",
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
                    st.write("**ZIP Archive File Listing (First 30):**", apk_res["files_inside_zip"])

    # =========================================================================
    # TAB 3: OPTIONAL ML EVALUATION & RESPONSIBLE AI DISCLOSURES
    # =========================================================================
    with tab_eval:
        st.subheader("📊 Optional Local ML Baseline & Responsible AI Methodology")
        eval_bundle = train_and_evaluate_local_model()

        if not eval_bundle.get("is_available"):
            st.warning(f"Optional ML module status: {eval_bundle.get('error')}")
        else:
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Sample Dataset", f"{eval_bundle['total_samples']} messages")
            m2.metric("Training Split (75%)", f"{eval_bundle['train_count']} messages")
            m3.metric("Unseen Test Split (25%)", f"{eval_bundle['test_count']} messages")
            m4.metric("Unseen Test Accuracy", f"{eval_bundle['test_accuracy_pct']}%")

            st.markdown("#### Confusion Matrix on Unseen 25% Test Split (5 Messages)")
            st.table(
                [
                    {
                        "Metric": "True Positives (Phishing Correctly Flagged)",
                        "Count": eval_bundle["true_positives"],
                    },
                    {
                        "Metric": "True Negatives (Legitimate Correctly Cleared)",
                        "Count": eval_bundle["true_negatives"],
                    },
                    {
                        "Metric": "False Positives (Legitimate Wrongly Flagged)",
                        "Count": eval_bundle["false_positives"],
                    },
                    {
                        "Metric": "False Negatives (Phishing Missed)",
                        "Count": eval_bundle["false_negatives"],
                    },
                ]
            )
            st.info(eval_bundle["methodology_note"])

        st.markdown("#### 🛡️ Summary of Responsible AI & Security Boundaries")
        st.markdown(
            "1. **Static vs. Dynamic Boundary:** Static manifest inspection identifies declared capabilities (`READ_SMS`, `BIND_ACCESSIBILITY_SERVICE`), not runtime behavior. A legitimate banking app may request SMS permissions, and a sophisticated malicious app may hide code in encrypted assets.\n"
            "2. **Synthetic Fixture Transparency:** Test files generated by `create_sample_apks.py` are explicitly flagged in the UI so synthetic test fixtures are never misrepresented as real malware.\n"
            "3. **Language Coverage:** The vernacular detector targets common Marathi (Devanagari), Romanized Marathi, and English scam templates in Maharashtra (such as MSEDCL bill disconnection, KYC expiry, and RTO challan lures). It does not cover all regional dialects."
        )


if __name__ == "__main__":
    main()