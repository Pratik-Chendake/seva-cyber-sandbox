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

from src.apk_analyzer import MAX_APK_UPLOAD_BYTES, analyze_apk_bytes
from src.audio_alert import (
    generate_alert_wav_bytes,
    get_spoken_script,
    inspect_installed_tts_voices,
    speak_offline_windows_tts,
)
from src.ml_classifier import predict_with_local_ml
from src.phishing_detector import analyze_message_text
from src.risk_scorer import score_apk_analysis, score_message_analysis
from src.scheme_verifier import load_official_sources, verify_scheme_claim
from src.url_analyzer import analyze_url
from src.hybrid_decision_engine import evaluate_message_hybrid
from src.model_registry import get_default_model_registry
from src.unified_workspace_ui import render_unified_evidence_workspace
from src.case_manager import (
    SessionCaseStore,
    create_apk_case,
    create_message_case,
    create_scheme_case,
    create_url_case,
    generate_evidence_report,
)
from src.ui_theme import (
    inject_custom_theme,
    render_bento_overview,
    render_editorial_header,
    render_threat_banner,
)
try:
    from evaluation.evaluate_phishing import get_cached_evaluation_report
except Exception:
    get_cached_evaluation_report = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def render_risk_assessment_panel(
    scored: Dict[str, Any], enable_audio: bool, key_prefix: str
) -> None:
    """Renders the unified risk level, score, bilingual summaries, evidence, next steps, and audio alert."""
    color = scored.get("badge_color", "gray")
    analysis_type = scored.get("analysis_type", "Security Assessment")
    score_val = scored.get("score", 0)
    risk_level_str = scored.get("risk_level", "Unknown")

    st.markdown("---")
    render_threat_banner(risk_level_str, color, analysis_type, score_val)

    # Bilingual Summaries in a Bento 2-column layout
    col_en, col_mr = st.columns(2)
    with col_en:
        st.markdown(
            f"""
            <div class="bento-card">
                <div class="bento-card-header">
                    <span class="bento-card-label">01 // ENGLISH EXPLANATION</span>
                    <span class="bento-card-meta">ANALYSIS SUMMARY</span>
                </div>
                <div style="font-size:0.92rem; line-height:1.55; color:var(--text-primary);">
                    {scored['summary_en']}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_mr:
        st.markdown(
            f"""
            <div class="bento-card">
                <div class="bento-card-header">
                    <span class="bento-card-label">02 // मराठी स्पष्टीकरण (MARATHI)</span>
                    <span class="bento-card-meta">प्रादेशिक विश्लेषण</span>
                </div>
                <div style="font-size:0.92rem; line-height:1.55; color:var(--text-primary);">
                    {scored['summary_mr']}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

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

    col_steps_en, col_steps_mr = st.columns(2)
    with col_steps_en:
        st.markdown("#### 🛡️ Suggested Safe Next Steps (English)")
        for idx, step in enumerate(scored.get("safe_next_steps_en", []), start=1):
            st.markdown(f"{idx}. {step}")
    with col_steps_mr:
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
        page_title="SEVA // CYBER INTEL PLATFORM",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    inject_custom_theme()

    if "case_store" not in st.session_state:
        st.session_state.case_store = SessionCaseStore()

    if "session_id" not in st.session_state:
        st.session_state.session_id = st.session_state.case_store.session_id

    if "auth_service" not in st.session_state:
        from src.operator_auth import OperatorAuthService
        st.session_state.auth_service = OperatorAuthService(
            db_path=st.session_state.case_store.repository.db_path
        )

    if "operator_session" not in st.session_state:
        st.session_state.operator_session = None

    case_count = st.session_state.case_store.count()
    render_editorial_header(session_case_count=case_count)
    render_bento_overview(case_count=case_count)

    st.markdown(
        """
        <div class="bento-card bento-card-elevated" style="border-left: 3px solid var(--accent-lime); margin-top: 1rem; margin-bottom: 1.5rem;">
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
                <span class="editorial-brand-badge">OPERATIONAL NOTICE</span>
                <span style="font-family:var(--font-mono); font-size:0.75rem; color:var(--accent-lime); text-transform:uppercase; letter-spacing:0.06em;">
                    LOCAL CYBERSECURITY ANALYSIS PLATFORM
                </span>
            </div>
            <div style="font-size:0.9rem; line-height:1.5; color:var(--text-primary);">
                This platform performs <strong>local static inspection</strong> of Android <code>.apk</code> packages, <strong>local rule-based phishing analysis</strong> of messages in Marathi, Romanized Marathi, Mixed, and English, and <strong>local URL structure analysis</strong>. Analysis is performed entirely on this device. No files or messages are uploaded to external services.
                <br>
                <span style="color:var(--text-secondary); font-size:0.82rem; font-family:var(--font-mono);">
                    [BOUNDARIES] 100% Local Execution • No External Network Requests • No Dynamic Code Execution • Offline Analysis Only
                </span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.markdown(
            """
            <div style="padding-bottom:12px; border-bottom:1px solid var(--border-color); margin-bottom:14px;">
                <span class="editorial-brand-badge">SEVA // CONTROLS</span>
                <div style="font-family:var(--font-heading); font-size:1.1rem; font-weight:700; color:var(--text-primary); margin-top:4px;">
                    ANALYSIS CONTROLS
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("<div class='bento-card-label'>00 // CONTROLS</div>", unsafe_allow_html=True)
        enable_audio = st.checkbox("Enable Audio Alert & TTS Controls", value=True)
        show_ml_panel = st.checkbox(
            "Show Experimental Local ML Baseline Comparison", value=True
        )

        if st.button("🔍 Check Windows TTS Voices", key="sidebar_tts_btn"):
            v_info = inspect_installed_tts_voices()
            if v_info["tts_available"]:
                st.success(f"Detected {len(v_info['voices'])} offline system voice(s).")
                st.code("\n".join(v_info["voices"]))
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
        st.markdown("<div class='bento-card-label'>00 // PRIVACY & BOUNDARIES</div>", unsafe_allow_html=True)
        st.markdown(
            "- **`[LOCAL HOST]`**: All files and messages are processed strictly in your laptop's RAM and never leave your machine.\n"
            "- **`[PUBLIC CLOUD DEMO]`**: Never upload private personal chats, real banking documents, or confidential files to a public demo server.\n"
            "- **`[AIR-GAPPED]`**: Neither local nor cloud mode writes uploaded APKs or pasted messages to a remote database.\n"
            "- **`[HELPLINE]`**: Report real financial cyber fraud immediately to **1930** or `https://cybercrime.gov.in`."
        )

    tab_unified, tab_apk, tab_url, tab_scheme, tab_cases, tab_eval, tab_review = st.tabs(
        [
            "01 // UNIFIED EVIDENCE ANALYSIS",
            "02 // APK INSPECTION",
            "03 // URL RADAR",
            "04 // SCHEME VERIFIER",
            "05 // THREAT CASES",
            "06 // EVALUATION & AI",
            "07 // OPERATOR DESK",
        ]
    )

    # =========================================================================
    # TAB 1: UNIFIED EVIDENCE ANALYSIS WORKSPACE (Phase 7.1.0)
    # =========================================================================
    with tab_unified:
        render_unified_evidence_workspace(
            case_store=st.session_state.case_store,
            session_id=st.session_state.session_id,
            enable_audio=enable_audio,
            show_ml_panel=show_ml_panel,
            operator_username=st.session_state.get("operator_username"),
        )

    # =========================================================================
    # TAB 2: APK STATIC SECURITY ANALYZER
    # =========================================================================
    with tab_apk:
        st.markdown("<div class='bento-card-label'>02 // APK STATIC SECURITY ANALYZER</div>", unsafe_allow_html=True)
        st.subheader("Safe Android .APK Static Security Analyzer")
        st.caption(
            f"Inspects `.apk` archives up to {MAX_APK_UPLOAD_BYTES // (1024 * 1024)} MB in memory without installing or executing code."
        )

        apk_bytes = None
        apk_filename = ""

        uploaded_file = st.file_uploader(
            "Upload an .apk file for local static inspection (Max 15 MB)",
            type=["apk"],  # only accept .apk, not zip/txt
        )
        if uploaded_file is not None:
            apk_bytes = uploaded_file.getvalue()
            apk_filename = uploaded_file.name

        if apk_bytes is None:
            st.info("Upload an .apk file above to begin static analysis. No file has been submitted yet.")

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
        st.markdown("<div class='bento-card-label'>03 // SAFE SUSPICIOUS URL & DOMAIN ANALYZER</div>", unsafe_allow_html=True)
        st.subheader("Safe Suspicious URL & Domain Analyzer")
        st.caption(
            "Defensively inspects suspicious web links, brand lookalikes, URL shorteners, punycode homoglyphs, "
            "and IP addresses 100% offline without ever opening or contacting the target server."
        )

        st.markdown("##### 📌 Enter a suspicious URL for local static analysis:")
        url_input_text = st.text_input(
            "Enter or paste a suspicious URL to inspect:",
            value="",
            placeholder="e.g., http://suspicious-link.xyz/pay or https://bit.ly/example",
            key="url_analyzer_input",
            help="STRICT SECURITY: The sandbox analyzes domain and protocol structure passively and NEVER connects to submitted URLs.",
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
                render_threat_banner(url_eval["risk_level"], color, "Link Security Assessment", url_eval["score"])

                # Urgent Citizen Safeguard Banner
                if color in ("red", "orange"):
                    st.error(
                        "🛑 **CRITICAL CITIZEN PROTECTION WARNING:**\n"
                        "**NEVER enter your Bank OTP, Netbanking Password, ATM PIN, or UPI PIN into this page.** "
                        "Legitimate banks, government portals, and MSEDCL never ask you to enter a UPI PIN to receive money."
                    )

                col_en, col_mr = st.columns(2)
                with col_en:
                    st.markdown(
                        f"""
                        <div class="bento-card">
                            <div class="bento-card-header">
                                <span class="bento-card-label">01 // ENGLISH EXPLANATION</span>
                                <span class="bento-card-meta">LINK SUMMARY</span>
                            </div>
                            <div style="font-size:0.92rem; line-height:1.55; color:var(--text-primary);">
                                {url_eval['summary_en']}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                with col_mr:
                    st.markdown(
                        f"""
                        <div class="bento-card">
                            <div class="bento-card-header">
                                <span class="bento-card-label">02 // मराठी स्पष्टीकरण (MARATHI)</span>
                                <span class="bento-card-meta">प्रादेशिक विश्लेषण</span>
                            </div>
                            <div style="font-size:0.92rem; line-height:1.55; color:var(--text-primary);">
                                {url_eval['summary_mr']}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                st.markdown("#### 🔍 Matched Evidence & Threat Indicators")
                for ev in url_eval["evidence"]:
                    st.markdown(f"- {ev}")

                # Observable Characteristics Bento Grid
                st.markdown("#### 🗂️ Observable URL Characteristics (Passive Extraction)")
                obs = url_eval["observable_characteristics"]
                c_o1, c_o2, c_o3 = st.columns(3)
                c_o1.metric("01 // PROTOCOL", url_eval['scheme'].upper() or 'NONE')
                c_o2.metric("02 // HOSTNAME", url_eval['hostname'] or 'N/A')
                c_o3.metric("03 // PORT", str(obs.get('port') or 'DEFAULT (80/443)'))

                c_o4, c_o5, c_o6 = st.columns(3)
                c_o4.metric("04 // ALLOWLISTED (.GOV.IN)", "YES (ALLOWLISTED)" if obs.get('is_official_allowlisted') else "NO (UNOFFICIAL)")
                c_o5.metric("05 // URL SHORTENER", f"YES ({obs.get('is_shortener')})" if obs.get('is_shortener') else "NO")
                c_o6.metric("06 // BRAND LOOKALIKE", f"YES ({obs.get('lookalike_brand')})" if obs.get('is_lookalike') else "NO")

                c_o7, c_o8, c_o9 = st.columns(3)
                c_o7.metric("07 // IP HOST TARGET", str(obs.get('ip_type')) if obs.get('is_ip_address') else "NO")
                c_o8.metric("08 // PUNYCODE / HOMOGLYPH", "YES" if obs.get('is_punycode_or_homoglyph') else "NO")
                c_o9.metric("09 // DIRECT APK TARGET", "YES (.APK)" if obs.get('has_apk_download') else "NO")

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
        st.markdown("<div class='bento-card-label'>04 // STATE SCHEME ANNOUNCEMENT VERIFIER</div>", unsafe_allow_html=True)
        st.subheader("Maharashtra Government Scheme & Announcement Verifier")
        st.caption(
            "Verifies claims and forwarded WhatsApp promises against official Government Resolutions (GRs) "
            "and allowlisted state portals (.gov.in, .maharashtra.gov.in, .mahadiscom.in)."
        )

        scheme_registry = load_official_sources()
        if not scheme_registry.get("is_valid"):
            st.error(f"Official registry notice: {scheme_registry.get('error')}")

        st.markdown("##### 📌 Enter a Government Scheme Claim or Forwarded Announcement to Verify:")
        c_claim, c_url = st.columns([2, 1])
        with c_claim:
            scheme_claim_input = st.text_area(
                "Paste Government Scheme Claim or WhatsApp Forward to Verify:",
                value="",
                height=110,
                placeholder="e.g., Paste a forwarded WhatsApp message or claim regarding a Maharashtra state welfare scheme...",
                key="scheme_claim_area",
            )
        with c_url:
            scheme_url_input = st.text_input(
                "Optional Scheme Link (Analyzed PASSIVELY without opening):",
                value="",
                placeholder="e.g., https://example-portal.maharashtra.gov.in",
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
                    st.markdown(
                        f"""
                        <div class="bento-card">
                            <div class="bento-card-header">
                                <span class="bento-card-label">01 // ENGLISH VERIFICATION SUMMARY</span>
                                <span class="bento-card-meta">OFFICIAL AUDIT</span>
                            </div>
                            <div style="font-size:0.92rem; line-height:1.55; color:var(--text-primary);">
                                {verification_res['summary_en']}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                with col_exp_mr:
                    st.markdown(
                        f"""
                        <div class="bento-card">
                            <div class="bento-card-header">
                                <span class="bento-card-label">02 // मराठी स्पष्टीकरण (MARATHI)</span>
                                <span class="bento-card-meta">शासकीय पडताळणी</span>
                            </div>
                            <div style="font-size:0.92rem; line-height:1.55; color:var(--text-primary);">
                                {verification_res['summary_mr']}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

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
        st.markdown("<div class='bento-card-label'>05 // THREAT CASE DASHBOARD & EVIDENCE EXPORT</div>", unsafe_allow_html=True)
        st.subheader("Threat Case Dashboard & Incident Evidence Export")
        st.caption(
            "Session-scoped incident management desk for citizen facilitation counters and cyber-awareness volunteers. "
            "Cases are securely persisted in SQLite with privacy-preserving redaction and automatic retention."
        )

        store: SessionCaseStore = st.session_state.case_store
        cases_list = store.list_cases()

        # Summary Metric Cards (Bento Grid)
        col_m1, col_m2, col_m3, col_m4 = st.columns(4)
        total_cnt = store.count()
        red_cnt = sum(1 for c in cases_list if c.get("badge_color") == "red" or c.get("risk_score", 0) >= 50)
        orange_cnt = sum(1 for c in cases_list if c.get("badge_color") == "orange" or (20 <= c.get("risk_score", 0) < 50))
        green_cnt = sum(1 for c in cases_list if c.get("badge_color") == "green" or c.get("risk_score", 0) < 20)

        col_m1.metric("01 // TOTAL CASES", f"{total_cnt}")
        col_m2.metric("02 // HIGH-RISK (RED)", f"{red_cnt}")
        col_m3.metric("03 // WARNING (ORANGE)", f"{orange_cnt}")
        col_m4.metric("04 // CLEARED (GREEN)", f"{green_cnt}")

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
        st.markdown("<div class='bento-card-label'>06 // EVALUATION BENCHMARK & RESPONSIBLE AI</div>", unsafe_allow_html=True)
        st.subheader("Phishing Detection Evaluation, Dataset Quality & Responsible AI")
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
            col_d1.metric("01 // BENCHMARK CORPUS", f"{meta.get('total_records', 0)} RECORDS")
            col_d2.metric("02 // UNIQUE CAMPAIGNS", f"{meta.get('unique_campaigns_count', 0)} GROUPS")
            labels_d = meta.get("label_distribution", {})
            col_d3.metric("03 // PHISH / LEGIT", f"{labels_d.get('phishing', 0)} / {labels_d.get('legitimate', 0)}")
            col_d4.metric("04 // ADVISORY / AMBIG", f"{labels_d.get('protective_advisory', 0)} / {labels_d.get('ambiguous_needs_review', 0)}")

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
                st.markdown("<div class='bento-card-label'>01 // DETERMINISTIC RULES</div>", unsafe_allow_html=True)
                st.markdown("##### 🛡️ Rule-Based Detector")
                st.markdown(f"- **Accuracy:** `{rb_m.get('accuracy_pct', 0)}%` ({rb_m.get('true_positives', 0) + rb_m.get('true_negatives', 0)}/{rb_m.get('total_samples', 0)})")
                st.markdown(f"- **Precision:** `{rb_m.get('precision_pct', 0)}%`")
                st.markdown(f"- **Recall (Sensitivity):** `{rb_m.get('recall_pct', 0)}%`")
                st.markdown(f"- **Specificity:** `{rb_m.get('specificity_pct', 0)}%`")
                st.markdown(f"- **F1 Score:** `{rb_m.get('f1_score_pct', 0)}%`")
                adv_rb = rb_eval.get("protective_advisory_evaluation", {})
                st.markdown(f"- **Protective Negation Rate:** `{adv_rb.get('safeguard_success_pct', 0)}%` ({adv_rb.get('correctly_cleared_count', 0)}/{adv_rb.get('total_advisories', 0)})")

            with c2:
                st.markdown("<div class='bento-card-label'>02 // EXPERIMENTAL ML</div>", unsafe_allow_html=True)
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
                st.markdown("<div class='bento-card-label'>03 // MODEL CONCORDANCE</div>", unsafe_allow_html=True)
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
        st.markdown("<div class='bento-card-label'>07 // OPERATOR ADJUDICATION & MODEL REGISTRY</div>", unsafe_allow_html=True)
        st.subheader("Human Review Desk & Model Version Registry")
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
            "- **Authenticated Operator Accountability:** Reviews, state transitions, and corroboration rationale are attributed "
            "to authenticated operator accounts via local PBKDF2-HMAC-SHA256 salted credentials."
        )

        auth_service = st.session_state.auth_service
        current_session = st.session_state.operator_session
        if current_session:
            valid_session = auth_service.validate_session(current_session.get("session_token"))
            if not valid_session:
                st.session_state.operator_session = None
                current_session = None

        col_auth_status, col_auth_action = st.columns([3, 1])
        with col_auth_status:
            if current_session:
                st.success(
                    f"👤 **Authenticated Operator:** `{current_session['username']}` | "
                    f"**Role:** `{current_session['role'].upper()}` | "
                    f"**Session Expires:** `{current_session['expires_at_utc']}`"
                )
            else:
                st.info("🔒 **Reviewer Identity:** `local_operator_unauthenticated` (Log in below to enable corroboration and lifecycle transitions)")

        with col_auth_action:
            if current_session:
                if st.button("🚪 Log Out", key="btn_operator_logout_top"):
                    auth_service.logout(current_session["session_token"])
                    st.session_state.operator_session = None
                    st.rerun()

        if not current_session:
            if not auth_service.has_any_operator():
                st.warning(
                    "⚠️ **Initial Operator Setup:** No operator accounts exist in SQLite yet. "
                    "Create the initial administrator account below. No hardcoded default credentials are permitted."
                )
                with st.expander("🛠️ First-Time Operator Registration", expanded=True):
                    with st.form("form_initial_operator_reg"):
                        init_user = st.text_input("Administrator Username:", value="admin").strip()
                        init_pass = st.text_input("Administrator Password (minimum 8 characters):", type="password")
                        init_pass_conf = st.text_input("Confirm Password:", type="password")
                        submit_init_btn = st.form_submit_button("🛡️ Create Initial Admin Account", type="primary")
                        if submit_init_btn:
                            if not init_user:
                                st.error("Username cannot be empty.")
                            elif len(init_pass) < 8:
                                st.error("Password must be at least 8 characters long.")
                            elif init_pass != init_pass_conf:
                                st.error("Passwords do not match.")
                            else:
                                try:
                                    auth_service.register_initial_operator(username=init_user, password=init_pass, role="admin")
                                    login_res = auth_service.login(username=init_user, password=init_pass)
                                    st.session_state.operator_session = login_res
                                    st.success(f"Administrator account '{init_user}' registered and authenticated!")
                                    st.rerun()
                                except Exception as ex:
                                    st.error(f"Registration failed: {ex}")
            else:
                with st.expander("🔐 Operator Login (Authenticate for Sensitive Review Actions)", expanded=False):
                    with st.form("form_operator_login"):
                        col_l1, col_l2 = st.columns(2)
                        with col_l1:
                            u_in = st.text_input("Operator Username:", key="txt_login_username").strip()
                        with col_l2:
                            p_in = st.text_input("Password:", type="password", key="txt_login_password")
                        btn_login_submit = st.form_submit_button("🔑 Authenticate Session", type="primary")
                        if btn_login_submit:
                            try:
                                res = auth_service.login(username=u_in, password=p_in)
                                if res.get("success"):
                                    st.session_state.operator_session = res
                                    st.success(f"Authenticated as '{u_in}'!")
                                    st.rerun()
                                else:
                                    st.error(res.get("error", "Invalid credentials."))
                            except Exception as ex:
                                st.error(f"Authentication failed: {ex}")

        subtab_desk, subtab_governance, subtab_registry, subtab_discovery, subtab_disagreement = st.tabs(
            [
                "07A // HUMAN REVIEW DESK",
                "07B // EVIDENCE GOVERNANCE & PROVENANCE",
                "07C // MODEL REGISTRY & ROLLBACK",
                "07D // FRAUD PATTERN DISCOVERY",
                "07E // MODEL DISAGREEMENT REVIEW",
            ]
        )

        # ---------------------------------------------------------------------
        # SECTION A: HUMAN REVIEW DESK
        # ---------------------------------------------------------------------
        with subtab_desk:
            store: SessionCaseStore = st.session_state.case_store
            stats = store.get_review_stats()

            col_r1, col_r2, col_r3, col_r4 = st.columns(4)
            col_r1.metric("01 // PENDING", stats.get("pending", 0))
            col_r2.metric("02 // UNDER REVIEW", stats.get("under_review", 0))
            col_r3.metric("03 // COMPLETED", stats.get("completed", 0))
            col_r4.metric("04 // INCONCLUSIVE", stats.get("inconclusive", 0))

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

        # ---------------------------------------------------------------------
        # SECTION B: EVIDENCE GOVERNANCE, PROVENANCE & LIFECYCLE (Phase 6.8.2)
        # ---------------------------------------------------------------------
        with subtab_governance:
            st.markdown("#### 🏛️ Evidence Governance, Provenance & Lifecycle Management")
            st.caption(
                "Traceable provenance tracking, multi-stage evidence lifecycle state machine, "
                "independent corroboration requirements, campaign clustering, and strict training eligibility gating."
            )

            store: SessionCaseStore = st.session_state.case_store
            all_evidence = store.list_evidence(limit=500)

            # Metrics
            total_evid = len(all_evidence)
            submitted_cnt = sum(1 for e in all_evidence if e["lifecycle_status"] == "submitted")
            awaiting_cnt = sum(1 for e in all_evidence if e["lifecycle_status"] == "awaiting_review")
            under_review_cnt = sum(1 for e in all_evidence if e["lifecycle_status"] == "under_review")
            corroborated_cnt = sum(1 for e in all_evidence if e["lifecycle_status"] == "corroborated")
            disputed_cnt = sum(1 for e in all_evidence if e["lifecycle_status"] in ("disputed", "rejected"))
            withdrawn_cnt = sum(1 for e in all_evidence if e["lifecycle_status"] == "withdrawn")

            col_g1, col_g2, col_g3, col_g4, col_g5, col_g6 = st.columns(6)
            col_g1.metric("01 // TOTAL", total_evid)
            col_g2.metric("02 // SUBMITTED", submitted_cnt)
            col_g3.metric("03 // AWAITING", awaiting_cnt)
            col_g4.metric("04 // REVIEW", under_review_cnt)
            col_g5.metric("05 // CORROBORATED", corroborated_cnt)
            col_g6.metric("06 // DISPUTED", disputed_cnt)

            st.markdown("---")
            st.markdown("##### 📥 Evidence Provenance Queue & Filters")

            col_flt_orig, col_flt_stat = st.columns(2)
            with col_flt_orig:
                flt_orig = st.selectbox(
                    "Filter by Evidence Origin:",
                    ["all", "user_reported", "analyst_submitted", "internal_case", "public_source_reference", "system_generated", "synthetic_test_data"],
                    key="sel_filter_evid_origin",
                )
            with col_flt_stat:
                flt_stat = st.selectbox(
                    "Filter by Lifecycle Status:",
                    ["all", "submitted", "awaiting_review", "under_review", "corroborated", "disputed", "rejected", "withdrawn"],
                    key="sel_filter_evid_status",
                )

            req_origin = None if flt_orig == "all" else flt_orig
            req_status = None if flt_stat == "all" else flt_stat
            filtered_evidence = store.list_evidence(origin=req_origin, lifecycle_status=req_status, limit=100)

            if not filtered_evidence:
                st.info(
                    "No evidence records matching the selected filters found. "
                    "Analyze messages, APKs, URLs, or scheme claims in Tabs 01-04 to log genuine submissions into the evidence queue."
                )
            else:
                table_rows = []
                for ev in filtered_evidence:
                    table_rows.append({
                        "Evidence ID": ev["evidence_id"],
                        "Case ID": ev["case_id"],
                        "Origin": ev["evidence_origin"],
                        "Type": ev["evidence_type"].upper(),
                        "Lifecycle Status": ev["lifecycle_status"].upper(),
                        "User Class": ev.get("user_classification") or "N/A",
                        "Rule Assessment": ev.get("rule_assessment") or "N/A",
                        "Model Pred": ev.get("model_prediction") or "N/A",
                        "Reviewer Class": ev.get("reviewer_classification") or "Unreviewed",
                        "Corroborated": ev.get("corroborated_conclusion") or "Pending",
                        "Consented": "Yes" if ev.get("consent_given") else "No",
                        "Created At (UTC)": ev.get("created_at_utc"),
                    })
                st.dataframe(table_rows, use_container_width=True)

                st.markdown("---")
                st.markdown("##### 🔍 Evidence Inspector & State Transition Desk")
                ev_options = [f"{e['evidence_id']} — {e['evidence_type'].upper()} ({e['lifecycle_status']})" for e in filtered_evidence]
                chosen_ev_entry = st.selectbox("Select Evidence Item to Inspect & Adjudicate:", ev_options, key="sel_evid_item")

                if chosen_ev_entry:
                    chosen_ev_id = chosen_ev_entry.split(" — ")[0].strip()
                    chosen_ev = store.get_evidence(chosen_ev_id)

                    st.markdown("###### 📋 Provenance, Integrity & Trust Verification")
                    c_ev1, c_ev2 = st.columns(2)
                    with c_ev1:
                        st.markdown(f"- **Evidence ID:** `{chosen_ev['evidence_id']}`")
                        st.markdown(f"- **Case ID:** `{chosen_ev['case_id']}`")
                        st.markdown(f"- **Origin Category:** `{chosen_ev['evidence_origin']}`")
                        st.markdown(f"- **Evidence Type:** `{chosen_ev['evidence_type']}`")
                        st.markdown(f"- **Sanitization Status:** `{chosen_ev['sanitization_status']}`")
                        st.markdown(f"- **Consent Status:** `{'Affirmative Consent Granted' if chosen_ev['consent_given'] else 'Consent Not Granted'}`")
                        st.markdown(f"- **Artifact SHA-256:** `{chosen_ev.get('artifact_sha256') or 'Not recorded'}`")
                    with c_ev2:
                        st.markdown(f"- **Lifecycle Status:** `{chosen_ev['lifecycle_status'].upper()}`")
                        v_level = (chosen_ev.get('verification_level') or 'unverified').upper()
                        if v_level == "INDEPENDENTLY_CORROBORATED":
                            st.markdown(f"- **Trust Level:** 🟢 `{v_level}` (Dual-Review Verified)")
                        elif v_level in ("SINGLE_REVIEWED", "SELF_REVIEWED"):
                            st.markdown(f"- **Trust Level:** 🟡 `{v_level}` (Single-Analyst Verification)")
                        elif v_level in ("DISPUTED", "REJECTED"):
                            st.markdown(f"- **Trust Level:** 🔴 `{v_level}` (Adjudicated Ineligible)")
                        else:
                            st.markdown(f"- **Trust Level:** ⚪ `{v_level}`")

                        st.markdown(f"- **Submitted By:** `{chosen_ev.get('submitted_by') or 'Client / Ingestion'}`")
                        st.markdown(f"- **Reviewed By:** `{chosen_ev.get('reviewed_by') or 'Pending'}`")
                        st.markdown(f"- **Corroborated By:** `{chosen_ev.get('corroborated_by') or 'Pending'}`")
                        st.markdown(f"- **Corroborated Conclusion:** `{chosen_ev.get('corroborated_conclusion') or 'None'}`")

                    # Cryptographic Tamper Verification Button
                    if chosen_ev.get("artifact_sha256"):
                        if st.button("🛡️ Cryptographically Verify Artifact Integrity", key=f"btn_verify_digest_{chosen_ev_id}"):
                            try:
                                v_res = store.verify_evidence_integrity(chosen_ev_id)
                                if v_res["is_valid"]:
                                    st.success(f"✅ Cryptographic digest verified: {v_res['digest']}")
                                else:
                                    st.error("❌ Tamper detected: digest mismatch.")
                            except Exception as ex:
                                st.error(f"Integrity check failed: {ex}")

                    if chosen_ev.get("corroboration_rationale"):
                        st.info(f"📌 **Recorded Corroboration Rationale:** {chosen_ev['corroboration_rationale']}")

                    # Training Eligibility Section
                    st.markdown("###### 🛡️ Multi-Tier Training Eligibility Gate Evaluation")
                    elig = store.check_training_eligibility(chosen_ev_id)
                    tier = elig.get("eligibility_tier", "not_eligible")

                    if tier == "independently_corroborated_evaluation_candidate":
                        st.success("🌟 **TIER 4 — EVALUATION CANDIDATE:** Independently corroborated via dual-review. Reserved exclusively for evaluation benchmarks (strictly isolated from training).")
                    elif tier == "eligible_supervised_candidate_training":
                        st.success("✅ **TIER 3 — SUPERVISED CANDIDATE TRAINING:** Fully vetted, consented, sanitized, and human-reviewed. Eligible for candidate model retraining.")
                    elif tier == "eligible_exploratory_review":
                        st.info("ℹ️ **TIER 2 — EXPLORATORY REVIEW ONLY:** Consented and sanitized, but unverified or single-reviewer. Restricted from model training.")
                    else:
                        st.error("❌ **TIER 1 — INELIGIBLE:** Governance, consent, or corroboration criteria not satisfied. Strictly excluded from all models.")

                    with st.expander("View 8-Point Governance Gate Breakdown", expanded=False):
                        checks = elig["checks"]
                        chk_cols = st.columns(4)
                        chk_cols[0].markdown(f"- **Consent Valid:** {'✅ Yes' if checks['consent_valid'] else '❌ No'}")
                        chk_cols[0].markdown(f"- **Genuine Origin:** {'✅ Yes' if checks['provenance_valid'] else '❌ No'}")
                        chk_cols[1].markdown(f"- **Corroborated:** {'✅ Yes' if checks['human_review_completed'] else '❌ No'}")
                        chk_cols[1].markdown(f"- **Definitive Class:** {'✅ Yes' if checks['classification_definitive'] else '❌ No'}")
                        chk_cols[2].markdown(f"- **Not Withdrawn:** {'✅ Yes' if checks['not_withdrawn'] else '❌ No'}")
                        chk_cols[2].markdown(f"- **Sanitization Passed:** {'✅ Yes' if checks['privacy_sanitization_passed'] else '❌ No'}")
                        chk_cols[3].markdown(f"- **Conflict Resolved:** {'✅ Yes' if checks['conflict_resolved'] else '❌ No'}")
                        chk_cols[3].markdown(f"- **Feature Vector Available:** {'✅ Yes' if checks['feature_vector_available'] else '❌ No'}")
                        st.markdown("**Governance Assessment Notes:**")
                        for r in elig["reasons"]:
                            st.markdown(f"- {r}")

                    # Two-Person Rule Corroboration & Lifecycle State Transition Controls
                    st.markdown("###### 🔄 Independent Corroboration & State Transition Controls")
                    curr_status = chosen_ev["lifecycle_status"]
                    from src.case_repository import VALID_LIFECYCLE_TRANSITIONS, ALLOWED_VERIFICATION_METHODS
                    allowed_next = sorted(list(VALID_LIFECYCLE_TRANSITIONS.get(curr_status, set())))

                    if not allowed_next:
                        st.warning(f"Evidence is in terminal state `{curr_status}`. No further transitions allowed.")
                    else:
                        st.markdown(f"**Current State:** `{curr_status}` | **Permissible Next States:** `{allowed_next}`")

                        if not current_session:
                            st.warning("⚠️ **Authentication Required:** You must log in as an operator above to perform lifecycle state transitions.")
                        else:
                            # Two-person review warning
                            is_self_submission = bool(chosen_ev.get("submitted_by") and chosen_ev["submitted_by"] == current_session["username"])
                            is_same_reviewer = bool(chosen_ev.get("reviewed_by") and chosen_ev["reviewed_by"] == current_session["username"])
                            if is_self_submission or is_same_reviewer:
                                st.info(
                                    "ℹ️ **Two-Person Rule Notice:** You submitted or performed primary review on this evidence. "
                                    "Your corroboration will be recorded as `self_reviewed` or `single_reviewed`. "
                                    "Independent corroboration (`independently_corroborated`) requires a distinct second reviewer."
                                )

                            with st.form(f"form_transition_{chosen_ev_id}"):
                                target_status = st.selectbox("Target Lifecycle Status:", allowed_next)
                                rev_class = st.selectbox(
                                    "Reviewer Classification:",
                                    ["phishing", "legitimate", "protective_advisory", "unknown"],
                                    index=0 if not chosen_ev.get("reviewer_classification") else
                                          ["phishing", "legitimate", "protective_advisory", "unknown"].index(chosen_ev.get("reviewer_classification", "phishing")),
                                )
                                trans_reason = st.text_input(
                                    "State Transition Reason (Mandatory, min 5 chars):",
                                    placeholder="Explain why this state transition is occurring...",
                                )

                                corr_rationale = ""
                                corr_conclusion = None
                                v_method = None
                                ref_input = ""
                                if target_status == "corroborated":
                                    st.markdown("---")
                                    st.markdown("**Two-Person Corroboration & Verification Requirements:**")
                                    v_method = st.selectbox(
                                        "Verification Method (Approved Standards):",
                                        sorted(list(ALLOWED_VERIFICATION_METHODS)),
                                    )
                                    ref_input = st.text_input(
                                        "Supporting Technical References (Mandatory, e.g. APK SHA-256, domain, or GR reference):",
                                        value=chosen_ev.get("artifact_sha256") or "",
                                        placeholder="Enter specific indicators, hashes, or Government Resolution citations...",
                                    )
                                    corr_rationale = st.text_area(
                                        "Independent Verification Rationale (Mandatory, min 15 chars):",
                                        value=chosen_ev.get("corroboration_rationale", ""),
                                        placeholder="Detail independent technical indicators or external verification confirming this finding...",
                                    )
                                    corr_conclusion = st.selectbox(
                                        "Corroborated Ground Truth Conclusion:",
                                        ["phishing", "legitimate", "protective_advisory"],
                                        help="Cannot be 'unknown' for corroboration.",
                                    )

                                submit_trans_btn = st.form_submit_button("⚡ Execute State Transition", type="primary")

                                if submit_trans_btn:
                                    try:
                                        if target_status == "corroborated" and v_method and ref_input:
                                            # Use corroborate_evidence method
                                            refs = [r.strip() for r in ref_input.split(",") if r.strip()]
                                            res = store.corroborate_evidence(
                                                evidence_id=chosen_ev_id,
                                                operator_username=current_session["username"],
                                                rationale=corr_rationale,
                                                conclusion=corr_conclusion or rev_class,
                                                verification_method=v_method,
                                                supporting_references=refs,
                                                require_independent=False,  # Allow single-analyst local mode without exception
                                                operator_role=current_session.get("role", "reviewer"),
                                            )
                                        else:
                                            res = store.transition_evidence(
                                                evidence_id=chosen_ev_id,
                                                to_status=target_status,
                                                operator_username=current_session["username"],
                                                transition_reason=trans_reason,
                                                corroboration_rationale=corr_rationale,
                                                reviewer_classification=rev_class,
                                                corroborated_conclusion=corr_conclusion,
                                            )
                                        st.success(f"Evidence successfully transitioned from '{curr_status}' to '{target_status}'!")
                                        st.rerun()
                                    except Exception as ex:
                                        st.error(f"Transition rejected: {ex}")

                    # Campaign Association & Conflict View
                    st.markdown("###### 🏷️ Campaign Association & Anti-Poisoning Controls")
                    col_camp1, col_camp2 = st.columns(2)
                    with col_camp1:
                        st.markdown(f"- **Assigned Campaign ID:** `{chosen_ev.get('campaign_id') or 'None'}`")
                        st.markdown(f"- **Relationship Strength:** `{chosen_ev.get('relationship_strength', 'unrelated_evidence')}`")
                        if chosen_ev.get("relationship_strength") == "weak_similarity":
                            st.warning("⚠️ **Shared Infrastructure:** Coarse domain association suppressed to prevent false campaign clustering.")
                        if chosen_ev.get("campaign_id"):
                            conf_info = store.get_campaign_conflict_status(chosen_ev["campaign_id"])
                            if conf_info.get("is_conflict"):
                                st.error(f"⚠️ **Conflict in Campaign:** Mixed labels detected: {conf_info.get('conflicting_labels')}. Campaign quarantined from training.")
                            else:
                                st.success(f"✅ **Consistent Labels:** {conf_info.get('distinct_labels') or 'Unclassified'}")
                    with col_camp2:
                        if current_session:
                            with st.expander("Reassign Campaign Cluster", expanded=False):
                                new_camp = st.text_input("New Campaign ID:", value=chosen_ev.get("campaign_id") or "").strip()
                                reassign_reason = st.text_input("Reassignment Justification:", placeholder="Reason for updating campaign association")
                                if st.button("Update Campaign", key=f"btn_reassign_camp_{chosen_ev_id}"):
                                    if new_camp and reassign_reason:
                                        try:
                                            store.assign_campaign(chosen_ev_id, new_camp, current_session["username"], reassign_reason)
                                            st.success("Campaign association updated!")
                                            st.rerun()
                                        except Exception as ex:
                                            st.error(f"Reassignment failed: {ex}")
                                    else:
                                        st.error("Campaign ID and Justification are required.")

                    # Withdrawal Control
                    if chosen_ev["lifecycle_status"] != "withdrawn" and current_session:
                        with st.expander("⚠️ Withdraw Evidence from System", expanded=False):
                            st.warning(
                                "Withdrawing evidence moves it to the terminal 'withdrawn' state, "
                                "immediately revokes training consent, and excludes it from all candidate exports."
                            )
                            w_reason = st.text_input("Withdrawal Reason:", key=f"txt_w_reason_{chosen_ev_id}")
                            if st.button("🚨 Withdraw Evidence", type="secondary", key=f"btn_withdraw_{chosen_ev_id}"):
                                if len(w_reason.strip()) >= 5:
                                    try:
                                        store.withdraw_evidence(chosen_ev_id, current_session["username"], w_reason)
                                        st.success(f"Evidence {chosen_ev_id} withdrawn.")
                                        st.rerun()
                                    except Exception as ex:
                                        st.error(f"Withdrawal failed: {ex}")
                                else:
                                    st.error("Withdrawal reason must be at least 5 characters.")

                    # Audit Trail Viewer
                    st.markdown("###### 📜 State Transition Audit Trail (Append-Only)")
                    hist = store.get_evidence_history(chosen_ev_id)
                    if hist:
                        hist_rows = []
                        for h in hist:
                            hist_rows.append({
                                "Timestamp (UTC)": h["timestamp_utc"],
                                "Actor": h["operator_username"],
                                "From Status": h["from_status"].upper(),
                                "To Status": h["to_status"].upper(),
                                "Reason": h["transition_reason"],
                            })
                        st.dataframe(hist_rows, use_container_width=True)

        # -----------------------------------------------------------------
        # SECTION C: MODEL VERSION REGISTRY & ROLLBACK
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

                # Shadow diagnostics telemetry and operator controls
                try:
                    from src.shadow_controller import ShadowMonitorController
                    smc = ShadowMonitorController(registry=registry)
                    smc_status = smc.get_shadow_load_status()
                    smc_counts = smc.get_aggregate_prediction_counts()

                    st.markdown("##### 🩺 Shadow Diagnostics Telemetry & Controls")
                    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
                    col_m1.metric("Shadow Status", smc_status.get("status_label", "UNKNOWN"))
                    col_m2.metric("Total Inferences", smc_counts.get("total_evaluations", 0))
                    col_m3.metric("Rule/Model Agreements", smc_counts.get("agreements", 0))
                    col_m4.metric("Disagreements", smc_counts.get("disagreements", 0))

                    col_t1, col_t2 = st.columns([2, 1])
                    with col_t1:
                        st.caption(
                            "Disabling shadow inference switches the engine to rules_only mode. "
                            "Authoritative deterministic scoring remains 100% functional."
                        )
                    with col_t2:
                        if active_cfg.get("operating_mode") == "shadow":
                            if st.button("⏹️ Disable Shadow Diagnostics", type="secondary", key="btn_disable_shadow"):
                                smc.disable_shadow_inference(operator_label="operator_local")
                                st.rerun()
                        else:
                            if st.button("▶️ Enable Shadow Diagnostics", type="primary", key="btn_enable_shadow"):
                                smc.enable_shadow_inference(operator_label="operator_local")
                                st.rerun()
                except Exception as smc_err:
                    st.caption(f"Telemetry controller notice: {smc_err}")

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

        # ---------------------------------------------------------------------
        # SECTION D: MODEL DISAGREEMENT REVIEW DESK & ANALYTICS (Phase 6.6)
        # ---------------------------------------------------------------------
        with subtab_disagreement:
            st.markdown("#### ⚖️ Model Disagreement Review Desk & Feedback Analytics")
            st.caption(
                "Detects and manages disagreements between deterministic rules and the shadow neural model. "
                "Enables local human adjudication, records comparative assessments, and curates consented training features. "
                "Production threat scoring remains 100% governed by deterministic rules (GR-01)."
            )

            st.warning(
                "🔒 **HITL PRIVACY & GOVERNANCE BOUNDARIES:**\n"
                "- **Zero Raw Text Retention:** The review desk operates strictly on sanitized structural metadata. "
                "Original message text is not retained on disk (GR-08).\n"
                "- **Unauthenticated Operator Attribution:** Review decisions are attributed to `local_operator_unauthenticated`. "
                "Do not interpret reviewer assessments as certified ground truth.\n"
                "- **Zero Automated Production Modification:** Human reviews or candidate pattern approvals NEVER "
                "automatically activate production rules, retrain models, or alter risk scores."
            )

            store: SessionCaseStore = st.session_state.case_store
            disagree_stats = store.get_disagreement_stats()

            # Metric Cards
            col_d1, col_d2, col_d3, col_d4, col_d5 = st.columns(5)
            col_d1.metric("Total Events", disagree_stats.get("total_events", 0))
            col_d2.metric("Disagreements", disagree_stats.get("disagreements_count", 0))
            col_d3.metric("Agreements", disagree_stats.get("agreements_count", 0))
            col_d4.metric("Pending Reviews", disagree_stats.get("pending_reviews", 0))
            col_d5.metric("Completed Reviews", disagree_stats.get("completed_reviews", 0))

            st.markdown("---")
            st.markdown("##### 📥 Disagreement Events & Review Queue")

            # Filters
            col_f1, col_f2 = st.columns(2)
            with col_f1:
                filter_state = st.selectbox(
                    "Filter by Review State:",
                    ["all", "pending", "completed", "insufficient_evidence", "superseded"],
                    key="sel_filter_disagree_state",
                )
            with col_f2:
                filter_type = st.selectbox(
                    "Filter by Event Type:",
                    ["all", "rule_phishing_model_legitimate", "rule_phishing_model_advisory",
                     "rule_legitimate_model_phishing", "rule_legitimate_model_advisory",
                     "rule_advisory_model_phishing", "rule_advisory_model_legitimate",
                     "agreement", "non_comparable"],
                    key="sel_filter_disagree_type",
                )

            req_state = None if filter_state == "all" else filter_state
            req_type = None if filter_type == "all" else filter_type
            disagree_events = store.list_disagreement_events(review_state=req_state, event_type=req_type, limit=50)

            if not disagree_events:
                st.info("No disagreement events matching the selected filters found.")
            else:
                event_table_rows = []
                for ev in disagree_events:
                    event_table_rows.append({
                        "Event ID": ev["event_id"],
                        "Event Type": ev["event_type"],
                        "Rule Decision": f"{ev['rule_decision']} (Score: {ev.get('rule_score', 'N/A')})",
                        "Model Prediction": f"{ev.get('model_prediction', 'None')} ({ev.get('model_confidence_bucket', 'N/A')})",
                        "Model Version": ev.get("model_version", "N/A"),
                        "Length Bucket": ev.get("message_length_bucket", "N/A"),
                        "Consented": "Yes" if ev.get("consent_given") else "No",
                        "Review State": ev["review_state"].upper(),
                    })
                st.dataframe(event_table_rows, use_container_width=True)

                st.markdown("##### ✍️ Disagreement Adjudication Form")
                ev_ids = [e["event_id"] for e in disagree_events]
                chosen_ev_id = st.selectbox("Select Event ID to Review:", ev_ids, key="sel_disagree_ev")

                if chosen_ev_id:
                    chosen_ev = next(e for e in disagree_events if e["event_id"] == chosen_ev_id)
                    existing_rev = store.get_disagreement_review(chosen_ev_id)

                    st.markdown("###### 🔍 Event Metadata & Structural Observations (Zero Raw Content)")
                    ev_c1, ev_c2 = st.columns(2)
                    with ev_c1:
                        st.markdown(f"- **Event ID:** `{chosen_ev['event_id']}`")
                        st.markdown(f"- **Event Type:** `{chosen_ev['event_type']}`")
                        st.markdown(f"- **Rule Decision:** `{chosen_ev['rule_decision']}` (Score: `{chosen_ev.get('rule_score')}`) [{chosen_ev.get('rule_score_bucket')}]")
                        st.markdown(f"- **Model Prediction:** `{chosen_ev.get('model_prediction')}` (Conf: `{chosen_ev.get('model_confidence')}`) [{chosen_ev.get('model_confidence_bucket')}]")
                        st.markdown(f"- **Model Version:** `{chosen_ev.get('model_version')}`")
                    with ev_c2:
                        st.markdown(f"- **Timestamp (UTC):** `{chosen_ev.get('created_at_utc')}`")
                        st.markdown(f"- **Language / Script:** `{chosen_ev.get('language_category')}` / `{chosen_ev.get('script_category')}`")
                        st.markdown(f"- **Length Bucket:** `{chosen_ev.get('message_length_bucket')}`")
                        st.markdown(f"- **Current Review State:** `{chosen_ev.get('review_state').upper()}`")
                        st.markdown(f"- **Training Feature Consented:** `{'YES' if chosen_ev.get('consent_given') else 'NO'}`")

                    obs = chosen_ev.get("metadata", {}).get("structural_observations", {})
                    if obs:
                        with st.expander("View Passively Observed Structural Traits", expanded=False):
                            st.json(obs)

                    if existing_rev:
                        st.info(
                            f"📌 **Current Adjudication:** `{existing_rev.get('outcome_label')}` | "
                            f"Assessment: `{existing_rev.get('reviewer_assessment')}` | "
                            f"Confidence: `{existing_rev.get('confidence_rating')}` by `{existing_rev.get('reviewer_label')}`"
                        )

                    with st.form(key=f"form_disagree_review_{chosen_ev_id}"):
                        form_outcome = st.selectbox(
                            "Adjudicated Ground-Truth Classification:",
                            ["phishing", "legitimate", "protective_advisory", "insufficient_evidence"],
                            index=0 if not existing_rev else ["phishing", "legitimate", "protective_advisory", "insufficient_evidence"].index(existing_rev.get("outcome_label", "phishing")),
                            help="Adjudicate the correct classification based on structural evidence.",
                        )
                        form_assessment = st.selectbox(
                            "Operator Comparative Assessment:",
                            ["rules_correct", "model_correct", "both_investigate", "neither_sufficient"],
                            index=0 if not existing_rev else ["rules_correct", "model_correct", "both_investigate", "neither_sufficient"].index(existing_rev.get("reviewer_assessment", "rules_correct")),
                            help="Record which decision system was judged more accurate.",
                        )
                        form_conf = st.radio(
                            "Reviewer Confidence Rating:",
                            ["high", "medium", "low"],
                            index=1 if not existing_rev else ["high", "medium", "low"].index(existing_rev.get("confidence_rating", "medium")),
                            horizontal=True,
                        )
                        form_notes = st.text_area(
                            "Adjudication Rationale / Notes (Max 1000 chars — No PII allowed):",
                            value=existing_rev.get("notes", "") if existing_rev else "",
                            max_chars=1000,
                            placeholder="State objective rationale for this adjudication...",
                        )
                        form_supersede = st.checkbox(
                            "Supersede existing review if already completed",
                            value=bool(existing_rev),
                            help="Check to supersede prior adjudication with an auditable reason.",
                        )
                        form_supersede_reason = st.text_input(
                            "Supersede Justification (Required if superseding):",
                            value="Operator re-adjudication based on updated structural evidence" if existing_rev else "",
                        )

                        submit_disagree_btn = st.form_submit_button("💾 Submit Disagreement Adjudication", type="primary")

                        if submit_disagree_btn:
                            try:
                                rev_res = store.submit_disagreement_review(
                                    event_id=chosen_ev_id,
                                    outcome_label=form_outcome,
                                    reviewer_assessment=form_assessment,
                                    confidence_rating=form_conf,
                                    reviewer_label=current_session["username"] if current_session else "local_operator_unauthenticated",
                                    notes=form_notes,
                                    supersede_existing=form_supersede,
                                    reason=form_supersede_reason,
                                )
                                st.success(f"Review `{rev_res['review_id']}` submitted successfully! State: `{rev_res['review_state']}`.")
                                st.rerun()
                            except Exception as d_err:
                                st.error(f"Review submission failed: {d_err}")

            st.markdown("---")
            st.markdown("##### 📊 Operational Feedback Analytics & Trends")
            try:
                from src.feedback_analytics import FeedbackAnalytics
                analytics = FeedbackAnalytics(repository=store.repository)
                analytics_data = analytics.compute_analytics()

                a_col1, a_col2, a_col3 = st.columns(3)
                with a_col1:
                    st.metric("Agreement Rate", f"{analytics_data['disagreement_metrics']['agreement_rate'] * 100:.1f}%")
                with a_col2:
                    st.metric("Rules Judged Correct", f"{analytics_data['operator_accuracy_assessments']['rules_judged_correct_percentage']}%")
                with a_col3:
                    st.metric("Model Judged Correct", f"{analytics_data['operator_accuracy_assessments']['model_judged_correct_percentage']}%")

                with st.expander("🔬 View Detailed Feedback Analytics & Comparative Accuracy", expanded=False):
                    st.json(analytics_data)

                # Download buttons for reports
                report_md = analytics.generate_markdown_report()
                report_json = json.dumps(analytics_data, indent=2, ensure_ascii=False)

                dl_c1, dl_c2 = st.columns(2)
                with dl_c1:
                    st.download_button(
                        label="📥 Download Analytics Report (Markdown)",
                        data=report_md,
                        file_name="feedback_analytics_report.md",
                        mime="text/markdown",
                        key="dl_analytics_md",
                    )
                with dl_c2:
                    st.download_button(
                        label="📊 Download Analytics Data (JSON)",
                        data=report_json,
                        file_name="feedback_analytics_report.json",
                        mime="application/json",
                        key="dl_analytics_json",
                    )
            except Exception as an_err:
                st.info(f"Feedback analytics preview unavailable: {an_err}")


if __name__ == "__main__":
    main()