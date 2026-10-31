"""
Streamlit UI Component for Unified Evidence Analysis Workspace.
Seva Cyber Sandbox — Phase 7.1.0

Provides the central single-screen interface for submitting and analyzing
heterogeneous cybersecurity evidence: messages, URLs, APKs, PDFs, images, and text.
"""

import io
import os
from typing import Any, Dict, List, Optional
import streamlit as st

from src.case_manager import SessionCaseStore
from src.unified_analyzer import (
    EvidenceType,
    ProcessingStatus,
    UnifiedEvidenceAnalyzer,
    compute_sha256,
    detect_evidence_type,
)


def get_type_icon(etype: str) -> str:
    """Returns a visual emoji icon for an evidence type."""
    mapping = {
        EvidenceType.MESSAGE: "💬",
        EvidenceType.URL: "🌐",
        EvidenceType.APK: "🤖",
        EvidenceType.DOCUMENT_PDF: "📄",
        EvidenceType.IMAGE: "🖼️",
        EvidenceType.TEXT_FILE: "📝",
        EvidenceType.UNSUPPORTED: "📦",
    }
    return mapping.get(etype, "📎")


def render_unified_evidence_workspace(
    case_store: SessionCaseStore,
    session_id: str,
    enable_audio: bool = False,
    show_ml_panel: bool = True,
    operator_username: Optional[str] = None,
) -> None:
    """
    Renders the unified evidence submission form, file inventory,
    analysis progress, consolidated findings, cross-evidence correlations,
    per-artifact expandable reports, and case saving controls.
    """
    st.markdown(
        "<div class='bento-card-label'>01 // UNIFIED EVIDENCE ANALYSIS WORKSPACE</div>",
        unsafe_allow_html=True,
    )
    st.subheader("Central Multi-Artifact Cyber Investigation & Evidence Correlation")
    st.caption(
        "Submit suspicious messages, phishing URLs, Android APK files, and supporting documents "
        "(PDF, screenshots, text) together. Seva executes isolated local security analysis, "
        "correlates cross-artifact findings, and generates a consolidated investigation report."
    )

    # -------------------------------------------------------------------------
    # EVIDENCE INTAKE FORM (ALL ON ONE SCREEN)
    # -------------------------------------------------------------------------
    col_msg, col_url = st.columns(2)

    with col_msg:
        st.markdown("##### 💬 1. Message or Communication Text")
        message_input = st.text_area(
            "Suspicious Message Text (WhatsApp, SMS, Email, etc.)",
            height=140,
            placeholder=(
                "Paste suspicious communication here...\n"
                "Supports Marathi (देवनागरी), Romanized Marathi, English, or mixed."
            ),
            help="Raw message text is analyzed locally with privacy redaction for Aadhaar and phone numbers.",
            key="unified_msg_input",
        )

    with col_url:
        st.markdown("##### 🌐 2. Suspicious Target URLs")
        urls_input = st.text_area(
            "URLs or Web Domains (One per line)",
            height=140,
            placeholder=(
                "https://ladkibahin-portal.cc/apply\n"
                "http://msedcl-bill-update.xyz/login\n"
                "http://192.168.1.50/pay.apk"
            ),
            help="URLs are parsed statically without establishing network connections.",
            key="unified_urls_input",
        )

    st.markdown("##### 📎 3. Supporting Evidence Files (APKs, PDFs, Screenshots, Text)")
    uploaded_files = st.file_uploader(
        "Attach Files for Investigation (Max 10 files, 15 MB per file)",
        type=["apk", "pdf", "png", "jpg", "jpeg", "webp", "txt", "log", "csv"],
        accept_multiple_files=True,
        help="Files are inspected locally in memory. Zero external APIs or cloud storage.",
        key="unified_file_uploader",
    )

    # Staged Files Inventory & User Overrides
    staged_files: List[Dict[str, Any]] = []
    if uploaded_files:
        st.markdown("###### 📋 Staged Artifacts Inventory")
        for idx, uf in enumerate(uploaded_files):
            file_bytes = uf.getvalue()
            f_size_kb = len(file_bytes) / 1024
            f_sha = compute_sha256(file_bytes)
            det_type, det_method, _ = detect_evidence_type(file_bytes, uf.name)

            c_inv1, c_inv2, c_inv3, c_inv4 = st.columns([3, 2, 2, 1])
            with c_inv1:
                icon = get_type_icon(det_type)
                st.write(f"{icon} **{uf.name}** ({f_size_kb:.1f} KB)")
                st.caption(f"`SHA-256: {f_sha[:16]}...`")
            with c_inv2:
                type_options = [
                    EvidenceType.APK,
                    EvidenceType.DOCUMENT_PDF,
                    EvidenceType.IMAGE,
                    EvidenceType.TEXT_FILE,
                    EvidenceType.UNSUPPORTED,
                ]
                selected_type = st.selectbox(
                    f"Type for #{idx+1}",
                    options=type_options,
                    index=type_options.index(det_type) if det_type in type_options else 4,
                    key=f"type_override_{idx}_{uf.name}",
                    label_visibility="collapsed",
                )
            with c_inv3:
                st.caption(f"Detected via `{det_method}`")
            with c_inv4:
                include_file = st.checkbox(
                    "Include",
                    value=True,
                    key=f"inc_file_{idx}_{uf.name}",
                    help="Uncheck to exclude this attachment from analysis.",
                )

            if include_file:
                staged_files.append({
                    "filename": uf.name,
                    "content": file_bytes,
                    "user_override_type": selected_type,
                })

    # Submission Controls & Governance Consent
    st.markdown("---")
    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([2, 2, 2])
    with ctrl_col1:
        enable_shadow = st.checkbox(
            "Enable Shadow Neural Classifier (custom-mlp-v4.0.0-seed42)",
            value=True,
            help="Executes custom neural model in shadow mode for telemetry without affecting production scores.",
        )
    with ctrl_col2:
        training_consent = st.checkbox(
            "Citizen Consent: Allow PII-Sanitized Feature Staging",
            value=False,
            help="If checked, abstract derived feature records may be staged for operator review and training gating.",
        )
    with ctrl_col3:
        submit_clicked = st.button(
            "🔍 ANALYZE ALL SUBMITTED EVIDENCE",
            type="primary",
            use_container_width=True,
        )

    # -------------------------------------------------------------------------
    # ANALYSIS EXECUTION
    # -------------------------------------------------------------------------
    if submit_clicked:
        parsed_urls = [u.strip() for u in urls_input.splitlines() if u.strip()] if urls_input else []
        has_message = bool(message_input and message_input.strip())
        has_urls = bool(parsed_urls)
        has_files = bool(staged_files)

        if not has_message and not has_urls and not has_files:
            st.warning("⚠️ Please provide at least one piece of evidence (message text, URL, or file attachment).")
            return

        with st.spinner("Executing isolated local analysis across all submitted evidence artifacts..."):
            analyzer = UnifiedEvidenceAnalyzer(case_repository=case_store.repository)
            result = analyzer.analyze_submission(
                message_text=message_input if has_message else None,
                urls=parsed_urls if has_urls else None,
                files=staged_files if has_files else None,
                enable_shadow_ai=enable_shadow,
                training_consent_opt_in=training_consent,
                operator_username=operator_username or "local_investigator",
            )
            st.session_state["unified_last_analysis"] = result
            st.session_state["unified_saved_investigation"] = None

    # -------------------------------------------------------------------------
    # DISPLAY CONSOLIDATED INVESTIGATION REPORT
    # -------------------------------------------------------------------------
    analysis_res = st.session_state.get("unified_last_analysis")
    if analysis_res:
        st.markdown("---")
        inv_id = analysis_res["investigation_id"]
        stats = analysis_res["summary_stats"]
        verdict = analysis_res["overall_verdict"]
        score = verdict["score"]
        v_category = verdict["risk_category"]
        v_color = verdict["badge_color"]

        # 1. High-Level Investigation Banner
        st.markdown(
            f"""
            <div style="background-color:var(--bg-secondary); border-left: 6px solid {v_color};
                        padding: 16px 20px; border-radius: 8px; margin-bottom: 20px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span style="font-family:monospace; font-weight:700; color:var(--text-secondary);">
                            INVESTIGATION: {inv_id}
                        </span>
                        <h2 style="margin: 4px 0 6px 0; color:var(--text-primary);">
                            {v_category.upper()} (Risk Index: {score} / 100)
                        </h2>
                    </div>
                    <div style="text-align:right;">
                        <span style="background-color:{v_color}; color:white; padding:6px 14px;
                                     border-radius:20px; font-weight:700; font-size:0.9rem;">
                            AUTHORITATIVE VERDICT: {v_category}
                        </span>
                    </div>
                </div>
                <div style="font-size:0.9rem; color:var(--text-secondary); margin-top:8px;">
                    Intake Timestamp: {analysis_res['created_at_utc']} | Driving Artifact: <code>{verdict.get('driving_artifact_id') or 'Composite Rules'}</code>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # 2. Metric Columns
        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
        m_col1.metric("Submitted Artifacts", stats["total_artifacts"])
        m_col2.metric("Successfully Analyzed", stats["completed_count"])
        m_col3.metric("Unsupported Artifacts", stats["unsupported_count"])
        m_col4.metric("Cross-Correlations", len(analysis_res.get("correlations", [])))

        # 3. Key Observations & Summary
        st.markdown("#### 🔍 Overall Investigation Summary")
        for obs in verdict.get("key_observations", []):
            st.markdown(f"- {obs}")

        # 4. Cross-Evidence Correlation Findings (Part 5)
        corrs = analysis_res.get("correlations", [])
        if corrs:
            st.markdown("#### ⚡ Cross-Evidence Relationships & Threat Linkages")
            st.caption(
                "Automated structural cross-referencing connects domains, hashes, and tokens across artifacts. "
                "Note: Cross-correlation does not prove identical fraud campaign attribution without corroboration."
            )
            for c in corrs:
                c_icon = "🚨" if c["confidence"] == "HIGH" else "⚠️"
                with st.expander(f"{c_icon} [{c['correlation_type']}] {c['headline_en']}", expanded=True):
                    st.write(f"**English Details:** {c['detail_en']}")
                    st.write(f"**मराठी स्पष्टीकरण:** {c['detail_mr']}")
                    st.markdown(f"- **Source Artifact:** `{c['source_artifact_id']}`")
                    st.markdown(f"- **Target Artifact:** `{c['target_artifact_id']}`")
                    st.markdown(f"- **Confidence Assessment:** `{c['confidence']}`")
                    st.caption(f"🛡️ *Safeguard Note: {c['limitations_note']}*")
        else:
            st.info("ℹ️ No cross-artifact shared domains, package tokens, or known threat intel matches detected.")

        # 5. Per-Artifact Expandable Deep-Dives (Part 6.C)
        st.markdown("#### 📦 Per-Artifact Evidence Deep-Dive")
        for art in analysis_res.get("artifacts", []):
            art_id = art["artifact_id"]
            atype = art["artifact_type"]
            target = art["target_identifier"]
            status = art["status"]
            a_score = art.get("risk_score", 0)
            a_cat = art.get("risk_category", "Unknown")
            icon = get_type_icon(atype)

            status_label = f"[{status.upper()}]"
            title = f"{icon} {art_id} — {atype.upper()}: '{target}' | Score: {a_score}/100 ({a_cat}) {status_label}"

            with st.expander(title, expanded=(a_score >= 60)):
                st.caption(f"Cryptographic SHA-256 Digest: `{art.get('artifact_sha256')}`")
                if art.get("error"):
                    st.error(f"⚠️ Processing Observation: {art['error']}")

                # Detail views by type
                res = art.get("analysis_result", {})

                # Message Deep-Dive
                if atype in (EvidenceType.MESSAGE, EvidenceType.TEXT_FILE) and status == ProcessingStatus.COMPLETED:
                    st.markdown(f"**Detected Script:** `{res.get('script_detected', 'N/A')}`")
                    scored = art.get("scored_result", {})
                    if scored:
                        st.write(f"**Summary (EN):** {scored.get('summary_en', 'N/A')}")
                        st.write(f"**Summary (MR):** {scored.get('summary_mr', 'N/A')}")
                    if res.get("findings"):
                        st.markdown("**Matched Threat Indicators:**")
                        st.table([
                            {
                                "Category": f["category"],
                                "Severity": f["severity"],
                                "Matched Text": f["matched_text"],
                                "Why It Matters": f["why_it_matters_en"],
                            }
                            for f in res["findings"]
                        ])
                    if res.get("extracted_urls"):
                        st.markdown("**Extracted Web Links:**")
                        for u in res["extracted_urls"]:
                            st.markdown(f"- `{u}`")

                # URL Deep-Dive
                elif atype == EvidenceType.URL and status == ProcessingStatus.COMPLETED:
                    st.write(f"**Analyzed URL:** `{res.get('url')}`")
                    st.write(f"**Summary (EN):** {res.get('summary_en')}")
                    st.write(f"**Summary (MR):** {res.get('summary_mr')}")
                    obs = res.get("observable_characteristics", {})
                    st.markdown("**Structural Checks:**")
                    c1, c2, c3 = st.columns(3)
                    c1.write(f"- Official Allowlisted: `{obs.get('is_official_allowlisted')}`")
                    c2.write(f"- IP Host: `{obs.get('is_ip_address')}`")
                    c3.write(f"- Homoglyph/Punycode: `{obs.get('is_punycode_or_homoglyph')}`")
                    if res.get("evidence"):
                        st.markdown("**Forensic Evidence:**")
                        for ev in res["evidence"]:
                            st.markdown(f"- {ev}")

                # APK Deep-Dive
                elif atype == EvidenceType.APK and status == ProcessingStatus.COMPLETED:
                    st.write(f"**Package Name:** `{res.get('package_name', 'Unknown')}`")
                    st.write(f"**File Size:** `{res.get('file_size_bytes', 0):,} bytes`")
                    st.write(f"**Manifest Format:** `{res.get('manifest_format')}` | **DEX Format:** `{res.get('dex_format')}`")
                    perms = res.get("permissions_found", [])
                    st.write(f"**Declared Permissions ({len(perms)}):**")
                    if perms:
                        st.table([
                            {"Permission": p["permission"], "Severity": p["severity"], "Family": p["family"]}
                            for p in perms
                        ])
                    if res.get("heuristic_warnings"):
                        st.markdown("**Heuristic Warnings:**")
                        for hw in res["heuristic_warnings"]:
                            st.markdown(f"- ⚠️ {hw}")
                    if res.get("passive_urls"):
                        st.markdown("**Passive URLs in Manifest/Strings:**")
                        for pu in res["passive_urls"]:
                            st.markdown(f"- `{pu}`")

                # PDF Document Deep-Dive
                elif atype == EvidenceType.DOCUMENT_PDF and status == ProcessingStatus.COMPLETED:
                    st.write(f"**Page Count:** `{res.get('page_count', 0)}`")
                    if res.get("extracted_urls"):
                        st.markdown("**Hyperlinks Found Inside PDF:**")
                        for pu in res["extracted_urls"]:
                            st.markdown(f"- `{pu}`")
                    pdf_txt = res.get("extracted_text", "")
                    if pdf_txt:
                        st.markdown(f"**Extracted Text Sample ({len(pdf_txt)} chars):**")
                        st.text_area("PDF Text", pdf_txt[:2000], height=100, disabled=True, key=f"pdf_txt_{art_id}")
                    if art.get("text_rule_analysis") and art["text_rule_analysis"].get("findings"):
                        st.markdown("**Threat Indicators Detected in PDF Content:**")
                        for f in art["text_rule_analysis"]["findings"]:
                            st.markdown(f"- ⚠️ [{f['category']}] {f['why_it_matters_en']}")

                # Image Deep-Dive
                elif atype == EvidenceType.IMAGE:
                    c_im1, c_im2, c_im3 = st.columns(3)
                    c_im1.write(f"- Format: `{res.get('format')}`")
                    c_im2.write(f"- Dimensions: `{res.get('dimensions')}`")
                    c_im3.write(f"- Color Mode: `{res.get('color_mode')}`")
                    st.info(f"ℹ️ **OCR Status:** `{res.get('ocr_status')}`\n\n{res.get('ocr_explanation')}")

                # Unsupported Deep-Dive
                elif atype == EvidenceType.UNSUPPORTED:
                    st.warning(f"⚠️ {art.get('error')}")

        # 6. AI & Rule-Engine Comparison (Part 6.D)
        shadow_eval = None
        for a in analysis_res.get("artifacts", []):
            if a.get("shadow_eval") and isinstance(a["shadow_eval"], dict) and "final_decision" in a["shadow_eval"]:
                shadow_eval = a["shadow_eval"]
                break

        if shadow_eval and show_ml_panel:
            with st.expander("🛡️ AI & Rule-Engine Shadow Comparison", expanded=False):
                c_s1, c_s2, c_s3 = st.columns(3)
                c_s1.metric("Engine Mode", shadow_eval.get("operating_mode", "shadow").upper())
                c_s2.metric("Deterministic Rule Verdict", shadow_eval.get("rule_based_evidence", {}).get("rule_label", "Unknown"))
                conc = shadow_eval.get("concordance", {}).get("status", "UNKNOWN")
                c_s3.metric(
                    "Concordance",
                    conc,
                    delta="Agreed" if conc == "AGREEMENT" else ("Disagreed" if conc == "DISAGREEMENT" else "N/A"),
                )
                exp_m = shadow_eval.get("experimental_model", {})
                if exp_m.get("is_available"):
                    st.write(
                        f"- **Active Shadow Model (`custom-mlp-v4.0.0-seed42`):** `{exp_m.get('predicted_label')}` "
                        f"(Confidence: `{exp_m.get('confidence', 0.0):.2%}`)"
                    )
                else:
                    st.write(f"- **Active Shadow Model:** Unavailable ({exp_m.get('fallback_reason', 'N/A')})")
                st.caption(
                    "⚠️ *Governance Invariant: The custom neural classifier executes purely in shadow mode. "
                    "The authoritative score difference between rule and model is strictly 0.00.*"
                )

        # 7. Save Investigation Action (Part 7)
        st.markdown("---")
        saved_status = st.session_state.get("unified_saved_investigation")
        if saved_status:
            st.success(
                f"✅ **Investigation Saved Successfully!**\n\n"
                f"- Parent Investigation Case ID: `{saved_status['parent_case_id']}`\n"
                f"- Linked Artifact Cases ({len(saved_status['child_case_ids'])}): "
                f"`{', '.join(saved_status['child_case_ids'])}`\n\n"
                f"Inspect complete forensic records in **05 // THREAT CASES** or review queues in **07 // OPERATOR DESK**."
            )
        else:
            save_col1, save_col2 = st.columns([3, 1])
            with save_col1:
                st.write("Save this investigation and link all submitted artifacts into persistent SQLite cases.")
            with save_col2:
                if st.button("💾 SAVE INVESTIGATION", type="secondary", use_container_width=True):
                    analyzer = UnifiedEvidenceAnalyzer(case_repository=case_store.repository)
                    saved = analyzer.save_investigation_cases(
                        case_store=case_store,
                        analysis_result=analysis_res,
                        submitted_by=operator_username or "local_investigator",
                        consent_given=training_consent,
                    )
                    st.session_state["unified_saved_investigation"] = saved
                    st.rerun()
