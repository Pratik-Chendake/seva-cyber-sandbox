# SEVA CYBER SANDBOX — FRONTEND COMPONENT MAP

This document provides an exhaustive, line-by-line architectural mapping between the extracted standalone HTML/CSS/JS frontend in `frontend_handoff/` and the underlying Python Streamlit application (`app.py`), backend security modules (`src/`), and persistent SQLite schemas.

---

## 1. Global Shell & Layout Hierarchy

| Frontend Element | HTML Selector / ID | Streamlit Source (`app.py`) | Backend Function / Module | State & Session Dependencies |
| :--- | :--- | :--- | :--- | :--- |
| **Theme & Tokens** | `:root` in `styles.css` | `app.py:59` (`inject_custom_theme()`) | `src/ui_theme.py:28` (`THEME_CSS`) | None (Stateless CSS injection) |
| **Branding Topbar** | `.editorial-topbar` | `app.py:64` (`render_editorial_header()`) | `src/ui_theme.py:568` | `st.session_state.case_store.count()` |
| **Hero Statement** | `.editorial-hero` | `app.py:64` (`render_editorial_header()`) | `src/ui_theme.py:585` | None (Static editorial copy) |
| **Bento Overview** | `.bento-grid-4` (top) | `app.py:68` (`render_bento_overview()`) | `src/ui_theme.py:601` | Dynamic case count from SQLite |
| **Operational Notice** | `.alert-warning` | `app.py:73` (`st.warning()`) | Standard Streamlit Alert | None |
| **3D Radar Viewport** | `#threejs-threat-canvas` | Ready for `st.components.v1.html` | Interactive WebGL / Canvas Drop-in | Active cases spatial distribution |
| **Sidebar Drawer** | `.sidebar` | `app.py:207-252` (`with st.sidebar:`) | `pyttsx3`, `src/case_manager.py` | Audio flags & SQLite DB path |

---

## 2. Tab-by-Tab Functional Component Mapping

### Tab 01 // MESSAGE INTEL (`#tab-01`)
*Streamlit Anchor: `app.py:269-486` (`with tab_phishing:`)*

| UI Component | HTML Element ID | Streamlit Widget / Code | Backend Function | Output / Response Payload |
| :--- | :--- | :--- | :--- | :--- |
| **Sample Selector** | `#msg-sample-select` | `st.selectbox()` (`app.py:281`) | `load_sample_messages()` (`src/phishing_detector.py`) | Pre-populates textarea with Devanagari/Latn text |
| **Message Input** | `#msg-textarea-input` | `st.text_area()` (`app.py:292`) | User input text | Raw text passed to analyzer |
| **Opt-in Feature Capture** | `#msg-optin-checkbox` | `st.checkbox()` (`app.py:299`) | `capture_training_features()` (`src/case_manager.py`) | Flags anonymous 1024-dim n-gram feature extraction |
| **Analyze Button** | `#msg-analyze-btn` | `st.button()` (`app.py:311`) | `analyze_message_text()` (`src/phishing_detector.py`) | Triggers full analysis pipeline |
| **Threat Banner** | `.threat-banner-red/green` | `render_threat_banner()` (`app.py:94`) | `score_message_analysis()` (`src/risk_scorer.py`) | Risk Level, Score (0-100), Badge Color |
| **Bilingual Bento** | `.bento-grid-2` | `render_risk_assessment_panel()` (`app.py:97`) | `src/risk_scorer.py` | `summary_en`, `summary_mr` |
| **Hybrid Diagnostics** | `.expander` (Hybrid Engine) | `evaluate_message_hybrid()` (`app.py:358`) | `src/hybrid_decision_engine.py` | Operating mode, rule score, concordance, neural prediction |
| **Warning Indicators Table**| `table` in `#msg-results-container` | `st.table()` (`app.py:392`) | `msg_res["findings"]` | Severity, Matched Substring, Bilingual Explanations |
| **Extracted URLs** | `.expander` (URLs) | `analyze_url()` (`app.py:408`) | `src/url_analyzer.py` | Passive risk level, domain allowlist check |
| **Webhook Simulator** | `.expander` (Webhook) | `load_whatsapp_config()` (`app.py:433`) | `src/whatsapp_webhook.py` | Local simulation endpoint `http://localhost:8000/webhook` |

---

### Tab 02 // APK INSPECTION (`#tab-02`)
*Streamlit Anchor: `app.py:488-608` (`with tab_apk:`)*

| UI Component | HTML Element ID | Streamlit Widget / Code | Backend Function | Output / Response Payload |
| :--- | :--- | :--- | :--- | :--- |
| **APK Source Selector** | Radio `name="apk_mode"` | `st.radio()` (`app.py:495`) | Internal selector | Pre-generated samples vs `st.file_uploader` |
| **Sample APK Select** | `#apk-file-select` | `st.selectbox()` (`app.py:512`) | `ensure_sample_apks_exist()` | Reads binary bytes from `sample_apks/` |
| **Inspect Button** | `#apk-analyze-btn` | `st.button()` (`app.py:528`) | `analyze_apk_bytes()` (`src/apk_analyzer.py`) | Triggers structural AXML disassembly |
| **Metadata Metrics** | `.metric-tile` (Package, Format) | `st.metric()` (`app.py:556-558`) | `apk_res["package_name"]`, `manifest_format` | Binary AXML `0x80003`, Dalvik bytecode check |
| **Telemetry Monospace** | `pre` in `#apk-results-container` | `st.code()` (`app.py:560`) | Static hash & signature engine | SHA-256 hash, DEX format, fixture flag |
| **Permissions Table** | `table` in `#apk-results-container` | `st.table()` (`app.py:571`) | `apk_res["permissions_found"]` | Capability family, severity, weight, bilingual reasons |
| **Passive URLs Expander** | `.expander` (Passive URLs) | `st.expander()` (`app.py:589`) | `apk_res["passive_urls"]` | Inert strings from DEX string pool |

---

### Tab 03 // URL RADAR (`#tab-03`)
*Streamlit Anchor: `app.py:610-752` (`with tab_url:`)*

| UI Component | HTML Element ID | Streamlit Widget / Code | Backend Function | Output / Response Payload |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario Quick-Fill** | `#url-sample-select` | `st.selectbox()` (`app.py:629`) | Preset lookup | Fills input with MSEDCL lookalike, SBI lure, etc. |
| **URL Input Field** | `#url-text-input` | `st.text_input()` (`app.py:651`) | URL parser | Strips protocol, parses domain & port safely |
| **Analyze Button** | `#url-analyze-btn` | `st.button()` (`app.py:659`) | `analyze_url()` (`src/url_analyzer.py`) | Passive syntactic & heuristic evaluation |
| **Threat Assessment Banner**| `.threat-banner-red/green` | `render_threat_banner()` (`app.py:670`) | `src/url_analyzer.py` | Score (0-100), Risk level, Badge color |
| **9-Tile Characteristics** | `.bento-grid-3` in `#url-results` | `st.metric()` x 9 (`app.py:718-733`) | `url_eval["observable_characteristics"]` | Protocol, Hostname, Port, Allowlisted, Shortener, Lookalike, IP, Punycode, APK |
| **Citizen Safe Steps** | `.bento-grid-2` (Steps) | `st.markdown()` (`app.py:741`) | Bilingual guidance | `safe_next_steps_en`, `safe_next_steps_mr` |

---

### Tab 04 // SCHEME VERIFIER (`#tab-04`)
*Streamlit Anchor: `app.py:755-946` (`with tab_scheme:`)*

| UI Component | HTML Element ID | Streamlit Widget / Code | Backend Function | Output / Response Payload |
| :--- | :--- | :--- | :--- | :--- |
| **Claim Textarea** | `#scheme-claim-input` | `st.text_area()` (`app.py:798`) | Scheme claim matcher | Input text describing benefit or welfare promise |
| **Suspicious Link Field** | `#scheme-url-input` | `st.text_input()` (`app.py:806`) | Passive domain check | Evaluates against allowlisted `.gov.in` list |
| **Live Health Toggle** | `#scheme-probe-toggle` | `st.checkbox()` (`app.py:813`) | `probe_official_portal()` | Optional 3.0s bounded latency check for .gov.in |
| **Verify Button** | `#scheme-analyze-btn` | `st.button()` (`app.py:819`) | `verify_scheme_claim()` (`src/scheme_verifier.py`) | Matches official Government Resolutions (GRs) |
| **Official Verdict** | `.alert-box` | `st.success/error()` (`app.py:835`) | Classification engine | `SUPPORTED BY OFFICIAL SOURCE`, `CONFLICTING` |
| **Evidence Breakdown** | `.bento-grid-2` (Supporting vs Conflicting) | Columns (`app.py:880`) | Discrepancy detector | Direct financial or portal contradictions |
| **Official GR Card** | `.bento-card` (GR Details) | `st.container()` (`app.py:910`) | `verification_res["official_sources"]` | GR Number, Publishing Department, Official Portal Link |

---

### Tab 05 // THREAT CASES (`#tab-05`)
*Streamlit Anchor: `app.py:949-1059` (`with tab_cases:`)*

| UI Component | HTML Element ID | Streamlit Widget / Code | Backend Function | Output / Response Payload |
| :--- | :--- | :--- | :--- | :--- |
| **Metric Cards** | `.bento-grid-4` (Cases) | `st.metric()` x 4 (`app.py:967`) | `store.count()`, risk buckets | Total, High-Risk (Red), Warning (Orange), Cleared (Green) |
| **Cases Data Table** | `#cases-table-body` | `st.dataframe()` (`app.py:984`) | `store.export_summary_table_rows()` | Dynamic listing of all session incidents |
| **CSV Export Button** | `button` Download CSV | `st.download_button()` (`app.py:990`) | `store.export_csv()` | Generates `seva_cyber_cases_summary.csv` |
| **JSON Export Button** | `button` Download JSON | `st.download_button()` (`app.py:999`) | `store.export_json()` | Generates `seva_cyber_cases_registry.json` |
| **Section 65B Console** | `pre` (Evidence Report) | `st.text_area()` (`app.py:1028`) | `generate_evidence_report()` (`src/case_manager.py`) | Formatted technical advisory report with disclaimer |

---

### Tab 06 // EVALUATION & AI (`#tab-06`)
*Streamlit Anchor: `app.py:1063-1193` (`with tab_eval:`)*

| UI Component | HTML Element ID | Streamlit Widget / Code | Backend Function | Output / Response Payload |
| :--- | :--- | :--- | :--- | :--- |
| **Corpus Metrics** | `.bento-grid-4` (Eval) | `st.metric()` x 4 (`app.py:1088`) | `eval_report["dataset_metadata"]` | Benchmark corpus size, campaigns, label split |
| **Rule-Based Metrics** | `.bento-card` (01 // RULES) | Columns (`app.py:1121`) | `eval_report["rule_based_evaluation"]` | Accuracy (100%), Precision, Recall, Specificity, F1 |
| **ML Baseline Metrics** | `.bento-card` (02 // ML) | Columns (`app.py:1133`) | `eval_report["ml_baseline_evaluation"]` | Holdout accuracy (73.3%), false alarm rate on advisories |
| **Concordance Metrics** | `.bento-card` (03 // CONCORDANCE) | Columns (`app.py:1147`) | `eval_report["model_comparison"]` | Agreement rate (73.3%), architectural distinction note |

---

### Tab 07 // OPERATOR DESK (`#tab-07`)
*Streamlit Anchor: `app.py:1197-1644` (`with tab_review:`)*

#### 07A // HUMAN REVIEW DESK (`#subtab-07a`)
- **Review Stats:** Pending, Under Review, Completed, Inconclusive (`store.get_review_stats()`).
- **Adjudication Form:** Outcome (`phishing`, `legitimate`, `protective_advisory`, `insufficient_evidence`), Confidence (`high`, `medium`, `low`), Reviewer Rationale (`store.submit_review()`).
- **Feature Curation Export:** 1024-dimensional privacy-preserving feature vector extraction (`store.export_curated_training_features()`).

#### 07B // MODEL REGISTRY & ROLLBACK (`#subtab-07b`)
- **Active Diagnostic Config:** Current version (`nn_v2_focal_loss`), Operating Mode (`SHADOW`), Last Known-Good (`nn_v1_baseline`).
- **Cryptographic Verification:** SHA-256 checkpoint verification (`registry.verify_checkpoint_integrity()`).
- **Registered Models Catalog:** Catalog table of version IDs, hyperparameters, validation accuracy, and weights hashes.
- **Rollback Control:** Emergency atomic revert to last known-good version (`registry.rollback_model()`).

#### 07C // FRAUD PATTERN DISCOVERY (`#subtab-07c`)
- **Offline Pattern Mining:** Statistical support slider & mining trigger (`store.discover_patterns()`).
- **Candidate Patterns Table:** Candidate ID, Pattern Type, Target Class, Support, Wilson Lower Bound, Lift (`cat_mgr.load_catalog()`).
- **Operator Adjudication:** Review decision (`approved_by_human`, `rejected`, `needs_more_evidence`) with append-only audit trail.
