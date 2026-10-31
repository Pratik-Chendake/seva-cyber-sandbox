# PHASE 1 — COMPLETE REPOSITORY AUDIT & STREAMLIT MIGRATION INVENTORY

**Project:** Seva Cyber Sandbox  
**Target Milestone:** Full Migration from Streamlit to React 19 + FastAPI + Supabase + Cloudflare R2  
**Date:** 2026-10-31  
**Database Backup:** `instance/backups/seva_cases_pre_streamlit_migration.sqlite3`  
**Database SHA-256:** `2a95edf9b5719f50406807b4aacee6fbdd3cd80c8734bfbae49586803a2029eb`  
**Git Checkpoint Branch:** `checkpoint/pre-streamlit-removal`  

---

## 1. REPOSITORY INVENTORY & STREAMLIT DEPENDENCY AUDIT

### 1.1. Streamlit Code Locations (To Be Removed / Replaced)
| File | Role | Action Required |
|:---|:---|:---|
| `app.py` | Monolithic Streamlit application UI (1944 lines) | **Decommission & delete** after verifying all UI features exist in React. |
| `src/unified_workspace_ui.py` | Streamlit multi-artifact intake component (446 lines) | **Decommission & delete**; UI already reimplemented in React. |
| `src/ui_theme.py` | Streamlit CSS theme injector (`st.markdown`) | **Decommission & delete**; styled via Tailwind CSS v4 Liquid Glass in React. |
| `.streamlit/config.toml` | Streamlit server & port configuration | **Delete**. |
| `requirements.txt` | Contains `streamlit>=1.38.0` | **Remove `streamlit`** from requirements. |
| `tests/test_phase7_1_1_interactive_acceptance.py` | AppTest-based Streamlit DOM tests (23 tests) | **Retire & replace** with comprehensive FastAPI + REST acceptance tests. |
| `run_all.py` | Launcher referencing Streamlit mode | **Update** to pure FastAPI / Vite launcher. |

### 1.2. Reusable Core Python Services (Retained Unchanged)
| Module | Core Cyber Capability | Status |
|:---|:---|:---:|
| `src/phishing_detector.py` | Devanagari Unicode homoglyph analysis, Marathi NLP, SMS heuristics | **Retained 100% Unchanged** |
| `src/apk_analyzer.py` | Safe in-memory binary manifest unpacking, dangerous permissions, DEX checks | **Retained 100% Unchanged** |
| `src/url_analyzer.py` | Air-gapped static URL radar, lookalike domains, TLD abuse scoring | **Retained 100% Unchanged** |
| `src/scheme_verifier.py` | Official Maharashtra GR registry verification (Ladki Bahin, MSEDCL, PM Kisan) | **Retained 100% Unchanged** |
| `src/risk_scorer.py` | Deterministic heuristic risk aggregator (0-100 scale, bilingual summaries) | **Retained 100% Unchanged** |
| `src/privacy_gate.py` | Deterministic in-memory Verhoeff Aadhaar & phone PII scrubber | **Retained 100% Unchanged** |
| `src/unified_analyzer.py` | Multi-artifact intake orchestrator & cross-artifact correlation engine | **Retained 100% Unchanged** |
| `src/case_manager.py` | Case serialization, session stores, markdown report generation, review desk | **Retained 100% Unchanged** |
| `src/case_repository.py` | SQLite schema v2, campaign clustering, indicators, audit trail | **Enhanced for Supabase PG** |
| `src/model_registry.py` | Model versioning, active model configuration, shadow mode telemetry | **Retained 100% Unchanged** |
| `src/ml_classifier.py` | NumPy 3-layer scratch MLP (`custom-mlp-v4.0.0-seed42`) | **Retained 100% Unchanged** |
| `src/candidate_trainer.py` | 8-point training gate (`BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE`) | **Retained 100% Unchanged** |
| `src/feedback_collector.py` | Two-person rule, dispute management, human corroboration | **Retained 100% Unchanged** |
| `src/audio_alert.py` | Local Windows SAPI voice synthesizer & WAV generator | **Docstring cleaned** |

---

## 2. FUNCTIONALITY MIGRATION MATRIX

| Capability | Old Streamlit Mechanism | New Architecture Mechanism |
|:---|:---|:---|
| **Frontend Framework** | Streamlit Python server-side widgets | React 19 + Vite 8 + TypeScript + Tailwind CSS v4 |
| **Visual Identity** | Static injected CSS rules in `src/ui_theme.py` | Liquid Glass design system (`frontend/src/index.css`) |
| **3D Interactivity** | None (HTML embeds / static images) | Real Three.js WebGL procedural scenes with 2D fallbacks |
| **Backend API** | Internal Python function calls inside Streamlit | FastAPI REST API (`api_server.py`) |
| **Session State** | `st.session_state` dict (ephemeral server-side) | Client-side React state + REST session headers |
| **Structured Database** | SQLite file `instance/seva_cases.sqlite3` | Dual Support: SQLite (local dev) + Supabase PostgreSQL (prod) |
| **Evidence & File Storage** | Local filesystem (`instance/uploads/`) | Cloudflare R2 / S3-compatible private bucket with local fallback |
| **Authentication** | Streamlit sidebar forms with scrypt verification | REST API `/api/auth/login` with JWT / secure session tokens |
| **Hosting & Deployment** | Streamlit Community Cloud (`streamlit run`) | Vercel (Frontend) + Render (Backend Web Service) |

---

## 3. DATABASE INSPECTION & INTEGRITY AUDIT

### 3.1. Tables & Schema Verification
Inspected `instance/seva_cases.sqlite3`:
- `threat_cases`: Primary case records table.
- `evidence_provenance`: Provenance metadata, corroboration states, and consent tracking.
- `campaign_clusters`: Deduplicated threat cluster keys (domain, package, phone, campaign).
- `threat_indicators`: Extracted indicators with confidence ratings, severity, and review states.
- `operator_users`: Local operator credentials encrypted with OWASP scrypt.
- `human_reviews`: Independent corroboration and review desk logs.
- `lifecycle_audit_log`: Cryptographic event audit trail for state-machine transitions.

**Row Counts:** All operational and provenance tables are verified pristine. No synthetic or test data was leaked into production storage.
