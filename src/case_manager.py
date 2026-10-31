"""
Threat Case Management & Evidence Export Module for Seva Cyber Sandbox.

PRIVACY & FORENSIC BOUNDARIES:
1. Session-Scoped Storage: Cases are kept strictly in local session memory and are never shared across users.
2. Zero Raw Data Retention by Default: Uploaded APK binaries and raw chat messages are discarded immediately
   after static feature extraction; only structural observations, hashes, and indicators are preserved.
3. Transparent Disclaimers: Exported summaries are explicitly labeled
   "Cybersecurity Analysis Summary — Not an Official Forensic Certification" and make no claims
   of legal admissibility under Section 65B of the Indian Evidence Act.
4. No Automatic External Submission: Never automatically contacts or transmits records to MahaCyber,
   I4C, or helpline 1930; provides verified citizen guidance and official reporting links instead.
"""

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import uuid
from typing import Any, Dict, List, Optional

from src.case_repository import (
    CaseRepository,
    get_default_case_repository,
    sanitize_evidence_text,
    redact_url_credentials,
)

SANDBOX_ENGINE_VERSION = "1.0.0"


def generate_case_id(prefix: str = "CASE") -> str:
    """Generates an unambiguous, collision-resistant unique Case ID."""
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    short_uuid = uuid.uuid4().hex[:8].upper()
    return f"{prefix}-{now_str}-{short_uuid}"


def get_utc_timestamp_iso() -> str:
    """Returns the current UTC timestamp formatted as an ISO 8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SessionCaseStore:
    """
    Session-isolated case history store backed by secure SQLite persistence.
    Guarantees that one browser session's cases are never exposed to or merged with another,
    while persisting across process restarts and application reloads.
    """

    def __init__(
        self,
        session_id: Optional[str] = None,
        repository: Optional[CaseRepository] = None,
    ):
        self.session_id: str = session_id or uuid.uuid4().hex
        self.repository: CaseRepository = repository or get_default_case_repository()

    @property
    def _cases(self) -> Dict[str, Dict[str, Any]]:
        """Backwards compatibility property returning session cases as a dictionary."""
        return {c["case_id"]: c for c in self.list_cases()}

    def add_case(self, case_record: Dict[str, Any]) -> str:
        """Adds a case record to this session's isolated SQLite store."""
        case_id = case_record.get("case_id") or generate_case_id()
        case_record["case_id"] = case_id
        if "timestamp_utc" not in case_record or not case_record["timestamp_utc"]:
            case_record["timestamp_utc"] = get_utc_timestamp_iso()

        return self.repository.save_case(
            case_record=case_record,
            session_id=self.session_id,
            source_type="web_simulator",
        )

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a specific case belonging to this session by its ID."""
        return self.repository.get_case(case_id, session_id=self.session_id)

    def list_cases(self) -> List[Dict[str, Any]]:
        """Returns all cases in this session sorted by timestamp descending."""
        return self.repository.list_cases(session_id=self.session_id)

    def clear(self) -> None:
        """Clears all records belonging to this session."""
        self.repository.clear_session(session_id=self.session_id)

    def count(self) -> int:
        """Returns the number of cases in this session."""
        return self.repository.count_cases(session_id=self.session_id)

    def summary_table_rows(self) -> List[Dict[str, Any]]:
        return self.export_summary_table_rows()

    def export_summary_table_rows(self) -> List[Dict[str, Any]]:
        """Formats cases for the main dashboard display table matching all required dashboard fields."""
        return self.repository.export_summary_table_rows(session_id=self.session_id)

    def export_json(self) -> str:
        """Exports all session cases as formatted JSON."""
        return self.repository.export_json(session_id=self.session_id)

    def export_csv(self) -> str:
        """Exports all session cases as standard CSV."""
        return self.repository.export_csv(session_id=self.session_id)

    # -------------------------------------------------------------------------
    # Phase 5: Human Review Desk Integration
    # -------------------------------------------------------------------------

    def create_or_get_review(
        self,
        case_id: str,
        reviewer_label: str = "local_operator",
        notes: str = "",
    ) -> Dict[str, Any]:
        """Creates or retrieves a pending review for a session case."""
        return self.repository.create_or_get_review(
            case_id=case_id,
            reviewer_label=reviewer_label,
            notes=notes,
        )

    def submit_review(
        self,
        case_id: str,
        outcome_category: str,
        notes: str = "",
        confidence_rating: str = "medium",
        reviewer_label: str = "local_operator",
    ) -> Dict[str, Any]:
        """Submits an operator review classification for a session case."""
        return self.repository.submit_review(
            case_id=case_id,
            outcome_category=outcome_category,
            notes=notes,
            confidence_rating=confidence_rating,
            reviewer_label=reviewer_label,
        )

    def get_review(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves active review for a session case."""
        return self.repository.get_review_by_case(case_id)

    def list_reviews(
        self,
        review_state: Optional[str] = None,
        outcome_category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Lists reviews filtered by state or outcome."""
        return self.repository.list_reviews(
            review_state=review_state,
            outcome_category=outcome_category,
        )

    def get_review_stats(self) -> Dict[str, Any]:
        """Returns review desk queue statistics."""
        return self.repository.get_review_stats()

    def list_review_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns the most recent review audit log entries."""
        return self.repository.list_review_audit_logs(limit=limit)

    def export_human_reviews_corpus(self) -> str:
        """Exports completed human reviews in privacy-safe JSONL format."""
        records = self.repository.export_human_reviews_corpus()
        return "\n".join(json.dumps(r, ensure_ascii=False) for r in records)

    # -------------------------------------------------------------------------
    # Phase 6.1: Derived Training Features & Curation
    # -------------------------------------------------------------------------

    def capture_training_features(
        self,
        case_id: str,
        message_text: str,
        consent_given: bool = False,
        secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Captures derived 1024-dim neural model features from raw message text if explicit consent is granted.
        Raw text is immediately discarded and never stored.
        """
        if not consent_given:
            return {"captured": False, "reason": "Consent not granted"}

        from src.dataset_preprocessing import extract_derived_training_features

        ok, feat_vec, fingerprint, err = extract_derived_training_features(message_text, secret=secret)
        if not ok or feat_vec is None or fingerprint is None:
            return {"captured": False, "reason": err or "Feature extraction failed"}

        try:
            record = self.repository.record_training_features(
                case_id=case_id,
                feature_vector=feat_vec,
                dedup_fingerprint=fingerprint,
                consent_given=True,
            )
            return {
                "captured": True,
                "feature_record_id": record["feature_record_id"],
                "feature_dim": record["feature_dim"],
            }
        except Exception as exc:
            return {"captured": False, "reason": f"Persistence failed: {str(exc)}"}

    def get_training_features(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves derived feature record for a case."""
        return self.repository.get_training_features_by_case(case_id)

    def revoke_training_consent(
        self,
        case_id: Optional[str] = None,
        feature_record_id: Optional[str] = None,
        reason: str = "user_revoked",
    ) -> int:
        """Revokes training consent for feature records associated with case_id or feature_record_id."""
        return self.repository.revoke_training_consent(
            case_id=case_id,
            feature_record_id=feature_record_id,
            reason=reason,
        )

    def export_curated_training_features(
        self,
        export_path: Optional[str] = None,
        secret: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Exports eligible curated feature records."""
        return self.repository.export_curated_training_features(export_path=export_path, secret=secret)

    def generate_curation_report(
        self,
        secret: Optional[str] = None,
        output_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generates sanitized curation report and data quality check."""
        return self.repository.generate_curation_report(secret=secret, output_path=output_path)

    # -------------------------------------------------------------------------
    # Phase 6.2: Offline Pattern Discovery & Catalogue
    # -------------------------------------------------------------------------

    def discover_patterns(
        self,
        secret: Optional[str] = None,
        min_support: int = 3,
        catalog_manager: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Runs offline pattern discovery over eligible, consented, human-reviewed feature records."""
        from src.pattern_discovery import PatternDiscoveryEngine
        engine = PatternDiscoveryEngine(catalog_manager=catalog_manager)
        return engine.discover_patterns_from_curated_feedback(
            repository=self.repository,
            secret=secret,
            min_support=min_support,
        )

    # -------------------------------------------------------------------------
    # Phase 6.6: Model Disagreement & Human-in-the-Loop Methods
    # -------------------------------------------------------------------------

    def record_disagreement(
        self,
        message_text: str,
        evaluation_result: Dict[str, Any],
        consent_given: bool = False,
        case_id: Optional[str] = None,
        secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Classifies and records a model-rule disagreement event with consent-gated feature capture."""
        from src.disagreement_engine import DisagreementEngine
        engine = DisagreementEngine(repository=self.repository)
        return engine.process_and_record(
            message_text=message_text,
            evaluation_result=evaluation_result,
            consent_given=consent_given,
            case_id=case_id,
            secret=secret,
        )

    def get_disagreement_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a disagreement event by ID."""
        return self.repository.get_disagreement_event(event_id)

    def list_disagreement_events(
        self,
        review_state: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Lists disagreement events."""
        return self.repository.list_disagreement_events(review_state=review_state, event_type=event_type, limit=limit)

    def get_disagreement_stats(self) -> Dict[str, Any]:
        """Returns disagreement event statistics."""
        return self.repository.get_disagreement_stats()

    def submit_disagreement_review(
        self,
        event_id: str,
        outcome_label: str,
        reviewer_assessment: str,
        confidence_rating: str = "medium",
        reviewer_label: str = "local_operator_unauthenticated",
        notes: str = "",
        supersede_existing: bool = False,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Submits an operator adjudication review for a disagreement event."""
        return self.repository.submit_disagreement_review(
            event_id=event_id,
            outcome_label=outcome_label,
            reviewer_assessment=reviewer_assessment,
            confidence_rating=confidence_rating,
            reviewer_label=reviewer_label,
            notes=notes,
            supersede_existing=supersede_existing,
            reason=reason,
        )

    def get_disagreement_review(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves the active review for a disagreement event."""
        return self.repository.get_disagreement_review(event_id)

    def list_disagreement_reviews(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Lists disagreement reviews."""
        return self.repository.list_disagreement_reviews(limit=limit)

    def list_disagreement_audit_logs(self, event_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Lists review audit entries."""
        return self.repository.list_disagreement_audit_logs(event_id=event_id, limit=limit)

    def generate_feedback_analytics(self) -> Dict[str, Any]:
        """Generates comprehensive feedback analytics."""
        from src.feedback_analytics import FeedbackAnalytics
        analytics = FeedbackAnalytics(repository=self.repository)
        return analytics.compute_analytics()


# =============================================================================
# CASE CREATION FACTORIES (Privacy-Preserving Feature Extraction)
# =============================================================================

def create_apk_case(
    apk_res: Dict[str, Any],
    scored_res: Dict[str, Any],
    store_raw_bytes: bool = False,
) -> Dict[str, Any]:
    """
    Creates a case record from an APK analysis dictionary.
    STRICT PRIVACY: Never stores file_bytes by default.
    """
    observed_evidence = list(apk_res.get("confirmed_observations", []))
    for p in apk_res.get("permissions_found", []):
        observed_evidence.append(
            f"Declared Permission: {p['permission']} ({p['severity']} severity, family: {p['family']})"
        )

    heuristic_inferences = list(apk_res.get("heuristic_warnings", []))
    heuristic_inferences.append(
        f"Capability Family Scoring applied. Calculated index: {scored_res.get('score', 0)}/100."
    )

    next_steps = scored_res.get("safe_next_steps_en", [])
    rec_action = next_steps[0] if next_steps else "Delete unverified APK from Downloads"

    case_record = {
        "case_id": generate_case_id("CASE-APK"),
        "timestamp_utc": get_utc_timestamp_iso(),
        "analysis_type": "Android .APK Static Security Inspection",
        "analysis_status": "Completed" if apk_res.get("is_valid_apk") else "Corrupted/Unreadable",
        "risk_score": scored_res.get("score", 0),
        "risk_category": scored_res.get("risk_level", "Unknown"),
        "badge_color": scored_res.get("badge_color", "gray"),
        "indicator_count": len(apk_res.get("permissions_found", [])) + len(apk_res.get("heuristic_warnings", [])),
        "sha256_hash": apk_res.get("sha256_hash") or "N/A",
        "hash_algorithm": "SHA-256" if apk_res.get("sha256_hash") else None,
        "extracted_urls": apk_res.get("passive_urls", []),
        "observed_evidence": observed_evidence,
        "heuristic_inferences": heuristic_inferences,
        "official_sources": [],
        "source_url": None,
        "target_identifier": apk_res.get("filename", "uploaded.apk"),
        "package_name": apk_res.get("package_name", "Unknown"),
        "manifest_format": apk_res.get("manifest_format", "Unknown"),
        "dex_format": apk_res.get("dex_format", "Unknown"),
        "file_size_bytes": apk_res.get("file_size_bytes", 0),
        "recommended_action": rec_action,
        "raw_data_stored": store_raw_bytes,
        "limitations": scored_res.get("limitations", "Static permission analysis does not inspect runtime bytecode execution."),
    }
    return case_record


def create_message_case(
    msg_res: Dict[str, Any],
    scored_res: Dict[str, Any],
    store_raw_text: bool = False,
) -> Dict[str, Any]:
    """
    Creates a case record from a vernacular phishing message analysis.
    STRICT PRIVACY: Does NOT store original raw text by default. Only stores matched tokens.
    """
    observed_evidence = []
    if msg_res.get("script_detected"):
        observed_evidence.append(f"Script Characteristic: {msg_res['script_detected']}.")
    if msg_res.get("extracted_urls"):
        observed_evidence.append(f"Contains {len(msg_res['extracted_urls'])} web link(s).")
    if msg_res.get("context_only_suppressed"):
        observed_evidence.append("Context Safeguard Active: Public utility/bank name mentioned in legitimate context.")
    if msg_res.get("protective_advisory_detected"):
        observed_evidence.append("Protective Negation Active: Message explicitly advises not sharing OTPs or downloading APKs.")

    heuristic_inferences = []
    for f in msg_res.get("findings", []):
        heuristic_inferences.append(
            f"Indicator [{f['category']}] (Matched: '{f['matched_text']}'): {f['why_it_matters_en']}"
        )

    next_steps = scored_res.get("safe_next_steps_en", [])
    rec_action = next_steps[0] if next_steps else "Do not click links or share credentials"

    case_record = {
        "case_id": generate_case_id("CASE-MSG"),
        "timestamp_utc": get_utc_timestamp_iso(),
        "analysis_type": "WhatsApp Vernacular Phishing Analysis",
        "analysis_status": "Completed" if not msg_res.get("is_empty") else "Empty Input",
        "risk_score": scored_res.get("score", 0),
        "risk_category": scored_res.get("risk_level", "Unknown"),
        "badge_color": scored_res.get("badge_color", "gray"),
        "indicator_count": len(msg_res.get("findings", [])),
        "sha256_hash": None,
        "hash_algorithm": None,
        "extracted_urls": [redact_url_credentials(u) for u in msg_res.get("extracted_urls", [])],
        "observed_evidence": observed_evidence,
        "heuristic_inferences": heuristic_inferences,
        "official_sources": [],
        "source_url": None,
        "target_identifier": f"Message ({msg_res.get('script_detected', 'Unknown Script')})",
        "recommended_action": rec_action,
        "raw_data_stored": store_raw_text,
        "limitations": scored_res.get("limitations", "Rule-based matching does not understand all regional dialects."),
    }

    if store_raw_text:
        case_record["raw_text_sample"] = msg_res.get("normalized_text", "")

    return case_record


def create_url_case(url_eval: Dict[str, Any]) -> Dict[str, Any]:
    """
    Creates a case record from a suspicious URL inspection dictionary.
    """
    obs_char = url_eval.get("observable_characteristics", {})
    observed_evidence = [
        f"Host: {url_eval.get('hostname')}",
        f"Scheme: {url_eval.get('scheme')}",
        f"Allowlisted Official Domain: {obs_char.get('is_official_allowlisted', False)}",
        f"IP Address Host: {obs_char.get('is_ip_address', False)} (Type: {obs_char.get('ip_type', 'None')})",
        f"Punycode / Homoglyph Host: {obs_char.get('is_punycode_or_homoglyph', False)}",
        f"URL Shortener: {obs_char.get('is_shortener', False)}",
        f"APK File Target: {obs_char.get('has_apk_download', False)}",
    ]

    heuristic_inferences = []
    for ind in url_eval.get("matched_indicators", []):
        heuristic_inferences.append(
            f"Indicator [{ind['category']}] ({ind['severity']}): {ind['evidence_en']}"
        )

    next_steps = url_eval.get("safe_next_steps_en", [])
    rec_action = next_steps[0] if next_steps else "Do not open link; delete message"

    case_record = {
        "case_id": generate_case_id("CASE-URL"),
        "timestamp_utc": get_utc_timestamp_iso(),
        "analysis_type": "Suspicious URL & Domain Inspection",
        "analysis_status": "Completed" if url_eval.get("is_valid_url") else "Invalid/Blocked Scheme",
        "risk_score": url_eval.get("score", 0),
        "risk_category": url_eval.get("risk_level", "Unknown"),
        "badge_color": url_eval.get("badge_color", "gray"),
        "indicator_count": len(url_eval.get("matched_indicators", [])),
        "sha256_hash": None,
        "hash_algorithm": None,
        "extracted_urls": [redact_url_credentials(url_eval.get("url"))] if url_eval.get("url") else [],
        "observed_evidence": observed_evidence,
        "heuristic_inferences": heuristic_inferences,
        "official_sources": [],
        "source_url": redact_url_credentials(url_eval.get("url")) if url_eval.get("url") else None,
        "target_identifier": url_eval.get("hostname", "unnamed_url"),
        "recommended_action": rec_action,
        "raw_data_stored": False,
        "limitations": url_eval.get("limitations", "Static URL analysis does not fetch remote server content."),
    }
    return case_record


def create_scheme_case(scheme_res: Dict[str, Any]) -> Dict[str, Any]:
    """
    Creates a case record from a Maharashtra Government scheme verification result.
    Preserves official evidence citations and retrieval timestamps.
    """
    observed_evidence = list(scheme_res.get("supporting_evidence", []))
    heuristic_inferences = list(scheme_res.get("conflicting_evidence", []))

    # Calculate an approximate risk score based on classification
    cls_name = scheme_res.get("classification", "NOT ENOUGH EVIDENCE")
    if cls_name == "CONFLICTING EVIDENCE FOUND":
        score = 80
        badge = "red"
    elif cls_name == "NOT ENOUGH EVIDENCE":
        score = 30
        badge = "orange"
    elif cls_name == "SOURCE UNAVAILABLE":
        score = 0
        badge = "gray"
    else:
        score = 0
        badge = "green"

    next_steps = scheme_res.get("safe_next_steps_en", [])
    rec_action = next_steps[0] if next_steps else "Verify at official government portal"

    extracted_urls = []
    if scheme_res.get("url_assessment", {}).get("url"):
        extracted_urls.append(scheme_res["url_assessment"]["url"])

    case_record = {
        "case_id": generate_case_id("CASE-GOV"),
        "timestamp_utc": get_utc_timestamp_iso(),
        "analysis_type": "Maharashtra Government Scheme Verification",
        "analysis_status": cls_name,
        "risk_score": score,
        "risk_category": cls_name,
        "badge_color": badge,
        "indicator_count": len(scheme_res.get("conflicting_evidence", [])),
        "sha256_hash": None,
        "hash_algorithm": None,
        "extracted_urls": extracted_urls,
        "observed_evidence": observed_evidence,
        "heuristic_inferences": heuristic_inferences,
        "official_sources": scheme_res.get("official_sources", []),
        "source_url": extracted_urls[0] if extracted_urls else None,
        "target_identifier": scheme_res.get("matched_scheme_title") or "Unindexed Scheme Claim",
        "retrieval_metadata": scheme_res.get("retrieval_metadata", {}),
        "recommended_action": rec_action,
        "raw_data_stored": False,
        "limitations": scheme_res.get("limitations", "Verification compares claim against listed official Government Resolutions."),
    }
    return case_record


# =============================================================================
# EVIDENCE REPORT GENERATOR (Forensically Honest Citizen Summary)
# =============================================================================

def generate_evidence_report(case_record: Dict[str, Any]) -> str:
    """
    Generates an exportable evidence report labeled:
    'Cybersecurity Analysis Summary — Not an Official Forensic Certification'
    """
    created_at = get_utc_timestamp_iso()
    case_id = case_record.get("case_id", "N/A")
    atype = case_record.get("analysis_type", "General Inspection")
    score = case_record.get("risk_score", 0)
    category = case_record.get("risk_category", "Unspecified")
    status = case_record.get("analysis_status", "Completed")
    target = case_record.get("target_identifier", "Target")

    hash_val = case_record.get("sha256_hash")
    hash_algo = case_record.get("hash_algorithm") or ("SHA-256" if hash_val and hash_val != "N/A" else None)

    report_lines = [
        "=" * 78,
        "CYBERSECURITY ANALYSIS SUMMARY — NOT AN OFFICIAL FORENSIC CERTIFICATION",
        "Document Class: Cybersecurity Analysis Summary — Not an Official Forensic Certification",
        "=" * 78,
        f"Report Generated (UTC): {created_at}",
        f"Case Identifier:       {case_id}",
        f"Analysis Target:       {target}",
        f"Analysis Type:         {atype}",
        f"Analysis Method:       Static Offline Feature Inspection (Engine v{SANDBOX_ENGINE_VERSION})",
        f"Analysis Status:       {status}",
        f"Heuristic Risk Index:  {score} / 100",
        f"Risk Category:         {category}",
    ]

    if hash_algo and hash_val and hash_val != "N/A":
        report_lines.append(f"Hash Algorithm:        {hash_algo}")
        report_lines.append(f"Payload Fingerprint:   {hash_val}")
    else:
        report_lines.append("Payload Fingerprint:   Not Applicable (Text / Non-File Stream)")

    report_lines.append("-" * 78)
    report_lines.append("1. OBSERVED EVIDENCE (Objective Technical Traits):")
    obs = case_record.get("observed_evidence", [])
    if obs:
        for idx, item in enumerate(obs, start=1):
            report_lines.append(f"   1.{idx} {item}")
    else:
        report_lines.append("   (No specific structural observations recorded)")

    report_lines.append("")
    report_lines.append("2. HEURISTIC INFERENCES & WARNING SIGNS:")
    heur = case_record.get("heuristic_inferences", [])
    if heur:
        for idx, item in enumerate(heur, start=1):
            report_lines.append(f"   2.{idx} {item}")
    else:
        report_lines.append("   (No threat indicator patterns triggered)")

    sources = case_record.get("official_sources", [])
    if sources:
        report_lines.append("")
        report_lines.append("3. OFFICIAL SOURCE CITATIONS & GOVERNMENT RESOLUTIONS:")
        for idx, s in enumerate(sources, start=1):
            report_lines.append(
                f"   3.{idx} [{s.get('title')}] GR No: {s.get('gr_number', 'N/A')} "
                f"(Date: {s.get('publication_date', 'N/A')}) — Portal: {s.get('portal_url', 'N/A')}"
            )

    urls = case_record.get("extracted_urls", [])
    if urls:
        report_lines.append("")
        report_lines.append("4. EXTRACTED TARGET WEBLINKS (Passive Inspection — Never Contacted):")
        for idx, u in enumerate(urls, start=1):
            report_lines.append(f"   4.{idx} {u}")

    report_lines.append("-" * 78)
    report_lines.append("5. RECOMMENDED NEXT ACTIONS & OFFICIAL REPORTING CHANNELS:")
    report_lines.append(f"   Primary Recommendation: {case_record.get('recommended_action', 'Verify independently')}")
    report_lines.append("   - National Cyber Crime Reporting Portal: https://cybercrime.gov.in")
    report_lines.append("   - National Cyber Financial Fraud Helpline: 1930")
    report_lines.append("   - Government of Maharashtra Official Portal: https://maharashtra.gov.in")
    report_lines.append("   - MahaVitaran (MSEDCL) Official Website: https://www.mahadiscom.in")

    report_lines.append("-" * 78)
    report_lines.append("6. EXPLICIT LIMITATIONS & LEGAL DISCLAIMER:")
    report_lines.append(
        "   - Automated Decision Support Only: This analysis was conducted strictly in computer memory\n"
        "     without dynamic sandboxing, code de-obfuscation, or network telemetry."
    )
    report_lines.append(
        "   - Not a Legal Certificate: This document does NOT constitute an expert forensic certificate\n"
        "     under Section 65B of the Indian Evidence Act or equivalent cyber statutes."
    )
    report_lines.append(
        "   - Privacy Boundary: Uploaded raw files and complete chat texts are discarded by default\n"
        "     to respect citizen privacy; case records hold only derived metadata."
    )
    report_lines.append("=" * 78)

    return "\n".join(report_lines)
