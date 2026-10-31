"""
Phase 6.8.6 — Real-World Evidence Quality and Dataset Readiness Test Suite.

Verifies:
1. Operational database correctly issues 'BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE' (zero fabrication).
2. Comprehensive distribution calculations (status, origin, type, classification, language, campaigns).
3. Campaign conflict detection.
4. Readiness threshold evaluation and transition to 'READY_FOR_DATASET_CONSTRUCTION' when thresholds are satisfied.
5. Multilingual heuristic detection.
6. Markdown report generation.
"""

import json
import os
import tempfile
import pytest
from src.dataset_readiness import DatasetReadinessAnalyzer, detect_language_from_text
from src.case_repository import CaseRepository


def test_operational_database_readiness_is_blocked():
    """Confirms operational database issues BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE without fake data."""
    analyzer = DatasetReadinessAnalyzer("instance/seva_cases.sqlite3")
    res = analyzer.analyze_readiness()

    assert res["gate_verdict"] == "BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE"
    assert res["is_ready_for_training"] is False
    assert res["total_evidence_count"] == 0
    assert res["corroborated_count"] == 0
    assert len(res["blocking_reasons"]) > 0
    assert "deficits" in res
    assert res["deficits"]["corroborated_samples_needed"] >= 30


def test_language_detection_heuristic():
    """Verifies heuristic detection for Marathi, Romanized Marathi, Mixed, and English."""
    # Devanagari Marathi
    assert detect_language_from_text("तुमचे वीज बिल थकबाकी आहे. लगेच अपडेट करा.") == "mr"

    # Mixed Marathi / English
    assert detect_language_from_text("तुमचे Mahavitaran account suspend केले जाईल. Click here.") == "mr-en"

    # Romanized Marathi
    assert detect_language_from_text("Tumcha PM Kisan hafta block zala ahe, link tap kara.") == "mr-Latn"

    # English
    assert detect_language_from_text("Urgent security alert: Your account has been temporarily locked.") == "en"

    # Unknown / empty
    assert detect_language_from_text("") == "unknown"


def test_dataset_readiness_breakdown_and_conflict_detection():
    """Verifies evidence breakdown and conflict detection on an isolated test fixture."""
    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db_path = os.path.join(temp_dir.name, "test_readiness.sqlite3")

    repo = CaseRepository(db_path=db_path)

    # Create 2 campaign clusters
    c1 = repo.create_or_get_campaign_cluster("url_domain", "portal-update.org", campaign_name="Campaign A")
    c2 = repo.create_or_get_campaign_cluster("apk_sha256", "HASH123", campaign_name="Campaign B")

    # Evidence 1: Corroborated phishing
    e1 = repo.register_evidence_provenance(
        case_id="CASE-R01",
        evidence_origin="user_reported",
        evidence_type="message_text",
        user_classification="phishing",
        consent_given=True,
        metadata={"text": "तुमचे खाते बंद झाले आहे.", "language": "mr"},
    )
    repo.assign_campaign_cluster(e1["evidence_id"], c1["campaign_id"], operator_username="system")
    repo.transition_evidence_status(e1["evidence_id"], "awaiting_review", "analyst1", "Triage")
    repo.transition_evidence_status(e1["evidence_id"], "under_review", "analyst1", "Investigating", reviewer_classification="phishing")
    repo.corroborate_evidence(
        e1["evidence_id"],
        "reviewer2",
        "Confirmed phishing site spoofing government portal.",
        "phishing",
        "official_gazette_scheme_crosscheck",
        ["REF-01"],
    )

    # Evidence 2: Corroborated legitimate in Campaign B
    e2 = repo.register_evidence_provenance(
        case_id="CASE-R02",
        evidence_origin="analyst_submitted",
        evidence_type="url",
        user_classification="legitimate",
        consent_given=True,
        metadata={"text": "Official Maharashtra portal link.", "language": "en"},
    )
    repo.assign_campaign_cluster(e2["evidence_id"], c2["campaign_id"], operator_username="system")
    repo.transition_evidence_status(e2["evidence_id"], "awaiting_review", "analyst1", "Triage")
    repo.transition_evidence_status(e2["evidence_id"], "under_review", "analyst1", "Investigating", reviewer_classification="legitimate")
    repo.corroborate_evidence(
        e2["evidence_id"],
        "reviewer2",
        "Verified legitimate official portal with valid TLS cert.",
        "legitimate",
        "official_gazette_scheme_crosscheck",
        ["REF-02"],
    )

    # Evidence 3: Conflicting item in Campaign A (classified legitimate, whereas e1 is phishing)
    e3 = repo.register_evidence_provenance(
        case_id="CASE-R03",
        evidence_origin="user_reported",
        evidence_type="url",
        user_classification="legitimate",
        consent_given=True,
        metadata={"text": "Legitimate mirror.", "language": "mr-Latn"},
    )
    repo.assign_campaign_cluster(e3["evidence_id"], c1["campaign_id"], operator_username="system")
    repo.transition_evidence_status(e3["evidence_id"], "awaiting_review", "analyst1", "Triage")
    repo.transition_evidence_status(e3["evidence_id"], "under_review", "analyst1", "Investigating", reviewer_classification="legitimate")

    analyzer = DatasetReadinessAnalyzer(db_path=db_path)
    res = analyzer.analyze_readiness()

    assert res["total_evidence_count"] == 3
    assert res["corroborated_count"] == 2
    assert res["status_distribution"]["corroborated"] == 2
    assert res["status_distribution"]["under_review"] == 1
    assert res["independent_campaign_count"] == 2
    assert res["campaign_conflict_count"] == 1  # Campaign A has conflicting labels
    assert res["language_distribution"]["mr"] >= 1
    assert res["language_distribution"]["en"] >= 1
    assert res["language_distribution"]["mr-Latn"] >= 1
    assert res["gate_verdict"] == "BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE"


def test_dataset_readiness_threshold_satisfaction():
    """Verifies that when custom thresholds are satisfied, gate transitions to READY_FOR_DATASET_CONSTRUCTION."""
    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db_path = os.path.join(temp_dir.name, "test_ready.sqlite3")

    repo = CaseRepository(db_path=db_path)

    # Set custom lightweight thresholds: 2 corroborated (1 phishing, 1 legitimate), 2 campaigns, 2 languages
    custom_thresholds = {
        "min_total_corroborated": 2,
        "min_per_class": 1,
        "min_independent_campaigns": 2,
        "min_distinct_languages": 2,
        "max_campaign_conflicts": 0,
        "min_eligible_ratio": 0.80,
    }

    c1 = repo.create_or_get_campaign_cluster("url_domain", "camp1.com")
    c2 = repo.create_or_get_campaign_cluster("url_domain", "camp2.com")

    # Item 1: Phishing in c1, Marathi
    e1 = repo.register_evidence_provenance(
        case_id="CASE-P01",
        evidence_origin="user_reported",
        evidence_type="message_text",
        user_classification="phishing",
        consent_given=True,
        metadata={"text": "तुमचे वीज बिल भरा.", "language": "mr"},
    )
    repo.assign_campaign_cluster(e1["evidence_id"], c1["campaign_id"], operator_username="system")
    repo.transition_evidence_status(e1["evidence_id"], "awaiting_review", "u1", "Triage")
    repo.transition_evidence_status(e1["evidence_id"], "under_review", "u1", "Review", reviewer_classification="phishing")
    repo.corroborate_evidence(e1["evidence_id"], "u2", "Verified phishing payload.", "phishing", "official_gazette_scheme_crosscheck", ["REF-01"])

    # Item 2: Legitimate in c2, English
    e2 = repo.register_evidence_provenance(
        case_id="CASE-L01",
        evidence_origin="user_reported",
        evidence_type="message_text",
        user_classification="legitimate",
        consent_given=True,
        metadata={"text": "Official government announcement.", "language": "en"},
    )
    repo.assign_campaign_cluster(e2["evidence_id"], c2["campaign_id"], operator_username="system")
    repo.transition_evidence_status(e2["evidence_id"], "awaiting_review", "u1", "Triage")
    repo.transition_evidence_status(e2["evidence_id"], "under_review", "u1", "Review", reviewer_classification="legitimate")
    repo.corroborate_evidence(e2["evidence_id"], "u2", "Verified legitimate notice.", "legitimate", "official_gazette_scheme_crosscheck", ["REF-02"])

    analyzer = DatasetReadinessAnalyzer(db_path=db_path, thresholds=custom_thresholds)
    res = analyzer.analyze_readiness()

    assert res["gate_verdict"] == "READY_FOR_DATASET_CONSTRUCTION"
    assert res["is_ready_for_training"] is True
    assert len(res["blocking_reasons"]) == 0
    assert len(res["deficits"]) == 0

    # Markdown report check
    report = analyzer.generate_markdown_report()
    assert "READY_FOR_DATASET_CONSTRUCTION" in report
    assert "Target Database:" in report
