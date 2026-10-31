"""
Phase 6.9.1 — Real-World Model Training Readiness Gate Test Suite.

Verifies:
1. Operational environment is correctly blocked from candidate retraining.
2. Invariant violations in active model configuration are caught.
3. Gate approves candidate retraining only when all evidence, dataset, and safety criteria are satisfied.
4. Markdown gate report generation.
"""

import json
import os
import tempfile
import pytest

from src.training_readiness_gate import TrainingReadinessGate
from src.case_repository import CaseRepository
from src.dataset_constructor import RealWorldDatasetConstructor


def test_operational_training_readiness_is_blocked():
    """Confirms operational environment refuses model retraining due to insufficient evidence."""
    gate = TrainingReadinessGate(
        db_path="instance/seva_cases.sqlite3",
        dataset_dir="data/real_world_datasets",
        active_config_path="models/active_model_config.json",
    )
    res = gate.evaluate_gate()

    assert res["gate_decision"] == "BLOCKED_INSUFFICIENT_EVIDENCE"
    assert res["allow_training"] is False
    assert res["checks"]["evidence_readiness_passed"] is False
    assert res["checks"]["model_governance_invariants_valid"] is True
    assert res["checks"]["hardware_safety_verified"] is True
    assert res["active_model_preserved"] == "custom-mlp-v4.0.0-seed42"
    assert res["operating_mode"] == "shadow"


def test_training_gate_detects_broken_model_invariants():
    """Confirms gate detects and rejects unauthorized changes to active model configuration."""
    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    bad_config_path = os.path.join(temp_dir.name, "active_model_config.json")

    # Tampered config: claiming production authority and non-shadow mode
    bad_config = {
        "active_model_version": "unvetted-candidate-v99",
        "last_known_good_version": "custom-mlp-v1.1.0-preproc",
        "operating_mode": "active_production",
        "is_production_authoritative": True,
    }
    with open(bad_config_path, "w", encoding="utf-8") as f:
        json.dump(bad_config, f)

    gate = TrainingReadinessGate(
        db_path="instance/seva_cases.sqlite3",
        active_config_path=bad_config_path,
    )
    res = gate.evaluate_gate()

    assert res["checks"]["model_governance_invariants_valid"] is False
    assert res["allow_training"] is False
    assert any("Model governance violation" in r for r in res["blocking_reasons"])


def test_training_gate_approves_when_prerequisites_satisfied():
    """Confirms gate approves candidate training when an isolated fixture satisfies all criteria."""
    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db_path = os.path.join(temp_dir.name, "test_gate_ready.sqlite3")
    dataset_dir = os.path.join(temp_dir.name, "dataset_out")

    repo = CaseRepository(db_path=db_path)

    # Populate 5 campaigns with consistent labels (no campaign conflicts)
    # Total 15 items: 6 phishing (camps 2 & 4), 9 legitimate (camps 1, 3, 5)
    for i in range(1, 6):
        camp = repo.create_or_get_campaign_cluster("url_domain", f"camp-{i}.in")
        cls = "phishing" if i % 2 == 0 else "legitimate"
        lang = "mr" if i % 2 == 0 else "en"
        for j in range(3):
            ev = repo.register_evidence_provenance(
                case_id=f"CASE-GATE-{i}-{j}",
                evidence_origin="user_reported",
                evidence_type="message_text",
                user_classification=cls,
                consent_given=True,
                metadata={"text": f"Lure {i}-{j}", "language": lang},
            )
            repo.assign_campaign_cluster(ev["evidence_id"], camp["campaign_id"], operator_username="system")
            repo.transition_evidence_status(ev["evidence_id"], "awaiting_review", "u1", "Triage")
            repo.transition_evidence_status(ev["evidence_id"], "under_review", "u1", "Review", reviewer_classification=cls)
            repo.corroborate_evidence(
                ev["evidence_id"],
                "u2",
                f"Corroborated technical verification for {i}-{j}.",
                cls,
                "official_gazette_scheme_crosscheck",
                [f"REF-{i}-{j}"],
            )

    # Construct dataset with custom thresholds satisfied
    constructor = RealWorldDatasetConstructor(
        db_path=db_path,
        output_dir=dataset_dir,
    )
    res_ds = constructor.construct_dataset(allow_insufficient=True)
    assert res_ds["status"] == "CONSTRUCTED"

    # Evaluate gate with custom thresholds satisfied
    override_thresholds = {
        "min_total_corroborated": 10,
        "min_per_class": 5,
        "min_independent_campaigns": 5,
        "min_distinct_languages": 2,
        "max_campaign_conflicts": 0,
        "min_eligible_ratio": 0.80,
    }
    gate = TrainingReadinessGate(
        db_path=db_path,
        dataset_dir=dataset_dir,
        active_config_path="models/active_model_config.json",
        thresholds=override_thresholds,
    )

    gate_res = gate.evaluate_gate()
    assert gate_res["gate_decision"] == "APPROVED_FOR_CANDIDATE_TRAINING"
    assert gate_res["allow_training"] is True
    assert all(gate_res["checks"].values())


def test_markdown_gate_report_generation():
    """Verifies that generate_gate_report_markdown generates valid markdown."""
    gate = TrainingReadinessGate()
    md = gate.generate_gate_report_markdown()
    assert "Real-World Model Training Readiness Gate Decision" in md
    assert "Gate Decision:" in md
    assert "Safety & Governance Checks" in md
