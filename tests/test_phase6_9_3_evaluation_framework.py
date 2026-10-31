"""
Phase 6.9.3 — Independent Real-World Model Evaluation Test Suite.

Verifies:
1. Operational evaluation correctly returns 'INSUFFICIENT_EVALUATION_EVIDENCE' (zero fake evaluation).
2. Independent evaluation on sealed evaluation split computes accuracy, precision, recall, F1, FPR/FNR.
3. Valid 3x3 confusion matrix calculation.
4. Multilingual robustness breakdown.
5. Markdown evaluation report generation.
"""

import json
import os
import tempfile
import pytest

from src.real_world_evaluator import RealWorldModelEvaluator
from src.real_world_candidate_trainer import RealWorldCandidateTrainer
from src.case_repository import CaseRepository
from src.dataset_constructor import RealWorldDatasetConstructor


def test_operational_evaluation_blocked_when_evidence_insufficient():
    """Confirms operational model evaluation is blocked when operational evaluation evidence is absent."""
    evaluator = RealWorldModelEvaluator(
        dataset_dir="data/real_world_datasets",
        candidates_dir="models/candidates",
    )
    res = evaluator.evaluate_candidate(
        candidate_dir="models/candidates/candidate_v4_seed42",
        force_test=False,
    )

    assert res["status"] == "EVALUATION_BLOCKED"
    assert res["evaluation_verdict"] == "INSUFFICIENT_EVALUATION_EVIDENCE"
    assert "unavailable or holds 0 records" in res["reason"]
    assert res["metrics"] is None


def test_independent_evaluation_on_sealed_eval_split():
    """Verifies complete metric calculation on an isolated sealed evaluation dataset."""
    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db_path = os.path.join(temp_dir.name, "test_eval.sqlite3")
    dataset_dir = os.path.join(temp_dir.name, "dataset_splits")
    candidates_dir = os.path.join(temp_dir.name, "candidates")

    repo = CaseRepository(db_path=db_path)

    # Create 6 campaigns (total 18 items across 2 languages)
    for i in range(1, 7):
        camp = repo.create_or_get_campaign_cluster("url_domain", f"eval-camp-{i}.in")
        cls = "phishing" if i % 2 == 0 else "legitimate"
        lang = "mr" if i % 2 == 0 else "en"
        for j in range(3):
            ev = repo.register_evidence_provenance(
                case_id=f"CASE-EV-{i}-{j}",
                evidence_origin="user_reported",
                evidence_type="message_text",
                user_classification=cls,
                consent_given=True,
                metadata={"text": f"Evaluation lure text {i}-{j}", "language": lang},
            )
            repo.assign_campaign_cluster(ev["evidence_id"], camp["campaign_id"], operator_username="system")
            repo.transition_evidence_status(ev["evidence_id"], "awaiting_review", "u1", "Triage")
            repo.transition_evidence_status(ev["evidence_id"], "under_review", "u1", "Review", reviewer_classification=cls)
            repo.corroborate_evidence(
                ev["evidence_id"],
                "u2",
                f"Independent technical corroboration {i}-{j}.",
                cls,
                "official_gazette_scheme_crosscheck",
                [f"REF-EV-{i}-{j}"],
            )

    # Construct dataset splits (train, dev, sealed_eval)
    constructor = RealWorldDatasetConstructor(db_path=db_path, output_dir=dataset_dir)
    constructor.construct_dataset(allow_insufficient=True)

    # Train a candidate model on train.jsonl
    trainer = RealWorldCandidateTrainer(
        candidates_dir=candidates_dir,
        active_config_path="models/active_model_config.json",
        seed=42,
    )
    train_res = trainer.train_from_dataset(
        dataset_dir=dataset_dir,
        candidate_version="candidate_eval_test",
        epochs=5,
        force_test=True,
    )
    candidate_dir = train_res["candidate_dir"]

    # Evaluate candidate on sealed_eval.jsonl
    evaluator = RealWorldModelEvaluator(
        dataset_dir=dataset_dir,
        candidates_dir=candidates_dir,
    )
    eval_res = evaluator.evaluate_candidate(
        candidate_dir=candidate_dir,
        force_test=True,
    )

    assert eval_res["status"] == "EVALUATION_COMPLETED"
    assert eval_res["evaluation_verdict"] in ("PASS_EVALUATION_CRITERIA", "FAIL_EVALUATION_CRITERIA")
    assert eval_res["total_eval_samples"] > 0

    m = eval_res["metrics"]
    assert 0.0 <= m["overall_accuracy"] <= 1.0
    assert 0.0 <= m["macro_f1"] <= 1.0
    assert 0.0 <= m["weighted_f1"] <= 1.0
    assert 0.0 <= m["false_positive_rate"] <= 1.0
    assert 0.0 <= m["false_negative_rate"] <= 1.0

    # Verify per-class metrics
    for c in ["phishing", "legitimate", "protective_advisory"]:
        assert c in m["per_class"]
        assert "precision" in m["per_class"][c]
        assert "recall" in m["per_class"][c]
        assert "f1_score" in m["per_class"][c]

    # Verify 3x3 confusion matrix
    cm = m["confusion_matrix"]["matrix"]
    assert len(cm) == 3
    assert len(cm[0]) == 3
    matrix_sum = sum(sum(row) for row in cm)
    assert matrix_sum == eval_res["total_eval_samples"]

    # Verify language breakdown
    assert len(m["language_breakdown"]) > 0

    # Markdown report generation
    report = evaluator.generate_evaluation_markdown(eval_res)
    assert "Real-World Model Evaluation Report" in report
    assert "Overall Accuracy:" in report
    assert "Confusion Matrix" in report
