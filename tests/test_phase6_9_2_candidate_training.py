"""
Phase 6.9.2 — Controlled Real-World Candidate Model Training Test Suite.

Verifies:
1. Operational candidate training is blocked by TrainingReadinessGate (zero fake data).
2. Candidate training executes from pure random initialization on partitioned dataset.
3. Cryptographic integrity of candidate checkpoint (.npz) and metadata.
4. Active model governance invariant: custom-mlp-v4.0.0-seed42 is immutable and untouched.
5. Zero promotion: candidate is labeled candidate_unqualified and is_active_model=False.
"""

import hashlib
import json
import os
import tempfile
import pytest

from src.real_world_candidate_trainer import (
    RealWorldCandidateTrainer,
    TrainingBlockedError,
)
from src.case_repository import CaseRepository
from src.dataset_constructor import RealWorldDatasetConstructor


def test_operational_candidate_training_blocked_by_gate():
    """Confirms operational candidate training is rejected due to gate blocker."""
    trainer = RealWorldCandidateTrainer(
        candidates_dir="models/candidates",
        active_config_path="models/active_model_config.json",
    )
    with pytest.raises(TrainingBlockedError) as exc_info:
        trainer.train_from_dataset("data/real_world_datasets", force_test=False)

    assert "Candidate training is blocked" in str(exc_info.value)

    # Verify active model config was NOT touched
    with open("models/active_model_config.json", "r", encoding="utf-8") as f:
        cfg = json.load(f)
    assert cfg["active_model_version"] == "custom-mlp-v4.0.0-seed42"
    assert cfg["operating_mode"] == "shadow"
    assert cfg["is_production_authoritative"] is False


def test_candidate_training_on_valid_dataset():
    """Verifies candidate training execution from random initialization on an isolated dataset."""
    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db_path = os.path.join(temp_dir.name, "test_train.sqlite3")
    dataset_dir = os.path.join(temp_dir.name, "dataset_splits")
    candidates_dir = os.path.join(temp_dir.name, "candidates")

    repo = CaseRepository(db_path=db_path)

    # Populate 4 campaigns with 12 items
    for i in range(1, 5):
        camp = repo.create_or_get_campaign_cluster("url_domain", f"camp-{i}.org")
        cls = "phishing" if i % 2 == 0 else "legitimate"
        for j in range(3):
            ev = repo.register_evidence_provenance(
                case_id=f"CASE-TR-{i}-{j}",
                evidence_origin="user_reported",
                evidence_type="message_text",
                user_classification=cls,
                consent_given=True,
                metadata={"text": f"Urgent alert notice {i}-{j}", "language": "en"},
            )
            repo.assign_campaign_cluster(ev["evidence_id"], camp["campaign_id"], operator_username="system")
            repo.transition_evidence_status(ev["evidence_id"], "awaiting_review", "u1", "Triage")
            repo.transition_evidence_status(ev["evidence_id"], "under_review", "u1", "Review", reviewer_classification=cls)
            repo.corroborate_evidence(
                ev["evidence_id"],
                "u2",
                f"Corroborated verification {i}-{j}.",
                cls,
                "official_gazette_scheme_crosscheck",
                [f"REF-{i}-{j}"],
            )

    # Construct dataset splits
    constructor = RealWorldDatasetConstructor(db_path=db_path, output_dir=dataset_dir)
    ds_res = constructor.construct_dataset(allow_insufficient=True)
    assert ds_res["status"] == "CONSTRUCTED"

    # Train candidate model
    trainer = RealWorldCandidateTrainer(
        candidates_dir=candidates_dir,
        active_config_path="models/active_model_config.json",
        seed=999,
    )
    result = trainer.train_from_dataset(
        dataset_dir=dataset_dir,
        candidate_version="candidate_realworld_test_v1",
        epochs=5,
        batch_size=4,
        force_test=True,
    )

    assert result["status"] == "CANDIDATE_TRAINED"
    assert result["candidate_version"] == "candidate_realworld_test_v1"
    assert os.path.exists(result["weights_path"])
    assert os.path.exists(result["metadata_path"])

    # Verify SHA-256 matches
    with open(result["weights_path"], "rb") as f:
        actual_sha = hashlib.sha256(f.read()).hexdigest()
    assert actual_sha == result["weights_sha256"]

    # Verify metadata invariants
    with open(result["metadata_path"], "r", encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["initialization"] == "random"
    assert meta["seed"] == 999
    assert meta["status"] == "candidate_unqualified"
    assert meta["is_active_model"] is False
    assert meta["is_production_authoritative"] is False

    # Verify active model remains custom-mlp-v4.0.0-seed42
    assert result["active_model_preserved"] == "custom-mlp-v4.0.0-seed42"


def test_empty_training_split_rejection():
    """Confirms training rejects missing or empty dataset directories."""
    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    empty_dataset_dir = os.path.join(temp_dir.name, "empty_ds")
    os.makedirs(empty_dataset_dir, exist_ok=True)

    trainer = RealWorldCandidateTrainer(
        candidates_dir=os.path.join(temp_dir.name, "candidates"),
        active_config_path="models/active_model_config.json",
    )
    with pytest.raises(FileNotFoundError):
        trainer.train_from_dataset(empty_dataset_dir, force_test=True)
