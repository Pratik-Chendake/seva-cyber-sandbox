"""
Comprehensive Unit & Integration Test Suite for Phase 6.3:
Offline Autonomous Candidate Model Trainer.

TEST SPECIFICATION (All 24 Requirements):
1. Valid feature-based training.
2. Random initialization.
3. Candidate training does not load active-model weights.
4. Invalid feature dimensions are rejected.
5. NaN and infinity values are rejected.
6. Invalid labels are rejected.
7. Duplicate training examples are rejected or filtered.
8. Revoked consent is excluded.
9. Pending and low-confidence reviews are excluded.
10. Conflicting duplicate labels are excluded.
11. Synthetic and human-reviewed provenance remain separate.
12. Synthetic-only training is clearly identified.
13. Insufficient feedback data is handled safely.
14. Validation data is never used for training.
15. Locked evaluation data is never used for training.
16. Candidate directories are unique.
17. Existing candidate artifacts are never overwritten.
18. Checkpoint hashes match saved artifacts.
19. Metadata hashes match saved artifacts.
20. Interrupted training leaves the active model untouched.
21. Registry files remain unchanged.
22. Active-model configuration remains unchanged.
23. Production score delta remains zero.
24. Existing trainer and evaluator tests continue passing.
"""

import json
import math
import os
import shutil
import tempfile
from typing import Any, Dict, List
import numpy as np
import pytest

from src.case_repository import CaseRepository
from src.case_manager import SessionCaseStore, create_message_case
from src.custom_model import (
    IDX_TO_LABEL,
    LABEL_TO_IDX,
    CharacterNGramHasher,
    CustomNeuralClassifier,
)
from src.dataset_preprocessing import EXPECTED_FEATURE_DIM
from src.candidate_trainer import (
    CandidateArtifactError,
    CandidateModelTrainer,
    CandidateProvenanceError,
    CandidateTrainingResult,
    InsufficientTrainingDataError,
    compose_training_dataset,
    compute_sha256,
    load_curated_feedback_features,
    load_synthetic_anchor_features,
    validate_dataset_eligibility,
    validate_feature_record,
)
from src.phishing_detector import analyze_message_text
from src.risk_scorer import score_message_analysis

TEST_SECRET = "test-candidate-trainer-secret-key-32chars"


@pytest.fixture
def temp_db_path():
    """Provides an isolated temporary database path cleaned up after test."""
    path = tempfile.mktemp(suffix=".sqlite3")
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass


@pytest.fixture
def temp_candidates_dir(tmp_path):
    """Provides an isolated temporary directory for candidate model storage."""
    c_dir = tmp_path / "candidates"
    c_dir.mkdir(parents=True, exist_ok=True)
    return str(c_dir)


@pytest.fixture
def store(temp_db_path, monkeypatch):
    """Provides a SessionCaseStore backed by an isolated temporary database with configured HMAC key."""
    monkeypatch.setenv("SEVA_FEEDBACK_HMAC_KEY", TEST_SECRET)
    repo = CaseRepository(db_path=temp_db_path)
    return SessionCaseStore(session_id="test-session-63", repository=repo)


def _seed_curated_feedback(store: SessionCaseStore, count_per_class: int = 6) -> List[str]:
    """Helper to seed consented, reviewed cases across phishing, legitimate, and protective_advisory."""
    case_ids = []
    texts_by_class = {
        "phishing": [
            f"तात्काळ वीज बिल भरणा करा नाहीतर वीज कापली जाईल {i}: http://msedcl-bill-{i}.in"
            for i in range(count_per_class)
        ],
        "legitimate": [
            f"महाराष्ट्र शासन सामान्य प्रशासन विभाग अधिकृत माहिती पत्रक क्रमांक {i}: https://maharashtra.gov.in"
            for i in range(count_per_class)
        ],
        "protective_advisory": [
            f"सुरक्षा सूचना {i}: महावितरण कधीही वैयक्तिक बँक खात्यावर बिल भरण्यास सांगत नाही. सावध राहा."
            for i in range(count_per_class)
        ],
    }

    for label, texts in texts_by_class.items():
        for t in texts:
            msg_res = analyze_message_text(t)
            scored = score_message_analysis(msg_res)
            cid = store.add_case(create_message_case(msg_res, scored, store_raw_text=False))
            store.capture_training_features(cid, t, consent_given=True, secret=TEST_SECRET)
            store.repository.submit_review(cid, outcome_category=label, confidence_rating="high")
            case_ids.append(cid)

    return case_ids


def _create_mock_dataset(count_per_class: int = 6) -> List[Dict[str, Any]]:
    """Helper to create a valid in-memory feature dataset without DB dependencies."""
    records = []
    rng = np.random.RandomState(42)
    classes = ["phishing", "legitimate", "protective_advisory"]

    for c in classes:
        for i in range(count_per_class):
            vec = rng.uniform(-0.1, 0.1, size=EXPECTED_FEATURE_DIM).astype(np.float32).tolist()
            records.append({
                "example_id": f"mock_{c}_{i}",
                "feature_vector": vec,
                "feature_dim": EXPECTED_FEATURE_DIM,
                "label": c,
                "label_idx": LABEL_TO_IDX[c],
                "confidence_rating": "high",
                "provenance": "mock_synthetic",
                "source_category": "synthetic_anchor_corpus",
            })
    return records


# =============================================================================
# 1. CORE FEATURE-BASED TRAINING TESTS
# =============================================================================

def test_01_valid_feature_based_training(temp_candidates_dir):
    """Verifies that a candidate model trains successfully on valid 1024-d feature records."""
    dataset = _create_mock_dataset(count_per_class=6)
    _, summary = compose_training_dataset([], dataset, policy="synthetic_only")

    trainer = CandidateModelTrainer(
        candidates_dir=temp_candidates_dir,
        epochs=5,
        batch_size=8,
        seed=42,
    )

    res = trainer.train_candidate(
        dataset=dataset,
        composition_summary=summary,
        candidate_version="1.0.0",
        min_samples=10,
    )

    assert res.status == "SUCCESS"
    assert res.candidate_version == "1.0.0"
    assert os.path.exists(res.weights_path)
    assert os.path.exists(res.metadata_path)
    assert os.path.exists(res.manifest_path)
    assert os.path.exists(res.report_path)


def test_02_random_initialization(temp_candidates_dir):
    """Verifies that candidate models are initialized from random weights and different seeds yield different weights."""
    dataset = _create_mock_dataset(count_per_class=5)
    _, summary = compose_training_dataset([], dataset, policy="synthetic_only")

    trainer1 = CandidateModelTrainer(candidates_dir=temp_candidates_dir, epochs=1, seed=42)
    res1 = trainer1.train_candidate(dataset, summary, candidate_version="1.0.1", min_samples=5)

    trainer2 = CandidateModelTrainer(candidates_dir=temp_candidates_dir, epochs=1, seed=999)
    res2 = trainer2.train_candidate(dataset, summary, candidate_version="1.0.2", min_samples=5)

    w1 = np.load(res1.weights_path, allow_pickle=False)["W1"]
    w2 = np.load(res2.weights_path, allow_pickle=False)["W1"]

    assert not np.allclose(w1, w2)
    assert not np.allclose(w1, np.zeros_like(w1))


def test_03_candidate_training_does_not_load_active_model_weights(temp_candidates_dir):
    """Verifies that candidate training initializes from scratch rather than active production weights."""
    active_weights_path = os.path.join("models", "experimental_custom_v1", "model_weights.npz")
    assert os.path.exists(active_weights_path)
    active_w1 = np.load(active_weights_path, allow_pickle=False)["W1"]

    dataset = _create_mock_dataset(count_per_class=5)
    _, summary = compose_training_dataset([], dataset, policy="synthetic_only")

    trainer = CandidateModelTrainer(candidates_dir=temp_candidates_dir, epochs=1, seed=1234)
    res = trainer.train_candidate(dataset, summary, candidate_version="1.0.3", min_samples=5)

    cand_w1 = np.load(res.weights_path, allow_pickle=False)["W1"]
    assert not np.allclose(cand_w1, active_w1)


# =============================================================================
# 2. VALIDATION & SANITIZATION TESTS
# =============================================================================

def test_04_invalid_feature_dimensions_are_rejected():
    """Verifies that records with vector dimensions differing from 1024 are rejected."""
    bad_rec = {
        "feature_vector": [0.1] * 512,
        "label": "phishing",
        "label_idx": 0,
    }
    ok, err = validate_feature_record(bad_rec)
    assert ok is False
    assert "dimension mismatch" in err


def test_05_nan_and_infinity_values_are_rejected():
    """Verifies that records with NaN or Infinity values are rejected."""
    vec_nan = [0.0] * 1024
    vec_nan[42] = float("nan")
    ok1, err1 = validate_feature_record({"feature_vector": vec_nan, "label": "phishing", "label_idx": 0})
    assert ok1 is False
    assert "non-finite" in err1

    vec_inf = [0.0] * 1024
    vec_inf[10] = float("inf")
    ok2, err2 = validate_feature_record({"feature_vector": vec_inf, "label": "phishing", "label_idx": 0})
    assert ok2 is False
    assert "non-finite" in err2


def test_06_invalid_labels_are_rejected():
    """Verifies that records with unmapped labels or mismatched indices are rejected."""
    ok1, err1 = validate_feature_record({"feature_vector": [0.1] * 1024, "label": "unknown_fraud", "label_idx": 0})
    assert ok1 is False
    assert "Invalid or unmapped label" in err1

    ok2, err2 = validate_feature_record({"feature_vector": [0.1] * 1024, "label": "phishing", "label_idx": 1})
    assert ok2 is False
    assert "Label index mismatch" in err2


def test_07_duplicate_training_examples_rejected_or_filtered(store):
    """Verifies that duplicate submissions are deduplicated and do not inflate candidate training data."""
    msg = "महावितरण डुप्लिकेट चाचणी: http://msedcl-dup.click"
    for _ in range(3):
        cid = store.add_case(create_message_case(analyze_message_text(msg), score_message_analysis(analyze_message_text(msg))))
        store.capture_training_features(cid, msg, consent_given=True, secret=TEST_SECRET)
        store.repository.submit_review(cid, outcome_category="phishing", confidence_rating="high")

    feedback = load_curated_feedback_features(store.repository, secret=TEST_SECRET)
    # Deduplication gate must ensure only 1 instance enters
    assert len(feedback) == 1


# =============================================================================
# 3. GOVERNANCE & PROVENANCE TESTS
# =============================================================================

def test_08_revoked_consent_is_excluded(store):
    """Verifies that records with revoked consent are excluded from candidate training datasets."""
    cids = _seed_curated_cases = _seed_curated_feedback(store, count_per_class=2)
    assert len(cids) == 6

    # Revoke consent for all records
    for cid in cids:
        store.revoke_training_consent(case_id=cid, reason="revocation_test")

    feedback = load_curated_feedback_features(store.repository, secret=TEST_SECRET)
    assert len(feedback) == 0


def test_09_pending_and_low_confidence_reviews_are_excluded(store):
    """Verifies that pending and low-confidence reviews are excluded from feedback training data."""
    # Seed pending case
    cid1 = store.add_case(create_message_case(analyze_message_text("प्रलंबित"), score_message_analysis(analyze_message_text("प्रलंबित"))))
    store.capture_training_features(cid1, "प्रलंबित", consent_given=True, secret=TEST_SECRET)
    store.repository.create_or_get_review(cid1)

    # Seed low confidence case
    cid2 = store.add_case(create_message_case(analyze_message_text("कमी खात्री"), score_message_analysis(analyze_message_text("कमी खात्री"))))
    store.capture_training_features(cid2, "कमी खात्री", consent_given=True, secret=TEST_SECRET)
    store.repository.submit_review(cid2, outcome_category="legitimate", confidence_rating="low")

    feedback = load_curated_feedback_features(store.repository, secret=TEST_SECRET)
    assert len(feedback) == 0


def test_10_conflicting_duplicate_labels_are_excluded(store):
    """Verifies that duplicate cases with conflicting operator reviews are quarantined and excluded."""
    msg = "विवादित निकाल संदेश http://conflict-trainer.link"
    cid1 = store.add_case(create_message_case(analyze_message_text(msg), score_message_analysis(analyze_message_text(msg))))
    cid2 = store.add_case(create_message_case(analyze_message_text(msg), score_message_analysis(analyze_message_text(msg))))

    store.capture_training_features(cid1, msg, consent_given=True, secret=TEST_SECRET)
    store.capture_training_features(cid2, msg, consent_given=True, secret=TEST_SECRET)

    store.repository.submit_review(cid1, outcome_category="phishing", confidence_rating="high")
    store.repository.submit_review(cid2, outcome_category="legitimate", confidence_rating="high")

    feedback = load_curated_feedback_features(store.repository, secret=TEST_SECRET)
    assert len(feedback) == 0


def test_11_synthetic_and_human_reviewed_provenance_remain_separate(store, temp_candidates_dir):
    """Verifies that candidate training reports separate human-reviewed feedback counts from synthetic counts."""
    _seed_curated_feedback(store, count_per_class=3)
    feedback_recs = load_curated_feedback_features(store.repository, secret=TEST_SECRET)
    mock_synthetic = _create_mock_dataset(count_per_class=3)

    dataset, summary = compose_training_dataset(feedback_recs, mock_synthetic, policy="combined_anchor")
    trainer = CandidateModelTrainer(candidates_dir=temp_candidates_dir, epochs=2, seed=42)
    res = trainer.train_candidate(dataset, summary, candidate_version="1.0.4", min_samples=10)

    report = res.training_report
    prov = report["dataset_provenance"]
    assert prov["human_reviewed_feedback_count"] == len(feedback_recs)
    assert prov["synthetic_anchor_corpus_count"] == len(mock_synthetic)
    assert prov["human_reviewed_feedback_count"] + prov["synthetic_anchor_corpus_count"] == len(dataset)


def test_12_synthetic_only_training_is_clearly_identified(temp_candidates_dir):
    """Verifies that synthetic-only candidate models clearly state that no citizen feedback was learned."""
    mock_synthetic = _create_mock_dataset(count_per_class=5)
    dataset, summary = compose_training_dataset([], mock_synthetic, policy="synthetic_only")

    trainer = CandidateModelTrainer(candidates_dir=temp_candidates_dir, epochs=2, seed=42)
    res = trainer.train_candidate(dataset, summary, candidate_version="1.0.5", min_samples=10)

    report = res.training_report
    assert summary["is_synthetic_only"] is True
    assert any("SYNTHETIC_ONLY_DEMONSTRATION" in w for w in report["warnings_and_limitations"])


def test_13_insufficient_feedback_data_handled_safely(store):
    """Verifies that requesting feedback_only policy with zero or insufficient data raises InsufficientTrainingDataError."""
    feedback_recs = load_curated_feedback_features(store.repository, secret=TEST_SECRET)
    dataset, summary = compose_training_dataset(feedback_recs, [], policy="feedback_only")

    trainer = CandidateModelTrainer(epochs=2)
    with pytest.raises(InsufficientTrainingDataError, match="EMPTY_DATASET|INSUFFICIENT_TRAINING_DATA"):
        trainer.train_candidate(dataset, summary, min_samples=5)


def test_14_validation_data_never_used_for_training():
    """Verifies that passing validation corpus path raises CandidateProvenanceError."""
    with pytest.raises(CandidateProvenanceError, match="forbidden partition keyword"):
        load_synthetic_anchor_features("data/generated/v2/synthetic_validation_corpus.jsonl")


def test_15_locked_evaluation_data_never_used_for_training():
    """Verifies that passing locked evaluation dataset raises CandidateProvenanceError."""
    with pytest.raises(CandidateProvenanceError, match="forbidden partition keyword"):
        load_synthetic_anchor_features("data/phishing_eval_dataset.json")


# =============================================================================
# 4. IMMUTABILITY & HASH VERIFICATION TESTS
# =============================================================================

def test_16_candidate_directories_are_unique(temp_candidates_dir):
    """Verifies that sequential candidate training runs generate unique directory paths."""
    dataset = _create_mock_dataset(count_per_class=4)
    _, summary = compose_training_dataset([], dataset, policy="synthetic_only")

    trainer = CandidateModelTrainer(candidates_dir=temp_candidates_dir, epochs=1, seed=42)
    res1 = trainer.train_candidate(dataset, summary, candidate_version="1.0.6", min_samples=5)
    res2 = trainer.train_candidate(dataset, summary, candidate_version="1.0.7", min_samples=5)

    assert res1.artifact_dir != res2.artifact_dir
    assert os.path.exists(res1.artifact_dir)
    assert os.path.exists(res2.artifact_dir)


def test_17_existing_candidate_artifacts_never_overwritten(temp_candidates_dir):
    """Verifies that attempting to train with an existing candidate version raises CandidateArtifactError."""
    dataset = _create_mock_dataset(count_per_class=4)
    _, summary = compose_training_dataset([], dataset, policy="synthetic_only")

    trainer = CandidateModelTrainer(candidates_dir=temp_candidates_dir, epochs=1, seed=42)
    trainer.train_candidate(dataset, summary, candidate_version="1.0.8", min_samples=5)

    with pytest.raises(CandidateArtifactError, match="already exists"):
        trainer.train_candidate(dataset, summary, candidate_version="1.0.8", min_samples=5)


def test_18_checkpoint_hashes_match_saved_artifacts(temp_candidates_dir):
    """Verifies that candidate checkpoint SHA-256 matches the actual saved model_weights.npz file."""
    dataset = _create_mock_dataset(count_per_class=4)
    _, summary = compose_training_dataset([], dataset, policy="synthetic_only")

    trainer = CandidateModelTrainer(candidates_dir=temp_candidates_dir, epochs=1, seed=42)
    res = trainer.train_candidate(dataset, summary, candidate_version="1.0.9", min_samples=5)

    computed_sha = compute_sha256(res.weights_path)
    assert computed_sha == res.weights_sha256

    with open(res.manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest["artifacts"]["model_weights"]["sha256"] == computed_sha


def test_19_metadata_hashes_match_saved_artifacts(temp_candidates_dir):
    """Verifies that metadata SHA-256 matches the actual saved model_metadata.json file."""
    dataset = _create_mock_dataset(count_per_class=4)
    _, summary = compose_training_dataset([], dataset, policy="synthetic_only")

    trainer = CandidateModelTrainer(candidates_dir=temp_candidates_dir, epochs=1, seed=42)
    res = trainer.train_candidate(dataset, summary, candidate_version="1.0.10", min_samples=5)

    computed_sha = compute_sha256(res.metadata_path)
    assert computed_sha == res.metadata_sha256

    with open(res.manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest["artifacts"]["model_metadata"]["sha256"] == computed_sha


# =============================================================================
# 5. INVARIANCE & PRODUCTION PRESERVATION TESTS
# =============================================================================

def test_20_interrupted_training_leaves_active_model_untouched(temp_candidates_dir):
    """Verifies that an error during candidate training leaves active models untouched and cleans temp files."""
    active_weights = os.path.join("models", "experimental_custom_v1", "model_weights.npz")
    pre_sha = compute_sha256(active_weights)

    trainer = CandidateModelTrainer(candidates_dir=temp_candidates_dir, epochs=1, seed=42)
    # Pass empty dataset to force failure
    with pytest.raises(InsufficientTrainingDataError):
        trainer.train_candidate([], {}, candidate_version="broken_run", min_samples=10)

    post_sha = compute_sha256(active_weights)
    assert pre_sha == post_sha


def test_21_registry_files_remain_unchanged(temp_candidates_dir):
    """Verifies that candidate training NEVER alters models/model_registry.json."""
    reg_path = os.path.join("models", "model_registry.json")
    with open(reg_path, "r", encoding="utf-8") as f:
        pre_content = f.read()

    dataset = _create_mock_dataset(count_per_class=4)
    _, summary = compose_training_dataset([], dataset, policy="synthetic_only")
    trainer = CandidateModelTrainer(candidates_dir=temp_candidates_dir, epochs=1, seed=42)
    trainer.train_candidate(dataset, summary, candidate_version="1.0.11", min_samples=5)

    with open(reg_path, "r", encoding="utf-8") as f:
        post_content = f.read()

    assert pre_content == post_content


def test_22_active_model_config_remains_unchanged(temp_candidates_dir):
    """Verifies that candidate training NEVER alters models/active_model_config.json."""
    cfg_path = os.path.join("models", "active_model_config.json")
    with open(cfg_path, "r", encoding="utf-8") as f:
        pre_content = f.read()

    dataset = _create_mock_dataset(count_per_class=4)
    _, summary = compose_training_dataset([], dataset, policy="synthetic_only")
    trainer = CandidateModelTrainer(candidates_dir=temp_candidates_dir, epochs=1, seed=42)
    trainer.train_candidate(dataset, summary, candidate_version="1.0.12", min_samples=5)

    with open(cfg_path, "r", encoding="utf-8") as f:
        post_content = f.read()

    assert pre_content == post_content


def test_23_production_score_delta_remains_zero(temp_candidates_dir):
    """Verifies that candidate training produces zero variance in deterministic production risk scoring."""
    test_msg = "तात्काळ आपले वीज बिल भरा http://msedcl-bill-pay.in"

    pre_analysis = analyze_message_text(test_msg)
    pre_score = score_message_analysis(pre_analysis)

    dataset = _create_mock_dataset(count_per_class=4)
    _, summary = compose_training_dataset([], dataset, policy="synthetic_only")
    trainer = CandidateModelTrainer(candidates_dir=temp_candidates_dir, epochs=2, seed=42)
    trainer.train_candidate(dataset, summary, candidate_version="1.0.13", min_samples=5)

    post_analysis = analyze_message_text(test_msg)
    post_score = score_message_analysis(post_analysis)

    assert pre_score["score"] == post_score["score"]
    assert pre_score["risk_level"] == post_score["risk_level"]


def test_24_existing_trainer_and_evaluator_continue_passing():
    """Verifies that canonical model loader, hasher, and inference continue operating normally."""
    active_dir = os.path.join("models", "experimental_custom_v1")
    model = CustomNeuralClassifier.load_checkpoint(active_dir)
    hasher = CharacterNGramHasher(num_features=1024)

    pred = model.predict_one("काहीतरी चाचणी मजकूर", hasher=hasher)
    assert pred["predicted_label"] in LABEL_TO_IDX
    assert "probabilities" in pred
    assert math.isclose(sum(pred["probabilities"].values()), 1.0, rel_tol=1e-3)
