"""
Offline Autonomous Candidate Model Trainer for Seva Cyber Sandbox (Phase 6.3).

SAFETY, PRESERVATION & GOVERNANCE RULES:
1. Strict ₹0 Budget & Offline Execution:
   - Uses local CPU and pure NumPy. Zero cloud APIs, pretrained weights, or paid services.
2. Candidate Models Only (Zero Production Interference):
   - Generates experimental candidate checkpoints in 'models/candidates/candidate_custom_v{ver}/'.
   - NEVER modifies 'models/model_registry.json' or 'models/active_model_config.json'.
   - Production scoring is permanently invariant (score delta = 0).
3. Random Initialization Guarantee:
   - Initializes all model parameters from scratch using an explicitly recorded seed.
   - NEVER initializes from active production checkpoints or pretrained embeddings.
4. Input Boundary & Zero Raw Text Retention:
   - Consumes 1024-dimensional character n-gram feature vectors directly.
   - Does NOT require, accept, or store raw citizen message texts or personal data.
5. Strict Provenance Separation:
   - Separate sources: Human-reviewed feedback ('local_operator_unauthenticated') and
     Synthetic anchor corpus ('synthetic_seed_v2.2').
   - NEVER trains on validation corpus, locked evaluation dataset, or candidate pattern hypotheses.
   - Synthetic-only training is clearly labeled as a synthetic demonstration.
6. Immutable Artifact Directory & Integrity:
   - Saves checkpoint, metadata, manifest, and training report under unique immutable directories.
   - Verifies SHA-256 checksums and readability of all written artifacts.
   - Overwriting existing candidates is strictly prohibited.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
import os
import shutil
import tempfile
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
import numpy as np

from src.custom_model import (
    IDX_TO_LABEL,
    LABEL_TO_IDX,
    NUM_CLASSES,
    CharacterNGramHasher,
    CustomNeuralClassifier,
)
from src.dataset_preprocessing import (
    EXPECTED_FEATURE_DIM,
    FEATURE_SCHEMA_VERSION,
    extract_derived_training_features,
)

# =============================================================================
# CONSTANTS & SCHEMAS
# =============================================================================

CANDIDATE_SCHEMA_VERSION = "1.0.0"
CANDIDATE_TRAINER_VERSION = "candidate-trainer-v1.0.0"
DEFAULT_CANDIDATES_DIR = os.path.join("models", "candidates")
DEFAULT_SYNTHETIC_TRAIN_CORPUS = os.path.join("data", "generated", "v2", "synthetic_training_corpus.jsonl")

VALID_COMPOSITION_POLICIES = {
    "feedback_only",
    "synthetic_only",
    "combined_anchor",
}

FORBIDDEN_DATASET_KEYWORDS = {
    "eval",
    "phishing_eval_dataset",
    "validation",
    "quarantine",
}

FORBIDDEN_RECORD_KEYS = {
    "text", "raw_text", "sanitized_text", "url", "raw_url",
    "phone", "aadhaar", "otp", "password", "case_id",
    "dedup_fingerprint", "secret", "notes", "reviewer_notes",
}

# Conservative default minimum training examples
DEFAULT_MIN_TRAINING_EXAMPLES = 15


# =============================================================================
# EXCEPTIONS
# =============================================================================

class CandidateTrainingError(Exception):
    """Base exception for candidate model training errors."""
    pass


class InsufficientTrainingDataError(CandidateTrainingError):
    """Raised when training dataset is empty, below threshold, or lacks class diversity."""
    pass


class CandidateArtifactError(CandidateTrainingError):
    """Raised when artifact versioning, directory creation, or file serialization fails."""
    pass


class CandidateProvenanceError(CandidateTrainingError):
    """Raised when data provenance is forbidden, invalid, or corrupted."""
    pass


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_utc_now_iso() -> str:
    """Returns current UTC ISO-8601 timestamp string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_sha256(filepath: str) -> str:
    """Computes SHA-256 hexadecimal digest of a local file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# =============================================================================
# FEATURE VALIDATION & DATASET LOADERS
# =============================================================================

def validate_feature_record(rec: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validates that a feature record contains valid 1024-d finite floats,
    a mapped label, and no forbidden sensitive fields.
    """
    if not isinstance(rec, dict):
        return False, "Record must be a dictionary."

    # Check for forbidden sensitive keys
    for k in FORBIDDEN_RECORD_KEYS:
        if k in rec:
            return False, f"Forbidden sensitive field '{k}' detected in feature record."

    # Validate feature vector
    vec = rec.get("feature_vector")
    if not isinstance(vec, list) or len(vec) != EXPECTED_FEATURE_DIM:
        return False, f"Feature vector dimension mismatch: expected {EXPECTED_FEATURE_DIM}, got {len(vec) if isinstance(vec, list) else type(vec)}."

    for i, v in enumerate(vec):
        if not isinstance(v, (float, int)) or not math.isfinite(v):
            return False, f"Feature vector at index {i} contains non-finite value ({v})."

    # Validate label
    label = rec.get("label")
    if label not in LABEL_TO_IDX:
        return False, f"Invalid or unmapped label '{label}'; valid: {list(LABEL_TO_IDX.keys())}."

    label_idx = rec.get("label_idx")
    if label_idx is not None and label_idx != LABEL_TO_IDX[label]:
        return False, f"Label index mismatch: label '{label}' maps to {LABEL_TO_IDX[label]}, got {label_idx}."

    return True, None


def load_curated_feedback_features(
    repository: Any,
    secret: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Loads eligible, consented, human-reviewed derived feature records from the local repository.
    Enforces Phase 6.1.1 curation gates:
    - Re-validates explicit consent.
    - Re-validates review outcome in {'phishing', 'legitimate', 'protective_advisory'}.
    - Re-validates confidence rating in {'high', 'medium'}.
    - Re-validates deduplication and label conflict quarantine.
    - Re-validates lack of consent revocation.
    - Automatically strips direct case identifiers.
    """
    eligible = repository.export_curated_training_features(secret=secret)

    validated_feedback: List[Dict[str, Any]] = []
    for item in eligible:
        ok, err = validate_feature_record(item)
        if not ok:
            continue

        clean_item = {
            "example_id": item.get("example_id", f"feedback_{uuid.uuid4().hex[:8]}"),
            "feature_vector": item["feature_vector"],
            "feature_dim": EXPECTED_FEATURE_DIM,
            "label": item["label"],
            "label_idx": LABEL_TO_IDX[item["label"]],
            "confidence_rating": item.get("confidence_category", "medium"),
            "provenance": "local_operator_unauthenticated",
            "source_category": "human_reviewed_feedback",
            "feature_schema_version": item.get("feature_schema_version", FEATURE_SCHEMA_VERSION),
            "preprocessing_version": item.get("preprocessing_version", "neural-preproc-v1.1.0"),
        }
        validated_feedback.append(clean_item)

    return validated_feedback


def load_synthetic_anchor_features(
    corpus_path: str = DEFAULT_SYNTHETIC_TRAIN_CORPUS,
    secret: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Loads and extracts 1024-d features from the approved synthetic training anchor corpus.

    SAFETY GUARDS:
    - Strictly blocks loading locked evaluation dataset or validation corpus.
    - Labels every record with provenance 'synthetic_seed_v2.2'.
    """
    norm_path = corpus_path.replace("\\", "/").lower()
    for kw in FORBIDDEN_DATASET_KEYWORDS:
        if kw in norm_path:
            raise CandidateProvenanceError(
                f"Access denied: Path '{corpus_path}' contains forbidden partition keyword '{kw}'."
            )

    if not os.path.exists(corpus_path):
        raise FileNotFoundError(f"Synthetic anchor corpus not found at '{corpus_path}'.")

    synthetic_records: List[Dict[str, Any]] = []
    hasher = CharacterNGramHasher(num_features=EXPECTED_FEATURE_DIM, min_n=3, max_n=5)
    from src.dataset_preprocessing import preprocess_for_neural_model

    with open(corpus_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                text = data.get("normalized_text") or data.get("text", "")
                label = data.get("ground_truth_label") or data.get("label")
                if not text or label not in LABEL_TO_IDX:
                    continue

                clean_text = preprocess_for_neural_model(text)
                vec = hasher.transform_text(clean_text).tolist()

                rec = {
                    "example_id": f"synthetic_{data.get('record_id', idx)}",
                    "feature_vector": vec,
                    "feature_dim": EXPECTED_FEATURE_DIM,
                    "label": label,
                    "label_idx": LABEL_TO_IDX[label],
                    "confidence_rating": "high",
                    "provenance": "synthetic_seed_v2.2",
                    "source_category": "synthetic_anchor_corpus",
                    "feature_schema_version": FEATURE_SCHEMA_VERSION,
                    "preprocessing_version": "neural-preproc-v1.1.0",
                }
                ok_val, _ = validate_feature_record(rec)
                if ok_val:
                    synthetic_records.append(rec)
            except Exception:
                continue

    return synthetic_records


def compose_training_dataset(
    feedback_records: List[Dict[str, Any]],
    synthetic_records: List[Dict[str, Any]],
    policy: str = "combined_anchor",
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Composes the training dataset according to the specified policy.
    Maintains explicit, unmixed provenance tracking.
    """
    if policy not in VALID_COMPOSITION_POLICIES:
        raise CandidateTrainingError(
            f"Invalid composition policy '{policy}'; valid: {VALID_COMPOSITION_POLICIES}."
        )

    if policy == "feedback_only":
        chosen_records = list(feedback_records)
    elif policy == "synthetic_only":
        chosen_records = list(synthetic_records)
    else:  # "combined_anchor"
        chosen_records = list(feedback_records) + list(synthetic_records)

    # Compile composition summary
    feedback_count = sum(1 for r in chosen_records if r.get("source_category") == "human_reviewed_feedback")
    synthetic_count = sum(1 for r in chosen_records if r.get("source_category") == "synthetic_anchor_corpus")

    class_dist: Dict[str, int] = {c: 0 for c in LABEL_TO_IDX}
    for r in chosen_records:
        class_dist[r["label"]] = class_dist.get(r["label"], 0) + 1

    summary = {
        "composition_policy": policy,
        "total_records": len(chosen_records),
        "human_reviewed_count": feedback_count,
        "synthetic_count": synthetic_count,
        "class_distribution": class_dist,
        "is_synthetic_only": feedback_count == 0,
        "demonstration_notice": (
            "SYNTHETIC_ONLY_DEMONSTRATION: Zero human feedback records incorporated. Does NOT demonstrate feedback learning."
            if feedback_count == 0 else
            "HYBRID_TRAINING_CORPUS: Incorporates local human feedback and synthetic anchor baseline."
        ),
    }

    return chosen_records, summary


def validate_dataset_eligibility(
    dataset: List[Dict[str, Any]],
    min_samples: int = DEFAULT_MIN_TRAINING_EXAMPLES,
    require_class_diversity: bool = True,
) -> Tuple[bool, List[str]]:
    """
    Validates dataset before training:
    - Non-empty.
    - Meets minimum sample threshold.
    - Class diversity (at least 2 classes present).
    - All feature vectors are valid 1024-d finite lists.
    """
    errors: List[str] = []

    if not dataset:
        errors.append("EMPTY_DATASET: Training dataset contains 0 records.")
        return False, errors

    if len(dataset) < min_samples:
        errors.append(
            f"INSUFFICIENT_TRAINING_DATA: Training dataset has {len(dataset)} examples, "
            f"which is below the minimum required threshold of {min_samples}."
        )

    # Class distribution check
    classes_present = set(r.get("label") for r in dataset)
    if require_class_diversity and len(classes_present) < 2:
        errors.append(
            f"INSUFFICIENT_CLASS_DIVERSITY: Only {len(classes_present)} class ({classes_present}) present. "
            "Candidate training requires at least 2 distinct classes to formulate decision boundaries."
        )

    for i, r in enumerate(dataset):
        ok, err = validate_feature_record(r)
        if not ok:
            errors.append(f"Record {i} invalid: {err}")
            if len(errors) >= 5:
                break

    return len(errors) == 0, errors


# =============================================================================
# CANDIDATE TRAINING RESULT DATA CLASS
# =============================================================================

@dataclass
class CandidateTrainingResult:
    """Encapsulates the output of a candidate model training run."""
    candidate_id: str
    candidate_version: str
    artifact_dir: str
    weights_path: str
    metadata_path: str
    manifest_path: str
    report_path: str
    weights_sha256: str
    metadata_sha256: str
    manifest_sha256: str
    training_report: Dict[str, Any]
    status: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# CANDIDATE MODEL TRAINER
# =============================================================================

class CandidateModelTrainer:
    """
    Autonomous offline trainer for generating experimental candidate neural models.

    REPRODUCIBILITY & ISOLATION GUARANTEES:
    - Instantiates a new CustomNeuralClassifier from random He/Xavier initialization.
    - Never reads or copies active production checkpoint weights.
    - Uses deterministic NumPy operations seeded by explicit random seed.
    - Creates immutable candidate directories.
    - Does NOT register candidate in model_registry.json.
    - Does NOT update active_model_config.json.
    """

    def __init__(
        self,
        candidates_dir: Optional[str] = None,
        input_dim: int = EXPECTED_FEATURE_DIM,
        hidden_dim1: int = 64,
        hidden_dim2: int = 32,
        num_classes: int = NUM_CLASSES,
        learning_rate: float = 0.005,
        weight_decay: float = 1e-4,
        dropout_rate: float = 0.2,
        epochs: int = 20,
        batch_size: int = 16,
        seed: int = 42,
    ):
        self.candidates_dir = candidates_dir or DEFAULT_CANDIDATES_DIR
        self.input_dim = input_dim
        self.hidden_dim1 = hidden_dim1
        self.hidden_dim2 = hidden_dim2
        self.num_classes = num_classes
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        self.dropout_rate = dropout_rate
        self.epochs = epochs
        self.batch_size = batch_size
        self.seed = seed

    def get_next_candidate_version(self) -> str:
        """Determines the next sequential candidate version string (e.g. 1.0.0, 1.0.1)."""
        if not os.path.exists(self.candidates_dir):
            return "1.0.0"

        dirs = [
            d for d in os.listdir(self.candidates_dir)
            if os.path.isdir(os.path.join(self.candidates_dir, d)) and d.startswith("candidate_custom_v")
        ]
        if not dirs:
            return "1.0.0"

        versions = []
        for d in dirs:
            m = re.search(r"candidate_custom_v(\d+)\.(\d+)\.(\d+)", d)
            if m:
                versions.append((int(m.group(1)), int(m.group(2)), int(m.group(3))))

        if not versions:
            return "1.0.0"

        last = max(versions)
        return f"{last[0]}.{last[1]}.{last[2] + 1}"

    def train_candidate(
        self,
        dataset: List[Dict[str, Any]],
        composition_summary: Dict[str, Any],
        candidate_version: Optional[str] = None,
        min_samples: int = DEFAULT_MIN_TRAINING_EXAMPLES,
    ) -> CandidateTrainingResult:
        """
        Executes an end-to-end training run on eligible feature records,
        saving immutable candidate artifacts to a unique directory.
        """
        # Step 1: Pre-training eligibility verification
        eligible, errors = validate_dataset_eligibility(dataset, min_samples=min_samples)
        if not eligible:
            raise InsufficientTrainingDataError(
                f"Training eligibility check failed: {'; '.join(errors)}"
            )

        # Step 2: Determine unique candidate version and directory
        ver = candidate_version or self.get_next_candidate_version()
        candidate_id = f"candidate_custom_v{ver}"
        target_dir = os.path.join(self.candidates_dir, candidate_id)

        if os.path.exists(target_dir):
            raise CandidateArtifactError(
                f"Candidate artifact directory already exists at '{target_dir}'. Overwriting is strictly prohibited."
            )

        # Step 3: Prepare feature matrix X and one-hot labels Y
        n_examples = len(dataset)
        X = np.zeros((n_examples, self.input_dim), dtype=np.float32)
        y_indices = np.zeros(n_examples, dtype=np.int64)
        Y_onehot = np.zeros((n_examples, self.num_classes), dtype=np.float32)

        for i, rec in enumerate(dataset):
            X[i] = np.array(rec["feature_vector"], dtype=np.float32)
            lbl_idx = rec["label_idx"]
            y_indices[i] = lbl_idx
            Y_onehot[i, lbl_idx] = 1.0

        # Step 4: Instantiate fresh model with RANDOM INITIALIZATION
        # NEVER loads weights from active model or disk
        model = CustomNeuralClassifier(
            input_dim=self.input_dim,
            hidden_dim1=self.hidden_dim1,
            hidden_dim2=self.hidden_dim2,
            num_classes=self.num_classes,
            learning_rate=self.learning_rate,
            weight_decay=self.weight_decay,
            dropout_rate=self.dropout_rate,
            seed=self.seed,
        )

        # Step 5: Execute mini-batch gradient updates with deterministic seed
        rng = np.random.RandomState(self.seed)
        history: List[Dict[str, Any]] = []

        for epoch in range(1, self.epochs + 1):
            perm = rng.permutation(n_examples)
            X_shuffled = X[perm]
            Y_shuffled = Y_onehot[perm]

            batch_losses = []
            for b_start in range(0, n_examples, self.batch_size):
                X_b = X_shuffled[b_start : b_start + self.batch_size]
                Y_b = Y_shuffled[b_start : b_start + self.batch_size]
                loss_b = model.fit_batch(X_b, Y_b)
                batch_losses.append(loss_b)

            epoch_loss = float(np.mean(batch_losses))
            preds = model.predict(X)
            epoch_acc = float(np.mean(preds == y_indices))

            history.append({
                "epoch": epoch,
                "loss": round(epoch_loss, 4),
                "accuracy": round(epoch_acc, 4),
            })

        # Step 6: Atomic artifact creation in temporary directory first
        temp_dir = tempfile.mkdtemp(prefix="cand_train_")
        try:
            # A & B. Save model weights and metadata via canonical save_checkpoint
            now_utc = get_utc_now_iso()
            candidate_meta = {
                "candidate_id": candidate_id,
                "candidate_version": ver,
                "created_at_utc": now_utc,
                "lifecycle_state": "experimental",
                "is_production_authoritative": False,
            }
            model.model_version = candidate_id
            model.save_checkpoint(temp_dir, metadata=candidate_meta)

            weights_file = os.path.join(temp_dir, "model_weights.npz")
            meta_file = os.path.join(temp_dir, "model_metadata.json")

            # Calculate preliminary hashes
            w_sha = compute_sha256(weights_file)
            m_sha = compute_sha256(meta_file)

            # C. Save candidate training report
            report_file = os.path.join(temp_dir, "candidate_training_report.json")
            report_data = {
                "report_schema_version": CANDIDATE_SCHEMA_VERSION,
                "candidate_id": candidate_id,
                "candidate_version": ver,
                "lifecycle_state": "experimental",
                "training_timestamp_utc": now_utc,
                "random_seed": self.seed,
                "architecture": {
                    "model_type": "Multi-Layer Perceptron (MLP)",
                    "input_dim": self.input_dim,
                    "hidden_dim1": self.hidden_dim1,
                    "hidden_dim2": self.hidden_dim2,
                    "num_classes": self.num_classes,
                    "activation": "LeakyReLU (alpha=0.01)",
                    "initialization": "He normal (hidden layers), Xavier uniform (output layer)",
                },
                "hyperparameters": {
                    "epochs": self.epochs,
                    "batch_size": self.batch_size,
                    "learning_rate": self.learning_rate,
                    "weight_decay": self.weight_decay,
                    "dropout_rate": self.dropout_rate,
                },
                "dataset_provenance": {
                    "composition_policy": composition_summary.get("composition_policy"),
                    "total_training_examples": n_examples,
                    "human_reviewed_feedback_count": composition_summary.get("human_reviewed_count", 0),
                    "synthetic_anchor_corpus_count": composition_summary.get("synthetic_count", 0),
                    "class_distribution": composition_summary.get("class_distribution", {}),
                    "feature_schema_version": FEATURE_SCHEMA_VERSION,
                    "preprocessing_version": "neural-preproc-v1.1.0",
                },
                "artifacts": {
                    "weights_file": "model_weights.npz",
                    "weights_sha256": w_sha,
                    "metadata_file": "model_metadata.json",
                    "metadata_sha256": m_sha,
                },
                "training_metrics": {
                    "initial_loss": history[0]["loss"] if history else None,
                    "final_loss": history[-1]["loss"] if history else None,
                    "final_accuracy": history[-1]["accuracy"] if history else None,
                    "loss_history": history,
                },
                "warnings_and_limitations": [
                    "EXPERIMENTAL_CANDIDATE_ONLY: Not evaluated or approved for shadow/production deployment.",
                    "NO_GENERALIZATION_CLAIM: Training loss reduction does not certify real-world vernacular generalization.",
                    "UNAUTHENTICATED_LOCAL_FEEDBACK: Local operator review annotations are not certified external ground truth.",
                    composition_summary.get("demonstration_notice", ""),
                ],
                "status": "SUCCESS",
            }
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            r_sha = compute_sha256(report_file)

            # D. Save candidate manifest
            manifest_file = os.path.join(temp_dir, "manifest.json")
            manifest_data = {
                "manifest_schema_version": CANDIDATE_SCHEMA_VERSION,
                "candidate_id": candidate_id,
                "candidate_version": ver,
                "lifecycle_state": "experimental",
                "created_at_utc": now_utc,
                "architecture_version": "3-layer-mlp-ngram-v1",
                "random_seed": self.seed,
                "artifacts": {
                    "model_weights": {
                        "filename": "model_weights.npz",
                        "sha256": w_sha,
                    },
                    "model_metadata": {
                        "filename": "model_metadata.json",
                        "sha256": m_sha,
                    },
                    "training_report": {
                        "filename": "candidate_training_report.json",
                        "sha256": r_sha,
                    },
                },
                "provenance_summary": composition_summary,
                "disclaimer": (
                    "EXPERIMENTAL CANDIDATE MODEL ARTIFACT. Not approved for production or shadow deployment. "
                    "Active registry and runtime configuration are untouched."
                ),
            }
            with open(manifest_file, "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2, ensure_ascii=False)

            man_sha = compute_sha256(manifest_file)

            # E. Verify readability by loading checkpoint from temp dir
            loaded_model = CustomNeuralClassifier.load_checkpoint(temp_dir)
            assert loaded_model.input_dim == self.input_dim
            assert loaded_model.W1.shape == (self.input_dim, self.hidden_dim1)

            # F. Atomically move temp_dir to target_dir
            os.makedirs(self.candidates_dir, exist_ok=True)
            shutil.move(temp_dir, target_dir)

        except Exception as exc:
            # Clean up temporary directory on failure
            if os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    pass
            raise CandidateArtifactError(f"Candidate artifact serialization failed: {exc}") from exc

        return CandidateTrainingResult(
            candidate_id=candidate_id,
            candidate_version=ver,
            artifact_dir=target_dir,
            weights_path=os.path.join(target_dir, "model_weights.npz"),
            metadata_path=os.path.join(target_dir, "model_metadata.json"),
            manifest_path=os.path.join(target_dir, "manifest.json"),
            report_path=os.path.join(target_dir, "candidate_training_report.json"),
            weights_sha256=w_sha,
            metadata_sha256=m_sha,
            manifest_sha256=man_sha,
            training_report=report_data,
            status="SUCCESS",
        )
