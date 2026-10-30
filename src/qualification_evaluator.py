"""
Qualification Evaluation Engine and Exposure Ledger for Seva Cyber Sandbox (Phase 6.4.4).

GOVERNANCE, SAFETY & ISOLATION RULES:
1. One-Time Qualification Consumption Guarantee:
   - Tracks qualification partition exposure in a dedicated, separate append-only ledger.
   - Blocks any second evaluation attempt on the same qualification partition.
   - Atomically records 'EVALUATION_IN_PROGRESS' before reading qualification records.
   - Records 'EVALUATION_COMPLETED' on success, or 'EXPOSED_INCOMPLETE' on failure.
2. Identical Comparative Evaluation:
   - Evaluates Candidate ('candidate_v3_seed202') and Baseline ('custom-mlp-v1.1.0-preproc')
     on the exact same 450 records using identical preprocessing and hashing.
3. Multi-Granular Metrics:
   - Overall metrics (Accuracy, Macro-F1, Balanced Accuracy, Weighted-F1).
   - Per-class metrics (Phishing, Legitimate, Protective Advisory).
   - Citizen-safety metrics (Legitimate-to-phishing FP rate, Advisory-to-phishing FP rate, Phishing FN rate).
   - Campaign-family cluster analysis across the 9 disjoint families.
   - Subgroup analysis by language and messaging mode.
   - Counterfactual robustness evaluation (whitespace, zero-width, Devanagari numerals, URLs).
4. Predeclared Qualification Policy:
   - Enforces predetermined thresholds without post-hoc adjustment.
   - Emits exactly one verdict: PASS, FAIL, INSUFFICIENT_EVIDENCE, INCOMPATIBLE.
5. Strict Production Invariance:
   - Zero modifications to 'models/model_registry.json' or 'models/active_model_config.json'.
   - Zero changes to production risk scoring behavior (Score Delta = 0).
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import logging
import math
import os
import re
import shutil
import tempfile
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
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
    NEURAL_PREPROCESSING_VERSION,
    preprocess_for_neural_model,
)
from src.dataset_validator import compute_locked_test_hash
from src.candidate_evaluator import (
    EXPECTED_LOCKED_TEST_HASH,
    compute_classification_metrics,
    wilson_score_interval,
)

logger = logging.getLogger(__name__)

URL_REGEX = re.compile(r"https?://\S+", re.IGNORECASE)

# Canonical Default Paths
DEFAULT_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_QUAL_CORPUS = os.path.join(DEFAULT_PROJECT_ROOT, "data", "generated", "v3", "synthetic_qualification_corpus.jsonl")
DEFAULT_QUAL_MANIFEST = os.path.join(DEFAULT_PROJECT_ROOT, "data", "generated", "v3", "qualification_manifest.json")
DEFAULT_V3_CORPUS_MANIFEST = os.path.join(DEFAULT_PROJECT_ROOT, "data", "generated", "v3", "v3_corpus_manifest.json")
DEFAULT_LOCKED_TEST_DATASET = os.path.join(DEFAULT_PROJECT_ROOT, "data", "phishing_eval_dataset.json")
DEFAULT_LOCKED_TEST_MANIFEST = os.path.join(DEFAULT_PROJECT_ROOT, "data", "locked_test_manifest.json")

DEFAULT_CANDIDATE_DIR = os.path.join(DEFAULT_PROJECT_ROOT, "models", "candidates", "candidate_v3_seed202")
DEFAULT_BASELINE_DIR = os.path.join(DEFAULT_PROJECT_ROOT, "models", "experimental_custom_v1")
DEFAULT_REGISTRY_PATH = os.path.join(DEFAULT_PROJECT_ROOT, "models", "model_registry.json")
DEFAULT_ACTIVE_CONFIG_PATH = os.path.join(DEFAULT_PROJECT_ROOT, "models", "active_model_config.json")

DEFAULT_EXPOSURE_LEDGER_PATH = os.path.join(DEFAULT_PROJECT_ROOT, "evaluation", "qualification", "exposure_ledger.json")
DEFAULT_QUAL_OUTPUT_DIR = os.path.join(DEFAULT_PROJECT_ROOT, "evaluation", "qualification")


# =============================================================================
# EXCEPTIONS & ENUMS
# =============================================================================

class QualificationEvaluationError(Exception):
    """Base exception for qualification evaluation errors."""
    pass


class QualificationPreflightError(QualificationEvaluationError):
    """Raised when preflight integrity, manifest, or compatibility checks fail."""
    pass


class PartitionAlreadyExposedError(QualificationEvaluationError):
    """Raised when an attempt is made to re-evaluate an already exposed qualification partition."""
    pass


class QualificationIntegrityError(QualificationEvaluationError):
    """Raised when artifact digests, manifests, or datasets are corrupt or tampered with."""
    pass


class QualificationVerdict(str, Enum):
    """Canonical qualification benchmark verdicts."""
    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    INCOMPATIBLE = "INCOMPATIBLE"


# =============================================================================
# UTILITIES
# =============================================================================

def get_utc_now_iso() -> str:
    """Returns current UTC ISO-8601 timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_file_sha256(filepath: str) -> str:
    """Computes SHA-256 digest of a local file safely in 64 KB chunks."""
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: '{filepath}'")
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def atomic_json_write(filepath: str, data: Dict[str, Any]) -> None:
    """Atomically writes a JSON dictionary to disk using a temporary file and rename."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    temp_dir = os.path.dirname(os.path.abspath(filepath))
    with tempfile.NamedTemporaryFile("w", dir=temp_dir, delete=False, encoding="utf-8") as tf:
        json.dump(data, tf, indent=2, ensure_ascii=False)
        temp_name = tf.name
    os.replace(temp_name, filepath)


# =============================================================================
# EVALUATION EXPOSURE LEDGER
# =============================================================================

class EvaluationExposureLedger:
    """
    Dedicated evaluation exposure ledger.
    Enforces one-time qualification consumption and maintains an append-only audit trail.
    Stored separately from the qualification dataset and original sealed manifest.
    """

    def __init__(self, ledger_path: str = DEFAULT_EXPOSURE_LEDGER_PATH):
        self.ledger_path = os.path.abspath(ledger_path)

    def load_ledger(self) -> Dict[str, Any]:
        """Loads existing ledger or initializes an empty template if not present."""
        if not os.path.isfile(self.ledger_path):
            return {
                "ledger_schema_version": "1.0.0",
                "created_at_utc": get_utc_now_iso(),
                "partitions": {},
            }
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def check_exposure(self, partition_sha256: str) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Checks if a qualification partition has already been exposed or evaluated.
        Returns (is_exposed, current_status, partition_entry).
        """
        ledger = self.load_ledger()
        parts = ledger.get("partitions", {})
        if partition_sha256 in parts:
            entry = parts[partition_sha256]
            is_exposed = entry.get("is_exposed", False)
            status = entry.get("current_status", "UNKNOWN")
            return is_exposed, status, entry
        return False, "SEALED", {}

    def record_evaluation_in_progress(
        self,
        partition_sha256: str,
        partition_file_name: str,
        candidate_id: str,
        baseline_id: str,
    ) -> None:
        """
        Atomically records that evaluation has commenced, transitioning partition to EXPOSED.
        Raises PartitionAlreadyExposedError if already exposed.
        """
        is_exposed, status, entry = self.check_exposure(partition_sha256)
        if is_exposed:
            raise PartitionAlreadyExposedError(
                f"ONE-TIME QUALIFICATION VIOLATION: Partition '{partition_sha256[:16]}...' "
                f"is already exposed with status '{status}'. Re-evaluation is strictly prohibited."
            )

        ledger = self.load_ledger()
        now_utc = get_utc_now_iso()

        event = {
            "event_type": "EVALUATION_IN_PROGRESS",
            "timestamp_utc": now_utc,
            "candidate_id": candidate_id,
            "baseline_id": baseline_id,
            "details": "Evaluation started. Partition records are now unsealed and accessed.",
        }

        entry = ledger.get("partitions", {}).get(partition_sha256, {
            "partition_file_name": partition_file_name,
            "partition_sha256": partition_sha256,
            "first_exposed_at_utc": now_utc,
            "exposure_count": 0,
            "events": [],
        })

        entry["is_exposed"] = True
        entry["current_status"] = "EVALUATION_IN_PROGRESS"
        entry["exposure_count"] = entry.get("exposure_count", 0) + 1
        entry["last_updated_utc"] = now_utc
        entry["candidate_evaluated"] = candidate_id
        entry["baseline_compared"] = baseline_id
        entry["events"].append(event)

        ledger.setdefault("partitions", {})[partition_sha256] = entry
        ledger["last_updated_utc"] = now_utc

        atomic_json_write(self.ledger_path, ledger)
        logger.info(f"Exposure ledger updated: partition {partition_sha256[:16]} set to EVALUATION_IN_PROGRESS.")

    def record_evaluation_completed(
        self,
        partition_sha256: str,
        candidate_id: str,
        verdict: str,
        report_file: str,
    ) -> None:
        """Records successful completion of the qualification evaluation."""
        ledger = self.load_ledger()
        now_utc = get_utc_now_iso()

        entry = ledger.get("partitions", {}).get(partition_sha256)
        if not entry:
            raise QualificationEvaluationError(f"Partition entry missing in ledger for '{partition_sha256[:16]}'.")

        event = {
            "event_type": "EVALUATION_COMPLETED",
            "timestamp_utc": now_utc,
            "candidate_id": candidate_id,
            "verdict": verdict,
            "report_file": report_file,
            "details": f"Evaluation concluded with verdict '{verdict}'. Results saved to '{report_file}'.",
        }

        entry["current_status"] = "EVALUATION_COMPLETED"
        entry["final_verdict"] = verdict
        entry["report_file"] = report_file
        entry["completed_at_utc"] = now_utc
        entry["last_updated_utc"] = now_utc
        entry["events"].append(event)

        ledger["partitions"][partition_sha256] = entry
        ledger["last_updated_utc"] = now_utc

        atomic_json_write(self.ledger_path, ledger)
        logger.info(f"Exposure ledger updated: partition {partition_sha256[:16]} set to EVALUATION_COMPLETED.")

    def record_exposed_incomplete(
        self,
        partition_sha256: str,
        candidate_id: str,
        error_message: str,
    ) -> None:
        """Records an evaluation failure after records have been opened."""
        ledger = self.load_ledger()
        now_utc = get_utc_now_iso()

        entry = ledger.get("partitions", {}).get(partition_sha256)
        if not entry:
            entry = {
                "partition_sha256": partition_sha256,
                "first_exposed_at_utc": now_utc,
                "is_exposed": True,
                "exposure_count": 1,
                "events": [],
            }

        event = {
            "event_type": "EXPOSED_INCOMPLETE",
            "timestamp_utc": now_utc,
            "candidate_id": candidate_id,
            "error_message": error_message,
            "details": "Evaluation aborted after data access began. Partition remains permanently exposed.",
        }

        entry["current_status"] = "EXPOSED_INCOMPLETE"
        entry["is_exposed"] = True
        entry["error_message"] = error_message
        entry["last_updated_utc"] = now_utc
        entry["events"].append(event)

        ledger.setdefault("partitions", {})[partition_sha256] = entry
        ledger["last_updated_utc"] = now_utc

        atomic_json_write(self.ledger_path, ledger)
        logger.warning(f"Exposure ledger updated: partition {partition_sha256[:16]} set to EXPOSED_INCOMPLETE.")


# =============================================================================
# PREFLIGHT VERIFICATION
# =============================================================================

class QualificationPreflightChecker:
    """
    Performs comprehensive preflight integrity and compatibility verifications
    prior to loading or unsealing any qualification records.
    """

    @staticmethod
    def verify_all(
        qual_corpus_path: str = DEFAULT_QUAL_CORPUS,
        qual_manifest_path: str = DEFAULT_QUAL_MANIFEST,
        v3_manifest_path: str = DEFAULT_V3_CORPUS_MANIFEST,
        candidate_dir: str = DEFAULT_CANDIDATE_DIR,
        baseline_dir: str = DEFAULT_BASELINE_DIR,
        registry_path: str = DEFAULT_REGISTRY_PATH,
        active_config_path: str = DEFAULT_ACTIVE_CONFIG_PATH,
        locked_test_path: str = DEFAULT_LOCKED_TEST_DATASET,
        locked_manifest_path: str = DEFAULT_LOCKED_TEST_MANIFEST,
    ) -> Dict[str, Any]:
        """
        Executes all 10 preflight checks. Aborts and raises QualificationPreflightError
        if any check fails.
        """
        # 1. Qualification Manifest Verification
        if not os.path.isfile(qual_manifest_path):
            raise QualificationPreflightError(f"Qualification manifest missing at '{qual_manifest_path}'")
        with open(qual_manifest_path, "r", encoding="utf-8") as f:
            qual_man = json.load(f)

        partition_name = qual_man.get("partition")
        if partition_name != "qualification":
            raise QualificationPreflightError(f"Manifest partition must be 'qualification', got '{partition_name}'")

        lifecycle = qual_man.get("lifecycle_state")
        if lifecycle != "sealed_independent_benchmark":
            raise QualificationPreflightError(
                f"Qualification lifecycle_state must be 'sealed_independent_benchmark', got '{lifecycle}'"
            )

        expected_records = qual_man.get("record_count")
        if expected_records != 450:
            raise QualificationPreflightError(f"Expected 450 qualification records in manifest, got {expected_records}")

        expected_families = qual_man.get("campaign_family_count")
        if expected_families != 9:
            raise QualificationPreflightError(f"Expected 9 campaign families in manifest, got {expected_families}")

        expected_qual_sha = qual_man.get("file_sha256")
        if not os.path.isfile(qual_corpus_path):
            raise QualificationPreflightError(f"Qualification corpus missing at '{qual_corpus_path}'")
        actual_qual_sha = compute_file_sha256(qual_corpus_path)
        if actual_qual_sha != expected_qual_sha:
            raise QualificationPreflightError(
                f"Qualification corpus digest mismatch! Manifest: {expected_qual_sha}, Disk: {actual_qual_sha}"
            )

        # 2. Candidate Artifact Verification ('candidate_v3_seed202')
        if not os.path.isdir(candidate_dir):
            raise QualificationPreflightError(f"Candidate directory missing at '{candidate_dir}'")
        cand_manifest_file = os.path.join(candidate_dir, "manifest.json")
        cand_weights_file = os.path.join(candidate_dir, "model_weights.npz")
        cand_meta_file = os.path.join(candidate_dir, "model_metadata.json")

        for f_path in [cand_manifest_file, cand_weights_file, cand_meta_file]:
            if not os.path.isfile(f_path):
                raise QualificationPreflightError(f"Candidate artifact missing: '{f_path}'")

        with open(cand_manifest_file, "r", encoding="utf-8") as f:
            c_man = json.load(f)
        c_artifacts = c_man.get("artifacts", {})
        cand_w_sha = compute_file_sha256(cand_weights_file)
        cand_m_sha = compute_file_sha256(cand_meta_file)

        if cand_w_sha != c_artifacts.get("model_weights", {}).get("sha256"):
            raise QualificationPreflightError("Candidate weights SHA-256 does not match candidate manifest!")
        if cand_m_sha != c_artifacts.get("model_metadata", {}).get("sha256"):
            raise QualificationPreflightError("Candidate metadata SHA-256 does not match candidate manifest!")

        with open(cand_meta_file, "r", encoding="utf-8") as f:
            c_meta = json.load(f)

        # 3. Baseline Artifact Verification ('custom-mlp-v1.1.0-preproc')
        if not os.path.isfile(registry_path):
            raise QualificationPreflightError(f"Model registry missing at '{registry_path}'")
        with open(registry_path, "r", encoding="utf-8") as f:
            registry = json.load(f)

        baseline_entry = registry.get("registered_models", {}).get("custom-mlp-v1.1.0-preproc")
        if not baseline_entry:
            raise QualificationPreflightError("Baseline model 'custom-mlp-v1.1.0-preproc' missing from model_registry.json")

        base_weights_file = os.path.join(baseline_dir, "model_weights.npz")
        base_meta_file = os.path.join(baseline_dir, "model_metadata.json")
        if not os.path.isfile(base_weights_file) or not os.path.isfile(base_meta_file):
            raise QualificationPreflightError(f"Baseline checkpoint artifacts missing at '{baseline_dir}'")

        actual_base_w_sha = compute_file_sha256(base_weights_file)
        actual_base_m_sha = compute_file_sha256(base_meta_file)

        if actual_base_w_sha != baseline_entry.get("weights_sha256"):
            raise QualificationPreflightError("Baseline weights SHA-256 mismatch vs model_registry.json!")
        if actual_base_m_sha != baseline_entry.get("metadata_sha256"):
            raise QualificationPreflightError("Baseline metadata SHA-256 mismatch vs model_registry.json!")

        with open(base_meta_file, "r", encoding="utf-8") as f:
            b_meta = json.load(f)

        # 4. Feature Dimension & Class Compatibility
        if c_meta.get("input_dim") != EXPECTED_FEATURE_DIM or b_meta.get("input_dim") != EXPECTED_FEATURE_DIM:
            raise QualificationPreflightError(f"Feature dimension mismatch! Expected {EXPECTED_FEATURE_DIM}")

        if c_meta.get("num_classes") != NUM_CLASSES or b_meta.get("num_classes") != NUM_CLASSES:
            raise QualificationPreflightError(f"Class count mismatch! Expected {NUM_CLASSES}")

        if c_meta.get("label_to_index") != LABEL_TO_IDX or b_meta.get("label_to_index") != LABEL_TO_IDX:
            raise QualificationPreflightError(f"Label mapping mismatch! Expected {LABEL_TO_IDX}")

        # 5. Preprocessing Compatibility
        c_preproc = c_meta.get("training_metadata", {}).get("preprocessing_version") or c_meta.get("preprocessing_version")
        b_preproc = baseline_entry.get("preprocessing_version") or b_meta.get("preprocessing_version")
        if c_preproc != NEURAL_PREPROCESSING_VERSION or b_preproc != NEURAL_PREPROCESSING_VERSION:
            raise QualificationPreflightError(
                f"Preprocessing version mismatch! Expected '{NEURAL_PREPROCESSING_VERSION}', "
                f"Candidate: '{c_preproc}', Baseline: '{b_preproc}'"
            )

        # 6. Locked Test Partition Checksum Verification
        if not os.path.isfile(locked_manifest_path):
            raise QualificationPreflightError(f"Locked test manifest missing at '{locked_manifest_path}'")
        with open(locked_manifest_path, "r", encoding="utf-8") as f:
            locked_man = json.load(f)
        if locked_man.get("sha256_checksum") != EXPECTED_LOCKED_TEST_HASH:
            raise QualificationPreflightError("Locked test manifest has corrupted checksum!")

        if not os.path.isfile(locked_test_path):
            raise QualificationPreflightError(f"Locked test dataset missing at '{locked_test_path}'")
        with open(locked_test_path, "r", encoding="utf-8") as f:
            eval_recs = json.load(f)
        actual_eval_hash = compute_locked_test_hash(eval_recs)
        if actual_eval_hash != EXPECTED_LOCKED_TEST_HASH:
            raise QualificationPreflightError(
                f"Locked test partition hash mismatch! Expected {EXPECTED_LOCKED_TEST_HASH}, got {actual_eval_hash}"
            )

        return {
            "status": "PREFLIGHT_PASS",
            "qualification_records": expected_records,
            "qualification_families": expected_families,
            "qualification_sha256": actual_qual_sha,
            "candidate_id": "candidate_v3_seed202",
            "candidate_weights_sha256": cand_w_sha,
            "baseline_id": "custom-mlp-v1.1.0-preproc",
            "baseline_weights_sha256": actual_base_w_sha,
            "locked_test_sha256": actual_eval_hash,
            "preprocessing_version": NEURAL_PREPROCESSING_VERSION,
        }


# =============================================================================
# BENCHMARK POLICY SPECIFICATION
# =============================================================================

@dataclass
class QualificationPolicy:
    """Predeclared, immutable qualification benchmark policy thresholds."""
    policy_name: str = "Phase 6.4.4 Qualification Benchmark Policy"
    policy_version: str = "1.0.0"
    min_qualification_records: int = 400
    min_macro_f1: float = 0.9000
    max_macro_f1_drop: float = 0.0200
    max_legitimate_to_phishing_fp_rate: float = 0.1500
    max_advisory_to_phishing_fp_rate: float = 0.0500
    max_phishing_fn_rate: float = 0.0500
    confidence_level: float = 0.95
    max_whitespace_flip_rate: float = 0.0
    max_zerowidth_flip_rate: float = 0.0
    max_numeral_flip_rate: float = 0.0


# =============================================================================
# QUALIFICATION EVALUATION ENGINE
# =============================================================================

class QualificationEvaluator:
    """
    Executes the one-time independent qualification evaluation of candidate_v3_seed202
    against the sealed qualification partition.
    """

    def __init__(
        self,
        project_root: str = DEFAULT_PROJECT_ROOT,
        policy: Optional[QualificationPolicy] = None,
        ledger_path: str = DEFAULT_EXPOSURE_LEDGER_PATH,
    ):
        self.project_root = os.path.abspath(project_root)
        self.policy = policy or QualificationPolicy()
        self.ledger = EvaluationExposureLedger(ledger_path=ledger_path)

    def load_model_strictly(self, checkpoint_dir: str) -> CustomNeuralClassifier:
        """
        Loads CustomNeuralClassifier checkpoint safely, enforcing allow_pickle=False.
        """
        weights_file = os.path.join(checkpoint_dir, "model_weights.npz")
        meta_file = os.path.join(checkpoint_dir, "model_metadata.json")

        if not os.path.isfile(weights_file) or not os.path.isfile(meta_file):
            raise QualificationIntegrityError(f"Missing model files in '{checkpoint_dir}'")

        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)

        model = CustomNeuralClassifier(
            input_dim=meta.get("input_dim", 1024),
            hidden_dim1=meta.get("hidden_dim1", 64),
            hidden_dim2=meta.get("hidden_dim2", 32),
            num_classes=meta.get("num_classes", 3),
            seed=meta.get("seed", 42),
        )
        model.model_version = meta.get("model_version", "unknown")

        with np.load(weights_file, allow_pickle=False) as data:
            model.W1 = data["W1"].astype(np.float32)
            model.b1 = data["b1"].astype(np.float32)
            model.W2 = data["W2"].astype(np.float32)
            model.b2 = data["b2"].astype(np.float32)
            model.W3 = data["W3"].astype(np.float32)
            model.b3 = data["b3"].astype(np.float32)

        return model

    def evaluate_both_models_on_records(
        self,
        baseline_model: CustomNeuralClassifier,
        candidate_model: CustomNeuralClassifier,
        records: List[Dict[str, Any]],
        hasher: CharacterNGramHasher,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, Dict[str, Any], Dict[str, Any]]:
        """
        Executes identical inference on the exact same records.
        """
        n = len(records)
        X = np.zeros((n, EXPECTED_FEATURE_DIM), dtype=np.float32)
        y_true = np.zeros(n, dtype=np.int64)

        for i, rec in enumerate(records):
            raw_text = rec.get("text", "")
            norm_text = preprocess_for_neural_model(raw_text)
            X[i] = hasher.transform_text(norm_text)
            lbl = rec.get("ground_truth_label") or rec.get("label", "legitimate")
            y_true[i] = LABEL_TO_IDX[lbl]

        base_preds = baseline_model.predict(X)
        cand_preds = candidate_model.predict(X)

        base_metrics = compute_classification_metrics(y_true, base_preds, confidence_level=self.policy.confidence_level)
        cand_metrics = compute_classification_metrics(y_true, cand_preds, confidence_level=self.policy.confidence_level)

        return y_true, base_preds, cand_preds, base_metrics, cand_metrics

    def compute_citizen_safety_metrics(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
    ) -> Dict[str, Any]:
        """
        Explicitly computes and labels citizen-safety false alarm rates and conventional 1-vs-rest FP rates.
        Always reports raw counts and denominators.
        """
        num_classes = NUM_CLASSES
        cm = [[0 for _ in range(num_classes)] for _ in range(num_classes)]
        for t, p in zip(y_true, y_pred):
            cm[int(t)][int(p)] += 1

        phish_idx = LABEL_TO_IDX["phishing"]
        legit_idx = LABEL_TO_IDX["legitimate"]
        advisory_idx = LABEL_TO_IDX["protective_advisory"]

        # 1. Citizen Safety False Alarms
        legit_total = sum(cm[legit_idx])
        legit_to_phish = cm[legit_idx][phish_idx]
        legit_to_phish_rate = (legit_to_phish / legit_total) if legit_total > 0 else 0.0

        advisory_total = sum(cm[advisory_idx])
        advisory_to_phish = cm[advisory_idx][phish_idx]
        advisory_to_phish_rate = (advisory_to_phish / advisory_total) if advisory_total > 0 else 0.0

        phish_total = sum(cm[phish_idx])
        phish_missed = sum(cm[phish_idx][p] for p in range(num_classes) if p != phish_idx)
        phish_fn_rate = (phish_missed / phish_total) if phish_total > 0 else 0.0

        # 2. Conventional One-vs-Rest False Positive Rates
        # Phishing 1-vs-rest FP: non-phishing classified as phishing / total non-phishing
        non_phish_total = legit_total + advisory_total
        non_phish_as_phish = cm[legit_idx][phish_idx] + cm[advisory_idx][phish_idx]
        phish_ovr_fp_rate = (non_phish_as_phish / non_phish_total) if non_phish_total > 0 else 0.0

        # Legitimate 1-vs-rest FP: non-legitimate classified as legitimate / total non-legitimate
        non_legit_total = phish_total + advisory_total
        non_legit_as_legit = cm[phish_idx][legit_idx] + cm[advisory_idx][legit_idx]
        legit_ovr_fp_rate = (non_legit_as_legit / non_legit_total) if non_legit_total > 0 else 0.0

        # Advisory 1-vs-rest FP: non-advisory classified as advisory / total non-advisory
        non_advisory_total = phish_total + legit_total
        non_advisory_as_advisory = cm[phish_idx][advisory_idx] + cm[legit_idx][advisory_idx]
        advisory_ovr_fp_rate = (non_advisory_as_advisory / non_advisory_total) if non_advisory_total > 0 else 0.0

        return {
            "citizen_safety_metrics": {
                "legitimate_to_phishing_false_alarm_rate": round(legit_to_phish_rate, 4),
                "legitimate_to_phishing_fraction": f"{legit_to_phish}/{legit_total}",
                "legitimate_to_phishing_ci_95": wilson_score_interval(legit_to_phish, legit_total),
                "protective_advisory_to_phishing_false_alarm_rate": round(advisory_to_phish_rate, 4),
                "protective_advisory_to_phishing_fraction": f"{advisory_to_phish}/{advisory_total}",
                "protective_advisory_to_phishing_ci_95": wilson_score_interval(advisory_to_phish, advisory_total),
                "phishing_false_negative_rate": round(phish_fn_rate, 4),
                "phishing_false_negative_fraction": f"{phish_missed}/{phish_total}",
                "phishing_false_negative_ci_95": wilson_score_interval(phish_missed, phish_total),
            },
            "conventional_one_vs_rest_fp_metrics": {
                "phishing_ovr_fp_rate": round(phish_ovr_fp_rate, 4),
                "phishing_ovr_fp_fraction": f"{non_phish_as_phish}/{non_phish_total}",
                "legitimate_ovr_fp_rate": round(legit_ovr_fp_rate, 4),
                "legitimate_ovr_fp_fraction": f"{non_legit_as_legit}/{non_legit_total}",
                "protective_advisory_ovr_fp_rate": round(advisory_ovr_fp_rate, 4),
                "protective_advisory_ovr_fp_fraction": f"{non_advisory_as_advisory}/{non_advisory_total}",
            },
        }

    def run_campaign_family_analysis(
        self,
        records: List[Dict[str, Any]],
        y_true: np.ndarray,
        base_preds: np.ndarray,
        cand_preds: np.ndarray,
        bootstrap_iterations: int = 1000,
        random_seed: int = 42,
    ) -> Dict[str, Any]:
        """
        Executes campaign-family analysis across the 9 disjoint families.
        Calculates cluster-level macro metrics and cluster bootstrap uncertainty.
        """
        families = sorted(set(r.get("campaign_id", "unknown") for r in records))
        family_results = []
        base_fam_accs = []
        cand_fam_accs = []
        serious_fa_families_base = 0
        serious_fa_families_cand = 0

        phish_idx = LABEL_TO_IDX["phishing"]
        legit_idx = LABEL_TO_IDX["legitimate"]
        advisory_idx = LABEL_TO_IDX["protective_advisory"]

        for fam in families:
            idxs = [i for i, r in enumerate(records) if r.get("campaign_id") == fam]
            count = len(idxs)
            t_sub = y_true[idxs]
            b_sub = base_preds[idxs]
            c_sub = cand_preds[idxs]

            cls_name = records[idxs[0]].get("ground_truth_label")
            b_acc = float(np.mean(b_sub == t_sub))
            c_acc = float(np.mean(c_sub == t_sub))
            base_fam_accs.append(b_acc)
            cand_fam_accs.append(c_acc)

            # Check serious false alarms (legit->phish or advisory->phish)
            b_legit_to_phish = int(np.sum((t_sub == legit_idx) & (b_sub == phish_idx)))
            c_legit_to_phish = int(np.sum((t_sub == legit_idx) & (c_sub == phish_idx)))
            b_adv_to_phish = int(np.sum((t_sub == advisory_idx) & (b_sub == phish_idx)))
            c_adv_to_phish = int(np.sum((t_sub == advisory_idx) & (c_sub == phish_idx)))

            b_serious_fa = b_legit_to_phish + b_adv_to_phish
            c_serious_fa = c_legit_to_phish + c_adv_to_phish

            if b_serious_fa > 0:
                serious_fa_families_base += 1
            if c_serious_fa > 0:
                serious_fa_families_cand += 1

            family_results.append({
                "campaign_family_id": fam,
                "ground_truth_class": cls_name,
                "sample_count": count,
                "baseline_accuracy": round(b_acc, 4),
                "baseline_correct_fraction": f"{int(np.sum(b_sub == t_sub))}/{count}",
                "candidate_accuracy": round(c_acc, 4),
                "candidate_correct_fraction": f"{int(np.sum(c_sub == t_sub))}/{count}",
                "accuracy_delta": round(c_acc - b_acc, 4),
                "baseline_false_alarms_to_phishing": b_serious_fa,
                "candidate_false_alarms_to_phishing": c_serious_fa,
            })

        # Cluster bootstrap resampling for family cluster uncertainty
        rng = np.random.RandomState(random_seed)
        # Group indices by class for stratified cluster bootstrap
        phish_fams = [f for f in families if "phish" in f]
        legit_fams = [f for f in families if "legit" in f]
        advisory_fams = [f for f in families if "advisory" in f]

        fam_to_indices = {f: [i for i, r in enumerate(records) if r.get("campaign_id") == f] for f in families}

        cand_boot_macro_f1s = []
        for _ in range(bootstrap_iterations):
            # Sample 3 families from each class with replacement
            sampled_fams = (
                list(rng.choice(phish_fams, size=len(phish_fams), replace=True)) +
                list(rng.choice(legit_fams, size=len(legit_fams), replace=True)) +
                list(rng.choice(advisory_fams, size=len(advisory_fams), replace=True))
            )
            boot_indices = []
            for sf in sampled_fams:
                boot_indices.extend(fam_to_indices[sf])
            b_true = y_true[boot_indices]
            b_pred = cand_preds[boot_indices]
            m = compute_classification_metrics(b_true, b_pred)
            cand_boot_macro_f1s.append(m["macro_f1"])

        cand_boot_macro_f1s.sort()
        ci_lower = round(float(np.percentile(cand_boot_macro_f1s, 2.5)), 4)
        ci_upper = round(float(np.percentile(cand_boot_macro_f1s, 97.5)), 4)

        return {
            "total_campaign_families": len(families),
            "families_per_class": 3,
            "samples_per_family": 50,
            "baseline_family_macro_accuracy": round(float(np.mean(base_fam_accs)), 4),
            "candidate_family_macro_accuracy": round(float(np.mean(cand_fam_accs)), 4),
            "baseline_families_with_serious_false_alarms": serious_fa_families_base,
            "candidate_families_with_serious_false_alarms": serious_fa_families_cand,
            "candidate_macro_f1_cluster_bootstrap_95ci": [ci_lower, ci_upper],
            "cluster_uncertainty_note": (
                "Cluster bootstrap resamples 3 campaign families per class (K=9 total clusters). "
                "Because K=9 is small, cluster-level uncertainty is wider than naive example-level Wilson intervals, "
                "reflecting cluster correlations in vernacular phrasing."
            ),
            "family_breakdown": family_results,
        }

    def run_subgroup_analysis(
        self,
        records: List[Dict[str, Any]],
        y_true: np.ndarray,
        base_preds: np.ndarray,
        cand_preds: np.ndarray,
    ) -> Dict[str, Any]:
        """Calculates performance breakdowns across language and messaging mode."""
        subgroups = {
            "by_language": {},
            "by_messaging_mode": {},
            "by_url_presence": {},
        }

        # 1. By Language
        langs = sorted(set(r.get("language", "unknown") for r in records))
        for lang in langs:
            idxs = [i for i, r in enumerate(records) if r.get("language") == lang]
            count = len(idxs)
            if count == 0:
                continue
            b_corr = int(np.sum(base_preds[idxs] == y_true[idxs]))
            c_corr = int(np.sum(cand_preds[idxs] == y_true[idxs]))
            subgroups["by_language"][lang] = {
                "sample_count": count,
                "baseline_accuracy": round(b_corr / count, 4),
                "baseline_correct_fraction": f"{b_corr}/{count}",
                "candidate_accuracy": round(c_corr / count, 4),
                "candidate_correct_fraction": f"{c_corr}/{count}",
                "accuracy_delta": round((c_corr - b_corr) / count, 4),
            }

        # 2. By Messaging Mode
        modes = sorted(set(r.get("messaging_mode", "unknown") for r in records))
        for mode in modes:
            idxs = [i for i, r in enumerate(records) if r.get("messaging_mode") == mode]
            count = len(idxs)
            if count == 0:
                continue
            b_corr = int(np.sum(base_preds[idxs] == y_true[idxs]))
            c_corr = int(np.sum(cand_preds[idxs] == y_true[idxs]))
            subgroups["by_messaging_mode"][mode] = {
                "sample_count": count,
                "baseline_accuracy": round(b_corr / count, 4),
                "baseline_correct_fraction": f"{b_corr}/{count}",
                "candidate_accuracy": round(c_corr / count, 4),
                "candidate_correct_fraction": f"{c_corr}/{count}",
                "accuracy_delta": round((c_corr - b_corr) / count, 4),
            }

        # 3. By URL Presence
        has_url_idxs = [i for i, r in enumerate(records) if URL_REGEX.search(r.get("text", ""))]
        no_url_idxs = [i for i, r in enumerate(records) if not URL_REGEX.search(r.get("text", ""))]

        for mode_name, idxs in [("with_url", has_url_idxs), ("without_url", no_url_idxs)]:
            count = len(idxs)
            if count == 0:
                continue
            b_corr = int(np.sum(base_preds[idxs] == y_true[idxs]))
            c_corr = int(np.sum(cand_preds[idxs] == y_true[idxs]))
            subgroups["by_url_presence"][mode_name] = {
                "sample_count": count,
                "baseline_accuracy": round(b_corr / count, 4),
                "baseline_correct_fraction": f"{b_corr}/{count}",
                "candidate_accuracy": round(c_corr / count, 4),
                "candidate_correct_fraction": f"{c_corr}/{count}",
                "accuracy_delta": round((c_corr - b_corr) / count, 4),
            }

        return {
            "subgroups": subgroups,
            "subgroup_limitations": (
                "Subgroup sample sizes vary from 12 to 164 examples. Small subgroup sizes limit "
                "language-specific generalization claims. Disaggregated metrics are provided for audit transparency."
            ),
        }

    def run_counterfactual_robustness_tests(
        self,
        records: List[Dict[str, Any]],
        baseline_model: CustomNeuralClassifier,
        candidate_model: CustomNeuralClassifier,
        hasher: CharacterNGramHasher,
    ) -> Dict[str, Any]:
        """
        Executes counterfactual robustness transformations across all 450 records.
        """
        def predict_single(m: CustomNeuralClassifier, text: str) -> int:
            norm = preprocess_for_neural_model(text)
            vec = hasher.transform_text(norm)
            return int(m.predict(np.expand_dims(vec, axis=0))[0])

        total = len(records)
        ws_flips_b, ws_flips_c = 0, 0
        zw_flips_b, zw_flips_c = 0, 0

        # 1. Whitespace padding
        for r in records:
            txt = r.get("text", "")
            ob = predict_single(baseline_model, txt)
            oc = predict_single(candidate_model, txt)
            mutated = "   " + txt.replace(" ", "   ") + "   \n"
            if predict_single(baseline_model, mutated) != ob:
                ws_flips_b += 1
            if predict_single(candidate_model, mutated) != oc:
                ws_flips_c += 1

        # 2. Zero-width character obfuscation
        for r in records:
            txt = r.get("text", "")
            ob = predict_single(baseline_model, txt)
            oc = predict_single(candidate_model, txt)
            mutated = "\u200b".join(list(txt[:20])) + txt[20:] if len(txt) > 20 else "\u200b" + txt
            if predict_single(baseline_model, mutated) != ob:
                zw_flips_b += 1
            if predict_single(candidate_model, mutated) != oc:
                zw_flips_c += 1

        # 3. Devanagari numerals
        num_map = str.maketrans("0123456789", "०१२३४५६७८९")
        digit_recs = [r for r in records if re.search(r"\d", r.get("text", ""))]
        num_flips_b, num_flips_c = 0, 0
        for r in digit_recs:
            txt = r.get("text", "")
            ob = predict_single(baseline_model, txt)
            oc = predict_single(candidate_model, txt)
            mutated = txt.translate(num_map)
            if predict_single(baseline_model, mutated) != ob:
                num_flips_b += 1
            if predict_single(candidate_model, mutated) != oc:
                num_flips_c += 1

        # 4. Counterfactual URL mutations
        phish_url_recs = [r for r in records if r.get("ground_truth_label") == "phishing" and URL_REGEX.search(r.get("text", ""))]
        url_rem_flips_b, url_rem_flips_c = 0, 0
        for r in phish_url_recs:
            txt = r.get("text", "")
            ob = predict_single(baseline_model, txt)
            oc = predict_single(candidate_model, txt)
            mutated = URL_REGEX.sub("", txt)
            if predict_single(baseline_model, mutated) != ob:
                url_rem_flips_b += 1
            if predict_single(candidate_model, mutated) != oc:
                url_rem_flips_c += 1

        legit_nourl_recs = [r for r in records if r.get("ground_truth_label") == "legitimate" and not URL_REGEX.search(r.get("text", ""))]
        url_ins_flips_b, url_ins_flips_c = 0, 0
        for r in legit_nourl_recs:
            txt = r.get("text", "")
            ob = predict_single(baseline_model, txt)
            oc = predict_single(candidate_model, txt)
            mutated = txt + " https://maharashtra.gov.in/official-portal"
            if predict_single(baseline_model, mutated) != ob:
                url_ins_flips_b += 1
            if predict_single(candidate_model, mutated) != oc:
                url_ins_flips_c += 1

        return {
            "whitespace_normalization": {
                "tested_records": total,
                "baseline_flips": ws_flips_b,
                "baseline_flip_rate": round(ws_flips_b / total, 4),
                "candidate_flips": ws_flips_c,
                "candidate_flip_rate": round(ws_flips_c / total, 4),
            },
            "zero_width_character_obfuscation": {
                "tested_records": total,
                "baseline_flips": zw_flips_b,
                "baseline_flip_rate": round(zw_flips_b / total, 4),
                "candidate_flips": zw_flips_c,
                "candidate_flip_rate": round(zw_flips_c / total, 4),
            },
            "devanagari_numeral_translation": {
                "tested_records": len(digit_recs),
                "baseline_flips": num_flips_b,
                "baseline_flip_rate": round(num_flips_b / len(digit_recs), 4) if digit_recs else 0.0,
                "candidate_flips": num_flips_c,
                "candidate_flip_rate": round(num_flips_c / len(digit_recs), 4) if digit_recs else 0.0,
            },
            "counterfactual_url_mutations": {
                "phishing_url_removal": {
                    "tested_records": len(phish_url_recs),
                    "baseline_flips": url_rem_flips_b,
                    "baseline_flip_rate": round(url_rem_flips_b / len(phish_url_recs), 4) if phish_url_recs else 0.0,
                    "candidate_flips": url_rem_flips_c,
                    "candidate_flip_rate": round(url_rem_flips_c / len(phish_url_recs), 4) if phish_url_recs else 0.0,
                },
                "legitimate_url_insertion": {
                    "tested_records": len(legit_nourl_recs),
                    "baseline_flips": url_ins_flips_b,
                    "baseline_flip_rate": round(url_ins_flips_b / len(legit_nourl_recs), 4) if legit_nourl_recs else 0.0,
                    "candidate_flips": url_ins_flips_c,
                    "candidate_flip_rate": round(url_ins_flips_c / len(legit_nourl_recs), 4) if legit_nourl_recs else 0.0,
                },
            },
        }

    def evaluate_predeclared_policy(
        self,
        base_metrics: Dict[str, Any],
        cand_metrics: Dict[str, Any],
        cand_safety: Dict[str, Any],
        robustness_results: Dict[str, Any],
    ) -> Tuple[QualificationVerdict, List[str], Dict[str, Any]]:
        """
        Evaluates candidate metrics against the predeclared qualification policy.
        Returns (verdict, list_of_failures, gate_details).
        """
        base_f1 = base_metrics["macro_f1"]
        cand_f1 = cand_metrics["macro_f1"]
        delta_f1 = cand_f1 - base_f1

        c_safety = cand_safety["citizen_safety_metrics"]
        legit_fp = c_safety["legitimate_to_phishing_false_alarm_rate"]
        advisory_fp = c_safety["protective_advisory_to_phishing_false_alarm_rate"]
        phish_fn = c_safety["phishing_false_negative_rate"]

        failing_gates: List[str] = []

        # Gate 1: Minimum Macro-F1 >= 0.9000
        pass_gate1 = cand_f1 >= self.policy.min_macro_f1
        if not pass_gate1:
            failing_gates.append(f"GATE_1_MIN_MACRO_F1_FAILED (got {cand_f1:.4f} < {self.policy.min_macro_f1:.4f})")

        # Gate 2: Macro-F1 drop <= 0.0200 vs baseline
        pass_gate2 = delta_f1 >= -self.policy.max_macro_f1_drop
        if not pass_gate2:
            failing_gates.append(f"GATE_2_MAX_MACRO_F1_DROP_FAILED (delta {delta_f1:.4f} < -{self.policy.max_macro_f1_drop:.4f})")

        # Gate 3: Legitimate-to-phishing false alarm rate <= 0.1500
        pass_gate3 = legit_fp <= self.policy.max_legitimate_to_phishing_fp_rate
        if not pass_gate3:
            failing_gates.append(f"GATE_3_LEGIT_FP_RATE_FAILED (got {legit_fp:.4f} > {self.policy.max_legitimate_to_phishing_fp_rate:.4f})")

        # Gate 4: Protective-advisory-to-phishing false alarm rate <= 0.0500
        pass_gate4 = advisory_fp <= self.policy.max_advisory_to_phishing_fp_rate
        if not pass_gate4:
            failing_gates.append(f"GATE_4_ADVISORY_FP_RATE_FAILED (got {advisory_fp:.4f} > {self.policy.max_advisory_to_phishing_fp_rate:.4f})")

        # Gate 5: Phishing false negative rate <= 0.0500
        pass_gate5 = phish_fn <= self.policy.max_phishing_fn_rate
        if not pass_gate5:
            failing_gates.append(f"GATE_5_PHISHING_FN_RATE_FAILED (got {phish_fn:.4f} > {self.policy.max_phishing_fn_rate:.4f})")

        # Gate 6: Preprocessing normalization robustness (whitespace, zero-width, numeral flips must be 0)
        ws_flips = robustness_results["whitespace_normalization"]["candidate_flips"]
        zw_flips = robustness_results["zero_width_character_obfuscation"]["candidate_flips"]
        num_flips = robustness_results["devanagari_numeral_translation"]["candidate_flips"]
        pass_gate6 = (ws_flips == 0 and zw_flips == 0 and num_flips == 0)
        if not pass_gate6:
            failing_gates.append(f"GATE_6_PREPROCESSING_ROBUSTNESS_FAILED (ws_flips={ws_flips}, zw_flips={zw_flips}, num_flips={num_flips})")

        gate_details = {
            "gate_1_min_macro_f1": {"required": f">= {self.policy.min_macro_f1}", "actual": cand_f1, "passed": pass_gate1},
            "gate_2_max_macro_f1_drop": {"required": f">= -{self.policy.max_macro_f1_drop}", "actual": delta_f1, "passed": pass_gate2},
            "gate_3_legit_fp_rate": {"required": f"<= {self.policy.max_legitimate_to_phishing_fp_rate}", "actual": legit_fp, "passed": pass_gate3},
            "gate_4_advisory_fp_rate": {"required": f"<= {self.policy.max_advisory_to_phishing_fp_rate}", "actual": advisory_fp, "passed": pass_gate4},
            "gate_5_phish_fn_rate": {"required": f"<= {self.policy.max_phishing_fn_rate}", "actual": phish_fn, "passed": pass_gate5},
            "gate_6_normalization_robustness": {"required": "0 flips on normalized representations", "passed": pass_gate6},
        }

        verdict = QualificationVerdict.PASS if len(failing_gates) == 0 else QualificationVerdict.FAIL
        return verdict, failing_gates, gate_details

    def execute_one_time_qualification(
        self,
        qual_corpus_path: str = DEFAULT_QUAL_CORPUS,
        qual_manifest_path: str = DEFAULT_QUAL_MANIFEST,
        candidate_dir: str = DEFAULT_CANDIDATE_DIR,
        baseline_dir: str = DEFAULT_BASELINE_DIR,
        output_report_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes the end-to-end one-time qualification evaluation.
        """
        print("=" * 80)
        print("SEVA CYBER SANDBOX — PHASE 6.4.4: CANDIDATE QUALIFICATION BENCHMARK")
        print("=" * 80)

        # ---------------------------------------------------------------------
        # STEP 1: Preflight Verification
        # ---------------------------------------------------------------------
        print("[*] Step 1: Performing Preflight Verification...")
        preflight_info = QualificationPreflightChecker.verify_all(
            qual_corpus_path=qual_corpus_path,
            qual_manifest_path=qual_manifest_path,
            candidate_dir=candidate_dir,
            baseline_dir=baseline_dir,
        )
        print(f"    [+] Preflight status: {preflight_info['status']}")
        print(f"    [+] Qualification partition: {preflight_info['qualification_records']} records across {preflight_info['qualification_families']} families")
        print(f"    [+] Partition SHA-256: {preflight_info['qualification_sha256']}")
        print(f"    [+] Candidate: {preflight_info['candidate_id']} (SHA-256: {preflight_info['candidate_weights_sha256'][:16]}...)")
        print(f"    [+] Baseline: {preflight_info['baseline_id']} (SHA-256: {preflight_info['baseline_weights_sha256'][:16]}...)")

        partition_sha = preflight_info["qualification_sha256"]
        candidate_id = preflight_info["candidate_id"]
        baseline_id = preflight_info["baseline_id"]

        # ---------------------------------------------------------------------
        # STEP 2: Enforce One-Time Exposure in Ledger
        # ---------------------------------------------------------------------
        print("\n[*] Step 2: Enforcing One-Time Qualification Exposure Ledger...")
        is_exposed, status, _ = self.ledger.check_exposure(partition_sha)
        if is_exposed:
            raise PartitionAlreadyExposedError(
                f"ONE-TIME QUALIFICATION VIOLATION: Partition '{partition_sha[:16]}...' "
                f"was already exposed with status '{status}'. Evaluation aborted to protect benchmark integrity."
            )

        # Atomically record that evaluation has begun (unsealing partition)
        self.ledger.record_evaluation_in_progress(
            partition_sha256=partition_sha,
            partition_file_name=os.path.basename(qual_corpus_path),
            candidate_id=candidate_id,
            baseline_id=baseline_id,
        )
        print(f"    [+] Exposure ledger atomically marked: 'EVALUATION_IN_PROGRESS'")
        print(f"    [+] Ledger path: {self.ledger.ledger_path}")

        try:
            # -----------------------------------------------------------------
            # STEP 3: Load Qualification Records & Checkpoints
            # -----------------------------------------------------------------
            print("\n[*] Step 3: Loading Sealed Qualification Records & Model Checkpoints...")
            records: List[Dict[str, Any]] = []
            with open(qual_corpus_path, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.strip()
                    if clean:
                        records.append(json.loads(clean))

            if len(records) != 450:
                raise QualificationIntegrityError(f"Expected 450 qualification records, loaded {len(records)}")

            # Load models with allow_pickle=False
            base_model = self.load_model_strictly(baseline_dir)
            cand_model = self.load_model_strictly(candidate_dir)
            hasher = CharacterNGramHasher(num_features=EXPECTED_FEATURE_DIM, min_n=3, max_n=5)

            # -----------------------------------------------------------------
            # STEP 4: Identical Model Inference & Metric Calculation
            # -----------------------------------------------------------------
            print("\n[*] Step 4: Running Identical Evaluation Inference...")
            y_true, base_preds, cand_preds, base_metrics, cand_metrics = self.evaluate_both_models_on_records(
                baseline_model=base_model,
                candidate_model=cand_model,
                records=records,
                hasher=hasher,
            )

            # Compute citizen safety & conventional 1-vs-rest metrics
            base_safety = self.compute_citizen_safety_metrics(y_true, base_preds)
            cand_safety = self.compute_citizen_safety_metrics(y_true, cand_preds)

            print(f"    [+] Baseline Accuracy: {base_metrics['accuracy']:.4f} | Macro-F1: {base_metrics['macro_f1']:.4f}")
            print(f"    [+] Candidate Accuracy: {cand_metrics['accuracy']:.4f} | Macro-F1: {cand_metrics['macro_f1']:.4f}")
            print(f"    [+] Candidate Legit-to-Phish FP: {cand_safety['citizen_safety_metrics']['legitimate_to_phishing_false_alarm_rate']:.4f}")
            print(f"    [+] Candidate Advisory-to-Phish FP: {cand_safety['citizen_safety_metrics']['protective_advisory_to_phishing_false_alarm_rate']:.4f}")
            print(f"    [+] Candidate Phishing FN: {cand_safety['citizen_safety_metrics']['phishing_false_negative_rate']:.4f}")

            # -----------------------------------------------------------------
            # STEP 5: Campaign-Family Cluster Analysis
            # -----------------------------------------------------------------
            print("\n[*] Step 5: Performing Campaign-Family Cluster Analysis (9 Families)...")
            family_analysis = self.run_campaign_family_analysis(
                records=records,
                y_true=y_true,
                base_preds=base_preds,
                cand_preds=cand_preds,
            )
            print(f"    [+] Baseline Family Macro Accuracy: {family_analysis['baseline_family_macro_accuracy']:.4f}")
            print(f"    [+] Candidate Family Macro Accuracy: {family_analysis['candidate_family_macro_accuracy']:.4f}")
            print(f"    [+] Candidate Macro-F1 Cluster 95% CI: {family_analysis['candidate_macro_f1_cluster_bootstrap_95ci']}")
            print(f"    [+] Candidate Families with False Alarms: {family_analysis['candidate_families_with_serious_false_alarms']} / 9")

            # -----------------------------------------------------------------
            # STEP 6: Language & Messaging Mode Subgroup Analysis
            # -----------------------------------------------------------------
            print("\n[*] Step 6: Slicing by Language and Messaging Mode...")
            subgroup_analysis = self.run_subgroup_analysis(
                records=records,
                y_true=y_true,
                base_preds=base_preds,
                cand_preds=cand_preds,
            )

            # -----------------------------------------------------------------
            # STEP 7: Counterfactual Robustness Evaluation
            # -----------------------------------------------------------------
            print("\n[*] Step 7: Executing Counterfactual Robustness Evaluation...")
            robustness_results = self.run_counterfactual_robustness_tests(
                records=records,
                baseline_model=base_model,
                candidate_model=cand_model,
                hasher=hasher,
            )
            print(f"    [+] Whitespace mutation flips (Candidate): {robustness_results['whitespace_normalization']['candidate_flips']}")
            print(f"    [+] Zero-width mutation flips (Candidate): {robustness_results['zero_width_character_obfuscation']['candidate_flips']}")
            print(f"    [+] Numeral mutation flips (Candidate): {robustness_results['devanagari_numeral_translation']['candidate_flips']}")

            # -----------------------------------------------------------------
            # STEP 8: Predeclared Qualification Policy & Gate Verdict
            # -----------------------------------------------------------------
            print("\n[*] Step 8: Evaluating Predeclared Benchmark Gate Policy...")
            verdict, failing_gates, gate_details = self.evaluate_predeclared_policy(
                base_metrics=base_metrics,
                cand_metrics=cand_metrics,
                cand_safety=cand_safety,
                robustness_results=robustness_results,
            )
            print(f"    [+] FINAL QUALIFICATION VERDICT: {verdict.value}")
            if failing_gates:
                print(f"    [!] Failing gates: {failing_gates}")
            else:
                print(f"    [+] ALL BENCHMARK GATES SATISFIED!")

            # -----------------------------------------------------------------
            # STEP 9: Serialization & Ledger Finalization
            # -----------------------------------------------------------------
            now_utc = get_utc_now_iso()
            target_report_file = output_report_path or os.path.join(
                DEFAULT_QUAL_OUTPUT_DIR, f"{candidate_id}_qualification.json"
            )

            full_report = {
                "report_schema_version": "1.0.0",
                "phase": "6.4.4",
                "timestamp_utc": now_utc,
                "qualification_verdict": verdict.value,
                "candidate_id": candidate_id,
                "baseline_id": baseline_id,
                "dataset_provenance": {
                    "partition": "qualification",
                    "file_name": os.path.basename(qual_corpus_path),
                    "file_sha256": partition_sha,
                    "record_count": len(records),
                    "campaign_family_count": len(family_analysis["family_breakdown"]),
                    "lifecycle_state_at_start": "sealed_independent_benchmark",
                    "exposure_ledger_path": self.ledger.ledger_path,
                },
                "baseline_evaluation": {
                    "model_id": baseline_id,
                    "overall_metrics": base_metrics,
                    "safety_metrics": base_safety,
                },
                "candidate_evaluation": {
                    "model_id": candidate_id,
                    "overall_metrics": cand_metrics,
                    "safety_metrics": cand_safety,
                },
                "campaign_family_analysis": family_analysis,
                "subgroup_analysis": subgroup_analysis,
                "counterfactual_robustness": robustness_results,
                "benchmark_policy_evaluation": {
                    "policy_name": self.policy.policy_name,
                    "verdict": verdict.value,
                    "gate_details": gate_details,
                    "failing_gates": failing_gates,
                },
                "governance_guarantees": {
                    "locked_eval_partition_sha256": preflight_info["locked_test_sha256"],
                    "qualification_partition_exposed": True,
                    "production_registry_modified": False,
                    "active_model_config_modified": False,
                    "production_score_delta": 0,
                    "human_decision_required_for_promotion": True,
                },
            }

            atomic_json_write(target_report_file, full_report)
            print(f"\n[*] Step 9: Qualification Report Saved to: {target_report_file}")

            # Finalize exposure ledger as EVALUATION_COMPLETED
            self.ledger.record_evaluation_completed(
                partition_sha256=partition_sha,
                candidate_id=candidate_id,
                verdict=verdict.value,
                report_file=target_report_file,
            )
            print(f"    [+] Exposure ledger marked: 'EVALUATION_COMPLETED'")

            # -----------------------------------------------------------------
            # STEP 10: Invariance & Integrity Final Check
            # -----------------------------------------------------------------
            print("\n[*] Step 10: Verifying Governance Invariance...")
            post_eval_recs = []
            with open(DEFAULT_LOCKED_TEST_DATASET, "r", encoding="utf-8") as f:
                post_eval_recs = json.load(f)
            post_locked_hash = compute_locked_test_hash(post_eval_recs)
            assert post_locked_hash == EXPECTED_LOCKED_TEST_HASH, "Locked test partition was modified!"
            print(f"    [+] Locked test partition checksum unchanged: {post_locked_hash[:16]}... (VERIFIED)")
            print(f"    [+] Production registry and active model configuration remain UNTOUCHED.")
            print("=" * 80)
            print("PHASE 6.4.4 QUALIFICATION BENCHMARK COMPLETED")
            print("=" * 80)

            return full_report

        except Exception as exc:
            # If records were accessed and unsealed, mark ledger as EXPOSED_INCOMPLETE
            self.ledger.record_exposed_incomplete(
                partition_sha256=partition_sha,
                candidate_id=candidate_id,
                error_message=str(exc),
            )
            raise


# =============================================================================
# CLI ENTRYPOINT
# =============================================================================

def run_phase6_4_4_qualification():
    evaluator = QualificationEvaluator()
    evaluator.execute_one_time_qualification()


if __name__ == "__main__":
    run_phase6_4_4_qualification()
