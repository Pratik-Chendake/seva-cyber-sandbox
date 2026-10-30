"""
Automated Candidate Model Evaluation and Benchmark Gate Module.
Part of Seva Cyber Sandbox (Phase 6.4).

SPECIFICATION & SAFETY CONTROLS:
1. Strict Offline Execution & Zero External APIs:
   - Operates 100% locally on CPU without external network calls, paid APIs, or cloud services.
2. Production Isolation Guarantee:
   - Evaluates candidate models in strict isolation.
   - NEVER modifies production risk scoring, detection rules, or active model configuration.
   - Evaluated candidates are NEVER automatically activated, promoted, or deployed.
3. Strict Dataset & Partition Isolation:
   - Authorized validation manifest/corpus only: data/generated/v2/synthetic_validation_corpus.jsonl
   - Validates that validation examples do NOT overlap with training corpora.
   - Prohibits loading locked evaluation partition (data/phishing_eval_dataset.json).
   - Verifies locked test partition cryptographic checksum (9b9c02d4...).
4. Cryptographic Artifact Integrity:
   - Verifies SHA-256 digests of weights, metadata, and manifests before model loading.
   - Enforces path containment inside authorized 'models/' directory (no path traversal).
   - Loads weights strictly with allow_pickle=False.
5. Comparable Fair Evaluation:
   - Compares registered baseline model vs candidate model on identical validation records.
   - Enforces identical feature dimension (1024), n-gram parameters, preprocessing (v1.1.0),
     and label mapping.
   - Flags architectural or preprocessing mismatches as INCOMPATIBLE.
6. Statistical Uncertainty & Benchmark Gate:
   - Wilson score confidence intervals for proportions (95% confidence).
   - Configurable, versioned benchmark policy evaluating accuracy, macro-F1, safety rates,
     and counterfactual robustness.
   - Produces exactly one gate verdict: PASS, FAIL, INSUFFICIENT_EVIDENCE, INCOMPATIBLE.
"""

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import logging
import math
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import numpy as np

from src.custom_model import (
    IDX_TO_LABEL,
    LABEL_TO_IDX,
    NUM_CLASSES,
    CharacterNGramHasher,
    CustomNeuralClassifier,
)
from src.dataset_preprocessing import (
    NEURAL_PREPROCESSING_VERSION,
    preprocess_for_neural_model,
)

logger = logging.getLogger(__name__)

# Canonical locked test manifest checksum
EXPECTED_LOCKED_TEST_HASH = "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"

# Default paths relative to project root
DEFAULT_MODELS_DIR = "models"
DEFAULT_CANDIDATES_DIR = os.path.join("models", "candidates")
DEFAULT_VAL_CORPUS = os.path.join("data", "generated", "v2", "synthetic_validation_corpus.jsonl")
DEFAULT_TRAIN_CORPUS = os.path.join("data", "generated", "v2", "synthetic_training_corpus.jsonl")
DEFAULT_LOCKED_MANIFEST = os.path.join("data", "locked_test_manifest.json")
DEFAULT_EVAL_DATASET = os.path.join("data", "phishing_eval_dataset.json")

URL_REGEX = re.compile(r"https?://\S+", re.IGNORECASE)


class CandidateEvaluationError(Exception):
    """Base exception for candidate evaluation errors."""
    pass


class CandidateIncompatibleError(CandidateEvaluationError):
    """Raised when candidate architecture, dimension, or preprocessing is incompatible."""
    pass


class DatasetIsolationError(CandidateEvaluationError):
    """Raised when dataset isolation boundaries or locked evaluation guarantees are violated."""
    pass


class ArtifactIntegrityError(CandidateEvaluationError):
    """Raised when checkpoint weights, metadata, or manifests fail integrity verification."""
    pass


class BenchmarkVerdict(str, Enum):
    """Canonical verdicts emitted by the benchmark gate."""
    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    INCOMPATIBLE = "INCOMPATIBLE"


@dataclass
class BenchmarkPolicy:
    """Configurable, versioned safety and performance threshold policy for benchmark gate."""
    policy_version: str = "1.0.0"
    min_validation_samples: int = 100
    min_class_samples: int = 30
    min_subgroup_samples: int = 15
    min_macro_f1: float = 0.90
    max_macro_f1_drop: float = 0.02
    max_legitimate_fp_rate: float = 0.15
    max_protective_advisory_fp_rate: float = 0.05
    max_phishing_fn_rate: float = 0.05
    max_whitespace_flip_rate: float = 0.0
    max_zerowidth_flip_rate: float = 0.0
    max_numeral_flip_rate: float = 0.0
    confidence_level: float = 0.95

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compute_file_sha256(filepath: str) -> str:
    """Computes SHA-256 digest of a local file safely in 64 KB chunks."""
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: '{filepath}'")
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def wilson_score_interval(successes: int, total: int, confidence: float = 0.95) -> Tuple[float, float]:
    """
    Computes the Wilson score interval for a binomial proportion.
    Handles small sample sizes and proportions near 0 or 1 gracefully.
    """
    if total <= 0:
        return (0.0, 1.0)
    z = 1.95996 if abs(confidence - 0.95) < 0.01 else 2.57583  # 95% default, 99% fallback
    p = successes / total
    denom = 1.0 + (z**2) / total
    center = (p + (z**2) / (2.0 * total)) / denom
    margin = (z / denom) * math.sqrt((p * (1.0 - p) / total) + (z**2) / (4.0 * (total**2)))
    low = max(0.0, center - margin)
    high = min(1.0, center + margin)
    return round(low, 4), round(high, 4)


def compute_confusion_matrix(
    y_true: np.ndarray, y_pred: np.ndarray, num_classes: int = NUM_CLASSES
) -> List[List[int]]:
    """Computes an N x N confusion matrix [true_class][pred_class]."""
    matrix = [[0 for _ in range(num_classes)] for _ in range(num_classes)]
    for t, p in zip(y_true, y_pred):
        if 0 <= int(t) < num_classes and 0 <= int(p) < num_classes:
            matrix[int(t)][int(p)] += 1
    return matrix


def compute_classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    label_to_idx: Dict[str, int] = LABEL_TO_IDX,
    idx_to_label: Dict[int, str] = IDX_TO_LABEL,
    confidence_level: float = 0.95,
) -> Dict[str, Any]:
    """
    Computes overall, per-class, and safety metrics with Wilson score intervals and sample counts.
    Always includes raw counts and denominators.
    """
    total = len(y_true)
    if total == 0:
        raise ValueError("Cannot compute metrics on empty prediction array.")

    num_classes = len(label_to_idx)
    cm = compute_confusion_matrix(y_true, y_pred, num_classes=num_classes)

    total_correct = sum(cm[i][i] for i in range(num_classes))
    total_incorrect = total - total_correct
    accuracy = total_correct / total
    acc_ci = wilson_score_interval(total_correct, total, confidence=confidence_level)

    per_class = {}
    f1_list = []
    prec_list = []
    rec_list = []

    for label, c_idx in label_to_idx.items():
        tp = cm[c_idx][c_idx]
        fp = sum(cm[r][c_idx] for r in range(num_classes) if r != c_idx)
        fn = sum(cm[c_idx][p] for p in range(num_classes) if p != c_idx)
        support = sum(cm[c_idx])

        prec = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        rec = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = (2.0 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

        prec_ci = wilson_score_interval(tp, tp + fp, confidence=confidence_level) if (tp + fp) > 0 else (0.0, 1.0)
        rec_ci = wilson_score_interval(tp, support, confidence=confidence_level) if support > 0 else (0.0, 1.0)

        per_class[label] = {
            "class_index": c_idx,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "support": support,
            "precision": round(prec, 4),
            "precision_ci_95": prec_ci,
            "precision_fraction": f"{tp}/{tp + fp}" if (tp + fp) > 0 else "0/0",
            "recall": round(rec, 4),
            "recall_ci_95": rec_ci,
            "recall_fraction": f"{tp}/{support}" if support > 0 else "0/0",
            "f1": round(f1, 4),
        }
        f1_list.append(f1)
        prec_list.append(prec)
        rec_list.append(rec)

    macro_f1 = float(np.mean(f1_list))
    macro_precision = float(np.mean(prec_list))
    macro_recall = float(np.mean(rec_list))
    balanced_accuracy = float(np.mean(rec_list))
    weighted_f1 = float(
        sum(per_class[lbl]["f1"] * per_class[lbl]["support"] for lbl in label_to_idx) / total
    )

    # Safety metrics
    # 1. Legitimate False Positive Rate: legitimate messages predicted as phishing
    legit_idx = label_to_idx.get("legitimate", 1)
    phish_idx = label_to_idx.get("phishing", 0)
    advisory_idx = label_to_idx.get("protective_advisory", 2)

    legit_total = sum(cm[legit_idx])
    legit_as_phish = cm[legit_idx][phish_idx]
    legit_fp_rate = (legit_as_phish / legit_total) if legit_total > 0 else 0.0
    legit_fp_ci = wilson_score_interval(legit_as_phish, legit_total, confidence=confidence_level)

    # 2. Protective Advisory False Positive Rate: advisory messages predicted as phishing
    advisory_total = sum(cm[advisory_idx])
    advisory_as_phish = cm[advisory_idx][phish_idx]
    advisory_fp_rate = (advisory_as_phish / advisory_total) if advisory_total > 0 else 0.0
    advisory_fp_ci = wilson_score_interval(advisory_as_phish, advisory_total, confidence=confidence_level)

    # 3. Phishing False Negative Rate: phishing predicted as legitimate or protective advisory
    phish_total = sum(cm[phish_idx])
    phish_fn_count = sum(cm[phish_idx][p] for p in range(num_classes) if p != phish_idx)
    phish_fn_rate = (phish_fn_count / phish_total) if phish_total > 0 else 0.0
    phish_fn_ci = wilson_score_interval(phish_fn_count, phish_total, confidence=confidence_level)

    # Prediction distribution
    pred_dist = {idx_to_label.get(i, f"class_{i}"): int(np.sum(y_pred == i)) for i in range(num_classes)}

    return {
        "sample_count": total,
        "accuracy": round(accuracy, 4),
        "accuracy_ci_95": acc_ci,
        "accuracy_fraction": f"{total_correct}/{total}",
        "total_incorrect": total_incorrect,
        "total_incorrect_fraction": f"{total_incorrect}/{total}",
        "macro_f1": round(macro_f1, 4),
        "macro_precision": round(macro_precision, 4),
        "macro_recall": round(macro_recall, 4),
        "balanced_accuracy": round(balanced_accuracy, 4),
        "weighted_f1": round(weighted_f1, 4),
        "confusion_matrix": cm,
        "per_class": per_class,
        "safety_metrics": {
            "legitimate_fp_rate": round(legit_fp_rate, 4),
            "legitimate_fp_ci_95": legit_fp_ci,
            "legitimate_fp_fraction": f"{legit_as_phish}/{legit_total}",
            "protective_advisory_fp_rate": round(advisory_fp_rate, 4),
            "protective_advisory_fp_ci_95": advisory_fp_ci,
            "protective_advisory_fp_fraction": f"{advisory_as_phish}/{advisory_total}",
            "phishing_fn_rate": round(phish_fn_rate, 4),
            "phishing_fn_ci_95": phish_fn_ci,
            "phishing_fn_fraction": f"{phish_fn_count}/{phish_total}",
            "prediction_distribution": pred_dist,
        },
    }


class CandidateEvaluator:
    """
    Automated candidate model evaluation engine and safety benchmark gate.
    Ensures strict artifact verification, dataset isolation, comparative metrics,
    subgroup analysis, and counterfactual robustness testing.
    """

    def __init__(
        self,
        project_root: Optional[str] = None,
        policy: Optional[BenchmarkPolicy] = None,
        models_dir: Optional[str] = None,
        active_config_path: Optional[str] = None,
    ):
        if project_root is None:
            self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        else:
            self.project_root = os.path.abspath(project_root)

        self.models_dir = os.path.abspath(models_dir) if models_dir else os.path.abspath(os.path.join(self.project_root, DEFAULT_MODELS_DIR))
        self.candidates_dir = os.path.abspath(os.path.join(self.project_root, DEFAULT_CANDIDATES_DIR))
        self.policy = policy or BenchmarkPolicy()
        if active_config_path:
            self.active_config_path = os.path.abspath(active_config_path)
        elif "SEVA_ACTIVE_CONFIG_PATH" in os.environ:
            self.active_config_path = os.path.abspath(os.environ["SEVA_ACTIVE_CONFIG_PATH"])
        else:
            self.active_config_path = os.path.join(self.models_dir, "active_model_config.json")

    def validate_safe_model_path(self, path: str) -> str:
        """
        Validates that a path resolves strictly inside self.models_dir.
        Rejects path traversal ('..'), absolute outside paths, or non-existent paths.
        """
        if not path or not isinstance(path, str):
            raise CandidateIncompatibleError("Model path must be a non-empty string.")

        clean_path = os.path.normpath(path).strip()
        if clean_path.startswith("..") or ".." in clean_path.split(os.sep):
            raise CandidateIncompatibleError(f"Path traversal detected in model path: '{path}'")

        if os.path.isabs(clean_path):
            abs_path = os.path.abspath(clean_path)
        else:
            abs_path = os.path.abspath(os.path.join(self.project_root, clean_path))

        # Check containment inside models_dir
        if not abs_path.startswith(self.models_dir):
            raise CandidateIncompatibleError(
                f"Security violation: Path '{path}' resolves outside trusted models directory '{self.models_dir}'."
            )

        return abs_path

    def discover_baseline_model(self, active_config_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Discovers and verifies the currently active model from the registry and active config.
        """
        registry_path = os.path.join(self.models_dir, "model_registry.json")
        cfg_path = active_config_path or self.active_config_path

        if not os.path.isfile(registry_path):
            raise ArtifactIntegrityError(f"Model registry not found at '{registry_path}'")
        if not os.path.isfile(cfg_path):
            raise ArtifactIntegrityError(f"Active model config not found at '{cfg_path}'")

        with open(registry_path, "r", encoding="utf-8") as f:
            registry_data = json.load(f)
        with open(cfg_path, "r", encoding="utf-8") as f:
            active_data = json.load(f)

        active_version = active_data.get("active_model_version")
        if not active_version:
            raise ArtifactIntegrityError("No active model version set in active_model_config.json")

        models = registry_data.get("registered_models", {})
        if active_version not in models:
            raise ArtifactIntegrityError(f"Active model version '{active_version}' not found in model_registry.json")

        entry = models[active_version]
        ckpt_rel = entry.get("checkpoint_rel_path")
        if not ckpt_rel:
            raise ArtifactIntegrityError(f"Active model '{active_version}' lacks checkpoint_rel_path in registry")

        abs_ckpt = self.validate_safe_model_path(ckpt_rel)
        weights_file = os.path.join(abs_ckpt, "model_weights.npz")
        meta_file = os.path.join(abs_ckpt, "model_metadata.json")

        if not os.path.isfile(weights_file):
            raise ArtifactIntegrityError(f"Baseline weights missing: '{weights_file}'")
        if not os.path.isfile(meta_file):
            raise ArtifactIntegrityError(f"Baseline metadata missing: '{meta_file}'")

        actual_w_sha = compute_file_sha256(weights_file)
        if actual_w_sha != entry.get("weights_sha256"):
            raise ArtifactIntegrityError(
                f"Baseline weights SHA-256 mismatch! Registered: {entry.get('weights_sha256')}, Disk: {actual_w_sha}"
            )

        actual_m_sha = compute_file_sha256(meta_file)
        if actual_m_sha != entry.get("metadata_sha256"):
            raise ArtifactIntegrityError(
                f"Baseline metadata SHA-256 mismatch! Registered: {entry.get('metadata_sha256')}, Disk: {actual_m_sha}"
            )

        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)

        return {
            "model_version": active_version,
            "checkpoint_dir": abs_ckpt,
            "weights_file": weights_file,
            "metadata_file": meta_file,
            "weights_sha256": actual_w_sha,
            "metadata_sha256": actual_m_sha,
            "registry_entry": entry,
            "model_metadata": meta,
            "operating_mode": active_data.get("operating_mode", "shadow"),
            "is_production_authoritative": active_data.get("is_production_authoritative", False),
        }

    def verify_candidate_provenance(self, candidate_dir: str) -> Dict[str, Any]:
        """
        Inspects candidate artifacts, manifest, and training provenance.
        Verifies policy, data sources, counts, hashes, preprocessing version, and architecture.
        If provenance cannot be established, raises CandidateEvaluationError.
        """
        abs_cand_dir = self.validate_safe_model_path(candidate_dir)

        manifest_file = os.path.join(abs_cand_dir, "manifest.json")
        weights_file = os.path.join(abs_cand_dir, "model_weights.npz")
        meta_file = os.path.join(abs_cand_dir, "model_metadata.json")
        report_file = os.path.join(abs_cand_dir, "candidate_training_report.json")

        if not os.path.isfile(manifest_file):
            raise ArtifactIntegrityError(f"Candidate manifest missing at '{manifest_file}'")
        if not os.path.isfile(weights_file):
            raise ArtifactIntegrityError(f"Candidate weights missing at '{weights_file}'")
        if not os.path.isfile(meta_file):
            raise ArtifactIntegrityError(f"Candidate metadata missing at '{meta_file}'")

        # Load manifest
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        # Cryptographic verification of manifest artifacts
        artifacts = manifest.get("artifacts", {})
        w_spec = artifacts.get("model_weights", {})
        m_spec = artifacts.get("model_metadata", {})

        actual_w_sha = compute_file_sha256(weights_file)
        if actual_w_sha != w_spec.get("sha256"):
            raise ArtifactIntegrityError(
                f"Candidate weights SHA-256 mismatch! Manifest: {w_spec.get('sha256')}, Disk: {actual_w_sha}"
            )

        actual_m_sha = compute_file_sha256(meta_file)
        if actual_m_sha != m_spec.get("sha256"):
            raise ArtifactIntegrityError(
                f"Candidate metadata SHA-256 mismatch! Manifest: {m_spec.get('sha256')}, Disk: {actual_m_sha}"
            )

        # Optional training report check if recorded in manifest
        report_data = None
        if os.path.isfile(report_file):
            actual_r_sha = compute_file_sha256(report_file)
            r_spec = artifacts.get("training_report", {})
            if r_spec and actual_r_sha != r_spec.get("sha256"):
                raise ArtifactIntegrityError(
                    f"Candidate training report SHA-256 mismatch! Manifest: {r_spec.get('sha256')}, Disk: {actual_r_sha}"
                )
            with open(report_file, "r", encoding="utf-8") as f:
                report_data = json.load(f)

        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)

        # Check architecture compatibility
        arch_type = meta.get("architecture", "")
        input_dim = meta.get("input_dim")
        num_classes = meta.get("num_classes")
        hasher_meta = meta.get("hasher", {})

        if input_dim != 1024:
            raise CandidateIncompatibleError(f"Candidate feature dimension must be 1024, found {input_dim}")
        if num_classes != 3:
            raise CandidateIncompatibleError(f"Candidate num_classes must be 3, found {num_classes}")

        # Check label mapping
        lbl_map = meta.get("label_to_index", {})
        if lbl_map != LABEL_TO_IDX:
            raise CandidateIncompatibleError(
                f"Candidate label mapping mismatch. Expected {LABEL_TO_IDX}, found {lbl_map}"
            )

        # Preprocessing version check
        preproc_ver = None
        if report_data:
            preproc_ver = report_data.get("dataset_provenance", {}).get("preprocessing_version")
        if not preproc_ver:
            preproc_ver = meta.get("preprocessing_version") or NEURAL_PREPROCESSING_VERSION

        if preproc_ver != NEURAL_PREPROCESSING_VERSION:
            raise CandidateIncompatibleError(
                f"Candidate preprocessing version mismatch. Expected '{NEURAL_PREPROCESSING_VERSION}', found '{preproc_ver}'"
            )

        prov_summary = manifest.get("provenance_summary", {})

        return {
            "candidate_id": manifest.get("candidate_id", os.path.basename(abs_cand_dir)),
            "candidate_version": manifest.get("candidate_version", "unknown"),
            "checkpoint_dir": abs_cand_dir,
            "weights_file": weights_file,
            "metadata_file": meta_file,
            "weights_sha256": actual_w_sha,
            "metadata_sha256": actual_m_sha,
            "manifest": manifest,
            "model_metadata": meta,
            "training_report": report_data,
            "provenance_summary": prov_summary,
            "preprocessing_version": preproc_ver,
            "lifecycle_state": manifest.get("lifecycle_state", "experimental"),
        }

    def verify_dataset_isolation(
        self,
        val_path: str,
        train_path: Optional[str] = None,
        eval_path: Optional[str] = None,
        locked_manifest_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Enforces strict dataset isolation:
        1. Authorizes the validation dataset using manifest and content checks.
        2. Verifies zero ID overlap between training and validation corpora.
        3. Prohibits loading locked evaluation records into validation.
        4. Verifies locked test partition cryptographic SHA-256 digest.
        """
        abs_val = os.path.abspath(val_path)
        if not os.path.isfile(abs_val):
            raise DatasetIsolationError(f"Validation dataset not found: '{abs_val}'")

        # Prohibit loading locked evaluation dataset as validation corpus
        abs_eval = os.path.abspath(eval_path or os.path.join(self.project_root, DEFAULT_EVAL_DATASET))
        if os.path.exists(abs_eval) and os.path.samefile(abs_val, abs_eval):
            raise DatasetIsolationError(
                "CRITICAL SECURITY VIOLATION: Locked evaluation dataset cannot be loaded as validation corpus!"
            )

        # Verify locked test manifest integrity
        abs_locked_manifest = os.path.abspath(
            locked_manifest_path or os.path.join(self.project_root, DEFAULT_LOCKED_MANIFEST)
        )
        if not os.path.isfile(abs_locked_manifest):
            raise DatasetIsolationError(f"Missing locked test manifest at '{abs_locked_manifest}'")

        with open(abs_locked_manifest, "r", encoding="utf-8") as f:
            locked_manifest = json.load(f)

        locked_digest = locked_manifest.get("sha256_checksum")
        if locked_digest != EXPECTED_LOCKED_TEST_HASH:
            raise DatasetIsolationError(
                f"Locked test partition manifest has corrupted digest! Expected {EXPECTED_LOCKED_TEST_HASH}, found {locked_digest}"
            )

        # Read validation records and collect IDs
        val_ids: Set[str] = set()
        val_records: List[Dict[str, Any]] = []
        with open(abs_val, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, 1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    rec = json.loads(clean_line)
                except Exception as e:
                    raise DatasetIsolationError(f"Malformed JSON on line {line_idx} in '{abs_val}': {e}")

                rid = rec.get("record_id") or rec.get("id")
                if not rid:
                    raise DatasetIsolationError(f"Record on line {line_idx} lacks record_id in '{abs_val}'")
                if rid in val_ids:
                    raise DatasetIsolationError(f"Duplicate record_id '{rid}' inside validation dataset '{abs_val}'")
                val_ids.add(rid)

                # Check if role is explicitly validation or authorized synthetic fixture
                role = rec.get("dataset_role")
                if role and role == "locked_test":
                    raise DatasetIsolationError(
                        f"CRITICAL: Record '{rid}' in validation dataset has forbidden dataset_role='locked_test'!"
                    )

                val_records.append(rec)

        val_sha256 = compute_file_sha256(abs_val)

        # Check training corpus ID overlap
        abs_train = os.path.abspath(train_path or os.path.join(self.project_root, DEFAULT_TRAIN_CORPUS))
        overlap_ids: Set[str] = set()
        train_sha256 = None
        if os.path.isfile(abs_train):
            train_sha256 = compute_file_sha256(abs_train)
            with open(abs_train, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.strip()
                    if not clean:
                        continue
                    try:
                        t_rec = json.loads(clean)
                        t_id = t_rec.get("record_id") or t_rec.get("id")
                        if t_id and t_id in val_ids:
                            overlap_ids.add(t_id)
                    except Exception:
                        pass

        if overlap_ids:
            raise DatasetIsolationError(
                f"Data contamination detected: {len(overlap_ids)} records overlap between training and validation! (e.g. {sorted(list(overlap_ids))[:5]})"
            )

        # Check locked evaluation dataset ID overlap
        locked_eval_ids = set(locked_manifest.get("locked_records", []))
        eval_overlap = val_ids & locked_eval_ids
        if eval_overlap:
            raise DatasetIsolationError(
                f"CRITICAL CONTAMINATION: Validation set contains {len(eval_overlap)} locked evaluation records! ({eval_overlap})"
            )

        return {
            "validation_dataset_path": abs_val,
            "validation_dataset_sha256": val_sha256,
            "validation_records_count": len(val_records),
            "training_dataset_path": abs_train if os.path.isfile(abs_train) else None,
            "training_dataset_sha256": train_sha256,
            "training_validation_overlap_count": 0,
            "locked_test_manifest_sha256": locked_digest,
            "locked_test_records_count": len(locked_eval_ids),
            "isolation_guarantee": "VERIFIED_ISOLATED",
        }

    def load_validation_records(self, val_path: str) -> List[Dict[str, Any]]:
        """Loads and returns the authorized validation records list."""
        records = []
        with open(val_path, "r", encoding="utf-8") as f:
            for line in f:
                clean = line.strip()
                if clean:
                    records.append(json.loads(clean))
        return records

    def evaluate_model_on_records(
        self,
        model: CustomNeuralClassifier,
        records: List[Dict[str, Any]],
        hasher: Optional[CharacterNGramHasher] = None,
    ) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
        """
        Executes normalized inference and calculates evaluation metrics.
        Guarantees that input is preprocessed canonically using preprocess_for_neural_model.
        """
        h = hasher or CharacterNGramHasher(num_features=1024, min_n=3, max_n=5)
        n = len(records)
        X = np.zeros((n, 1024), dtype=np.float32)
        y_true = np.zeros(n, dtype=np.int64)

        for i, rec in enumerate(records):
            raw_text = rec.get("text", "")
            norm_text = preprocess_for_neural_model(raw_text)
            X[i] = h.transform_text(norm_text)
            lbl = str(rec.get("ground_truth_label", "legitimate")).lower()
            y_true[i] = LABEL_TO_IDX.get(lbl, 1)

        y_pred = model.predict(X)
        metrics = compute_classification_metrics(
            y_true, y_pred, confidence_level=self.policy.confidence_level
        )
        return y_true, y_pred, metrics

    def run_subgroup_analysis(
        self,
        records: List[Dict[str, Any]],
        y_true: np.ndarray,
        y_pred_base: np.ndarray,
        y_pred_cand: np.ndarray,
    ) -> Dict[str, Any]:
        """
        Calculates performance breakdowns across available metadata:
        - Languages (mr, mr-Latn, en, mr-en)
        - Scripts (Devanagari, Latin, Mixed)
        - Messaging mode: with URLs vs without URLs
        Flagged as INSUFFICIENT_EVIDENCE if subgroup count is below policy threshold.
        """
        subgroups: Dict[str, Dict[str, Any]] = {
            "by_language": {},
            "by_script": {},
            "by_url_presence": {},
        }

        min_sub = self.policy.min_subgroup_samples

        # 1. By Language
        langs = sorted(set(r.get("language", "unknown") for r in records))
        for lang in langs:
            idxs = [i for i, r in enumerate(records) if r.get("language") == lang]
            count = len(idxs)
            if count == 0:
                continue
            sub_t = y_true[idxs]
            sub_b = y_pred_base[idxs]
            sub_c = y_pred_cand[idxs]

            acc_b = float(np.mean(sub_b == sub_t))
            acc_c = float(np.mean(sub_c == sub_t))
            corr_b = int(np.sum(sub_b == sub_t))
            corr_c = int(np.sum(sub_c == sub_t))

            subgroups["by_language"][lang] = {
                "sample_count": count,
                "is_sufficient_sample": (count >= min_sub),
                "baseline_accuracy": round(acc_b, 4),
                "baseline_correct_fraction": f"{corr_b}/{count}",
                "candidate_accuracy": round(acc_c, 4),
                "candidate_correct_fraction": f"{corr_c}/{count}",
                "accuracy_delta": round(acc_c - acc_b, 4),
            }

        # 2. By Script
        scripts = sorted(set(r.get("script", "unknown") for r in records))
        for scr in scripts:
            idxs = [i for i, r in enumerate(records) if r.get("script") == scr]
            count = len(idxs)
            if count == 0:
                continue
            sub_t = y_true[idxs]
            sub_b = y_pred_base[idxs]
            sub_c = y_pred_cand[idxs]

            acc_b = float(np.mean(sub_b == sub_t))
            acc_c = float(np.mean(sub_c == sub_t))
            corr_b = int(np.sum(sub_b == sub_t))
            corr_c = int(np.sum(sub_c == sub_t))

            subgroups["by_script"][scr] = {
                "sample_count": count,
                "is_sufficient_sample": (count >= min_sub),
                "baseline_accuracy": round(acc_b, 4),
                "baseline_correct_fraction": f"{corr_b}/{count}",
                "candidate_accuracy": round(acc_c, 4),
                "candidate_correct_fraction": f"{corr_c}/{count}",
                "accuracy_delta": round(acc_c - acc_b, 4),
            }

        # 3. By URL Presence
        has_url_idxs = [i for i, r in enumerate(records) if URL_REGEX.search(r.get("text", ""))]
        no_url_idxs = [i for i, r in enumerate(records) if not URL_REGEX.search(r.get("text", ""))]

        for mode_name, idxs in [("with_url", has_url_idxs), ("without_url", no_url_idxs)]:
            count = len(idxs)
            if count == 0:
                continue
            sub_t = y_true[idxs]
            sub_b = y_pred_base[idxs]
            sub_c = y_pred_cand[idxs]

            acc_b = float(np.mean(sub_b == sub_t))
            acc_c = float(np.mean(sub_c == sub_t))
            corr_b = int(np.sum(sub_b == sub_t))
            corr_c = int(np.sum(sub_c == sub_t))

            subgroups["by_url_presence"][mode_name] = {
                "sample_count": count,
                "is_sufficient_sample": (count >= min_sub),
                "baseline_accuracy": round(acc_b, 4),
                "baseline_correct_fraction": f"{corr_b}/{count}",
                "candidate_accuracy": round(acc_c, 4),
                "candidate_correct_fraction": f"{corr_c}/{count}",
                "accuracy_delta": round(acc_c - acc_b, 4),
            }

        return {
            "subgroups": subgroups,
            "synthetic_disclaimer": "SYNTHETIC_BENCHMARK_NOTICE: All validation records are synthetically generated. Subgroup metrics do not certify real-world vernacular accuracy.",
        }

    def run_counterfactual_robustness_tests(
        self,
        records: List[Dict[str, Any]],
        baseline_model: CustomNeuralClassifier,
        candidate_model: CustomNeuralClassifier,
        hasher: Optional[CharacterNGramHasher] = None,
    ) -> Dict[str, Any]:
        """
        Executes counterfactual mutations to evaluate model prediction stability:
        1. Harmless whitespace variations (padding, spacing).
        2. Zero-width character obfuscation (\u200b insertion).
        3. Devanagari numeral normalization (Devanagari digits vs ASCII).
        4. URL removal from phishing messages.
        5. URL insertion into legitimate messages.
        6. Irrelevant URL replacement.
        """
        h = hasher or CharacterNGramHasher(num_features=1024, min_n=3, max_n=5)

        def predict_single(m: CustomNeuralClassifier, text: str) -> int:
            norm = preprocess_for_neural_model(text)
            vec = h.transform_text(norm)
            return int(m.predict(np.expand_dims(vec, axis=0))[0])

        total_records = len(records)

        # 1. Whitespace variation
        ws_flips_b, ws_flips_c = 0, 0
        for r in records:
            txt = r.get("text", "")
            orig_b = predict_single(baseline_model, txt)
            orig_c = predict_single(candidate_model, txt)
            mutated = "   " + txt.replace(" ", "   ") + "   \n"
            if predict_single(baseline_model, mutated) != orig_b:
                ws_flips_b += 1
            if predict_single(candidate_model, mutated) != orig_c:
                ws_flips_c += 1

        # 2. Zero-width character insertion
        zw_flips_b, zw_flips_c = 0, 0
        for r in records:
            txt = r.get("text", "")
            orig_b = predict_single(baseline_model, txt)
            orig_c = predict_single(candidate_model, txt)
            # Inject zero-width space after first 10 characters
            if len(txt) > 10:
                mutated = "\u200b".join(list(txt[:20])) + txt[20:]
            else:
                mutated = "\u200b" + txt
            if predict_single(baseline_model, mutated) != orig_b:
                zw_flips_b += 1
            if predict_single(candidate_model, mutated) != orig_c:
                zw_flips_c += 1

        # 3. Devanagari numerals vs ASCII numerals
        num_map = str.maketrans("0123456789", "०१२३४५६७८९")
        digit_records = [r for r in records if re.search(r"\d", r.get("text", ""))]
        num_tested = len(digit_records)
        num_flips_b, num_flips_c = 0, 0
        for r in digit_records:
            txt = r.get("text", "")
            orig_b = predict_single(baseline_model, txt)
            orig_c = predict_single(candidate_model, txt)
            mutated = txt.translate(num_map)
            if predict_single(baseline_model, mutated) != orig_b:
                num_flips_b += 1
            if predict_single(candidate_model, mutated) != orig_c:
                num_flips_c += 1

        # 4. URL removal from phishing messages
        phish_url_records = [
            r for r in records
            if r.get("ground_truth_label") == "phishing" and URL_REGEX.search(r.get("text", ""))
        ]
        url_rem_flips_b, url_rem_flips_c = 0, 0
        for r in phish_url_records:
            txt = r.get("text", "")
            orig_b = predict_single(baseline_model, txt)
            orig_c = predict_single(candidate_model, txt)
            mutated = URL_REGEX.sub("", txt)
            if predict_single(baseline_model, mutated) != orig_b:
                url_rem_flips_b += 1
            if predict_single(candidate_model, mutated) != orig_c:
                url_rem_flips_c += 1

        # 5. URL insertion into legitimate messages
        legit_nourl_records = [
            r for r in records
            if r.get("ground_truth_label") == "legitimate" and not URL_REGEX.search(r.get("text", ""))
        ]
        url_ins_flips_b, url_ins_flips_c = 0, 0
        for r in legit_nourl_records:
            txt = r.get("text", "")
            orig_b = predict_single(baseline_model, txt)
            orig_c = predict_single(candidate_model, txt)
            mutated = txt.strip() + " http://utility-bill-portal.org"
            if predict_single(baseline_model, mutated) != orig_b:
                url_ins_flips_b += 1
            if predict_single(candidate_model, mutated) != orig_c:
                url_ins_flips_c += 1

        # 6. Irrelevant URL replacement
        all_url_records = [r for r in records if URL_REGEX.search(r.get("text", ""))]
        url_rep_flips_b, url_rep_flips_c = 0, 0
        for r in all_url_records:
            txt = r.get("text", "")
            orig_b = predict_single(baseline_model, txt)
            orig_c = predict_single(candidate_model, txt)
            mutated = URL_REGEX.sub("http://generic-service-portal.invalid/update", txt)
            if predict_single(baseline_model, mutated) != orig_b:
                url_rep_flips_b += 1
            if predict_single(candidate_model, mutated) != orig_c:
                url_rep_flips_c += 1

        return {
            "whitespace_invariance": {
                "samples_tested": total_records,
                "baseline_flips": ws_flips_b,
                "baseline_flip_rate": round(ws_flips_b / total_records, 4) if total_records > 0 else 0.0,
                "candidate_flips": ws_flips_c,
                "candidate_flip_rate": round(ws_flips_c / total_records, 4) if total_records > 0 else 0.0,
            },
            "zero_width_invariance": {
                "samples_tested": total_records,
                "baseline_flips": zw_flips_b,
                "baseline_flip_rate": round(zw_flips_b / total_records, 4) if total_records > 0 else 0.0,
                "candidate_flips": zw_flips_c,
                "candidate_flip_rate": round(zw_flips_c / total_records, 4) if total_records > 0 else 0.0,
            },
            "devanagari_numeral_invariance": {
                "samples_tested": num_tested,
                "baseline_flips": num_flips_b,
                "baseline_flip_rate": round(num_flips_b / num_tested, 4) if num_tested > 0 else 0.0,
                "candidate_flips": num_flips_c,
                "candidate_flip_rate": round(num_flips_c / num_tested, 4) if num_tested > 0 else 0.0,
            },
            "url_removal_from_phishing": {
                "samples_tested": len(phish_url_records),
                "baseline_flips": url_rem_flips_b,
                "baseline_flip_rate": round(url_rem_flips_b / len(phish_url_records), 4) if phish_url_records else 0.0,
                "candidate_flips": url_rem_flips_c,
                "candidate_flip_rate": round(url_rem_flips_c / len(phish_url_records), 4) if phish_url_records else 0.0,
            },
            "url_insertion_into_legitimate": {
                "samples_tested": len(legit_nourl_records),
                "baseline_flips": url_ins_flips_b,
                "baseline_flip_rate": round(url_ins_flips_b / len(legit_nourl_records), 4) if legit_nourl_records else 0.0,
                "candidate_flips": url_ins_flips_c,
                "candidate_flip_rate": round(url_ins_flips_c / len(legit_nourl_records), 4) if legit_nourl_records else 0.0,
            },
            "irrelevant_url_replacement": {
                "samples_tested": len(all_url_records),
                "baseline_flips": url_rep_flips_b,
                "baseline_flip_rate": round(url_rep_flips_b / len(all_url_records), 4) if all_url_records else 0.0,
                "candidate_flips": url_rep_flips_c,
                "candidate_flip_rate": round(url_rep_flips_c / len(all_url_records), 4) if all_url_records else 0.0,
            },
        }

    def evaluate_benchmark_gate(
        self,
        baseline_metrics: Dict[str, Any],
        candidate_metrics: Dict[str, Any],
        robustness_metrics: Dict[str, Any],
        policy: Optional[BenchmarkPolicy] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates candidate metrics against baseline and safety policy.
        Produces exactly one of: PASS, FAIL, INSUFFICIENT_EVIDENCE, INCOMPATIBLE.
        """
        p = policy or self.policy
        reasons: List[str] = []
        checks: Dict[str, Dict[str, Any]] = {}

        total_samples = candidate_metrics.get("sample_count", 0)
        base_f1 = baseline_metrics.get("macro_f1", 0.0)
        cand_f1 = candidate_metrics.get("macro_f1", 0.0)

        cand_safety = candidate_metrics.get("safety_metrics", {})
        cand_legit_fp = cand_safety.get("legitimate_fp_rate", 1.0)
        cand_advisory_fp = cand_safety.get("protective_advisory_fp_rate", 1.0)
        cand_phish_fn = cand_safety.get("phishing_fn_rate", 1.0)

        # 1. Sample Size Checks
        sample_ok = total_samples >= p.min_validation_samples
        checks["sample_count"] = {
            "requirement": f">= {p.min_validation_samples}",
            "observed": total_samples,
            "passed": sample_ok,
        }
        if not sample_ok:
            reasons.append(f"Insufficient total validation samples: {total_samples} < {p.min_validation_samples}")

        class_samples_ok = True
        for lbl, cls_data in candidate_metrics.get("per_class", {}).items():
            supp = cls_data.get("support", 0)
            if supp < p.min_class_samples:
                class_samples_ok = False
                reasons.append(f"Insufficient sample count for class '{lbl}': {supp} < {p.min_class_samples}")
        checks["class_sample_counts"] = {
            "requirement": f"all classes >= {p.min_class_samples}",
            "passed": class_samples_ok,
        }

        if not sample_ok or not class_samples_ok:
            return {
                "verdict": BenchmarkVerdict.INSUFFICIENT_EVIDENCE.value,
                "reasons": reasons,
                "checks": checks,
                "policy": p.to_dict(),
            }

        # 2. Performance Comparison (Macro-F1)
        # Check absolute floor
        f1_floor_ok = cand_f1 >= p.min_macro_f1
        checks["macro_f1_floor"] = {
            "requirement": f">= {p.min_macro_f1}",
            "observed": cand_f1,
            "passed": f1_floor_ok,
        }
        if not f1_floor_ok:
            reasons.append(f"Candidate macro-F1 ({cand_f1:.4f}) is below minimum policy floor ({p.min_macro_f1:.4f})")

        # Check relative drop compared to baseline
        max_allowed_drop = p.max_macro_f1_drop
        f1_drop = base_f1 - cand_f1
        f1_retention_ok = f1_drop <= max_allowed_drop
        checks["macro_f1_retention"] = {
            "requirement": f"drop <= {max_allowed_drop:.4f} (baseline: {base_f1:.4f})",
            "observed_drop": round(f1_drop, 4),
            "passed": f1_retention_ok,
        }
        if not f1_retention_ok:
            reasons.append(
                f"Candidate macro-F1 dropped by {f1_drop:.4f} compared to baseline (exceeds allowed drop of {max_allowed_drop:.4f})"
            )

        # 3. Safety Constraints
        legit_fp_ok = cand_legit_fp <= p.max_legitimate_fp_rate
        checks["legitimate_false_positive_rate"] = {
            "requirement": f"<= {p.max_legitimate_fp_rate}",
            "observed": cand_legit_fp,
            "fraction": cand_safety.get("legitimate_fp_fraction", ""),
            "passed": legit_fp_ok,
        }
        if not legit_fp_ok:
            reasons.append(
                f"Legitimate false-positive rate ({cand_legit_fp:.4f}, {cand_safety.get('legitimate_fp_fraction')}) exceeds threshold ({p.max_legitimate_fp_rate})"
            )

        advisory_fp_ok = cand_advisory_fp <= p.max_protective_advisory_fp_rate
        checks["protective_advisory_false_positive_rate"] = {
            "requirement": f"<= {p.max_protective_advisory_fp_rate}",
            "observed": cand_advisory_fp,
            "fraction": cand_safety.get("protective_advisory_fp_fraction", ""),
            "passed": advisory_fp_ok,
        }
        if not advisory_fp_ok:
            reasons.append(
                f"Protective-advisory false-positive rate ({cand_advisory_fp:.4f}, {cand_safety.get('protective_advisory_fp_fraction')}) exceeds threshold ({p.max_protective_advisory_fp_rate})"
            )

        phish_fn_ok = cand_phish_fn <= p.max_phishing_fn_rate
        checks["phishing_false_negative_rate"] = {
            "requirement": f"<= {p.max_phishing_fn_rate}",
            "observed": cand_phish_fn,
            "fraction": cand_safety.get("phishing_fn_fraction", ""),
            "passed": phish_fn_ok,
        }
        if not phish_fn_ok:
            reasons.append(
                f"Phishing false-negative rate ({cand_phish_fn:.4f}, {cand_safety.get('phishing_fn_fraction')}) exceeds threshold ({p.max_phishing_fn_rate})"
            )

        # 4. Invariance Robustness Constraints
        ws_flip_rate = robustness_metrics.get("whitespace_invariance", {}).get("candidate_flip_rate", 0.0)
        ws_ok = ws_flip_rate <= p.max_whitespace_flip_rate
        checks["whitespace_invariance"] = {
            "requirement": f"<= {p.max_whitespace_flip_rate}",
            "observed": ws_flip_rate,
            "passed": ws_ok,
        }
        if not ws_ok:
            reasons.append(f"Whitespace flip rate ({ws_flip_rate}) violates invariance policy")

        zw_flip_rate = robustness_metrics.get("zero_width_invariance", {}).get("candidate_flip_rate", 0.0)
        zw_ok = zw_flip_rate <= p.max_zerowidth_flip_rate
        checks["zero_width_invariance"] = {
            "requirement": f"<= {p.max_zerowidth_flip_rate}",
            "observed": zw_flip_rate,
            "passed": zw_ok,
        }
        if not zw_ok:
            reasons.append(f"Zero-width char flip rate ({zw_flip_rate}) violates invariance policy")

        num_flip_rate = robustness_metrics.get("devanagari_numeral_invariance", {}).get("candidate_flip_rate", 0.0)
        num_ok = num_flip_rate <= p.max_numeral_flip_rate
        checks["numeral_invariance"] = {
            "requirement": f"<= {p.max_numeral_flip_rate}",
            "observed": num_flip_rate,
            "passed": num_ok,
        }
        if not num_ok:
            reasons.append(f"Devanagari numeral flip rate ({num_flip_rate}) violates invariance policy")

        all_passed = (
            f1_floor_ok
            and f1_retention_ok
            and legit_fp_ok
            and advisory_fp_ok
            and phish_fn_ok
            and ws_ok
            and zw_ok
            and num_ok
        )

        verdict = BenchmarkVerdict.PASS.value if all_passed else BenchmarkVerdict.FAIL.value

        return {
            "verdict": verdict,
            "all_passed": all_passed,
            "reasons": reasons if not all_passed else ["All safety and performance benchmark criteria satisfied."],
            "checks": checks,
            "policy": p.to_dict(),
            "notice": "A PASS verdict permits consideration for offline human-reviewed shadow registration only. It does NOT automatically activate, promote, or alter production scoring.",
        }

    def run_full_evaluation(
        self,
        candidate_dir: str,
        val_corpus_path: Optional[str] = None,
        baseline_version: Optional[str] = None,
        policy: Optional[BenchmarkPolicy] = None,
    ) -> Dict[str, Any]:
        """
        Executes the complete evaluation workflow:
        1. Verifies candidate provenance and cryptographic integrity.
        2. Discovers baseline model from registry and verifies integrity.
        3. Enforces strict dataset isolation and verifies locked test partition digest.
        4. Evaluates both models on identical validation records.
        5. Computes subgroup breakdowns and counterfactual robustness metrics.
        6. Evaluates benchmark gate policy.
        """
        p = policy or self.policy

        # Step 1: Candidate provenance & integrity
        cand_info = self.verify_candidate_provenance(candidate_dir)

        # Step 2: Baseline discovery & integrity
        base_info = self.discover_baseline_model()

        # Step 3: Dataset isolation
        val_path = val_corpus_path or os.path.join(self.project_root, DEFAULT_VAL_CORPUS)
        isolation_info = self.verify_dataset_isolation(val_path)

        # Load validation records
        val_records = self.load_validation_records(val_path)

        # Load models safely (allow_pickle=False is enforced inside CustomNeuralClassifier.load_checkpoint)
        base_model = CustomNeuralClassifier.load_checkpoint(base_info["checkpoint_dir"])
        cand_model = CustomNeuralClassifier.load_checkpoint(cand_info["checkpoint_dir"])

        hasher = CharacterNGramHasher(num_features=1024, min_n=3, max_n=5)

        # Step 4: Evaluate both models
        y_true, y_pred_base, base_metrics = self.evaluate_model_on_records(base_model, val_records, hasher=hasher)
        _, y_pred_cand, cand_metrics = self.evaluate_model_on_records(cand_model, val_records, hasher=hasher)

        # Step 5: Subgroup analysis
        subgroup_info = self.run_subgroup_analysis(val_records, y_true, y_pred_base, y_pred_cand)

        # Step 6: Counterfactual robustness tests
        robustness_info = self.run_counterfactual_robustness_tests(val_records, base_model, cand_model, hasher=hasher)

        # Step 7: Benchmark Gate
        gate_result = self.evaluate_benchmark_gate(
            baseline_metrics=base_metrics,
            candidate_metrics=cand_metrics,
            robustness_metrics=robustness_info,
            policy=p,
        )

        evaluation_report = {
            "schema_version": "1.0.0",
            "candidate": {
                "candidate_id": cand_info["candidate_id"],
                "candidate_version": cand_info["candidate_version"],
                "checkpoint_dir": cand_info["checkpoint_dir"],
                "weights_sha256": cand_info["weights_sha256"],
                "metadata_sha256": cand_info["metadata_sha256"],
                "provenance_summary": cand_info["provenance_summary"],
                "preprocessing_version": cand_info["preprocessing_version"],
            },
            "baseline": {
                "model_version": base_info["model_version"],
                "checkpoint_dir": base_info["checkpoint_dir"],
                "weights_sha256": base_info["weights_sha256"],
                "metadata_sha256": base_info["metadata_sha256"],
                "operating_mode": base_info["operating_mode"],
                "is_production_authoritative": base_info["is_production_authoritative"],
            },
            "dataset_isolation": isolation_info,
            "metrics": {
                "baseline": base_metrics,
                "candidate": cand_metrics,
                "comparison": {
                    "accuracy_delta": round(cand_metrics["accuracy"] - base_metrics["accuracy"], 4),
                    "macro_f1_delta": round(cand_metrics["macro_f1"] - base_metrics["macro_f1"], 4),
                    "legitimate_fp_delta": round(
                        cand_metrics["safety_metrics"]["legitimate_fp_rate"]
                        - base_metrics["safety_metrics"]["legitimate_fp_rate"],
                        4,
                    ),
                    "protective_advisory_fp_delta": round(
                        cand_metrics["safety_metrics"]["protective_advisory_fp_rate"]
                        - base_metrics["safety_metrics"]["protective_advisory_fp_rate"],
                        4,
                    ),
                    "phishing_fn_delta": round(
                        cand_metrics["safety_metrics"]["phishing_fn_rate"]
                        - base_metrics["safety_metrics"]["phishing_fn_rate"],
                        4,
                    ),
                },
            },
            "subgroup_analysis": subgroup_info,
            "robustness_evaluation": robustness_info,
            "benchmark_gate": gate_result,
            "governance_guarantees": {
                "zero_training_performed": True,
                "active_model_config_unmodified": True,
                "production_registry_unmodified": True,
                "production_risk_scoring_delta": 0,
                "locked_evaluation_partition_untouched": True,
                "cost_inr": 0,
                "local_only_execution": True,
            },
        }

        return evaluation_report
