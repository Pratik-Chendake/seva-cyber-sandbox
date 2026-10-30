#!/usr/bin/env python3
"""
Seva Cyber Sandbox — Phase 6.4.7: Controlled Multi-Seed Candidate Training.

OBJECTIVE:
1. Train experimental candidate neural models using the v4 synthetic training partition:
   'data/generated/v4/synthetic_training_corpus.jsonl' (1,500 records across 30 families).
2. Monitor generalization and early stopping using the v4 development partition:
   'data/generated/v4/synthetic_dev_corpus.jsonl' (300 records across 6 families).
   ZERO gradient updates are ever computed from development examples.
3. Completely isolate and block the v4 qualification partition:
   'data/generated/v4/synthetic_qualification_corpus.jsonl' (450 records, sealed benchmark).
4. Train across three independent seeds: 42, 101, 202 from random initialization.
5. Save candidates under:
   - models/candidates/candidate_v4_seed42/
   - models/candidates/candidate_v4_seed101/
   - models/candidates/candidate_v4_seed202/
6. Compare candidates against baseline 'custom-mlp-v1.1.0-preproc' on the development set.
7. Execute a deterministic candidate selection policy.
8. Enforce zero side-effects on production registry and active runtime configuration.
"""

from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
import math
import os
import shutil
import sys
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple
import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

from src.custom_model import (
    CharacterNGramHasher,
    CustomNeuralClassifier,
    IDX_TO_LABEL,
    LABEL_TO_IDX,
    NUM_CLASSES,
)
from src.dataset_preprocessing import (
    NEURAL_PREPROCESSING_VERSION,
    normalize_record_text,
    preprocess_for_neural_model,
    validate_single_record,
)
from src.dataset_validator import compute_locked_test_hash

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Phase6_4_7_ControlledTraining")

# =============================================================================
# DEFAULT PATHS & CONFIGURATION
# =============================================================================

DEFAULT_V4_DIR = os.path.join(PROJECT_ROOT, "data", "generated", "v4")
DEFAULT_TRAIN_CORPUS = os.path.join(DEFAULT_V4_DIR, "synthetic_training_corpus.jsonl")
DEFAULT_DEV_CORPUS = os.path.join(DEFAULT_V4_DIR, "synthetic_dev_corpus.jsonl")
DEFAULT_QUAL_CORPUS = os.path.join(DEFAULT_V4_DIR, "synthetic_qualification_corpus.jsonl")

DEFAULT_TRAIN_MANIFEST = os.path.join(DEFAULT_V4_DIR, "training_manifest.json")
DEFAULT_DEV_MANIFEST = os.path.join(DEFAULT_V4_DIR, "dev_manifest.json")
DEFAULT_QUAL_MANIFEST = os.path.join(DEFAULT_V4_DIR, "qualification_manifest.json")
DEFAULT_CORPUS_MANIFEST = os.path.join(DEFAULT_V4_DIR, "v4_corpus_manifest.json")
DEFAULT_V4_EXPOSURE_LEDGER = os.path.join(PROJECT_ROOT, "evaluation", "qualification", "exposure_ledger_v4.json")

DEFAULT_LOCKED_TEST_MANIFEST = os.path.join(PROJECT_ROOT, "data", "locked_test_manifest.json")
DEFAULT_BASELINE_CHECKPOINT = os.path.join(PROJECT_ROOT, "models", "experimental_custom_v1")

DEFAULT_CANDIDATES_ROOT = os.path.join(PROJECT_ROOT, "models", "candidates")
DEFAULT_SELECTION_SUMMARY_PATH = os.path.join(
    PROJECT_ROOT, "evaluation", "candidates", "phase6_4_7_selection_summary.json"
)

# Training Hyperparameters
SEEDS = [42, 101, 202]
DEFAULT_BATCH_SIZE = 32
DEFAULT_MAX_EPOCHS = 50
DEFAULT_EARLY_STOPPING_PATIENCE = 10
DEFAULT_INITIAL_LR = 0.005
DEFAULT_WEIGHT_DECAY = 0.0005
DEFAULT_DROPOUT_RATE = 0.20
DEFAULT_INPUT_DIM = 1024
DEFAULT_HIDDEN_DIM1 = 64
DEFAULT_HIDDEN_DIM2 = 32
DEFAULT_NUM_CLASSES = 3

LR_SCHEDULE_MILESTONES = {
    15: 0.0025,
    30: 0.0010,
}

EXPECTED_LOCKED_DIGEST = "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"


# =============================================================================
# EXCEPTIONS
# =============================================================================

class ControlledTrainingError(Exception):
    """Base exception for Phase 6.4.7 controlled training errors."""
    pass


class DatasetIsolationViolation(ControlledTrainingError):
    """Raised when forbidden partitions or partition leakage is detected."""
    pass


class BenchmarkGovernanceViolation(ControlledTrainingError):
    """Raised when cryptographic digests or manifest checks fail."""
    pass


# =============================================================================
# UTILITIES
# =============================================================================

def get_utc_now_iso() -> str:
    """Returns current UTC ISO-8601 timestamp string."""
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


# =============================================================================
# DATASET ISOLATION & PROVENANCE VERIFICATION
# =============================================================================

def verify_phase6_4_7_isolation(
    train_path: str = DEFAULT_TRAIN_CORPUS,
    dev_path: str = DEFAULT_DEV_CORPUS,
    train_manifest_path: str = DEFAULT_TRAIN_MANIFEST,
    dev_manifest_path: str = DEFAULT_DEV_MANIFEST,
    qual_manifest_path: str = DEFAULT_QUAL_MANIFEST,
    exposure_ledger_path: str = DEFAULT_V4_EXPOSURE_LEDGER,
    locked_manifest_path: str = DEFAULT_LOCKED_TEST_MANIFEST,
) -> Dict[str, Any]:
    """
    Performs comprehensive pre-flight verification:
    1. Training and development files exist and match their manifests.
    2. Qualification partition manifest exists and is marked sealed_independent_benchmark.
    3. v4 exposure ledger exists and indicates UNEXPOSED state.
    4. ZERO qualification records are opened, read, or parsed.
    5. Locked evaluation partition digest is verified.
    """
    # 1. Verify Training Manifest & Dataset
    if not os.path.isfile(train_path):
        raise DatasetIsolationViolation(f"Missing authorized training corpus: '{train_path}'")
    if not os.path.isfile(train_manifest_path):
        raise BenchmarkGovernanceViolation(f"Missing training manifest: '{train_manifest_path}'")

    with open(train_manifest_path, "r", encoding="utf-8") as f:
        train_manifest = json.load(f)

    actual_train_sha = compute_file_sha256(train_path)
    if train_manifest.get("file_sha256") != actual_train_sha:
        raise BenchmarkGovernanceViolation(
            f"Training corpus SHA mismatch! Manifest: {train_manifest.get('file_sha256')}, Disk: {actual_train_sha}"
        )

    # 2. Verify Development Manifest & Dataset
    if not os.path.isfile(dev_path):
        raise DatasetIsolationViolation(f"Missing authorized dev corpus: '{dev_path}'")
    if not os.path.isfile(dev_manifest_path):
        raise BenchmarkGovernanceViolation(f"Missing dev manifest: '{dev_manifest_path}'")

    with open(dev_manifest_path, "r", encoding="utf-8") as f:
        dev_manifest = json.load(f)

    actual_dev_sha = compute_file_sha256(dev_path)
    if dev_manifest.get("file_sha256") != actual_dev_sha:
        raise BenchmarkGovernanceViolation(
            f"Development corpus SHA mismatch! Manifest: {dev_manifest.get('file_sha256')}, Disk: {actual_dev_sha}"
        )

    # 3. Verify Qualification Manifest & Ledger State WITHOUT reading qualification corpus
    if not os.path.isfile(qual_manifest_path):
        raise BenchmarkGovernanceViolation(f"Missing qualification manifest: '{qual_manifest_path}'")

    with open(qual_manifest_path, "r", encoding="utf-8") as f:
        qual_manifest = json.load(f)

    if qual_manifest.get("lifecycle_state") != "sealed_independent_benchmark":
        raise BenchmarkGovernanceViolation(
            f"Qualification manifest lifecycle state must be 'sealed_independent_benchmark', got: '{qual_manifest.get('lifecycle_state')}'"
        )

    if not os.path.isfile(exposure_ledger_path):
        raise BenchmarkGovernanceViolation(f"Missing v4 exposure ledger at: '{exposure_ledger_path}'")

    with open(exposure_ledger_path, "r", encoding="utf-8") as f:
        ledger = json.load(f)

    qual_sha = qual_manifest.get("file_sha256")
    if qual_sha not in ledger.get("partitions", {}):
        raise BenchmarkGovernanceViolation(f"Qualification partition SHA '{qual_sha}' not found in v4 exposure ledger!")

    ledger_entry = ledger["partitions"][qual_sha]
    if ledger_entry.get("is_exposed") is not False or ledger_entry.get("exposure_count", -1) != 0:
        raise BenchmarkGovernanceViolation(
            f"Qualification partition is already exposed in ledger: is_exposed={ledger_entry.get('is_exposed')}, count={ledger_entry.get('exposure_count')}"
        )

    # 4. Verify Locked Test Manifest and Dataset
    eval_dataset_path = os.path.join(PROJECT_ROOT, "data", "phishing_eval_dataset.json")
    if not os.path.isfile(eval_dataset_path):
        raise FileNotFoundError(f"Missing locked eval dataset: '{eval_dataset_path}'")

    with open(eval_dataset_path, "r", encoding="utf-8") as f:
        eval_recs = json.load(f)
    actual_locked_digest = compute_locked_test_hash(eval_recs)
    if actual_locked_digest != EXPECTED_LOCKED_DIGEST:
        raise BenchmarkGovernanceViolation(
            f"Locked evaluation dataset has been tampered with! Expected {EXPECTED_LOCKED_DIGEST}, got {actual_locked_digest}"
        )

    return {
        "training_sha256": actual_train_sha,
        "training_records": train_manifest.get("record_count", 1500),
        "dev_sha256": actual_dev_sha,
        "dev_records": dev_manifest.get("record_count", 300),
        "qual_sha256": qual_sha,
        "qual_status": ledger_entry.get("current_status"),
        "locked_test_manifest_sha256": actual_locked_digest,
    }


# =============================================================================
# DATASET LOADING & CANONICAL PREPROCESSING
# =============================================================================

def load_and_preprocess_partition(
    filepath: str,
    partition_name: str,
    hasher: CharacterNGramHasher,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[Dict[str, Any]]]:
    """
    Loads JSONL records, enforces strict schema validation, applies canonical
    neural preprocessing, extracts 1024-dim character n-gram feature vectors,
    and constructs label arrays.
    """
    if "qualification" in filepath.lower() or "qual" in os.path.basename(filepath).lower():
        if partition_name != "qualification_strictly_prohibited":
            raise DatasetIsolationViolation(
                f"ATTEMPTED QUALIFICATION LEAKAGE: Loading '{filepath}' is forbidden during candidate training!"
            )

    records: List[Dict[str, Any]] = []
    texts: List[str] = []
    labels: List[int] = []

    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            rec = json.loads(line_str)
            is_valid, errors = validate_single_record(rec)
            if not is_valid:
                raise ControlledTrainingError(f"Record validation failed in {filepath}:{line_num}: {errors}")

            raw_text = rec["text"]
            norm_text = preprocess_for_neural_model(raw_text)

            label_str = rec["ground_truth_label"]
            if label_str not in LABEL_TO_IDX:
                raise ControlledTrainingError(f"Unknown label '{label_str}' in {filepath}:{line_num}")

            records.append(rec)
            texts.append(norm_text)
            labels.append(LABEL_TO_IDX[label_str])

    n_samples = len(records)
    y = np.array(labels, dtype=np.int64)

    # One-hot encode targets
    Y = np.zeros((n_samples, NUM_CLASSES), dtype=np.float32)
    Y[np.arange(n_samples), y] = 1.0

    # Extract 1024-dim character n-gram features
    X = hasher.transform_batch(texts)

    assert X.shape == (n_samples, hasher.num_features)
    assert np.all(np.isfinite(X)), "Non-finite values detected in extracted feature matrix!"

    logger.info(
        f"Partition '{partition_name}' loaded from '{os.path.basename(filepath)}': "
        f"{n_samples} examples, feature shape {X.shape}, label distribution: {Counter(y)}"
    )
    return X, y, Y, records


# =============================================================================
# CLASSIFICATION & EVALUATION METRICS
# =============================================================================

def compute_wilson_ci(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float]:
    """Computes Wilson score interval for a binomial proportion."""
    if n <= 0:
        return 0.0, 0.0
    z = 1.959963984540054
    p = k / n
    denom = 1.0 + (z**2) / n
    center = (p + (z**2) / (2 * n)) / denom
    half = (z * math.sqrt((p * (1.0 - p) / n) + ((z**2) / (4 * (n**2))))) / denom
    return max(0.0, round(center - half, 4)), min(1.0, round(center + half, 4))


def compute_classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
) -> Dict[str, Any]:
    """
    Computes rigorous classification metrics including macro-F1, per-class F1,
    confusion matrix, and citizen safety metrics with Wilson 95% confidence intervals.
    """
    n_samples = len(y_true)
    assert len(y_pred) == n_samples

    cm = np.zeros((NUM_CLASSES, NUM_CLASSES), dtype=np.int64)
    for t, p in zip(y_true, y_pred):
        cm[t, p] += 1

    accuracy = float(np.trace(cm) / n_samples)
    acc_ci = compute_wilson_ci(int(np.trace(cm)), n_samples)

    per_class = {}
    f1s = []
    precisions = []
    recalls = []

    for c_idx in range(NUM_CLASSES):
        c_name = IDX_TO_LABEL[c_idx]
        tp = int(cm[c_idx, c_idx])
        fp = int(np.sum(cm[:, c_idx]) - tp)
        fn = int(np.sum(cm[c_idx, :]) - tp)
        support = int(np.sum(cm[c_idx, :]))

        prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

        prec_ci = compute_wilson_ci(tp, tp + fp)
        rec_ci = compute_wilson_ci(tp, tp + fn)

        per_class[c_name] = {
            "class_index": c_idx,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "support": support,
            "precision": round(prec, 4),
            "precision_ci_95": prec_ci,
            "precision_fraction": f"{tp}/{tp + fp}",
            "recall": round(rec, 4),
            "recall_ci_95": rec_ci,
            "recall_fraction": f"{tp}/{support}",
            "f1": round(f1, 4),
        }
        f1s.append(f1)
        precisions.append(prec)
        recalls.append(rec)

    macro_f1 = float(np.mean(f1s))
    macro_prec = float(np.mean(precisions))
    macro_rec = float(np.mean(recalls))
    balanced_acc = macro_rec

    weights = [per_class[IDX_TO_LABEL[c]]["support"] / n_samples for c in range(NUM_CLASSES)]
    weighted_f1 = float(np.sum([f1s[c] * weights[c] for c in range(NUM_CLASSES)]))

    # Safety metrics
    legit_idx = LABEL_TO_IDX["legitimate"]
    phish_idx = LABEL_TO_IDX["phishing"]
    adv_idx = LABEL_TO_IDX["protective_advisory"]

    legit_total = int(np.sum(cm[legit_idx, :]))
    legit_fp_to_phish = int(cm[legit_idx, phish_idx])
    legit_fp_rate = float(legit_fp_to_phish / legit_total) if legit_total > 0 else 0.0
    legit_fp_ci = compute_wilson_ci(legit_fp_to_phish, legit_total)

    adv_total = int(np.sum(cm[adv_idx, :]))
    adv_fp_to_phish = int(cm[adv_idx, phish_idx])
    adv_fp_rate = float(adv_fp_to_phish / adv_total) if adv_total > 0 else 0.0
    adv_fp_ci = compute_wilson_ci(adv_fp_to_phish, adv_total)

    phish_total = int(np.sum(cm[phish_idx, :]))
    phish_fn = int(phish_total - cm[phish_idx, phish_idx])
    phish_fn_rate = float(phish_fn / phish_total) if phish_total > 0 else 0.0
    phish_fn_ci = compute_wilson_ci(phish_fn, phish_total)

    return {
        "sample_count": n_samples,
        "accuracy": round(accuracy, 4),
        "accuracy_ci_95": acc_ci,
        "accuracy_fraction": f"{int(np.trace(cm))}/{n_samples}",
        "total_incorrect": int(n_samples - np.trace(cm)),
        "total_incorrect_fraction": f"{int(n_samples - np.trace(cm))}/{n_samples}",
        "macro_f1": round(macro_f1, 4),
        "macro_precision": round(macro_prec, 4),
        "macro_recall": round(macro_rec, 4),
        "balanced_accuracy": round(balanced_acc, 4),
        "weighted_f1": round(weighted_f1, 4),
        "confusion_matrix": cm.tolist(),
        "per_class": per_class,
        "safety_metrics": {
            "legitimate_fp_rate": round(legit_fp_rate, 4),
            "legitimate_fp_ci_95": legit_fp_ci,
            "legitimate_fp_fraction": f"{legit_fp_to_phish}/{legit_total}",
            "protective_advisory_fp_rate": round(adv_fp_rate, 4),
            "protective_advisory_fp_ci_95": adv_fp_ci,
            "protective_advisory_fp_fraction": f"{adv_fp_to_phish}/{adv_total}",
            "phishing_fn_rate": round(phish_fn_rate, 4),
            "phishing_fn_ci_95": phish_fn_ci,
            "phishing_fn_fraction": f"{phish_fn}/{phish_total}",
            "prediction_distribution": {
                IDX_TO_LABEL[c]: int(np.sum(cm[:, c])) for c in range(NUM_CLASSES)
            },
        },
    }


def compute_subgroup_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    records: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Computes disaggregated metrics across language, URL presence, and campaign families."""
    subgroups = {
        "by_language": {},
        "by_url_presence": {},
        "by_campaign_family": {},
    }

    # Language
    for lang in ["mr", "mr-Latn", "en", "mr-en"]:
        idx = [i for i, r in enumerate(records) if r["language"] == lang]
        if idx:
            sub_true = y_true[idx]
            sub_pred = y_pred[idx]
            acc = float(np.mean(sub_true == sub_pred))
            subgroups["by_language"][lang] = {
                "count": len(idx),
                "accuracy": round(acc, 4),
                "accuracy_fraction": f"{int(np.sum(sub_true == sub_pred))}/{len(idx)}",
            }

    # URL presence
    for url_val in [True, False]:
        idx = [i for i, r in enumerate(records) if r["has_url"] == url_val]
        if idx:
            sub_true = y_true[idx]
            sub_pred = y_pred[idx]
            acc = float(np.mean(sub_true == sub_pred))
            subgroups["by_url_presence"][str(url_val)] = {
                "count": len(idx),
                "accuracy": round(acc, 4),
                "accuracy_fraction": f"{int(np.sum(sub_true == sub_pred))}/{len(idx)}",
            }

    # Campaign Family
    fams = sorted(list({r["campaign_id"] for r in records}))
    for fam in fams:
        idx = [i for i, r in enumerate(records) if r["campaign_id"] == fam]
        if idx:
            sub_true = y_true[idx]
            sub_pred = y_pred[idx]
            acc = float(np.mean(sub_true == sub_pred))
            gt_lbl = records[idx[0]]["ground_truth_label"]
            subgroups["by_campaign_family"][fam] = {
                "count": len(idx),
                "ground_truth_label": gt_lbl,
                "accuracy": round(acc, 4),
                "accuracy_fraction": f"{int(np.sum(sub_true == sub_pred))}/{len(idx)}",
            }

    return subgroups


# =============================================================================
# MODEL TRAINING WITH EARLY STOPPING
# =============================================================================

@dataclass
class EpochMetrics:
    epoch: int
    lr: float
    train_loss: float
    train_accuracy: float
    dev_loss: float
    dev_accuracy: float
    dev_macro_f1: float
    dev_metrics: Dict[str, Any]


def train_candidate_seed(
    seed: int,
    X_train: np.ndarray,
    y_train: np.ndarray,
    Y_train: np.ndarray,
    X_dev: np.ndarray,
    y_dev: np.ndarray,
    Y_dev: np.ndarray,
    dev_records: List[Dict[str, Any]],
    candidates_root: str = DEFAULT_CANDIDATES_ROOT,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_epochs: int = DEFAULT_MAX_EPOCHS,
    early_stopping_patience: int = DEFAULT_EARLY_STOPPING_PATIENCE,
    initial_lr: float = DEFAULT_INITIAL_LR,
    weight_decay: float = DEFAULT_WEIGHT_DECAY,
    dropout_rate: float = DEFAULT_DROPOUT_RATE,
    hasher: Optional[CharacterNGramHasher] = None,
) -> Dict[str, Any]:
    """
    Trains a single candidate model from random He/Xavier initialization.
    
    GOVERNANCE & SAFETY CONTROLS:
    - Zero dev gradients: Dev partition is evaluated in inference mode only.
    - Early stopping: Monitors development Macro-F1 with patience.
    - Restores and saves weights from the epoch with highest dev Macro-F1.
    - Saves immutable artifacts under 'models/candidates/candidate_v4_seed{seed}/'.
    """
    candidate_id = f"candidate_v4_seed{seed}"
    candidate_dir = os.path.join(candidates_root, candidate_id)

    if os.path.exists(candidate_dir):
        raise ControlledTrainingError(
            f"Candidate directory already exists at '{candidate_dir}'. Overwriting is strictly forbidden."
        )

    hasher_obj = hasher or CharacterNGramHasher(num_features=DEFAULT_INPUT_DIM)
    n_train = len(X_train)
    n_dev = len(X_dev)

    # 1. Instantiate fresh model with RANDOM INITIALIZATION
    model = CustomNeuralClassifier(
        input_dim=DEFAULT_INPUT_DIM,
        hidden_dim1=DEFAULT_HIDDEN_DIM1,
        hidden_dim2=DEFAULT_HIDDEN_DIM2,
        num_classes=DEFAULT_NUM_CLASSES,
        learning_rate=initial_lr,
        weight_decay=weight_decay,
        dropout_rate=dropout_rate,
        seed=seed,
    )
    model.model_version = candidate_id

    rng = np.random.RandomState(seed)

    best_dev_macro_f1 = -1.0
    best_epoch = 0
    best_weights: Dict[str, np.ndarray] = {}
    best_dev_metrics: Dict[str, Any] = {}
    best_dev_subgroups: Dict[str, Any] = {}
    patience_counter = 0
    history: List[EpochMetrics] = []

    logger.info(f"--- Starting Training Run: {candidate_id} (Random Seed: {seed}) ---")

    for epoch in range(1, max_epochs + 1):
        if epoch in LR_SCHEDULE_MILESTONES:
            model.learning_rate = LR_SCHEDULE_MILESTONES[epoch]

        current_lr = model.learning_rate

        # Mini-batch training on training partition ONLY
        perm = rng.permutation(n_train)
        X_shuff = X_train[perm]
        Y_shuff = Y_train[perm]

        batch_losses = []
        for b_start in range(0, n_train, batch_size):
            X_b = X_shuff[b_start : b_start + batch_size]
            Y_b = Y_shuff[b_start : b_start + batch_size]
            b_loss = model.fit_batch(X_b, Y_b)
            if not np.isfinite(b_loss):
                raise ControlledTrainingError(f"Non-finite loss encountered at epoch {epoch}, batch {b_start}")
            batch_losses.append(b_loss)

        train_loss = float(np.mean(batch_losses))
        train_preds = model.predict(X_train)
        train_acc = float(np.mean(train_preds == y_train))

        # Evaluate on dev partition (INFERENCE ONLY, ZERO GRADIENTS)
        dev_probs = model.predict_proba(X_dev)
        dev_loss = float(model.compute_loss(dev_probs, Y_dev))
        dev_preds = np.argmax(dev_probs, axis=-1)
        dev_metrics = compute_classification_metrics(y_dev, dev_preds)
        dev_acc = dev_metrics["accuracy"]
        dev_macro_f1 = dev_metrics["macro_f1"]

        epoch_stat = EpochMetrics(
            epoch=epoch,
            lr=current_lr,
            train_loss=round(train_loss, 4),
            train_accuracy=round(train_acc, 4),
            dev_loss=round(dev_loss, 4),
            dev_accuracy=round(dev_acc, 4),
            dev_macro_f1=round(dev_macro_f1, 4),
            dev_metrics=dev_metrics,
        )
        history.append(epoch_stat)

        # Check for improvement
        if dev_macro_f1 > best_dev_macro_f1:
            best_dev_macro_f1 = dev_macro_f1
            best_epoch = epoch
            best_dev_metrics = dev_metrics
            best_dev_subgroups = compute_subgroup_metrics(y_dev, dev_preds, dev_records)
            best_weights = {
                "W1": model.W1.copy(),
                "b1": model.b1.copy(),
                "W2": model.W2.copy(),
                "b2": model.b2.copy(),
                "W3": model.W3.copy(),
                "b3": model.b3.copy(),
            }
            patience_counter = 0
            logger.info(
                f"Seed {seed} [Epoch {epoch:02d}]: *BEST* Train Loss: {train_loss:.4f}, "
                f"Dev Loss: {dev_loss:.4f}, Dev Acc: {dev_acc:.4f}, Dev Macro-F1: {dev_macro_f1:.4f}"
            )
        else:
            patience_counter += 1
            if patience_counter >= early_stopping_patience:
                logger.info(
                    f"Seed {seed}: Early stopping triggered at epoch {epoch} "
                    f"(best epoch {best_epoch} dev macro-F1: {best_dev_macro_f1:.4f})"
                )
                break

    # Restore best checkpoint weights
    model.W1 = best_weights["W1"]
    model.b1 = best_weights["b1"]
    model.W2 = best_weights["W2"]
    model.b2 = best_weights["b2"]
    model.W3 = best_weights["W3"]
    model.b3 = best_weights["b3"]

    # Verify best checkpoint evaluation matches exactly
    restored_dev_preds = model.predict(X_dev)
    restored_metrics = compute_classification_metrics(y_dev, restored_dev_preds)
    assert abs(restored_metrics["macro_f1"] - best_dev_macro_f1) < 1e-4

    # Atomic artifact creation
    temp_dir = tempfile.mkdtemp(prefix=f"cand_v4_seed{seed}_")
    now_utc = get_utc_now_iso()

    try:
        # A. Save model weights and metadata
        meta_extra = {
            "candidate_id": candidate_id,
            "seed": seed,
            "created_at_utc": now_utc,
            "lifecycle_state": "experimental",
            "is_production_authoritative": False,
            "preprocessing_version": NEURAL_PREPROCESSING_VERSION,
            "training_corpus": "synthetic_training_corpus.jsonl",
            "best_epoch": best_epoch,
            "total_epochs_trained": len(history),
            "best_dev_macro_f1": best_dev_macro_f1,
        }
        model.save_checkpoint(temp_dir, metadata=meta_extra)

        weights_file = os.path.join(temp_dir, "model_weights.npz")
        meta_file = os.path.join(temp_dir, "model_metadata.json")

        w_sha = compute_file_sha256(weights_file)
        m_sha = compute_file_sha256(meta_file)

        # B. Save candidate training report
        report_file = os.path.join(temp_dir, "candidate_training_report.json")
        report_data = {
            "report_schema_version": "1.0.0",
            "candidate_id": candidate_id,
            "random_seed": seed,
            "lifecycle_state": "experimental",
            "created_at_utc": now_utc,
            "architecture": {
                "model_type": "Multi-Layer Perceptron (MLP)",
                "input_dim": DEFAULT_INPUT_DIM,
                "hidden_dim1": DEFAULT_HIDDEN_DIM1,
                "hidden_dim2": DEFAULT_HIDDEN_DIM2,
                "num_classes": DEFAULT_NUM_CLASSES,
                "activation": "LeakyReLU (alpha=0.01)",
                "initialization": "He normal (hidden layers), Xavier uniform (output layer)",
            },
            "hyperparameters": {
                "max_epochs": max_epochs,
                "early_stopping_patience": early_stopping_patience,
                "batch_size": batch_size,
                "initial_learning_rate": initial_lr,
                "weight_decay": weight_decay,
                "dropout_rate": dropout_rate,
                "lr_schedule_milestones": LR_SCHEDULE_MILESTONES,
            },
            "training_run_summary": {
                "best_epoch": best_epoch,
                "total_epochs_trained": len(history),
                "stopped_early": len(history) < max_epochs,
                "best_dev_macro_f1": round(best_dev_macro_f1, 4),
                "best_dev_accuracy": round(best_dev_metrics["accuracy"], 4),
            },
            "dataset_provenance": {
                "training_corpus": "data/generated/v4/synthetic_training_corpus.jsonl",
                "training_examples": n_train,
                "dev_corpus": "data/generated/v4/synthetic_dev_corpus.jsonl",
                "dev_examples": n_dev,
                "qualification_partition": "SEALED",
                "feature_schema_version": "1.1.0",
                "preprocessing_version": NEURAL_PREPROCESSING_VERSION,
            },
            "dev_evaluation_metrics": best_dev_metrics,
            "dev_subgroup_metrics": best_dev_subgroups,
            "epoch_history": [
                {
                    "epoch": h.epoch,
                    "lr": h.lr,
                    "train_loss": h.train_loss,
                    "train_accuracy": h.train_accuracy,
                    "dev_loss": h.dev_loss,
                    "dev_accuracy": h.dev_accuracy,
                    "dev_macro_f1": h.dev_macro_f1,
                }
                for h in history
            ],
            "artifacts": {
                "model_weights": {"filename": "model_weights.npz", "sha256": w_sha},
                "model_metadata": {"filename": "model_metadata.json", "sha256": m_sha},
            },
            "warnings_and_limitations": [
                "Evaluated strictly on synthetic development partition (300 records).",
                "Synthetic performance does not establish certified real-world detection accuracy.",
                "Experimental candidate model. Not authorized for production promotion.",
            ],
            "status": "SUCCESS",
        }
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        r_sha = compute_file_sha256(report_file)

        # C. Save manifest.json
        manifest_file = os.path.join(temp_dir, "manifest.json")
        manifest_data = {
            "manifest_schema_version": "1.0.0",
            "candidate_id": candidate_id,
            "candidate_version": f"4.0.0-seed{seed}",
            "random_seed": seed,
            "lifecycle_state": "experimental",
            "created_at_utc": now_utc,
            "architecture_version": "3-layer-mlp-ngram-v1",
            "artifacts": {
                "model_weights": {"filename": "model_weights.npz", "sha256": w_sha},
                "model_metadata": {"filename": "model_metadata.json", "sha256": m_sha},
                "training_report": {"filename": "candidate_training_report.json", "sha256": r_sha},
            },
            "provenance_summary": {
                "training_corpus": "data/generated/v4/synthetic_training_corpus.jsonl",
                "training_samples": n_train,
                "dev_corpus": "data/generated/v4/synthetic_dev_corpus.jsonl",
                "dev_samples": n_dev,
                "qualification_partition": "SEALED",
            },
            "disclaimer": "EXPERIMENTAL CANDIDATE MODEL ARTIFACT. Not approved for production or shadow deployment. Active registry and runtime configuration are untouched.",
        }
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)
        man_sha = compute_file_sha256(manifest_file)

        # Atomic move to destination
        os.makedirs(candidates_root, exist_ok=True)
        shutil.move(temp_dir, candidate_dir)
        logger.info(f"Candidate '{candidate_id}' successfully saved to '{candidate_dir}'.")

    except Exception as exc:
        if os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass
        raise ControlledTrainingError(f"Candidate serialization failed for seed {seed}: {exc}") from exc

    return {
        "seed": seed,
        "candidate_id": candidate_id,
        "candidate_dir": candidate_dir,
        "best_epoch": best_epoch,
        "total_epochs": len(history),
        "best_dev_macro_f1": best_dev_macro_f1,
        "dev_metrics": best_dev_metrics,
        "dev_subgroups": best_dev_subgroups,
        "weights_sha256": w_sha,
        "metadata_sha256": m_sha,
        "manifest_sha256": man_sha,
        "report_sha256": r_sha,
    }


# =============================================================================
# BASELINE EVALUATION
# =============================================================================

def evaluate_baseline_on_dev(
    checkpoint_dir: str = DEFAULT_BASELINE_CHECKPOINT,
    X_dev: np.ndarray = None,
    y_dev: np.ndarray = None,
    dev_records: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Evaluates the registered baseline model ('custom-mlp-v1.1.0-preproc')
    on the v4 development partition.
    """
    if not os.path.isdir(checkpoint_dir):
        raise FileNotFoundError(f"Baseline checkpoint directory missing at '{checkpoint_dir}'")

    baseline_model = CustomNeuralClassifier.load_checkpoint(checkpoint_dir)
    preds = baseline_model.predict(X_dev)
    metrics = compute_classification_metrics(y_dev, preds)
    subgroups = compute_subgroup_metrics(y_dev, preds, dev_records)
    return {
        "model_version": baseline_model.model_version,
        "checkpoint_dir": checkpoint_dir,
        "metrics": metrics,
        "subgroups": subgroups,
    }


# =============================================================================
# DETERMINISTIC CANDIDATE SELECTION POLICY
# =============================================================================

@dataclass
class CandidateGateEvaluation:
    seed: int
    candidate_id: str
    dev_macro_f1: float
    macro_f1_delta_vs_baseline: float
    legitimate_fp_rate: float
    protective_advisory_fp_rate: float
    phishing_fn_rate: float
    passes_macro_f1_gate: bool
    passes_macro_f1_drop_gate: bool
    passes_legit_fp_gate: bool
    passes_advisory_fp_gate: bool
    passes_phish_fn_gate: bool
    overall_eligible: bool
    failing_gates: List[str]


def evaluate_candidate_selection(
    baseline_result: Dict[str, Any],
    candidate_summaries: List[Dict[str, Any]],
    min_macro_f1: float = 0.9000,
    max_macro_f1_drop: float = -0.0200,
    max_legit_fp: float = 0.1500,
    max_advisory_fp: float = 0.0500,
    max_phish_fn: float = 0.0500,
) -> Dict[str, Any]:
    """
    Executes the predeclared deterministic candidate selection policy.
    Evaluates each candidate across the 5 safety and performance gates.
    """
    base_f1 = baseline_result["metrics"]["macro_f1"]
    evaluations: List[CandidateGateEvaluation] = []
    eligible_cands: List[CandidateGateEvaluation] = []

    for c in candidate_summaries:
        m = c["dev_metrics"]
        s = m["safety_metrics"]

        dev_f1 = m["macro_f1"]
        delta_f1 = dev_f1 - base_f1
        legit_fp = s["legitimate_fp_rate"]
        advisory_fp = s["protective_advisory_fp_rate"]
        phish_fn = s["phishing_fn_rate"]

        failing = []
        p_f1 = dev_f1 >= min_macro_f1
        if not p_f1:
            failing.append(f"MIN_MACRO_F1_FAILED ({dev_f1:.4f} < {min_macro_f1})")

        p_drop = delta_f1 >= max_macro_f1_drop
        if not p_drop:
            failing.append(f"MACRO_F1_DROP_FAILED ({delta_f1:+.4f} < {max_macro_f1_drop})")

        p_legit = legit_fp <= max_legit_fp
        if not p_legit:
            failing.append(f"LEGIT_FP_RATE_FAILED ({legit_fp:.4f} > {max_legit_fp})")

        p_adv = advisory_fp <= max_advisory_fp
        if not p_adv:
            failing.append(f"ADVISORY_FP_RATE_FAILED ({advisory_fp:.4f} > {max_advisory_fp})")

        p_phish = phish_fn <= max_phish_fn
        if not p_phish:
            failing.append(f"PHISH_FN_RATE_FAILED ({phish_fn:.4f} > {max_phish_fn})")

        overall = len(failing) == 0

        gate_eval = CandidateGateEvaluation(
            seed=c["seed"],
            candidate_id=c["candidate_id"],
            dev_macro_f1=round(dev_f1, 4),
            macro_f1_delta_vs_baseline=round(delta_f1, 4),
            legitimate_fp_rate=round(legit_fp, 4),
            protective_advisory_fp_rate=round(advisory_fp, 4),
            phishing_fn_rate=round(phish_fn, 4),
            passes_macro_f1_gate=p_f1,
            passes_macro_f1_drop_gate=p_drop,
            passes_legit_fp_gate=p_legit,
            passes_advisory_fp_gate=p_adv,
            passes_phish_fn_gate=p_phish,
            overall_eligible=overall,
            failing_gates=failing,
        )
        evaluations.append(gate_eval)
        if overall:
            eligible_cands.append(gate_eval)

    if not eligible_cands:
        return {
            "status": "NO_CANDIDATE_SELECTED",
            "reason": "No trained candidate satisfied all benchmark gate criteria.",
            "selected_candidate_id": None,
            "selected_seed": None,
            "candidate_evaluations": [asdict(e) for e in evaluations],
        }

    # Deterministic ranking:
    # 1: highest dev_macro_f1 (descending)
    # 2: lowest total FP (ascending)
    # 3: lowest seed (ascending)
    def rank_key(e: CandidateGateEvaluation):
        total_fp = e.legitimate_fp_rate + e.protective_advisory_fp_rate
        return (-e.dev_macro_f1, total_fp, e.seed)

    ranked_eligible = sorted(eligible_cands, key=rank_key)
    winner = ranked_eligible[0]

    return {
        "status": "CANDIDATE_SELECTED",
        "selected_candidate_id": winner.candidate_id,
        "selected_seed": winner.seed,
        "selection_rationale": (
            f"Candidate '{winner.candidate_id}' achieved highest development Macro-F1 ({winner.dev_macro_f1:.4f}) "
            f"with legitimate false alarm rate {winner.legitimate_fp_rate:.4f} <= {max_legit_fp}, "
            f"advisory false alarm rate {winner.protective_advisory_fp_rate:.4f} <= {max_advisory_fp}, "
            f"and phishing false negative rate {winner.phishing_fn_rate:.4f} <= {max_phish_fn}."
        ),
        "ranking_order": [e.candidate_id for e in ranked_eligible],
        "candidate_evaluations": [asdict(e) for e in evaluations],
    }


# =============================================================================
# MAIN ORCHESTRATION PIPELINE
# =============================================================================

def run_phase6_4_7_pipeline(
    train_corpus: str = DEFAULT_TRAIN_CORPUS,
    dev_corpus: str = DEFAULT_DEV_CORPUS,
    train_manifest: str = DEFAULT_TRAIN_MANIFEST,
    dev_manifest: str = DEFAULT_DEV_MANIFEST,
    qual_manifest: str = DEFAULT_QUAL_MANIFEST,
    exposure_ledger: str = DEFAULT_V4_EXPOSURE_LEDGER,
    locked_manifest: str = DEFAULT_LOCKED_TEST_MANIFEST,
    baseline_dir: str = DEFAULT_BASELINE_CHECKPOINT,
    candidates_root: str = DEFAULT_CANDIDATES_ROOT,
    summary_output_path: str = DEFAULT_SELECTION_SUMMARY_PATH,
    seeds: List[int] = SEEDS,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_epochs: int = DEFAULT_MAX_EPOCHS,
    patience: int = DEFAULT_EARLY_STOPPING_PATIENCE,
    initial_lr: float = DEFAULT_INITIAL_LR,
    weight_decay: float = DEFAULT_WEIGHT_DECAY,
    dropout_rate: float = DEFAULT_DROPOUT_RATE,
) -> Dict[str, Any]:
    """
    Executes the entire Phase 6.4.7 multi-seed candidate training and selection pipeline.
    """
    print("=" * 80)
    print("SEVA CYBER SANDBOX — PHASE 6.4.7: CONTROLLED MULTI-SEED CANDIDATE TRAINING")
    print("=" * 80)

    # 1. Dataset Isolation & Manifest Governance Audit
    print("[*] Step 1: Auditing Dataset Isolation and Cryptographic Manifests...")
    iso_info = verify_phase6_4_7_isolation(
        train_path=train_corpus,
        dev_path=dev_corpus,
        train_manifest_path=train_manifest,
        dev_manifest_path=dev_manifest,
        qual_manifest_path=qual_manifest,
        exposure_ledger_path=exposure_ledger,
        locked_manifest_path=locked_manifest,
    )
    print(f"[+] Isolation Audit Passed: Training={iso_info['training_records']}, Dev={iso_info['dev_records']}")
    print(f"[+] Qualification Partition Status: {iso_info['qual_status']} (SEALED, ZERO ACCESS)")

    # 2. Instantiate Feature Hasher and Preprocess Partitions
    print("\n[*] Step 2: Vectorizing Training and Development Partitions...")
    hasher = CharacterNGramHasher(num_features=DEFAULT_INPUT_DIM, min_n=3, max_n=5)

    X_train, y_train, Y_train, train_recs = load_and_preprocess_partition(
        train_corpus, "v4_training", hasher
    )
    X_dev, y_dev, Y_dev, dev_recs = load_and_preprocess_partition(
        dev_corpus, "v4_development", hasher
    )

    # 3. Evaluate Baseline Model on Development Partition
    print("\n[*] Step 3: Evaluating Registered Baseline Model on Development Partition...")
    base_res = evaluate_baseline_on_dev(baseline_dir, X_dev, y_dev, dev_recs)
    base_m = base_res["metrics"]
    print(
        f"[+] Baseline '{base_res['model_version']}': Acc={base_m['accuracy']:.4f}, "
        f"Macro-F1={base_m['macro_f1']:.4f}, Legit FP={base_m['safety_metrics']['legitimate_fp_rate']:.4f}, "
        f"Advisory FP={base_m['safety_metrics']['protective_advisory_fp_rate']:.4f}, "
        f"Phish FN={base_m['safety_metrics']['phishing_fn_rate']:.4f}"
    )

    # 4. Multi-Seed Candidate Training
    print("\n[*] Step 4: Training Independent Candidates Across Seeds 42, 101, 202...")
    cand_summaries: List[Dict[str, Any]] = []

    for seed in seeds:
        print(f"\n--- Training Candidate: candidate_v4_seed{seed} ---")
        summary = train_candidate_seed(
            seed=seed,
            X_train=X_train,
            y_train=y_train,
            Y_train=Y_train,
            X_dev=X_dev,
            y_dev=y_dev,
            Y_dev=Y_dev,
            dev_records=dev_recs,
            candidates_root=candidates_root,
            batch_size=batch_size,
            max_epochs=max_epochs,
            early_stopping_patience=patience,
            initial_lr=initial_lr,
            weight_decay=weight_decay,
            dropout_rate=dropout_rate,
            hasher=hasher,
        )
        cand_summaries.append(summary)
        sm = summary["dev_metrics"]
        print(
            f"[+] Finished candidate_v4_seed{seed} (Best Epoch {summary['best_epoch']}): "
            f"Dev Acc={sm['accuracy']:.4f}, Macro-F1={sm['macro_f1']:.4f}, "
            f"Legit FP={sm['safety_metrics']['legitimate_fp_rate']:.4f}, "
            f"Advisory FP={sm['safety_metrics']['protective_advisory_fp_rate']:.4f}, "
            f"Phish FN={sm['safety_metrics']['phishing_fn_rate']:.4f}"
        )

    # 5. Deterministic Candidate Selection Policy
    print("\n[*] Step 5: Executing Deterministic Candidate Selection Policy...")
    selection_res = evaluate_candidate_selection(base_res, cand_summaries)
    print(f"[+] Selection Outcome: {selection_res['status']}")
    if selection_res["selected_candidate_id"]:
        print(f"[+] Selected Winner: {selection_res['selected_candidate_id']} (Seed {selection_res['selected_seed']})")
        print(f"[+] Rationale: {selection_res['selection_rationale']}")
    else:
        print(f"[-] No candidate selected: {selection_res['reason']}")

    # 6. Save Overall Experiment Selection Summary
    os.makedirs(os.path.dirname(summary_output_path), exist_ok=True)
    overall_summary = {
        "pipeline_schema_version": "1.0.0",
        "timestamp_utc": get_utc_now_iso(),
        "phase": "Phase 6.4.7",
        "dataset_provenance": {
            "training_corpus": train_corpus,
            "training_records": len(train_recs),
            "training_sha256": iso_info["training_sha256"],
            "dev_corpus": dev_corpus,
            "dev_records": len(dev_recs),
            "dev_sha256": iso_info["dev_sha256"],
            "qualification_partition": "SEALED_UNEXPOSED",
            "qualification_sha256": iso_info["qual_sha256"],
        },
        "baseline_evaluation": {
            "model_version": base_res["model_version"],
            "checkpoint_dir": base_res["checkpoint_dir"],
            "metrics": base_res["metrics"],
            "subgroups": base_res["subgroups"],
        },
        "candidate_evaluations": cand_summaries,
        "selection_policy_result": selection_res,
        "governance_status": {
            "model_registry_modified": False,
            "active_model_config_modified": False,
            "production_score_delta": 0,
            "qualification_exposed": False,
        },
    }

    with open(summary_output_path, "w", encoding="utf-8") as f:
        json.dump(overall_summary, f, indent=2)

    print(f"\n[+] Master selection summary saved to '{summary_output_path}'.")
    print("=" * 80)
    print("PHASE 6.4.7 CONTROLLED MULTI-SEED CANDIDATE TRAINING COMPLETE")
    print("=" * 80)
    return overall_summary


if __name__ == "__main__":
    run_phase6_4_7_pipeline()
