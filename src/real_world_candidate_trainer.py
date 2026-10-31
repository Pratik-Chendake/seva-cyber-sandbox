"""
Phase 6.9.2 — Real-World Candidate Model Trainer.

Safely trains experimental custom neural network candidate models from
genuine partitioned datasets. Enforces:
1. Training readiness gate validation (blocks execution when evidence is insufficient).
2. Pure random initialization (no pretrained weights).
3. 1024-dimensional feature extraction using CharacterNGramHasher.
4. Model governance isolation: candidate models NEVER alter active model configuration.
5. Zero external network calls or cloud dependencies (pure local NumPy).
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from src.custom_model import (
    IDX_TO_LABEL,
    LABEL_TO_IDX,
    CharacterNGramHasher,
    CustomNeuralClassifier,
)
from src.training_readiness_gate import TrainingReadinessGate


class TrainingBlockedError(Exception):
    """Raised when training is attempted while the readiness gate is BLOCKED."""
    pass


class RealWorldCandidateTrainer:
    """Trains custom neural network candidates from verified real-world dataset splits."""

    def __init__(
        self,
        candidates_dir: str = "models/candidates",
        active_config_path: str = "models/active_model_config.json",
        seed: int = 42,
    ):
        self.candidates_dir = candidates_dir
        self.active_config_path = active_config_path
        self.seed = seed

    def train_from_dataset(
        self,
        dataset_dir: str,
        candidate_version: Optional[str] = None,
        epochs: int = 15,
        batch_size: int = 16,
        learning_rate: float = 0.005,
        force_test: bool = False,
        readiness_gate: Optional[TrainingReadinessGate] = None,
    ) -> Dict[str, Any]:
        """
        Trains a candidate model on train.jsonl and validates on dev.jsonl.
        If readiness gate is BLOCKED and force_test is False, raises TrainingBlockedError.
        """
        # 1. Readiness Gate Check
        if not force_test:
            gate = readiness_gate or TrainingReadinessGate(dataset_dir=dataset_dir)
            gate_eval = gate.evaluate_gate()
            if not gate_eval["allow_training"]:
                raise TrainingBlockedError(
                    f"Candidate training is blocked by TrainingReadinessGate: {gate_eval['gate_decision']}. "
                    f"Reasons: {'; '.join(gate_eval['blocking_reasons'][:3])}"
                )

        # 2. Dataset Split Verification
        manifest_path = os.path.join(dataset_dir, "manifest.json")
        train_path = os.path.join(dataset_dir, "train.jsonl")
        dev_path = os.path.join(dataset_dir, "dev.jsonl")

        if not os.path.exists(train_path):
            raise FileNotFoundError(f"Missing train.jsonl in '{dataset_dir}'.")

        # 3. Load Samples
        def load_jsonl(path: str) -> List[Dict[str, Any]]:
            recs = []
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            recs.append(json.loads(line.strip()))
            return recs

        train_recs = load_jsonl(train_path)
        dev_recs = load_jsonl(dev_path)

        if not train_recs:
            raise ValueError("Training split is empty; cannot train candidate model.")

        # 4. Feature Extraction & One-Hot Target Encoding
        hasher = CharacterNGramHasher(num_features=1024)

        def extract_features_and_labels(records: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
            X_list: List[np.ndarray] = []
            y_indices: List[int] = []

            for r in records:
                meta = r.get("metadata") or {}
                text = (
                    meta.get("text")
                    or meta.get("message_text")
                    or meta.get("user_description")
                    or meta.get("url")
                    or r.get("evidence_id")
                    or ""
                )
                feat = hasher.transform_text(str(text))
                X_list.append(feat)

                label_str = r.get("ground_truth_label") or r.get("user_classification") or "phishing"
                label_idx = LABEL_TO_IDX.get(label_str, LABEL_TO_IDX["phishing"])
                y_indices.append(label_idx)

            X_arr = np.array(X_list, dtype=np.float32)
            y_arr = np.array(y_indices, dtype=np.int64)

            Y_onehot = np.zeros((len(y_indices), 3), dtype=np.float32)
            for i, idx in enumerate(y_indices):
                Y_onehot[i, idx] = 1.0

            return X_arr, y_arr, Y_onehot

        X_train, y_train, Y_train_onehot = extract_features_and_labels(train_recs)
        X_dev, y_dev, Y_dev_onehot = (
            extract_features_and_labels(dev_recs)
            if dev_recs
            else (np.empty((0, 1024), dtype=np.float32), np.empty((0,), dtype=np.int64), np.empty((0, 3), dtype=np.float32))
        )

        # 5. Initialize Model Strictly from Random Weights
        clf = CustomNeuralClassifier(
            seed=self.seed,
            input_dim=1024,
            hidden_dim1=64,
            hidden_dim2=32,
            num_classes=3,
            learning_rate=learning_rate,
        )

        # 6. Training Loop (Local CPU, pure NumPy)
        n_samples = len(X_train)
        history: List[Dict[str, float]] = []
        rng = np.random.RandomState(self.seed)

        for epoch in range(1, epochs + 1):
            indices = np.arange(n_samples)
            rng.shuffle(indices)

            epoch_losses = []
            for start_idx in range(0, n_samples, batch_size):
                end_idx = min(start_idx + batch_size, n_samples)
                batch_idx = indices[start_idx:end_idx]
                bx = X_train[batch_idx]
                by_onehot = Y_train_onehot[batch_idx]
                loss = clf.fit_batch(bx, by_onehot)
                epoch_losses.append(loss)

            avg_train_loss = float(np.mean(epoch_losses)) if epoch_losses else 0.0

            # Evaluate dev split if present
            dev_metrics: Dict[str, float] = {}
            if len(X_dev) > 0:
                dev_probs = clf.predict_proba(X_dev)
                dev_preds = clf.predict(X_dev)
                dev_loss = float(clf.compute_loss(dev_probs, Y_dev_onehot))
                dev_acc = float(np.mean(dev_preds == y_dev))
                dev_metrics = {"dev_loss": round(dev_loss, 4), "dev_accuracy": round(dev_acc, 4)}

            history.append({
                "epoch": epoch,
                "train_loss": round(avg_train_loss, 4),
                **dev_metrics,
            })

        # 7. Save Candidate Artifacts
        now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        version_name = candidate_version or f"candidate_custom_v{now_str}"
        candidate_dir = os.path.join(self.candidates_dir, version_name)
        os.makedirs(candidate_dir, exist_ok=True)

        clf.save_checkpoint(candidate_dir)
        weights_path = os.path.join(candidate_dir, "model_weights.npz")

        # Compute SHA-256 of weights
        hasher_sha = hashlib.sha256()
        with open(weights_path, "rb") as f:
            hasher_sha.update(f.read())
        weights_sha = hasher_sha.hexdigest()

        # Compute final evaluation metrics on train and dev
        train_preds = clf.predict(X_train)
        train_acc = float(np.mean(train_preds == y_train))
        dev_acc = float(np.mean(clf.predict(X_dev) == y_dev)) if len(X_dev) > 0 else 0.0

        metadata = {
            "candidate_version": version_name,
            "architecture": "CustomNeuralClassifier (1024 -> 64 -> 32 -> 3)",
            "initialization": "random",
            "seed": self.seed,
            "creation_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "training_samples": len(X_train),
            "dev_samples": len(X_dev),
            "epochs": epochs,
            "final_train_loss": history[-1]["train_loss"] if history else 0.0,
            "final_train_accuracy": round(train_acc, 4),
            "final_dev_accuracy": round(dev_acc, 4),
            "weights_file": "model_weights.npz",
            "weights_sha256": weights_sha,
            "status": "candidate_unqualified",
            "is_active_model": False,
            "is_production_authoritative": False,
        }

        meta_path = os.path.join(candidate_dir, "training_metadata.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        # 8. Assert Model Governance Invariant: Active config is UNTOUCHED
        if os.path.exists(self.active_config_path):
            with open(self.active_config_path, "r", encoding="utf-8") as f:
                act = json.load(f)
            assert act.get("active_model_version") == "custom-mlp-v4.0.0-seed42", "Active model version was modified!"
            assert act.get("operating_mode") == "shadow", "Active model operating mode was modified!"
            assert act.get("is_production_authoritative") is False, "Active model authority was modified!"

        return {
            "status": "CANDIDATE_TRAINED",
            "candidate_version": version_name,
            "candidate_dir": candidate_dir,
            "weights_path": weights_path,
            "weights_sha256": weights_sha,
            "metadata_path": meta_path,
            "train_accuracy": round(train_acc, 4),
            "dev_accuracy": round(dev_acc, 4),
            "history": history,
            "active_model_preserved": "custom-mlp-v4.0.0-seed42",
        }
