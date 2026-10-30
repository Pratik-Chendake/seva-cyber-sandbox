#!/usr/bin/env python3
"""
Reproducible Training Pipeline for Custom Neural Network Classifier.
Part of Seva Cyber Sandbox (Phase 3).

TRAINING SPECIFICATION:
1. Data Sources:
   - Train strictly on: data/generated/v2/synthetic_training_corpus.jsonl (360 records)
   - Validate strictly on: data/generated/v2/synthetic_validation_corpus.jsonl (135 records)
   - Zero access to quarantined or locked evaluation datasets.
2. Training Mechanics:
   - Weights randomly initialized from seed (default: 42).
   - Mini-batch gradient updates with Adam optimizer.
   - Early stopping tracking validation loss with configurable patience.
   - Best checkpoint saved to models/experimental_custom_v1/ using safe NumPy .npz.
   - Metrics history exported to JSON.
"""

import argparse
from collections import Counter
import json
import os
import random
import sys
import time
from typing import Any, Dict, List, Tuple
import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.custom_model import (
    IDX_TO_LABEL,
    LABEL_TO_IDX,
    MODEL_VERSION,
    NUM_CLASSES,
    CharacterNGramHasher,
    CustomNeuralClassifier,
)
from src.dataset_preprocessing import validate_single_record


def load_and_validate_dataset(path: str, expected_role: str) -> List[Dict[str, Any]]:
    """Loads and strictly validates records from JSONL file."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found at {path}")

    records = []
    with open(path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            valid, errors = validate_single_record(data)
            if not valid:
                raise ValueError(f"Record at line {idx} failed validation: {errors}")

            role = data.get("dataset_role")
            if role != expected_role:
                raise ValueError(f"Record at line {idx} has role '{role}', expected '{expected_role}'")

            label = data.get("ground_truth_label")
            if label not in LABEL_TO_IDX:
                raise ValueError(f"Record at line {idx} has unmapped label '{label}'")

            records.append(data)

    return records


def prepare_data(
    records: List[Dict[str, Any]], hasher: CharacterNGramHasher
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Extracts features and one-hot labels.
    Returns (X, Y_onehot, y_indices).
    """
    texts = [r.get("normalized_text", r.get("text", "")) for r in records]
    X = hasher.transform_batch(texts)

    n = len(records)
    y_indices = np.array([LABEL_TO_IDX[r["ground_truth_label"]] for r in records], dtype=np.int64)
    Y_onehot = np.zeros((n, NUM_CLASSES), dtype=np.float32)
    Y_onehot[np.arange(n), y_indices] = 1.0

    return X, Y_onehot, y_indices


def compute_metrics(
    y_true: np.ndarray, y_pred: np.ndarray
) -> Dict[str, Any]:
    """Computes overall accuracy and per-class precision, recall, and F1."""
    acc = float(np.mean(y_true == y_pred))
    per_class = {}
    f1_list = []

    for c in range(NUM_CLASSES):
        label_name = IDX_TO_LABEL[c]
        tp = int(np.sum((y_pred == c) & (y_true == c)))
        fp = int(np.sum((y_pred == c) & (y_true != c)))
        fn = int(np.sum((y_pred != c) & (y_true == c)))

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        f1_list.append(f1)

        per_class[label_name] = {
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "support": int(np.sum(y_true == c)),
        }

    macro_f1 = float(np.mean(f1_list))
    return {
        "accuracy": round(acc, 4),
        "macro_f1": round(macro_f1, 4),
        "per_class": per_class,
    }


def train_model(
    train_path: str,
    val_path: str,
    output_dir: str,
    seed: int = 42,
    epochs: int = 60,
    batch_size: int = 32,
    lr: float = 0.005,
    weight_decay: float = 1e-4,
    dropout: float = 0.2,
    input_dim: int = 1024,
    hidden_dim1: int = 64,
    hidden_dim2: int = 32,
    patience: int = 15,
) -> Dict[str, Any]:
    """
    Main training execution function.
    """
    start_time = time.time()
    print("=" * 76)
    print("SEVA CYBER SANDBOX — CUSTOM NEURAL MODEL TRAINING (PHASE 3)")
    print("=" * 76)
    print(f"[*] Deterministic Random Seed: {seed}")
    print(f"[*] Architecture: MLP ({input_dim} -> {hidden_dim1} -> {hidden_dim2} -> {NUM_CLASSES})")
    print(f"[*] Weight Initialization: Randomly initialized (He normal / Xavier uniform)")
    print(f"[*] Pretrained Weights: ZERO (learned strictly from scratch)")
    print(f"[*] Hardware Target: Local CPU")
    print(f"[*] Checkpoint Target: {output_dir}")

    # 1. Load and validate data
    train_recs = load_and_validate_dataset(train_path, expected_role="development")
    val_recs = load_and_validate_dataset(val_path, expected_role="validation")

    print(f"[+] Loaded Training Corpus: {len(train_recs)} records from {train_path}")
    print(f"[+] Loaded Validation Corpus: {len(val_recs)} records from {val_path}")
    print(f"[*] Train Label Distribution: {dict(Counter(r['ground_truth_label'] for r in train_recs))}")
    print(f"[*] Val Label Distribution: {dict(Counter(r['ground_truth_label'] for r in val_recs))}")

    # 2. Initialize feature hasher
    hasher = CharacterNGramHasher(num_features=input_dim, min_n=3, max_n=5)
    X_train, Y_train_oh, y_train = prepare_data(train_recs, hasher)
    X_val, Y_val_oh, y_val = prepare_data(val_recs, hasher)

    # 3. Instantiate model with random initialization
    model = CustomNeuralClassifier(
        input_dim=input_dim,
        hidden_dim1=hidden_dim1,
        hidden_dim2=hidden_dim2,
        num_classes=NUM_CLASSES,
        learning_rate=lr,
        weight_decay=weight_decay,
        dropout_rate=dropout,
        seed=seed,
    )

    # 4. Training loop with early stopping
    history: List[Dict[str, Any]] = []
    best_val_loss = float("inf")
    best_epoch = 0
    patience_counter = 0
    best_weights: Optional[Dict[str, np.ndarray]] = None

    rng = np.random.RandomState(seed)
    n_train = X_train.shape[0]

    print("\n--- BEGIN TRAINING LOOP ---")
    for epoch in range(1, epochs + 1):
        # Shuffle training indices
        perm = rng.permutation(n_train)
        X_shuffled = X_train[perm]
        Y_shuffled = Y_train_oh[perm]

        batch_losses = []
        for i in range(0, n_train, batch_size):
            X_b = X_shuffled[i : i + batch_size]
            Y_b = Y_shuffled[i : i + batch_size]
            loss_b = model.fit_batch(X_b, Y_b)
            batch_losses.append(loss_b)

        train_loss = float(np.mean(batch_losses))
        train_preds = model.predict(X_train)
        train_acc = float(np.mean(train_preds == y_train))

        # Evaluate on validation partition
        val_probs = model.predict_proba(X_val)
        val_loss = model.compute_loss(val_probs, Y_val_oh)
        val_preds = np.argmax(val_probs, axis=-1)
        val_metrics = compute_metrics(y_val, val_preds)

        epoch_record = {
            "epoch": epoch,
            "train_loss": round(train_loss, 4),
            "train_accuracy": round(train_acc, 4),
            "val_loss": round(float(val_loss), 4),
            "val_accuracy": val_metrics["accuracy"],
            "val_macro_f1": val_metrics["macro_f1"],
        }
        history.append(epoch_record)

        if epoch % 5 == 0 or epoch == 1:
            print(
                f"Epoch {epoch:02d}/{epochs:02d} | "
                f"Train Loss: {train_loss:.4f} | Train Acc: {train_acc*100:.1f}% | "
                f"Val Loss: {val_loss:.4f} | Val Acc: {val_metrics['accuracy']*100:.1f}% | "
                f"Val Macro-F1: {val_metrics['macro_f1']*100:.1f}%"
            )

        # Early stopping check based on validation loss
        if val_loss < best_val_loss - 1e-4:
            best_val_loss = val_loss
            best_epoch = epoch
            patience_counter = 0
            best_weights = {
                "W1": model.W1.copy(),
                "b1": model.b1.copy(),
                "W2": model.W2.copy(),
                "b2": model.b2.copy(),
                "W3": model.W3.copy(),
                "b3": model.b3.copy(),
            }
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"[*] Early stopping triggered at epoch {epoch} (no val_loss improvement for {patience} epochs).")
                break

    # Restore best weights
    if best_weights is not None:
        model.W1 = best_weights["W1"]
        model.b1 = best_weights["b1"]
        model.W2 = best_weights["W2"]
        model.b2 = best_weights["b2"]
        model.W3 = best_weights["W3"]
        model.b3 = best_weights["b3"]
        print(f"[+] Restored best weights from epoch {best_epoch} (Val Loss: {best_val_loss:.4f})")

    # Final evaluation on validation set with best weights
    final_val_probs = model.predict_proba(X_val)
    final_val_preds = np.argmax(final_val_probs, axis=-1)
    final_metrics = compute_metrics(y_val, final_val_preds)
    elapsed_time = round(time.time() - start_time, 2)

    print("\n--- FINAL VALIDATION PERFORMANCE (BEST CHECKPOINT) ---")
    print(f"Accuracy:  {final_metrics['accuracy']*100:.2f}%")
    print(f"Macro-F1:  {final_metrics['macro_f1']*100:.2f}%")
    for lbl, m in final_metrics["per_class"].items():
        print(f"  {lbl:20s}: Precision={m['precision']*100:5.1f}% | Recall={m['recall']*100:5.1f}% | F1={m['f1']*100:5.1f}% (N={m['support']})")

    # 5. Save model checkpoint and training metadata
    training_meta = {
        "dataset_version": "v2-deconfounded",
        "training_records_count": len(train_recs),
        "validation_records_count": len(val_recs),
        "train_source_file": train_path,
        "val_source_file": val_path,
        "seed": seed,
        "epochs_trained": len(history),
        "best_epoch": best_epoch,
        "best_val_loss": round(float(best_val_loss), 4),
        "final_val_accuracy": final_metrics["accuracy"],
        "final_val_macro_f1": final_metrics["macro_f1"],
        "elapsed_seconds": elapsed_time,
        "training_history": history,
    }

    model.save_checkpoint(output_dir, metadata=training_meta)
    print(f"\n[+] Saved Checkpoint & Weights to: {output_dir}")

    # Export history separately for plotting
    history_file = os.path.join(output_dir, "training_history.json")
    with open(history_file, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)
    print(f"[+] Saved Loss Curves & History to: {history_file}")
    print("=" * 76)

    return {
        "final_metrics": final_metrics,
        "best_epoch": best_epoch,
        "best_val_loss": best_val_loss,
        "history": history,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Custom Neural Model with Randomly Initialized Weights")
    parser.add_argument("--train-corpus", default="data/generated/v2/synthetic_training_corpus.jsonl", help="Training corpus JSONL")
    parser.add_argument("--val-corpus", default="data/generated/v2/synthetic_validation_corpus.jsonl", help="Validation corpus JSONL")
    parser.add_argument("--output-dir", default="models/experimental_custom_v1", help="Checkpoint directory")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed (default: 42)")
    parser.add_argument("--epochs", type=int, default=60, help="Maximum epochs (default: 60)")
    parser.add_argument("--batch-size", type=int, default=32, help="Mini-batch size (default: 32)")
    parser.add_argument("--lr", type=float, default=0.005, help="Learning rate (default: 0.005)")
    parser.add_argument("--weight-decay", type=float, default=1e-4, help="L2 regularization (default: 1e-4)")
    parser.add_argument("--dropout", type=float, default=0.2, help="Dropout probability (default: 0.2)")
    parser.add_argument("--patience", type=int, default=15, help="Early stopping patience (default: 15)")
    args = parser.parse_args()

    train_path = os.path.abspath(os.path.join(PROJECT_ROOT, args.train_corpus))
    val_path = os.path.abspath(os.path.join(PROJECT_ROOT, args.val_corpus))
    out_dir = os.path.abspath(os.path.join(PROJECT_ROOT, args.output_dir))

    train_model(
        train_path=train_path,
        val_path=val_path,
        output_dir=out_dir,
        seed=args.seed,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        weight_decay=args.weight_decay,
        dropout=args.dropout,
        patience=args.patience,
    )


if __name__ == "__main__":
    main()
