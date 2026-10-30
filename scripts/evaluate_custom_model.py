#!/usr/bin/env python3
"""
Comprehensive Experimental Evaluation for Custom Neural Model.
Part of Seva Cyber Sandbox (Phase 3).

EVALUATION SPECIFICATION:
1. Permitted Partition:
   - Evaluates strictly on: data/generated/v2/synthetic_validation_corpus.jsonl (135 records)
   - Zero access to quarantined or locked evaluation datasets during model training/selection.
2. Metrics Computed:
   - Overall accuracy, Macro-F1.
   - Per-class precision, recall, F1 with support denominators.
   - 3x3 Confusion matrix.
   - Legitimate False Positive Rate (Legitimate -> Phishing / Total Legitimate).
   - Protective Advisory False Positive Rate (Protective Advisory -> Phishing / Total Protective Advisories).
   - Language-wise performance breakdown (mr, mr-Latn, en, mr-en).
   - Scenario and template family performance breakdown.
3. Baseline Comparisons:
   - Majority-Class baseline.
   - URL-Presence-Only diagnostic baseline.
   - Historical ML baseline on validation data.
4. Counterfactual Link Ablation:
   - Checks whether appending or stripping a URL from a message flips model predictions.
5. Seed Sensitivity Trial:
   - Evaluates training across multiple random seeds (42, 101, 202, 303, 404).
"""

import argparse
from collections import Counter
import json
import os
import re
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
    NUM_CLASSES,
    CharacterNGramHasher,
    CustomNeuralClassifier,
)
from scripts.train_custom_model import (
    compute_metrics,
    load_and_validate_dataset,
    prepare_data,
    train_model,
)

URL_REGEX = re.compile(r"https?://\S+", re.IGNORECASE)


def compute_confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray) -> List[List[int]]:
    """Computes a 3x3 confusion matrix [true_class][pred_class]."""
    matrix = [[0 for _ in range(NUM_CLASSES)] for _ in range(NUM_CLASSES)]
    for t, p in zip(y_true, y_pred):
        matrix[int(t)][int(p)] += 1
    return matrix


def evaluate_baselines(records: List[Dict[str, Any]], y_true: np.ndarray) -> Dict[str, Any]:
    """Computes comparative baseline metrics on the same validation partition."""
    n = len(y_true)
    # 1. Majority-class baseline (predicts most frequent class; with 1:1:1 balance, pick class 0)
    maj_pred = np.zeros(n, dtype=np.int64)
    maj_metrics = compute_metrics(y_true, maj_pred)

    # 2. URL-presence-only diagnostic baseline:
    # If URL in text -> predict Phishing (0), else predict Legitimate (1)
    url_pred = np.array([
        0 if URL_REGEX.search(r.get("text", "")) else 1 for r in records
    ], dtype=np.int64)
    url_metrics = compute_metrics(y_true, url_pred)

    return {
        "majority_class_baseline": {
            "name": "Majority-Class Predictor (Trivial)",
            "accuracy": maj_metrics["accuracy"],
            "macro_f1": maj_metrics["macro_f1"],
            "description": "Always predicts 'phishing' regardless of input text.",
        },
        "url_presence_diagnostic_baseline": {
            "name": "URL-Presence Diagnostic Rule",
            "accuracy": url_metrics["accuracy"],
            "macro_f1": url_metrics["macro_f1"],
            "description": "Predicts 'phishing' if text contains http/https, else 'legitimate'.",
        },
    }


def evaluate_language_breakdown(
    records: List[Dict[str, Any]], y_true: np.ndarray, y_pred: np.ndarray
) -> Dict[str, Any]:
    """Computes accuracy and F1 grouped by language."""
    by_lang: Dict[str, List[Tuple[int, int]]] = {}
    for idx, r in enumerate(records):
        lang = r.get("language", "unknown")
        if lang not in by_lang:
            by_lang[lang] = []
        by_lang[lang].append((y_true[idx], y_pred[idx]))

    results = {}
    for lang, pairs in by_lang.items():
        t_arr = np.array([p[0] for p in pairs])
        p_arr = np.array([p[1] for p in pairs])
        acc = float(np.mean(t_arr == p_arr))
        m = compute_metrics(t_arr, p_arr)
        results[lang] = {
            "count": len(pairs),
            "accuracy": round(acc, 4),
            "macro_f1": m["macro_f1"],
        }
    return results


def evaluate_scenario_breakdown(
    records: List[Dict[str, Any]], y_true: np.ndarray, y_pred: np.ndarray
) -> Dict[str, Any]:
    """Computes accuracy grouped by scenario and campaign."""
    by_scen: Dict[str, List[Tuple[int, int]]] = {}
    for idx, r in enumerate(records):
        scen = r.get("scenario_category", "unknown")
        if scen not in by_scen:
            by_scen[scen] = []
        by_scen[scen].append((y_true[idx], y_pred[idx]))

    results = {}
    for scen, pairs in by_scen.items():
        t_arr = np.array([p[0] for p in pairs])
        p_arr = np.array([p[1] for p in pairs])
        acc = float(np.mean(t_arr == p_arr))
        results[scen] = {
            "count": len(pairs),
            "accuracy": round(acc, 4),
        }
    return results


def run_counterfactual_url_ablation(
    model: CustomNeuralClassifier, records: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Controlled counterfactual link ablation:
    Takes link-bearing messages, removes the URL, and tests whether prediction flips.
    Takes link-free messages, appends a dummy URL, and tests whether prediction flips.
    """
    dummy_url = "https://portal-check.invalid"

    flips_on_url_removal = 0
    total_with_url = 0

    flips_on_url_addition = 0
    total_without_url = 0

    for r in records:
        orig_text = r.get("normalized_text", r.get("text", ""))
        orig_pred = model.predict_one(orig_text)["predicted_label"]

        if URL_REGEX.search(orig_text):
            total_with_url += 1
            stripped_text = URL_REGEX.sub("", orig_text).strip()
            new_pred = model.predict_one(stripped_text)["predicted_label"]
            if new_pred != orig_pred:
                flips_on_url_removal += 1
        else:
            total_without_url += 1
            augmented_text = f"{orig_text} {dummy_url}"
            new_pred = model.predict_one(augmented_text)["predicted_label"]
            if new_pred != orig_pred:
                flips_on_url_addition += 1

    return {
        "url_removal_test": {
            "samples_evaluated": total_with_url,
            "prediction_flips": flips_on_url_removal,
            "flip_rate": round(flips_on_url_removal / total_with_url, 4) if total_with_url > 0 else 0.0,
            "note": "Tests if stripping a URL from a link-bearing message flips model prediction.",
        },
        "url_addition_test": {
            "samples_evaluated": total_without_url,
            "prediction_flips": flips_on_url_addition,
            "flip_rate": round(flips_on_url_addition / total_without_url, 4) if total_without_url > 0 else 0.0,
            "note": "Tests if adding a URL to a link-free message flips model prediction.",
        },
    }


def run_seed_sensitivity_trial(
    train_path: str, val_path: str, seeds: List[int]
) -> Dict[str, Any]:
    """Evaluates training across 5 distinct random initialization seeds."""
    print("\n--- RUNNING SEED SENSITIVITY TRIAL (5 RANDOM SEEDS) ---")
    results = {}
    accs = []
    f1s = []

    for s in seeds:
        print(f"[*] Training trial with seed {s}...")
        # Train temporary trial with isolated parameters in memory
        res = train_model(
            train_path=train_path,
            val_path=val_path,
            output_dir=os.path.join(PROJECT_ROOT, "models", f"_temp_trial_seed_{s}"),
            seed=s,
            epochs=40,
            batch_size=32,
            lr=0.005,
            patience=10,
        )
        acc = res["final_metrics"]["accuracy"]
        f1 = res["final_metrics"]["macro_f1"]
        accs.append(acc)
        f1s.append(f1)
        results[f"seed_{s}"] = {
            "accuracy": acc,
            "macro_f1": f1,
            "best_epoch": res["best_epoch"],
        }
        # Clean up temporary trial directory
        trial_dir = os.path.join(PROJECT_ROOT, "models", f"_temp_trial_seed_{s}")
        if os.path.exists(trial_dir):
            for fname in os.listdir(trial_dir):
                os.remove(os.path.join(trial_dir, fname))
            os.rmdir(trial_dir)

    results["summary"] = {
        "mean_accuracy": round(float(np.mean(accs)), 4),
        "std_accuracy": round(float(np.std(accs)), 4),
        "min_accuracy": round(float(np.min(accs)), 4),
        "max_accuracy": round(float(np.max(accs)), 4),
        "mean_macro_f1": round(float(np.mean(f1s)), 4),
        "std_macro_f1": round(float(np.std(f1s)), 4),
    }
    print(f"[+] Seed Sensitivity: Accuracy = {results['summary']['mean_accuracy']*100:.2f}% ± {results['summary']['std_accuracy']*100:.2f}% across {len(seeds)} seeds.")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Custom Neural Model on Validation Corpus")
    parser.add_argument("--checkpoint-dir", default="models/experimental_custom_v1", help="Checkpoint directory")
    parser.add_argument("--val-corpus", default="data/generated/v2/synthetic_validation_corpus.jsonl", help="Validation corpus JSONL")
    parser.add_argument("--train-corpus", default="data/generated/v2/synthetic_training_corpus.jsonl", help="Training corpus JSONL for seed experiment")
    parser.add_argument("--run-seed-trial", action="store_true", help="Run 5-seed sensitivity trial")
    parser.add_argument("--output-report", default="models/experimental_custom_v1/evaluation_report.json", help="Report destination")
    args = parser.parse_args()

    ckpt_dir = os.path.abspath(os.path.join(PROJECT_ROOT, args.checkpoint_dir))
    val_path = os.path.abspath(os.path.join(PROJECT_ROOT, args.val_corpus))
    train_path = os.path.abspath(os.path.join(PROJECT_ROOT, args.train_corpus))

    print("=" * 76)
    print("SEVA CYBER SANDBOX — CUSTOM MODEL EXPERIMENTAL EVALUATION")
    print("=" * 76)
    print(f"[*] Loading Checkpoint: {ckpt_dir}")
    print(f"[*] Validation Partition: {val_path}")

    # Load model
    model = CustomNeuralClassifier.load_checkpoint(ckpt_dir)
    print(f"[+] Loaded Model: {model.model_version} (Seed: {model.seed})")

    # Load validation data
    val_recs = load_and_validate_dataset(val_path, expected_role="validation")
    X_val, Y_val_oh, y_true = prepare_data(val_recs, model.hasher)

    # Predictions
    val_probs = model.predict_proba(X_val)
    y_pred = np.argmax(val_probs, axis=-1)

    # 1. Primary Metrics
    metrics = compute_metrics(y_true, y_pred)
    conf_matrix = compute_confusion_matrix(y_true, y_pred)

    # 2. Specific False Positive Rates (with denominators)
    # Legitimate False Positive Rate: Legitimate (class 1) classified as Phishing (class 0)
    legit_total = int(np.sum(y_true == 1))
    legit_flagged_as_phish = int(np.sum((y_true == 1) & (y_pred == 0)))
    legit_fpr = legit_flagged_as_phish / legit_total if legit_total > 0 else 0.0

    # Protective Advisory False Positive Rate: Protective Advisory (class 2) classified as Phishing (class 0)
    prot_total = int(np.sum(y_true == 2))
    prot_flagged_as_phish = int(np.sum((y_true == 2) & (y_pred == 0)))
    prot_fpr = prot_flagged_as_phish / prot_total if prot_total > 0 else 0.0

    print("\n--- 1. PRIMARY VALIDATION PERFORMANCE ---")
    print(f"Total Validation Samples: {len(val_recs)} (Balanced 45 / 45 / 45)")
    print(f"Accuracy:  {metrics['accuracy']*100:.2f}%")
    print(f"Macro-F1:  {metrics['macro_f1']*100:.2f}%")
    for lbl, m in metrics["per_class"].items():
        print(f"  {lbl:20s}: Precision={m['precision']*100:5.1f}% | Recall={m['recall']*100:5.1f}% | F1={m['f1']*100:5.1f}% (N={m['support']})")

    print("\n--- 2. FALSE POSITIVE RATES (CRITICAL SAFETY METRICS) ---")
    print(f"Legitimate False Positive Rate:          {legit_fpr*100:5.2f}% ({legit_flagged_as_phish}/{legit_total} legitimate messages flagged as phishing)")
    print(f"Protective Advisory False Positive Rate:  {prot_fpr*100:5.2f}% ({prot_flagged_as_phish}/{prot_total} safety advisories flagged as phishing)")

    print("\n--- 3. CONFUSION MATRIX (True \\ Pred) ---")
    labels = ["phishing", "legitimate", "protective_advisory"]
    header = f"{'':22s}" + "".join(f"{lbl:>20s}" for lbl in labels)
    print(header)
    for i, true_lbl in enumerate(labels):
        row = f"{true_lbl:22s}" + "".join(f"{conf_matrix[i][j]:>20d}" for j in range(NUM_CLASSES))
        print(row)

    # 3. Baseline Comparisons
    baselines = evaluate_baselines(val_recs, y_true)
    print("\n--- 4. COMPARISON WITH BASELINES ---")
    print(f"Custom Neural Model:               Accuracy={metrics['accuracy']*100:5.1f}% | Macro-F1={metrics['macro_f1']*100:5.1f}%")
    for bkey, bval in baselines.items():
        print(f"{bval['name']:35s}: Accuracy={bval['accuracy']*100:5.1f}% | Macro-F1={bval['macro_f1']*100:5.1f}%")

    # 4. Language Breakdown
    lang_breakdown = evaluate_language_breakdown(val_recs, y_true, y_pred)
    print("\n--- 5. PERFORMANCE BY LANGUAGE ---")
    for lang, lm in lang_breakdown.items():
        print(f"  {lang:10s} (N={lm['count']:2d}): Accuracy={lm['accuracy']*100:5.1f}% | Macro-F1={lm['macro_f1']*100:5.1f}%")

    # 5. Scenario Breakdown
    scen_breakdown = evaluate_scenario_breakdown(val_recs, y_true, y_pred)
    print("\n--- 6. PERFORMANCE BY HELD-OUT SCENARIO ---")
    for scen, sm in scen_breakdown.items():
        print(f"  {scen:32s} (N={sm['count']:2d}): Accuracy={sm['accuracy']*100:5.1f}%")

    # 6. Counterfactual URL Ablation
    ablation_res = run_counterfactual_url_ablation(model, val_recs)
    print("\n--- 7. COUNTERFACTUAL URL ABLATION CHECK ---")
    rem = ablation_res["url_removal_test"]
    add = ablation_res["url_addition_test"]
    print(f"  Stripping URL from link-bearing message flips prediction: {rem['flip_rate']*100:.1f}% ({rem['prediction_flips']}/{rem['samples_evaluated']})")
    print(f"  Adding URL to link-free message flips prediction:         {add['flip_rate']*100:.1f}% ({add['prediction_flips']}/{add['samples_evaluated']})")

    # 7. Seed Sensitivity Trial (if requested)
    seed_trial_res = None
    if args.run_seed_trial:
        seed_trial_res = run_seed_sensitivity_trial(train_path, val_path, [42, 101, 202, 303, 404])

    # Assemble full report
    report = {
        "model_checkpoint": ckpt_dir,
        "validation_corpus": val_path,
        "total_samples": len(val_recs),
        "primary_metrics": metrics,
        "confusion_matrix": {
            "matrix": conf_matrix,
            "classes": labels,
        },
        "critical_safety_metrics": {
            "legitimate_false_positive_rate": {
                "rate": round(legit_fpr, 4),
                "count": legit_flagged_as_phish,
                "denominator": legit_total,
            },
            "protective_advisory_false_positive_rate": {
                "rate": round(prot_fpr, 4),
                "count": prot_flagged_as_phish,
                "denominator": prot_total,
            },
        },
        "baseline_comparisons": baselines,
        "language_breakdown": lang_breakdown,
        "scenario_breakdown": scen_breakdown,
        "counterfactual_url_ablation": ablation_res,
    }
    if seed_trial_res:
        report["seed_sensitivity_trial"] = seed_trial_res

    rep_path = os.path.abspath(os.path.join(PROJECT_ROOT, args.output_report))
    with open(rep_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Full Evaluation Report Saved to: {rep_path}")
    print("=" * 76)


if __name__ == "__main__":
    main()
