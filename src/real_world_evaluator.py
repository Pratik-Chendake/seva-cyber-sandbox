"""
Phase 6.9.3 — Independent Real-World Model Evaluation Framework.

Evaluates custom neural network candidate models against sealed real-world
evaluation datasets (sealed_eval.jsonl).
Enforces:
1. Strict isolation from training data (sealed evaluation split).
2. Calculation of multi-class Accuracy, Precision, Recall, Macro F1, Weighted F1.
3. Class-specific metrics (phishing, legitimate, protective_advisory).
4. False Positive Rate (FPR) and False Negative Rate (FNR).
5. 3x3 Confusion Matrix.
6. Robustness breakdown across languages (Marathi, Romanized, Mixed, English).
7. Blocker condition: If sealed operational evaluation evidence is absent, issues:
   'EVALUATION VERDICT: INSUFFICIENT_EVALUATION_EVIDENCE'.
"""

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
from src.dataset_readiness import detect_language_from_text


class RealWorldModelEvaluator:
    """Evaluates candidate models on sealed evaluation splits with complete diagnostic metrics."""

    def __init__(
        self,
        dataset_dir: str = "data/real_world_datasets",
        candidates_dir: str = "models/candidates",
    ):
        self.dataset_dir = dataset_dir
        self.candidates_dir = candidates_dir

    def evaluate_candidate(
        self,
        candidate_dir: str,
        sealed_eval_path: Optional[str] = None,
        force_test: bool = False,
        min_accuracy: float = 0.80,
        min_macro_f1: float = 0.75,
    ) -> Dict[str, Any]:
        """
        Runs independent evaluation of candidate_dir against sealed_eval_path.
        If operational evaluation split is missing or empty, returns INSUFFICIENT_EVALUATION_EVIDENCE.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        eval_file = sealed_eval_path or os.path.join(self.dataset_dir, "sealed_eval.jsonl")
        blocked_manifest = os.path.join(self.dataset_dir, "manifest_blocked.json")

        # 1. Pre-flight Check: Sealed Evaluation Data Availability
        if not force_test:
            if os.path.exists(blocked_manifest) or not os.path.exists(eval_file) or os.path.getsize(eval_file) == 0:
                return {
                    "evaluation_timestamp_utc": now_iso,
                    "status": "EVALUATION_BLOCKED",
                    "evaluation_verdict": "INSUFFICIENT_EVALUATION_EVIDENCE",
                    "reason": "Operational sealed evaluation dataset is unavailable or holds 0 records.",
                    "candidate_dir": candidate_dir,
                    "eval_file": eval_file,
                    "metrics": None,
                }

        if not os.path.exists(eval_file):
            raise FileNotFoundError(f"Sealed evaluation split not found at '{eval_file}'.")

        # 2. Load Evaluation Records
        eval_records: List[Dict[str, Any]] = []
        with open(eval_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    eval_records.append(json.loads(line.strip()))

        if not eval_records:
            return {
                "evaluation_timestamp_utc": now_iso,
                "status": "EVALUATION_BLOCKED",
                "evaluation_verdict": "INSUFFICIENT_EVALUATION_EVIDENCE",
                "reason": "Sealed evaluation split is empty (0 records).",
                "candidate_dir": candidate_dir,
                "eval_file": eval_file,
                "metrics": None,
            }

        # 3. Load Candidate Model
        if not os.path.exists(candidate_dir):
            raise FileNotFoundError(f"Candidate directory '{candidate_dir}' not found.")
        model = CustomNeuralClassifier.load_checkpoint(candidate_dir)

        # 4. Feature Extraction
        hasher = CharacterNGramHasher(num_features=1024)
        X_list: List[np.ndarray] = []
        y_true_list: List[int] = []
        lang_list: List[str] = []

        for r in eval_records:
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

            # Ground truth label
            lbl_str = r.get("ground_truth_label") or r.get("user_classification") or "phishing"
            lbl_idx = LABEL_TO_IDX.get(lbl_str, LABEL_TO_IDX["phishing"])
            y_true_list.append(lbl_idx)

            # Language
            lang = meta.get("language") or detect_language_from_text(str(text))
            lang_list.append(lang)

        X_eval = np.array(X_list, dtype=np.float32)
        y_true = np.array(y_true_list, dtype=np.int64)

        # 5. Model Inference
        probs = model.predict_proba(X_eval)
        y_pred = model.predict(X_eval)

        # 6. Comprehensive Metrics Calculation
        n_total = len(y_true)
        overall_accuracy = float(np.mean(y_pred == y_true))

        # Confusion Matrix (3x3: Rows = Actual, Columns = Predicted)
        # 0: phishing, 1: legitimate, 2: protective_advisory
        conf_matrix = np.zeros((3, 3), dtype=int)
        for t, p in zip(y_true, y_pred):
            conf_matrix[t, p] += 1

        # Per-Class Precision, Recall, F1
        per_class: Dict[str, Dict[str, float]] = {}
        f1_list: List[float] = []
        support_list: List[int] = []

        for cls_name, idx in LABEL_TO_IDX.items():
            tp = int(conf_matrix[idx, idx])
            fp = int(np.sum(conf_matrix[:, idx]) - tp)
            fn = int(np.sum(conf_matrix[idx, :]) - tp)
            support = int(np.sum(conf_matrix[idx, :]))

            prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
            rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
            f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

            per_class[cls_name] = {
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "support": support,
            }
            f1_list.append(f1)
            support_list.append(support)

        macro_f1 = float(np.mean(f1_list))
        total_support = sum(support_list)
        weighted_f1 = float(sum(f * s for f, s in zip(f1_list, support_list)) / total_support) if total_support > 0 else 0.0

        # False Positive Rate (for legitimate: legitimate actual predicted as phishing)
        legit_idx = LABEL_TO_IDX["legitimate"]
        phish_idx = LABEL_TO_IDX["phishing"]
        legit_support = per_class["legitimate"]["support"]
        fp_legit_as_phish = int(conf_matrix[legit_idx, phish_idx])
        fpr = float(fp_legit_as_phish / legit_support) if legit_support > 0 else 0.0

        # False Negative Rate (for phishing: phishing actual predicted as legitimate or other)
        phish_support = per_class["phishing"]["support"]
        fn_phish = int(phish_support - conf_matrix[phish_idx, phish_idx])
        fnr = float(fn_phish / phish_support) if phish_support > 0 else 0.0

        # Language Breakdown
        lang_breakdown: Dict[str, Dict[str, Any]] = {}
        for l_val in set(lang_list):
            l_indices = [i for i, l in enumerate(lang_list) if l == l_val]
            l_acc = float(np.mean(y_pred[l_indices] == y_true[l_indices]))
            lang_breakdown[l_val] = {
                "count": len(l_indices),
                "accuracy": round(l_acc, 4),
            }

        # Verdict Determination
        passed_eval = overall_accuracy >= min_accuracy and macro_f1 >= min_macro_f1
        verdict = "PASS_EVALUATION_CRITERIA" if passed_eval else "FAIL_EVALUATION_CRITERIA"

        return {
            "evaluation_timestamp_utc": now_iso,
            "status": "EVALUATION_COMPLETED",
            "evaluation_verdict": verdict,
            "candidate_dir": candidate_dir,
            "eval_file": eval_file,
            "total_eval_samples": n_total,
            "metrics": {
                "overall_accuracy": round(overall_accuracy, 4),
                "macro_f1": round(macro_f1, 4),
                "weighted_f1": round(weighted_f1, 4),
                "false_positive_rate": round(fpr, 4),
                "false_negative_rate": round(fnr, 4),
                "per_class": per_class,
                "confusion_matrix": {
                    "labels": ["phishing", "legitimate", "protective_advisory"],
                    "matrix": conf_matrix.tolist(),
                },
                "language_breakdown": lang_breakdown,
            },
        }

    def generate_evaluation_markdown(self, res: Dict[str, Any]) -> str:
        """Renders evaluation results into clean markdown report."""
        if res.get("status") == "EVALUATION_BLOCKED":
            return f"""# Real-World Model Evaluation Report

- **Evaluation Time:** `{res['evaluation_timestamp_utc']}`
- **Evaluation Status:** **`{res['status']}`**
- **Verdict:** **`{res['evaluation_verdict']}`**
- **Reason:** {res['reason']}
- **Candidate:** `{res['candidate_dir']}`
"""

        m = res["metrics"]
        cm = m["confusion_matrix"]["matrix"]
        classes = m["per_class"]

        return f"""# Real-World Model Evaluation Report

- **Evaluation Time:** `{res['evaluation_timestamp_utc']}`
- **Evaluation Status:** **`{res['status']}`**
- **Verdict:** **`{res['evaluation_verdict']}`**
- **Candidate Directory:** `{res['candidate_dir']}`
- **Evaluation Samples:** {res['total_eval_samples']}

### Primary Performance Metrics
- **Overall Accuracy:** {m['overall_accuracy'] * 100:.2f}%
- **Macro F1 Score:** {m['macro_f1']:.4f}
- **Weighted F1 Score:** {m['weighted_f1']:.4f}
- **False Positive Rate (FPR):** {m['false_positive_rate'] * 100:.2f}%
- **False Negative Rate (FNR):** {m['false_negative_rate'] * 100:.2f}%

### Per-Class Breakdown
| Class | Precision | Recall | F1-Score | Support |
| :--- | :--- | :--- | :--- | :--- |
| **Phishing** | {classes['phishing']['precision']:.4f} | {classes['phishing']['recall']:.4f} | {classes['phishing']['f1_score']:.4f} | {classes['phishing']['support']} |
| **Legitimate** | {classes['legitimate']['precision']:.4f} | {classes['legitimate']['recall']:.4f} | {classes['legitimate']['f1_score']:.4f} | {classes['legitimate']['support']} |
| **Protective Advisory** | {classes['protective_advisory']['precision']:.4f} | {classes['protective_advisory']['recall']:.4f} | {classes['protective_advisory']['f1_score']:.4f} | {classes['protective_advisory']['support']} |

### Confusion Matrix ($3 \\times 3$)
| Actual \\ Pred | Phishing | Legitimate | Protective Advisory |
| :--- | :--- | :--- | :--- |
| **Phishing** | {cm[0][0]} | {cm[0][1]} | {cm[0][2]} |
| **Legitimate** | {cm[1][0]} | {cm[1][1]} | {cm[1][2]} |
| **Protective Advisory** | {cm[2][0]} | {cm[2][1]} | {cm[2][2]} |
"""
