"""
Optional Educational Machine-Learning Baseline (TF-IDF + Logistic Regression).

PURPOSE & HONEST DISCLOSURE:
- Demonstrates reproducible train/test splitting (75% train / 25% test) and confusion-matrix evaluation.
- Explicitly validates dataset schema and class balance before training.
- Caches the trained model in memory so it is not retrained on every UI click.
- Wrapped in safe fallback handling so the main app still launches even if scikit-learn is absent.
"""

import json
import os
from typing import Any, Dict, Optional

DATA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "sample_messages.json",
)

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline

    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False

_CACHED_BUNDLE: Optional[Dict[str, Any]] = None


def train_and_evaluate_local_model(
    dataset_path: str = DATA_PATH, force_retrain: bool = False
) -> Dict[str, Any]:
    """
    Validates the local JSON dataset, splits into 75% train and 25% unseen test sets,
    trains a TF-IDF + Logistic Regression pipeline, and returns evaluation metrics.
    """
    global _CACHED_BUNDLE
    if _CACHED_BUNDLE is not None and not force_retrain and dataset_path == DATA_PATH:
        return _CACHED_BUNDLE

    if not SKLEARN_AVAILABLE:
        return {
            "is_available": False,
            "error": "scikit-learn is not installed in this Python environment.",
        }

    if not os.path.exists(dataset_path):
        return {
            "is_available": False,
            "error": f"Sample dataset file not found at: {dataset_path}",
        }

    try:
        with open(dataset_path, "r", encoding="utf-8") as f:
            records = json.load(f)
    except Exception as exc:
        return {
            "is_available": False,
            "error": f"Failed to parse JSON dataset: {exc}",
        }

    if not isinstance(records, list) or len(records) < 8:
        return {
            "is_available": False,
            "error": "Dataset must be a JSON list containing at least 8 labeled messages.",
        }

    texts = []
    labels = []
    for item in records:
        if not isinstance(item, dict) or "text" not in item or "label" not in item:
            continue
        text_val = str(item["text"]).strip()
        label_val = str(item["label"]).strip().lower()
        if text_val and label_val in ("phishing", "legitimate"):
            texts.append(text_val)
            labels.append(1 if label_val == "phishing" else 0)

    phishing_count = sum(labels)
    legit_count = len(labels) - phishing_count
    if phishing_count < 4 or legit_count < 4:
        return {
            "is_available": False,
            "error": (
                f"Insufficient class balance for stratified train/test split "
                f"(phishing={phishing_count}, legitimate={legit_count}; need at least 4 of each)."
            ),
        }

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.25, random_state=42, stratify=labels
    )

    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1),
            ),
            ("clf", LogisticRegression(random_state=42, C=1.0)),
        ]
    )
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    acc = round(float(accuracy_score(y_test, y_pred)) * 100, 1)
    f1 = round(float(f1_score(y_test, y_pred, zero_division=0)) * 100, 1)

    bundle: Dict[str, Any] = {
        "is_available": True,
        "error": None,
        "pipeline": pipeline,
        "total_samples": len(labels),
        "phishing_samples": phishing_count,
        "legitimate_samples": legit_count,
        "train_count": len(X_train),
        "test_count": len(X_test),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "test_accuracy_pct": acc,
        "test_f1_pct": f1,
        "methodology_note": (
            f"Educational ML Baseline: Trained on {len(X_train)} messages and evaluated on {len(X_test)} unseen test messages "
            "from data/sample_messages.json. Because a 20-message sample is too small for production generalization, "
            "this classifier is provided strictly as a learning demonstration alongside the primary rule-based detector."
        ),
    }

    if dataset_path == DATA_PATH:
        _CACHED_BUNDLE = bundle
    return bundle


def predict_with_local_ml(text: str) -> Dict[str, Any]:
    """
    Runs the cached local ML model on an input string and returns its experimental prediction.
    """
    bundle = train_and_evaluate_local_model()
    if not bundle.get("is_available"):
        return {
            "is_available": False,
            "error": bundle.get("error", "ML baseline unavailable."),
            "experimental_ml_confidence": 0.0,
            "ml_flag": "Unavailable",
            "evaluation_summary": {},
        }

    cleaned = (text or "").strip()
    if not cleaned:
        return {
            "is_available": True,
            "error": None,
            "experimental_ml_confidence": 0.0,
            "ml_flag": "No Input",
            "evaluation_summary": {k: v for k, v in bundle.items() if k != "pipeline"},
        }

    model = bundle["pipeline"]
    proba_phishing = float(model.predict_proba([cleaned])[0][1])
    return {
        "is_available": True,
        "error": None,
        "experimental_ml_confidence": round(proba_phishing * 100, 1),
        "ml_flag": (
            "Flagged by Experimental ML Baseline (Score >= 50%)"
            if proba_phishing >= 0.5
            else "Not Flagged by Experimental ML Baseline (Score < 50%)"
        ),
        "evaluation_summary": {k: v for k, v in bundle.items() if k != "pipeline"},
    }


if __name__ == "__main__":
    res = train_and_evaluate_local_model(force_retrain=True)
    if res["is_available"]:
        print(
            f"ML Baseline Ready | Total: {res['total_samples']} | "
            f"Train: {res['train_count']} | Test: {res['test_count']} | "
            f"TP={res['true_positives']} FP={res['false_positives']} "
            f"TN={res['true_negatives']} FN={res['false_negatives']}"
        )
    else:
        print("ML Error:", res["error"])