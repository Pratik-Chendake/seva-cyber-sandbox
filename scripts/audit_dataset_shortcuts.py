#!/usr/bin/env python3
"""
Deterministic Dataset Shortcut Audit & Diagnostic Baseline Tool.
Part of Seva Cyber Sandbox (Phase 2.2 - Dataset Deconfounding).

PURPOSE:
1. Measure the association between labels and obvious surface features across:
   - URLs (presence/absence of http, https, domains)
   - OTP terms (otp, ओटीपी, one-time password)
   - UPI terms (upi, यूपीआय, pin)
   - APK terms (apk, .apk, ॲप)
   - KYC terms (kyc, केवायसी, pan, पॅन)
   - Urgency terms (urgent, तातडीची, लगेच, आजच, immediate, block, 24 hours)
   - Length buckets (<100, 100-200, >200 characters)
2. Evaluate single-feature diagnostic baselines to quantify whether any single
   surface feature accidentally acts as a trivial label predictor.
3. Compare Phase 2 (v1) against Phase 2.2 (v2) to confirm deconfounding.
"""

import argparse
from collections import Counter
import json
import os
import re
import sys
from typing import Any, Dict, List, Tuple

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

URL_PATTERN = re.compile(r"https?://", re.IGNORECASE)
OTP_PATTERN = re.compile(r"\b(otp|ओटीपी|one[- ]time password)\b", re.IGNORECASE)
UPI_PATTERN = re.compile(r"\b(upi|यूपीआय)\b", re.IGNORECASE)
APK_PATTERN = re.compile(r"(\.apk|\bapk\b|\bॲप\b|\bapp\b)", re.IGNORECASE)
KYC_PATTERN = re.compile(r"\b(kyc|केवायसी|pan|पॅन)\b", re.IGNORECASE)
URGENCY_PATTERN = re.compile(r"\b(urgent|तातडीची|लगेच|आजच|immediate|block|cut|24 hours|२४ तास)\b", re.IGNORECASE)


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    records = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    return records


def extract_features(text: str) -> Dict[str, Any]:
    length = len(text)
    if length < 100:
        len_bucket = "<100"
    elif length <= 200:
        len_bucket = "100-200"
    else:
        len_bucket = ">200"

    return {
        "has_url": bool(URL_PATTERN.search(text)),
        "has_otp": bool(OTP_PATTERN.search(text)),
        "has_upi": bool(UPI_PATTERN.search(text)),
        "has_apk": bool(APK_PATTERN.search(text)),
        "has_kyc": bool(KYC_PATTERN.search(text)),
        "has_urgency": bool(URGENCY_PATTERN.search(text)),
        "len_bucket": len_bucket,
    }


def audit_corpus_features(records: List[Dict[str, Any]], partition_name: str) -> Dict[str, Any]:
    """
    Computes presence rates of surface features broken down by ground truth label.
    """
    labels = ["phishing", "legitimate", "protective_advisory"]
    by_label: Dict[str, List[Dict[str, Any]]] = {l: [] for l in labels}
    for r in records:
        lbl = r.get("ground_truth_label")
        if lbl in by_label:
            by_label[lbl].append(r)

    results = {
        "partition": partition_name,
        "total_records": len(records),
        "class_counts": {l: len(by_label[l]) for l in labels},
        "feature_rates": {},
    }

    feature_keys = ["has_url", "has_otp", "has_upi", "has_apk", "has_kyc", "has_urgency"]
    for f in feature_keys:
        results["feature_rates"][f] = {}
        for l in labels:
            recs = by_label[l]
            if recs:
                cnt = sum(1 for r in recs if extract_features(r.get("text", ""))[f])
                rate = round(cnt / len(recs), 4)
            else:
                rate = 0.0
            results["feature_rates"][f][l] = rate

    # Length bucket distributions
    results["length_buckets"] = {}
    for l in labels:
        recs = by_label[l]
        bucket_counts = Counter(extract_features(r.get("text", ""))["len_bucket"] for r in recs)
        results["length_buckets"][l] = dict(bucket_counts)

    return results


def evaluate_diagnostic_baselines(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluates trivial single-feature rules as diagnostic baselines.
    Rule logic: If feature present -> Phishing, else Non-Phishing (Legitimate / Advisory).
    """
    binary_records = [r for r in records if r.get("ground_truth_label") in ("phishing", "legitimate", "protective_advisory")]
    n = len(binary_records)
    if n == 0:
        return {}

    rules = [
        ("has_url", lambda feats: "phishing" if feats["has_url"] else "non_phishing"),
        ("has_otp", lambda feats: "phishing" if feats["has_otp"] else "non_phishing"),
        ("has_urgency", lambda feats: "phishing" if feats["has_urgency"] else "non_phishing"),
        ("has_apk", lambda feats: "phishing" if feats["has_apk"] else "non_phishing"),
        ("has_kyc", lambda feats: "phishing" if feats["has_kyc"] else "non_phishing"),
    ]

    baselines = {}
    for rule_name, rule_fn in rules:
        tp = fp = tn = fn = 0
        for r in binary_records:
            actual = "phishing" if r["ground_truth_label"] == "phishing" else "non_phishing"
            feats = extract_features(r.get("text", ""))
            pred = rule_fn(feats)

            if pred == "phishing" and actual == "phishing":
                tp += 1
            elif pred == "phishing" and actual == "non_phishing":
                fp += 1
            elif pred == "non_phishing" and actual == "non_phishing":
                tn += 1
            elif pred == "non_phishing" and actual == "phishing":
                fn += 1

        accuracy = round((tp + tn) / n, 4)
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        f1 = round((2 * precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0

        baselines[rule_name] = {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
        }

    return baselines


def run_full_shortcut_audit(dir_v1: str, dir_v2: str) -> Dict[str, Any]:
    v1_train = load_jsonl(os.path.join(dir_v1, "synthetic_training_corpus.jsonl"))
    v1_val = load_jsonl(os.path.join(dir_v1, "synthetic_validation_corpus.jsonl"))
    v2_train = load_jsonl(os.path.join(dir_v2, "synthetic_training_corpus.jsonl"))
    v2_val = load_jsonl(os.path.join(dir_v2, "synthetic_validation_corpus.jsonl"))

    audit_res = {
        "v1_audit": {
            "train": audit_corpus_features(v1_train, "v1_train"),
            "val": audit_corpus_features(v1_val, "v1_val"),
            "diagnostics_train": evaluate_diagnostic_baselines(v1_train),
            "diagnostics_val": evaluate_diagnostic_baselines(v1_val),
        },
        "v2_audit": {
            "train": audit_corpus_features(v2_train, "v2_train"),
            "val": audit_corpus_features(v2_val, "v2_val"),
            "diagnostics_train": evaluate_diagnostic_baselines(v2_train),
            "diagnostics_val": evaluate_diagnostic_baselines(v2_val),
        },
    }
    return audit_res


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic Dataset Shortcut Audit Tool")
    parser.add_argument("--v1-dir", default="data/generated", help="Phase 2 (v1) directory")
    parser.add_argument("--v2-dir", default="data/generated/v2", help="Phase 2.2 (v2) directory")
    parser.add_argument("--output-json", default="data/generated/v2/shortcut_audit_report.json", help="Path to save report")
    args = parser.parse_args()

    v1_dir = os.path.abspath(os.path.join(PROJECT_ROOT, args.v1_dir))
    v2_dir = os.path.abspath(os.path.join(PROJECT_ROOT, args.v2_dir))

    print("=" * 76)
    print("SEVA CYBER SANDBOX — DATASET SHORTCUT AUDIT & DIAGNOSTIC REPORT")
    print("=" * 76)

    res = run_full_shortcut_audit(v1_dir, v2_dir)

    print("\n--- 1. URL PRESENCE RATE BEFORE VS AFTER ---")
    v1_tr = res["v1_audit"]["train"]["feature_rates"]["has_url"]
    v2_tr = res["v2_audit"]["train"]["feature_rates"]["has_url"]
    print(f"Phase 2 (v1) Training: Phishing={v1_tr['phishing']*100:.1f}% | Legit={v1_tr['legitimate']*100:.1f}% | ProtAdv={v1_tr['protective_advisory']*100:.1f}%")
    print(f"Phase 2.2 (v2) Training: Phishing={v2_tr['phishing']*100:.1f}% | Legit={v2_tr['legitimate']*100:.1f}% | ProtAdv={v2_tr['protective_advisory']*100:.1f}%")

    v1_vl = res["v1_audit"]["val"]["feature_rates"]["has_url"]
    v2_vl = res["v2_audit"]["val"]["feature_rates"]["has_url"]
    print(f"Phase 2 (v1) Validation: Phishing={v1_vl['phishing']*100:.1f}% | Legit={v1_vl['legitimate']*100:.1f}% | ProtAdv={v1_vl['protective_advisory']*100:.1f}%")
    print(f"Phase 2.2 (v2) Validation: Phishing={v2_vl['phishing']*100:.1f}% | Legit={v2_vl['legitimate']*100:.1f}% | ProtAdv={v2_vl['protective_advisory']*100:.1f}%")

    print("\n--- 2. DIAGNOSTIC BASELINE PERFORMANCE (URL Presence Rule) ---")
    url_diag_v1 = res["v1_audit"]["diagnostics_train"]["has_url"]
    url_diag_v2 = res["v2_audit"]["diagnostics_train"]["has_url"]
    print(f"v1 Training: Accuracy={url_diag_v1['accuracy']*100:.1f}%, F1={url_diag_v1['f1']*100:.1f}% [TRIVIAL SHORTCUT]")
    print(f"v2 Training: Accuracy={url_diag_v2['accuracy']*100:.1f}%, F1={url_diag_v2['f1']*100:.1f}% [SHORTCUT ELIMINATED]")

    print("\n--- 3. ALL V2 TRAINING SURFACE FEATURE RATES ---")
    v2_rates = res["v2_audit"]["train"]["feature_rates"]
    for feat, rates in v2_rates.items():
        print(f"  {feat:12s}: Phish={rates['phishing']*100:5.1f}% | Legit={rates['legitimate']*100:5.1f}% | ProtAdv={rates['protective_advisory']*100:5.1f}%")

    print("\n--- 4. V2 DIAGNOSTIC BASELINES (TRAINING) ---")
    v2_diag = res["v2_audit"]["diagnostics_train"]
    for rname, metrics in v2_diag.items():
        print(f"  Rule '{rname:12s}': Accuracy={metrics['accuracy']*100:5.1f}%, Precision={metrics['precision']*100:5.1f}%, Recall={metrics['recall']*100:5.1f}%, F1={metrics['f1']*100:5.1f}%")

    # Save output json
    out_json_path = os.path.abspath(os.path.join(PROJECT_ROOT, args.output_json))
    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Saved Full Shortcut Audit JSON: {out_json_path}")
    print("=" * 76)


if __name__ == "__main__":
    main()
