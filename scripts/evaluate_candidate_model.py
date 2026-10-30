#!/usr/bin/env python3
"""
CLI Tool for Automated Candidate Model Evaluation and Benchmark Gate.
Part of Seva Cyber Sandbox (Phase 6.4).

USAGE:
  python scripts/evaluate_candidate_model.py --candidate-dir models/candidates/candidate_custom_v1.0.0
"""

import argparse
import json
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.candidate_evaluator import (
    BenchmarkPolicy,
    CandidateEvaluator,
    CandidateEvaluationError,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate Candidate Neural Classifier against Baseline Model with Safety Gate"
    )
    parser.add_argument(
        "--candidate-dir",
        default="models/candidates/candidate_custom_v1.0.0",
        help="Path to candidate artifact directory",
    )
    parser.add_argument(
        "--val-corpus",
        default="data/generated/v2/synthetic_validation_corpus.jsonl",
        help="Path to authorized validation corpus JSONL",
    )
    parser.add_argument(
        "--output-json",
        default=None,
        help="Destination path for companion JSON report",
    )
    parser.add_argument(
        "--min-macro-f1",
        type=float,
        default=0.90,
        help="Minimum required candidate macro-F1",
    )
    parser.add_argument(
        "--max-f1-drop",
        type=float,
        default=0.02,
        help="Maximum permitted macro-F1 drop relative to baseline",
    )
    parser.add_argument(
        "--max-legit-fp",
        type=float,
        default=0.15,
        help="Maximum permitted legitimate false-positive rate",
    )
    parser.add_argument(
        "--max-advisory-fp",
        type=float,
        default=0.05,
        help="Maximum permitted protective-advisory false-positive rate",
    )
    parser.add_argument(
        "--max-phish-fn",
        type=float,
        default=0.05,
        help="Maximum permitted phishing false-negative rate",
    )

    args = parser.parse_args()

    policy = BenchmarkPolicy(
        min_macro_f1=args.min_macro_f1,
        max_macro_f1_drop=args.max_f1_drop,
        max_legitimate_fp_rate=args.max_legit_fp,
        max_protective_advisory_fp_rate=args.max_advisory_fp,
        max_phishing_fn_rate=args.max_phish_fn,
    )

    evaluator = CandidateEvaluator(project_root=PROJECT_ROOT, policy=policy)

    print("=" * 78)
    print("SEVA CYBER SANDBOX — AUTOMATED CANDIDATE BENCHMARK GATE (PHASE 6.4)")
    print("=" * 78)
    print(f"[*] Candidate Directory: {args.candidate_dir}")
    print(f"[*] Validation Corpus:   {args.val_corpus}")
    print(f"[*] Benchmark Policy:    v{policy.policy_version} (Max F1 drop: {policy.max_macro_f1_drop})")
    print("-" * 78)

    try:
        report = evaluator.run_full_evaluation(
            candidate_dir=args.candidate_dir,
            val_corpus_path=args.val_corpus,
            policy=policy,
        )
    except CandidateEvaluationError as e:
        print(f"\n[!] EVALUATION ERROR: {e}")
        sys.exit(1)

    cand = report["candidate"]
    base = report["baseline"]
    cand_m = report["metrics"]["candidate"]
    base_m = report["metrics"]["baseline"]
    comp = report["metrics"]["comparison"]
    gate = report["benchmark_gate"]

    print(f"\n[+] Baseline Model:   {base['model_version']} (Operating Mode: {base['operating_mode']})")
    print(f"[+] Candidate Model:  {cand['candidate_id']} (Lifecycle State: experimental)")
    print(f"[+] Validation Size:  {report['dataset_isolation']['validation_records_count']} records (Isolated)")
    print("-" * 78)
    print(f"{'Metric':<30} | {'Baseline':<12} | {'Candidate':<12} | {'Delta':<10}")
    print("-" * 78)
    print(f"{'Accuracy':<30} | {base_m['accuracy']:<12.4f} | {cand_m['accuracy']:<12.4f} | {comp['accuracy_delta']:<+10.4f}")
    print(f"{'Macro-F1':<30} | {base_m['macro_f1']:<12.4f} | {cand_m['macro_f1']:<12.4f} | {comp['macro_f1_delta']:<+10.4f}")
    print(f"{'Balanced Accuracy':<30} | {base_m['balanced_accuracy']:<12.4f} | {cand_m['balanced_accuracy']:<12.4f} | {cand_m['balanced_accuracy'] - base_m['balanced_accuracy']:<+10.4f}")
    print(f"{'Legitimate FP Rate':<30} | {base_m['safety_metrics']['legitimate_fp_rate']:<12.4f} | {cand_m['safety_metrics']['legitimate_fp_rate']:<12.4f} | {comp['legitimate_fp_delta']:<+10.4f}")
    print(f"{'Protective Advisory FP Rate':<30} | {base_m['safety_metrics']['protective_advisory_fp_rate']:<12.4f} | {cand_m['safety_metrics']['protective_advisory_fp_rate']:<12.4f} | {comp['protective_advisory_fp_delta']:<+10.4f}")
    print(f"{'Phishing FN Rate':<30} | {base_m['safety_metrics']['phishing_fn_rate']:<12.4f} | {cand_m['safety_metrics']['phishing_fn_rate']:<12.4f} | {comp['phishing_fn_delta']:<+10.4f}")
    print("-" * 78)

    print("\n[+] Per-Class Performance:")
    for lbl in ["phishing", "legitimate", "protective_advisory"]:
        bp = base_m["per_class"][lbl]
        cp = cand_m["per_class"][lbl]
        print(f"  • {lbl.upper():<20}: Baseline F1 = {bp['f1']:.4f} ({bp['recall_fraction']} rec, {bp['precision_fraction']} prec) | Candidate F1 = {cp['f1']:.4f} ({cp['recall_fraction']} rec, {cp['precision_fraction']} prec)")

    print("\n[+] Counterfactual Robustness:")
    for test_name, res in report["robustness_evaluation"].items():
        print(f"  • {test_name:<30}: Tested N={res['samples_tested']} | Baseline flips={res['baseline_flips']} | Candidate flips={res['candidate_flips']}")

    print("\n" + "=" * 78)
    print(f"BENCHMARK GATE VERDICT: >>> {gate['verdict']} <<<")
    print("=" * 78)
    for r in gate["reasons"]:
        print(f"  - {r}")
    print(f"\nNotice: {gate['notice']}")

    # Save output JSON report
    out_json = args.output_json
    if not out_json:
        candidate_slug = cand["candidate_id"].replace("/", "_")
        out_dir = os.path.join(PROJECT_ROOT, "evaluation", "candidates")
        os.makedirs(out_dir, exist_ok=True)
        out_json = os.path.join(out_dir, f"{candidate_slug}_evaluation.json")

    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Saved machine-readable companion evaluation report to: {out_json}")


if __name__ == "__main__":
    main()
