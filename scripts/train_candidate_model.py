#!/usr/bin/env python3
"""
CLI Script for Offline Autonomous Candidate Model Training (Phase 6.3).

Part of Seva Cyber Sandbox.

Trains an experimental candidate neural classifier from random weights using
eligible curated feedback features and/or synthetic anchor corpus data.
Outputs immutable artifacts to models/candidates/candidate_custom_v{version}/.
"""

import argparse
import os
import sys
from typing import Any, Dict

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.case_repository import CaseRepository, get_default_case_repository
from src.candidate_trainer import (
    DEFAULT_CANDIDATES_DIR,
    DEFAULT_MIN_TRAINING_EXAMPLES,
    DEFAULT_SYNTHETIC_TRAIN_CORPUS,
    CandidateModelTrainer,
    compose_training_dataset,
    load_curated_feedback_features,
    load_synthetic_anchor_features,
)


def run_candidate_training(
    policy: str = "combined_anchor",
    synthetic_corpus: str = DEFAULT_SYNTHETIC_TRAIN_CORPUS,
    candidate_version: str = None,
    candidates_dir: str = DEFAULT_CANDIDATES_DIR,
    epochs: int = 20,
    batch_size: int = 16,
    lr: float = 0.005,
    seed: int = 42,
    min_samples: int = DEFAULT_MIN_TRAINING_EXAMPLES,
    db_path: str = None,
    secret: str = None,
) -> Dict[str, Any]:
    """Orchestrates candidate model training from CLI or Python invocations."""
    print("=" * 76)
    print("SEVA CYBER SANDBOX — OFFLINE CANDIDATE MODEL TRAINER (PHASE 6.3)")
    print("=" * 76)
    print(f"[*] Composition Policy: {policy}")
    print(f"[*] Deterministic Random Seed: {seed}")
    print(f"[*] Epochs: {epochs} | Batch Size: {batch_size} | Learning Rate: {lr}")
    print(f"[*] Target Candidates Directory: {candidates_dir}")
    print(f"[*] Weight Initialization: Random He-normal / Xavier-uniform (From Scratch)")
    print(f"[*] Active Production Model Modification: STRICTLY FORBIDDEN (Score Delta = 0)")

    # 1. Load human-reviewed feedback records
    repo = CaseRepository(db_path=db_path) if db_path else get_default_case_repository()
    feedback_records = []
    if policy in ("feedback_only", "combined_anchor"):
        try:
            feedback_records = load_curated_feedback_features(repo, secret=secret)
            print(f"[+] Loaded Eligible Curated Feedback: {len(feedback_records)} records")
        except Exception as e:
            print(f"[!] Warning: Feedback feature loading failed: {e}")
            if policy == "feedback_only":
                raise

    # 2. Load synthetic anchor records
    synthetic_records = []
    if policy in ("synthetic_only", "combined_anchor"):
        if os.path.exists(synthetic_corpus):
            synthetic_records = load_synthetic_anchor_features(corpus_path=synthetic_corpus, secret=secret)
            print(f"[+] Loaded Synthetic Anchor Corpus: {len(synthetic_records)} records from {synthetic_corpus}")
        else:
            print(f"[!] Synthetic anchor corpus not found at {synthetic_corpus}")
            if policy == "synthetic_only":
                raise FileNotFoundError(f"Synthetic corpus missing at {synthetic_corpus}")

    # 3. Compose dataset
    dataset, summary = compose_training_dataset(
        feedback_records=feedback_records,
        synthetic_records=synthetic_records,
        policy=policy,
    )

    print(f"[*] Total Training Examples: {summary['total_records']}")
    print(f"    - Human Feedback: {summary['human_reviewed_count']}")
    print(f"    - Synthetic Anchor: {summary['synthetic_count']}")
    print(f"[*] Class Distribution: {summary['class_distribution']}")

    # 4. Instantiate trainer and run
    trainer = CandidateModelTrainer(
        candidates_dir=candidates_dir,
        epochs=epochs,
        batch_size=batch_size,
        learning_rate=lr,
        seed=seed,
    )

    print("\n--- EXECUTING CANDIDATE TRAINING ---")
    result = trainer.train_candidate(
        dataset=dataset,
        composition_summary=summary,
        candidate_version=candidate_version,
        min_samples=min_samples,
    )

    print(f"[+] Candidate Training SUCCESSFUL: {result.candidate_id}")
    print(f"[+] Artifact Directory: {result.artifact_dir}")
    print(f"[+] Checkpoint SHA-256: {result.weights_sha256}")
    print(f"[+] Metadata SHA-256:   {result.metadata_sha256}")
    print(f"[+] Manifest SHA-256:   {result.manifest_sha256}")
    print("=" * 76)

    return result.to_dict()


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Offline Candidate Neural Model")
    parser.add_argument("--policy", choices=["combined_anchor", "feedback_only", "synthetic_only"], default="combined_anchor", help="Data composition policy")
    parser.add_argument("--synthetic-corpus", default=DEFAULT_SYNTHETIC_TRAIN_CORPUS, help="Path to synthetic training corpus")
    parser.add_argument("--version", default=None, help="Explicit candidate version (e.g. 1.0.0)")
    parser.add_argument("--candidates-dir", default=DEFAULT_CANDIDATES_DIR, help="Base candidate directory")
    parser.add_argument("--epochs", type=int, default=20, help="Training epochs (default: 20)")
    parser.add_argument("--batch-size", type=int, default=16, help="Mini-batch size (default: 16)")
    parser.add_argument("--lr", type=float, default=0.005, help="Learning rate (default: 0.005)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    parser.add_argument("--min-samples", type=int, default=DEFAULT_MIN_TRAINING_EXAMPLES, help="Minimum required examples")
    parser.add_argument("--db-path", default=None, help="Optional SQLite database path")

    args = parser.parse_args()

    run_candidate_training(
        policy=args.policy,
        synthetic_corpus=args.synthetic_corpus,
        candidate_version=args.version,
        candidates_dir=args.candidates_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        seed=args.seed,
        min_samples=args.min_samples,
        db_path=args.db_path,
    )


if __name__ == "__main__":
    main()
