#!/usr/bin/env python3
"""
CLI Runner for Seva Cyber Sandbox — Phase 6.4.8: One-Time Candidate Qualification Benchmark (Dataset v4).
Evaluates candidate_v4_seed42 and baseline custom-mlp-v1.1.0-preproc against the sealed v4 qualification partition.
"""

import os
import sys

# Force UTF-8 encoding on Windows terminal
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.qualification_evaluator_v4 import QualificationEvaluatorV4


def main():
    evaluator = QualificationEvaluatorV4()
    evaluator.execute_one_time_qualification()


if __name__ == "__main__":
    main()
