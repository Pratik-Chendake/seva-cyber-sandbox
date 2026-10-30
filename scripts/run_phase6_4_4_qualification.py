#!/usr/bin/env python3
"""
CLI Runner for Seva Cyber Sandbox — Phase 6.4.4: One-Time Candidate Qualification Benchmark.
"""

import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.qualification_evaluator import QualificationEvaluator


def main():
    evaluator = QualificationEvaluator()
    evaluator.execute_one_time_qualification()


if __name__ == "__main__":
    main()
