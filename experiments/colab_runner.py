#!/usr/bin/env python3
"""
experiments/colab_runner.py

Headless execution script for Google Colab / Linux / Windows environments:
- Downloads and samples DistriNet CNS 2022 / CSE-CIC-IDS2018 datasets on-the-fly.
- Trains XGBoost, PyTorch Bi-LSTM, and Isolation Forest models.
- Generates publication-ready metrics, confusion matrices, and LaTeX tables.
"""

import sys
import os
import argparse
import time
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from experiments.train_models import train_pipeline


def main():
    parser = argparse.ArgumentParser(description="Headless Colab Research Pipeline Runner")
    parser.add_argument("--cns2022", action="store_true", default=True, help="Download/load CNS 2022 dataset")
    parser.add_argument("--dataset", type=str, default=None, help="Local dataset path")
    parser.add_argument("--samples", type=int, default=50000, help="Number of flow samples (default: 50,000)")
    parser.add_argument("--epochs", type=int, default=15, help="Bi-LSTM epochs (default: 15)")
    args = parser.parse_args()

    print("=" * 72)
    print("   AI-DRIVEN SDN THREAT ISOLATION: COLAB BENCHMARK RUNNER")
    print("   Advanced Computer Networks Research")
    print("=" * 72)

    results = train_pipeline(
        dataset_path=args.dataset,
        use_cns2022=args.cns2022,
        samples=args.samples,
        train_xgboost=True,
        train_bilstm=True,
        train_iforest=True,
    )

    # Save summary to file
    summary_path = os.path.join(PROJECT_ROOT, "experiments", "benchmark_summary.txt")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("BENCHMARK SUMMARY FOR RESEARCH PAPER\n")
        f.write("=" * 45 + "\n")
        for model_name, res in results.items():
            f.write(f"\nModel: {model_name.upper()}\n")
            for k, v in res.items():
                f.write(f"  {k}: {v}\n")
    print(f"\n[REPORT] Saved benchmark summary to: {summary_path}")


if __name__ == "__main__":
    main()
