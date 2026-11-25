#!/usr/bin/env python3
"""
experiments/train_models.py

Phase 4: Train and evaluate SDN threat isolation models
References: PRD (Section 5, Phase 4), DESIGN.md, AGENTS.md, ARCHITECTURE.md

Supported Datasets:
  - CNS 2022 Improved CIC-IDS-2017 / CSE-CIC-IDS-2018 (DistriNet, KU Leuven)
    Download portal: https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html
    Direct links:
      https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip
      https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CSECICIDS2018_improved.zip
  - InSDN Dataset (Elsayed et al., IEEE Access 2020)
  - Synthetic reproducible telemetry for offline testing

Models Trained:
  1. XGBoost Multi-Class Classifier (High-speed tabular gradient boosted trees)
  2. PyTorch Bidirectional LSTM (Bi-LSTM) Classifier (Sequential rate modeling)
  3. Isolation Forest Detector (Unsupervised baseline anomaly deviation)

Key Preprocessing & Modeling Principles:
  1. Stratified Partitioning: Avoids chronological distribution shift by ensuring proportional
     class representation across train and test partitions.
  2. CNS 2022 'Attempted' Label Sanitization: Flow records marked '- Attempted' represent non-malicious
     attempts. Mapping them to benign removes label ambiguity and sharpens decision boundaries.
  3. Feature Header Harmonization: Resolves all CICFlowMeter variants ('Pkt Len Mean', 'Tot Fwd Pkts').
  4. Class-Balanced Sample Weighting: Ensures minority attack classes receive proportional gradient weight.

Usage:
  # Automated Colab/Research training directly from DistriNet CNS2022 (no physical download needed):
  python3 experiments/train_models.py --cns2022 --samples 100000

  # Train on a specific local CSV file:
  python3 experiments/train_models.py --dataset /path/to/dataset.csv

  # Run offline unit test with synthetic data:
  python3 experiments/train_models.py --synthetic
"""

import sys
import os
import argparse
import logging
import time
from collections import Counter
from typing import List, Tuple, Dict, Any, Optional
import numpy as np

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("train_models")

from ai.features.feature_contract import FEATURE_NAMES


# ---------------------------------------------------------------------------
# Synthetic dataset generator for reproducible unit testing
# ---------------------------------------------------------------------------
def make_synthetic_dataset(n_samples: int = 4000, seed: int = 42) -> Tuple[np.ndarray, List[str]]:
    """
    Generates a synthetic dataset strictly adhering to the 6-feature contract
    with balanced realistic rate distributions across all 4 classes.
    """
    rng = np.random.default_rng(seed)
    vectors = []
    labels = []

    def _sample(rate_low, rate_high, byte_mult, size_low, size_high, label):
        pkt_rate = rng.uniform(rate_low, rate_high)
        byte_rate = pkt_rate * rng.uniform(byte_mult * 0.8, byte_mult * 1.2)
        avg_size = rng.uniform(size_low, size_high)
        pkt_cnt = rng.uniform(100, 10000)
        byte_cnt = pkt_cnt * avg_size
        duration = rng.uniform(0.5, 60.0)
        return [pkt_rate, byte_rate, avg_size, pkt_cnt, byte_cnt, duration], label

    n_per_class = n_samples // 4
    for _ in range(n_per_class):
        vec, lbl = _sample(5, 150, 600, 400, 1400, "benign")
        vectors.append(vec)
        labels.append(lbl)
    for _ in range(n_per_class):
        vec, lbl = _sample(10000, 60000, 64, 40, 80, "dos")
        vectors.append(vec)
        labels.append(lbl)
    for _ in range(n_per_class):
        vec, lbl = _sample(200, 2500, 80, 40, 120, "portscan")
        vectors.append(vec)
        labels.append(lbl)
    for _ in range(n_per_class):
        vec, lbl = _sample(50, 600, 400, 200, 800, "bruteforce")
        vectors.append(vec)
        labels.append(lbl)

    indices = np.arange(len(labels))
    rng.shuffle(indices)
    X = np.array([vectors[i] for i in indices], dtype=np.float32)
    y = [labels[i] for i in indices]
    return X, y


# ---------------------------------------------------------------------------
# Robust Stratified Train/Test Split
# ---------------------------------------------------------------------------
def split_data(
    X: np.ndarray,
    y: List[str],
    test_size: float = 0.20,
    random_state: int = 42,
    stratified: bool = True,
) -> Tuple[np.ndarray, np.ndarray, List[str], List[str]]:
    """
    Performs stratified train/test split to guarantee all classes are present
    and proportionally represented in both train and test partitions.
    """
    if stratified:
        from sklearn.model_selection import train_test_split
        return train_test_split(
            X, y,
            test_size=test_size,
            stratify=y,
            random_state=random_state,
        )
    else:
        # Time-ordered sequential split
        n_train = int(len(y) * (1.0 - test_size))
        return X[:n_train], X[n_train:], y[:n_train], y[n_train:]


# ---------------------------------------------------------------------------
# Main Training Function
# ---------------------------------------------------------------------------
def train_pipeline(
    dataset_path: Optional[str] = None,
    use_cns2022: bool = False,
    synthetic: bool = False,
    samples: int = 100000,
    train_xgboost: bool = True,
    train_bilstm: bool = True,
    train_iforest: bool = True,
    iforest_contamination: float = 0.05,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Executes the end-to-end multi-model training and evaluation pipeline.
    """
    from ai.models.xgboost_classifier import XGBoostThreatClassifier
    from ai.models.isolation_forest import IsolationForestDetector

    print("=" * 72)
    print("   AI-DRIVEN SDN THREAT ISOLATION: RESEARCH MODEL TRAINING")
    print("   Benchmark Datasets: CNS 2022 / CSE-CIC-IDS2018 / CIC-IDS-2017")
    print("=" * 72)

    # 1. Load Data
    if synthetic:
        print("\n[DATA] Generating synthetic telemetry dataset (offline unit test)...")
        X, y = make_synthetic_dataset(n_samples=samples, seed=random_state)
        data_source = "Synthetic Telemetry Generator"
    elif use_cns2022 or (dataset_path is None and not synthetic):
        print(f"\n[DATA] Loading DistriNet CNS 2022 Benchmark Dataset ({samples} flows)...")
        from ai.features.cns2022_loader import load_cns2022_benchmark_data
        X_train, X_test, y_train, y_test = load_cns2022_benchmark_data(
            dataset_path=dataset_path,
            max_samples=samples,
            test_size=0.20,
            random_state=random_state,
        )
        data_source = "DistriNet CNS2022 (IEEE CNS 2022 Improved NIDS)"
        # Data already split stratified
        skip_split = True
    elif dataset_path:
        print(f"\n[DATA] Loading dataset from path: {dataset_path}")
        from ai.features.insdn_mapper import load_insdn_csv
        X, y, col_map, n_skipped = load_insdn_csv(dataset_path)
        data_source = f"File: {os.path.basename(dataset_path)}"
        skip_split = False
    else:
        raise ValueError("Must specify --cns2022, --dataset, or --synthetic")

    if not ('skip_split' in locals() and skip_split):
        X_train, X_test, y_train, y_test = split_data(
            X, y, test_size=0.20, random_state=random_state, stratified=True
        )

    print(f"\n[DATASET SUMMARY] Source: {data_source}")
    print(f"  Total Samples:  {len(y_train) + len(y_test):,}")
    print(f"  Training Split: {len(y_train):,} ({len(y_train)/(len(y_train)+len(y_test))*100:.1f}%)")
    print(f"  Testing Split:  {len(y_test):,} ({len(y_test)/(len(y_train)+len(y_test))*100:.1f}%)")
    print(f"  Train Class Counts: {dict(Counter(y_train))}")
    print(f"  Test Class Counts:  {dict(Counter(y_test))}")

    results: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # 2. Train XGBoost Classifier
    # ------------------------------------------------------------------
    if train_xgboost:
        print("\n" + "-" * 55)
        print(" [MODEL 1/3] XGBoost Threat Classifier (Gradient Boosted Trees)")
        print("-" * 55)
        xgb = XGBoostThreatClassifier()
        xgb_result = xgb.train(
            X_train, y_train,
            X_test, y_test,
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            random_state=random_state,
            feature_names=FEATURE_NAMES,
        )
        xgb_path = xgb.save()
        results["xgboost"] = {
            "accuracy": xgb_result.accuracy,
            "train_duration_s": xgb_result.train_duration_s,
            "per_class_f1": xgb_result.per_class_f1,
            "model_path": xgb_path,
        }
        print(f"  >>> XGBoost Measured Accuracy: {xgb_result.accuracy * 100:.2f}%")
        print(f"  >>> Training Duration:         {xgb_result.train_duration_s:.2f}s")
        print("  >>> Per-Class F1 Scores:")
        for cls, f1 in (xgb_result.per_class_f1 or {}).items():
            print(f"        {cls:<14} F1 = {f1 * 100:.2f}%")

    # ------------------------------------------------------------------
    # 3. Train Bi-LSTM Classifier (PyTorch)
    # ------------------------------------------------------------------
    if train_bilstm:
        print("\n" + "-" * 55)
        print(" [MODEL 2/3] PyTorch Bidirectional LSTM (Bi-LSTM)")
        print("-" * 55)
        try:
            from ai.models.bilstm_classifier import BiLSTMThreatClassifier
            bilstm = BiLSTMThreatClassifier()
            bilstm_result = bilstm.train(
                X_train, y_train,
                X_test, y_test,
                epochs=15,
                batch_size=128,
                lr=0.001,
                random_state=random_state,
            )
            bilstm_path = bilstm.save()
            results["bilstm"] = {
                "accuracy": bilstm_result.accuracy,
                "macro_f1": bilstm_result.macro_f1,
                "train_duration_s": bilstm_result.train_duration_s,
                "per_class_f1": bilstm_result.per_class_f1,
                "model_path": bilstm_path,
            }
            print(f"  >>> Bi-LSTM Measured Accuracy: {bilstm_result.accuracy * 100:.2f}%")
            print(f"  >>> Bi-LSTM Macro F1:          {bilstm_result.macro_f1 * 100:.2f}%")
            print(f"  >>> Training Duration:         {bilstm_result.train_duration_s:.2f}s")
            print("  >>> Per-Class F1 Scores:")
            for cls, f1 in (bilstm_result.per_class_f1 or {}).items():
                print(f"        {cls:<14} F1 = {f1 * 100:.2f}%")
        except Exception as e:
            logger.warning("[BiLSTM] Training skipped or failed: %s", e)
            results["bilstm"] = {"error": str(e)}

    # ------------------------------------------------------------------
    # 4. Train Isolation Forest (Benign-only baseline anomaly detector)
    # ------------------------------------------------------------------
    if train_iforest:
        print("\n" + "-" * 55)
        print(" [MODEL 3/3] Isolation Forest Anomaly Detector")
        print("-" * 55)
        benign_indices = [i for i, lbl in enumerate(y_train) if lbl == "benign"]
        X_benign = X_train[benign_indices]

        ifd = IsolationForestDetector(contamination=iforest_contamination)
        if_result = ifd.train(X_benign, n_estimators=100, random_state=random_state)
        if_path = ifd.save()

        # Evaluate on test set
        y_test_binary = [1 if lbl == "benign" else -1 for lbl in y_test]
        eval_result = ifd.evaluate(X_test, y_test_binary)

        results["iforest"] = {
            "n_train_benign": len(X_benign),
            "train_duration_s": if_result.train_duration_s,
            "anomaly_precision": eval_result.get("anomaly_precision"),
            "anomaly_recall": eval_result.get("anomaly_recall"),
            "anomaly_f1": eval_result.get("anomaly_f1"),
            "model_path": if_path,
        }
        print(f"  >>> Benign Baseline Samples:   {len(X_benign):,}")
        print(f"  >>> Training Duration:         {if_result.train_duration_s:.2f}s")
        if "error" not in eval_result:
            print(f"  >>> Anomaly Precision:         {eval_result['anomaly_precision'] * 100:.2f}%")
            print(f"  >>> Anomaly Recall:            {eval_result['anomaly_recall'] * 100:.2f}%")
            print(f"  >>> Anomaly F1:                {eval_result['anomaly_f1'] * 100:.2f}%")

    # ------------------------------------------------------------------
    # 5. Evaluation summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 72)
    print(f"   MODEL EVALUATION SUMMARY: {data_source}")
    print("=" * 72)
    print(f"{'Model':<20} | {'Accuracy':<10} | {'F1':<21} | {'Train Time':<10}")
    print("-" * 72)
    if "xgboost" in results and "accuracy" in results["xgboost"]:
        model_result = results["xgboost"]
        f1_values = list(model_result["per_class_f1"].values())
        f1_display = f"{np.mean(f1_values):.2%} macro" if f1_values else "Unavailable"
        print(f"{'XGBoost':<20} | {model_result['accuracy']:>10.2%} | {f1_display:<21} | {model_result['train_duration_s']:>8.2f}s")
    if "bilstm" in results and "accuracy" in results["bilstm"]:
        model_result = results["bilstm"]
        f1_display = f"{model_result['macro_f1']:.2%} macro"
        print(f"{'Bi-LSTM (PyTorch)':<20} | {model_result['accuracy']:>10.2%} | {f1_display:<21} | {model_result['train_duration_s']:>8.2f}s")
    if "iforest" in results:
        model_result = results["iforest"]
        anomaly_f1 = model_result["anomaly_f1"]
        f1_display = f"{anomaly_f1:.2%} anomaly" if anomaly_f1 is not None else "Unavailable"
        print(f"{'Isolation Forest':<20} | {'N/A':>10} | {f1_display:<21} | {model_result['train_duration_s']:>8.2f}s")
    print("=" * 72 + "\n")

    return results


def main():
    parser = argparse.ArgumentParser(description="Train and evaluate SDN threat isolation models")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--cns2022", action="store_true", help="Automatically load/download DistriNet CNS 2022 dataset")
    group.add_argument("--dataset", type=str, help="Path to local dataset CSV file")
    group.add_argument("--synthetic", action="store_true", help="Generate synthetic dataset (offline test)")

    parser.add_argument("--samples", type=int, default=50000, help="Number of flow samples to benchmark (default: 50,000)")
    parser.add_argument("--no-bilstm", action="store_true", help="Skip Bi-LSTM training")
    parser.add_argument("--no-xgboost", action="store_true", help="Skip XGBoost training")
    parser.add_argument("--no-iforest", action="store_true", help="Skip Isolation Forest training")
    parser.add_argument("--iforest-contamination", type=float, default=0.05, help="Isolation Forest contamination")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")

    args = parser.parse_args()

    # Default to synthetic if nothing provided and dataset_path is empty
    if not args.cns2022 and not args.dataset and not args.synthetic:
        args.synthetic = True

    train_pipeline(
        dataset_path=args.dataset,
        use_cns2022=args.cns2022,
        synthetic=args.synthetic,
        samples=args.samples,
        train_xgboost=not args.no_xgboost,
        train_bilstm=not args.no_bilstm,
        train_iforest=not args.no_iforest,
        iforest_contamination=args.iforest_contamination,
        random_state=args.seed,
    )


if __name__ == "__main__":
    main()
