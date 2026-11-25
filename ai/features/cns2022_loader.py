"""
ai/features/cns2022_loader.py

Automated Downloader, Streamer & Preprocessor for CNS 2022 NIDS Datasets
References:
  - IEEE CNS 2022: "Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018"
    DistriNet Research Unit, KU Leuven
    Download Portal: https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html
    Direct Archives:
      CICIDS2017_improved.zip (~328 MB)
      CSECICIDS2018_improved.zip (~9.7 GB)

Purpose:
  Solves the problem: "do not need to physically download it. Wherever the dataset is too big,
  just take enough only that is enough for an excellent research paper."
  This module can:
  1. Download the compact, fully-featured CICIDS2017_improved.zip (328 MB) directly via HTTP.
  2. Extract representative days (e.g. Wednesday DoS, Thursday Web Attacks, Friday DDoS/Portscan).
  3. Perform stratified sampling (e.g., 100,000 balanced flows) to build a publication-grade benchmark.
  4. Cache the resulting clean benchmark dataset at `data/cns2022_benchmark_subset.csv`.
"""

import os
import sys
import zipfile
import urllib.request
import logging
from typing import Tuple, List, Optional, Dict
import numpy as np

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ai.features.feature_contract import FEATURE_NAMES, FlowFeatureVector
from ai.features.cns2022_mapper import (
    resolve_cns_columns,
    map_cns_label,
    sanitize_float,
    SUPPORTED_LABELS,
)

logger = logging.getLogger("cns2022_loader")

# Direct download links provided by DistriNet Research Unit
URL_CICIDS2017_IMPROVED = "https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip"
URL_CSECICIDS2018_IMPROVED = "https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CSECICIDS2018_improved.zip"

DEFAULT_CACHE_DIR = os.path.join(PROJECT_ROOT, "data")
DEFAULT_BENCHMARK_CSV = os.path.join(DEFAULT_CACHE_DIR, "cns2022_benchmark_subset.csv")


def _download_progress(block_num: int, block_size: int, total_size: int):
    """Prints a clean CLI download progress bar."""
    downloaded = block_num * block_size
    if total_size > 0:
        percent = min(100.0, downloaded * 100.0 / total_size)
        mb = downloaded / (1024 * 1024)
        total_mb = total_size / (1024 * 1024)
        sys.stdout.write(f"\r[DOWNLOAD] {mb:.1f}MB / {total_mb:.1f}MB ({percent:.1f}%)")
        sys.stdout.flush()
    else:
        mb = downloaded / (1024 * 1024)
        sys.stdout.write(f"\r[DOWNLOAD] {mb:.1f}MB downloaded")
        sys.stdout.flush()


def download_and_extract_cns2022(
    target_dir: str = DEFAULT_CACHE_DIR,
    use_2017_fast: bool = True,
) -> List[str]:
    """
    Downloads and extracts the CNS 2022 improved archive.
    Defaults to CICIDS2017_improved.zip (328 MB) which contains the complete spectrum
    of attacks (DoS, DDoS, PortScan, BruteForce, Botnet, Web Attacks) and is 30x faster
    to download than the 9.7 GB 2018 zip.

    Returns:
        List of paths to extracted CSV files.
    """
    os.makedirs(target_dir, exist_ok=True)
    url = URL_CICIDS2017_IMPROVED if use_2017_fast else URL_CSECICIDS2018_IMPROVED
    zip_name = "CICIDS2017_improved.zip" if use_2017_fast else "CSECICIDS2018_improved.zip"
    zip_path = os.path.join(target_dir, zip_name)

    extracted_dir = os.path.join(target_dir, zip_name.replace(".zip", ""))

    # If already extracted, return existing CSV files
    if os.path.exists(extracted_dir):
        csv_files = [
            os.path.join(extracted_dir, f)
            for f in os.listdir(extracted_dir)
            if f.lower().endswith(".csv")
        ]
        if csv_files:
            logger.info("Found cached CNS 2022 CSV files in %s", extracted_dir)
            return csv_files

    # Download archive if not already on disk
    if not os.path.exists(zip_path):
        print(f"\n[CNS2022] Downloading {zip_name} from DistriNet ({url})...")
        urllib.request.urlretrieve(url, zip_path, _download_progress)
        print("\n[CNS2022] Download complete.")

    # Extract archive
    print(f"[CNS2022] Extracting {zip_name} to {extracted_dir}...")
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(extracted_dir)
    print("[CNS2022] Extraction complete.")

    csv_files = [
        os.path.join(extracted_dir, f)
        for f in os.listdir(extracted_dir)
        if f.lower().endswith(".csv")
    ]
    return csv_files


def build_cns2022_benchmark_subset(
    csv_paths: List[str],
    output_csv: str = DEFAULT_BENCHMARK_CSV,
    max_samples_per_class: int = 25000,
    random_seed: int = 42,
) -> str:
    """
    Parses one or more CNS 2022 / CSE-CIC-IDS2018 CSV files, maps them to the frozen
    6-feature contract, strips 'Attempted' noise, performs stratified balanced sampling
    across the 4 research classes, and writes a consolidated research benchmark CSV.

    Args:
        csv_paths: List of raw CSV paths to process
        output_csv: Path where the balanced benchmark CSV will be written
        max_samples_per_class: Max samples per class (e.g. 25,000 * 4 = 100,000 samples)
        random_seed: Seed for reproducible sampling

    Returns:
        Path to output_csv
    """
    import csv
    from collections import defaultdict

    os.makedirs(os.path.dirname(os.path.abspath(output_csv)), exist_ok=True)
    rng = np.random.default_rng(random_seed)

    print(f"\n[CNS2022] Building stratified research subset from {len(csv_paths)} CSV files...")
    print(f"[CNS2022] Target: up to {max_samples_per_class} flows per class ({max_samples_per_class * 4} total)")

    collected: Dict[str, List[List[Any]]] = defaultdict(list)
    total_scanned = 0

    for csv_file in csv_paths:
        print(f"  Scanning: {os.path.basename(csv_file)}...")
        try:
            with open(csv_file, newline="", encoding="utf-8-sig", errors="ignore") as f:
                reader = csv.DictReader(f)
                if reader.fieldnames is None:
                    continue

                col_map = resolve_cns_columns(list(reader.fieldnames))
                if col_map.label_column is None:
                    continue

                for row in reader:
                    total_scanned += 1
                    raw_label = row.get(col_map.label_column, "")
                    attempted_val = row.get(col_map.attempted_column, None) if col_map.attempted_column else None

                    label = map_cns_label(raw_label, attempted_val)
                    if label is None:
                        continue

                    # If this class is already full, skip with high probability to preserve diversity
                    if len(collected[label]) >= max_samples_per_class * 2:
                        continue

                    # Extract the 6 features
                    feats = []
                    for fname in FEATURE_NAMES:
                        raw_val = row.get(col_map.resolved.get(fname, ""), "0.0")
                        val = sanitize_float(raw_val)
                        if fname == "flow_duration_sec":
                            # In CICFlowMeter, duration is typically microseconds
                            if val > 1000.0:
                                val = val / 1_000_000.0
                        feats.append(val)

                    # Ensure row has at least some traffic activity
                    if feats[0] == 0.0 and feats[1] == 0.0 and feats[3] == 0.0:
                        continue

                    collected[label].append(feats)
        except Exception as e:
            logger.warning("Error reading %s: %s", csv_file, e)

    print(f"[CNS2022] Scanned {total_scanned} total flows. Extracted candidates:")
    for lbl in SUPPORTED_LABELS:
        print(f"    - {lbl:<12}: {len(collected[lbl])} candidates")

    # Sample equally up to max_samples_per_class
    final_rows: List[Tuple[List[float], str]] = []
    for lbl in SUPPORTED_LABELS:
        items = collected[lbl]
        if not items:
            continue
        if len(items) > max_samples_per_class:
            chosen_indices = rng.choice(len(items), size=max_samples_per_class, replace=False)
            items = [items[i] for i in chosen_indices]
        for vec in items:
            final_rows.append((vec, lbl))

    # Shuffle the final combined rows with fixed seed
    rng.shuffle(final_rows)

    # Write out to clean CSV
    with open(output_csv, "w", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow(FEATURE_NAMES + ["label"])
        for vec, lbl in final_rows:
            writer.writerow(vec + [lbl])

    print(f"[CNS2022] Wrote {len(final_rows)} publication-grade flows to: {output_csv}\n")
    return output_csv


def load_cns2022_benchmark_data(
    dataset_path: Optional[str] = None,
    max_samples: int = 100000,
    test_size: float = 0.20,
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray, List[str], List[str]]:
    """
    High-level entrypoint for model training.
    Loads or automatically downloads CNS 2022 benchmark data,
    performs stratified splitting to guarantee no class collapse,
    and returns (X_train, X_test, y_train, y_test).
    """
    import csv

    csv_to_read = dataset_path or DEFAULT_BENCHMARK_CSV

    # If the file does not exist, build it from the official CNS2022 repository
    if not os.path.exists(csv_to_read):
        print(f"[CNS2022] Dataset file not found at {csv_to_read}.")
        print("[CNS2022] Triggering automated download & extraction of CNS2022 improved dataset...")
        csv_files = download_and_extract_cns2022(use_2017_fast=True)
        csv_to_read = build_cns2022_benchmark_subset(
            csv_files,
            output_csv=csv_to_read,
            max_samples_per_class=max_samples // 4,
            random_seed=random_state,
        )

    vectors: List[List[float]] = []
    labels: List[str] = []

    with open(csv_to_read, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            lbl = row.get("label", "")
            if lbl not in SUPPORTED_LABELS:
                continue
            vec = [sanitize_float(row.get(fn, 0.0)) for fn in FEATURE_NAMES]
            vectors.append(vec)
            labels.append(lbl)

    X = np.array(vectors, dtype=np.float32)
    y = labels

    # Perform Stratified Split so all classes are balanced in both train and test
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        stratify=y,
        random_state=random_state,
    )

    return X_train, X_test, y_train, y_test
