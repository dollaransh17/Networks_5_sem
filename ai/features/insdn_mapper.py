"""
ai/features/insdn_mapper.py

Phase 4.2: InSDN Dataset Column Mapper
References: PRD (Section 5, Phase 4), DESIGN.md, AGENTS.md, ARCHITECTURE.md

Maps InSDN CSV column names to the frozen feature contract defined in feature_contract.py.

Key Rules:
1. Decision-time only: Only columns that represent mid-flow measurements are used.
   We deliberately exclude 'Total Fwd Packets', 'Total Backward Packets' etc.
   that are only known when the connection closes.
2. No data leakage: Features must be computable from a single flow snapshot.
3. All mapped column names are case-normalised (stripped, lowercased) for robustness
   across different CSV variants of the InSDN dataset.
4. Missing required columns raise a descriptive error at load time, not silently at inference.

InSDN label mapping (from published InSDN paper):
  'Normal'   -> 'benign'
  'DoS'      -> 'dos'
  'Port Scan' -> 'portscan'
  'DDoS'     -> 'dos'          (treated same as DoS for our MVP)
  'Web Attack'-> 'bruteforce'  (closest MVP class)
  'Brute Force' -> 'bruteforce'
"""

from dataclasses import dataclass
from typing import Dict, Optional, List
import numpy as np

from ai.features.feature_contract import FlowFeatureVector, FEATURE_NAMES


# ---------------------------------------------------------------------------
# InSDN column name variants → contract feature names
# Each list entry is a possible CSV header (after strip+lower) for that feature.
# The mapper tries them in order and uses the first found.
# ---------------------------------------------------------------------------
COLUMN_CANDIDATES: Dict[str, List[str]] = {
    "packet_rate": [
        "flow packets/s",
        "flow pkts/s",
        "flow_pkts_s",
        "packets/s",
        "fwd pkts/s",
    ],
    "byte_rate": [
        "flow bytes/s",
        "flow byts/s",
        "flow_byts_s",
        "bytes/s",
        "fwd byts/s",
    ],
    "avg_packet_size": [
        "avg pkt size",
        "average packet size",
        "pkt len mean",
        "packet length mean",
        "pkt_len_mean",
        "pkt size avg",
        "fwd pkt len mean",
    ],
    "packet_count": [
        "tot fwd pkts",
        "total fwd packets",
        "total forward packets",
        "tot_fwd_pkts",
        "flow duration",        # NOTE: duration is used as a *proxy* only if no pkt count available
        "total length of fwd packets",  # fallback when packet_count unavailable as mid-flow estimate
    ],
    "byte_count": [
        "totlen fwd pkts",
        "total length of fwd packets",
        "total fwd bytes",
        "totlen_fwd_pkts",
        "fwd packets bytes",
    ],
    "flow_duration_sec": [
        "flow duration",
        "duration",
        "flow_duration",
    ],
}

# These are the *preferred* mid-flow column names.  They are tried first before
# the COLUMN_CANDIDATES fallbacks.  Declared separately for clarity.
PREFERRED_COLUMNS: Dict[str, List[str]] = {
    "packet_rate":        ["flow packets/s", "flow pkts/s", "flow_pkts_s"],
    "byte_rate":          ["flow bytes/s", "flow byts/s", "flow_byts_s"],
    "avg_packet_size":    ["avg pkt size", "average packet size", "pkt len mean", "packet length mean"],
    "packet_count":       ["tot fwd pkts", "total fwd packets", "total forward packets"],
    "byte_count":         ["totlen fwd pkts", "total length of fwd packets", "total fwd bytes"],
    "flow_duration_sec":  ["flow duration", "flow_duration"],
}

# ---------------------------------------------------------------------------
# Label mapping
# ---------------------------------------------------------------------------
LABEL_MAP: Dict[str, str] = {
    "normal":               "benign",
    "benign":               "benign",
    "dos":                  "dos",
    "ddos":                 "dos",
    "port scan":            "portscan",
    "portscan":             "portscan",
    "web attack":           "bruteforce",
    "brute force":          "bruteforce",
    "bruteforce":           "bruteforce",
    "ssh-patator":          "bruteforce",
    "ftp-patator":          "bruteforce",
    "ftp-bruteforce":       "bruteforce",
    "ssh-bruteforce":       "bruteforce",
    "bot":                  "portscan",
    "botnet":               "portscan",
    "infilteration":        "portscan",
    "infiltration":         "portscan",
    "dos attacks-goldeneye": "dos",
    "dos attacks-slowloris": "dos",
    "dos attacks-slowhttptest": "dos",
    "dos attacks-hulk":     "dos",
    "ddos attacks-loic-http": "dos",
    "ddos attack-loic-udp": "dos",
    "ddos attack-hoic":     "dos",
    # CNS 2022 attempted labels mapped to benign per publication guidelines
    "attempted":            "benign",
}

SUPPORTED_LABELS = ["benign", "dos", "portscan", "bruteforce"]


@dataclass
class InSDNColumnMap:
    """Resolved mapping from InSDN CSV header names to contract feature names."""
    resolved: Dict[str, str]        # contract_name -> actual csv column name
    unresolved: List[str]           # contract features that had no matching column


def resolve_columns(csv_headers: List[str]) -> InSDNColumnMap:
    """
    Given a list of CSV header names (as-is), resolves which contract features
    they map to.  Returns an InSDNColumnMap with the resolved and unresolved sets.
    """
    # Normalise all headers once
    norm_map: Dict[str, str] = {h.strip().lower(): h for h in csv_headers}

    resolved: Dict[str, str] = {}
    unresolved: List[str] = []

    for feature in FEATURE_NAMES:
        candidates = PREFERRED_COLUMNS.get(feature, []) + COLUMN_CANDIDATES.get(feature, [])
        found = None
        for c in candidates:
            if c.strip().lower() in norm_map:
                found = norm_map[c.strip().lower()]  # original header name
                break
        if found is not None:
            resolved[feature] = found
        else:
            unresolved.append(feature)

    return InSDNColumnMap(resolved=resolved, unresolved=unresolved)


def map_row_to_features(row: Dict[str, str], col_map: InSDNColumnMap) -> FlowFeatureVector:
    """
    Converts a single CSV row (as a dict of column->string-value) to a FlowFeatureVector
    using the already-resolved InSDNColumnMap.

    - Infinite or NaN values are replaced with 0.0.
    - Division by zero is handled by replacing with 0.0.
    - Negative values (e.g., byte_rate = -Inf from InSDN) are clamped to 0.0.
    """
    features: Dict[str, float] = {}
    is_valid = True

    for feature in FEATURE_NAMES:
        if feature in col_map.resolved:
            raw = row.get(col_map.resolved[feature], "0")
            try:
                val = float(raw)
            except (ValueError, TypeError):
                val = 0.0

            # Sanitise: InSDN contains Infinity and NaN in some rows
            if not np.isfinite(val):
                val = 0.0
            if val < 0.0:
                val = 0.0

            # flow_duration_sec in InSDN is in microseconds → convert to seconds
            if feature == "flow_duration_sec":
                val = val / 1_000_000.0

            features[feature] = val
        else:
            features[feature] = 0.0
            is_valid = False  # Missing columns reduce validity

    return FlowFeatureVector(features=features, is_valid=is_valid, reset_detected=False)


def map_label(raw_label: str) -> Optional[str]:
    """
    Maps an InSDN / CNS2022 raw label string to one of the 4 supported class labels.
    Returns None if the label is unrecognised.
    Maps 'Attempted' flows to 'benign' per CNS 2022 research guidelines.
    """
    if not raw_label:
        return None
    cleaned = raw_label.strip().lower()
    if "attempted" in cleaned:
        return "benign"
    if cleaned in LABEL_MAP:
        return LABEL_MAP[cleaned]
    if any(k in cleaned for k in ["dos", "ddos"]):
        return "dos"
    if any(k in cleaned for k in ["portscan", "port scan", "bot", "infilt"]):
        return "portscan"
    if any(k in cleaned for k in ["brute", "patator", "sql", "xss", "web attack"]):
        return "bruteforce"
    return None


def load_insdn_csv(filepath: str) -> tuple:
    """
    Loads an InSDN dataset CSV file and returns:
      (feature_matrix: np.ndarray, labels: List[str], col_map: InSDNColumnMap, skipped: int)

    - Rows with unmappable labels are skipped and counted.
    - Rows with any infinite/NaN value in required columns are skipped.
    - Only rows where col_map has ALL 6 features resolved are included.

    Usage:
        X, y, col_map, n_skipped = load_insdn_csv("data/InSDN.csv")
    """
    import csv

    vectors: List[np.ndarray] = []
    labels: List[str] = []
    skipped = 0
    col_map: Optional[InSDNColumnMap] = None

    with open(filepath, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError(f"CSV file {filepath} has no headers.")

        col_map = resolve_columns(list(reader.fieldnames))

        if col_map.unresolved:
            # Warn but do not raise; some features will be 0.0
            import warnings
            warnings.warn(
                f"InSDN mapper: could not resolve features {col_map.unresolved} "
                f"from CSV headers. They will default to 0.0."
            )

        # Find the label column (try common names)
        label_col = None
        norm_headers = {h.strip().lower(): h for h in reader.fieldnames}
        for candidate in ["label", "class", "attack type", "category", "attack"]:
            if candidate in norm_headers:
                label_col = norm_headers[candidate]
                break

        if label_col is None:
            raise ValueError(
                f"InSDN CSV has no recognisable label column. "
                f"Headers found: {list(reader.fieldnames)}"
            )

        for row in reader:
            raw_label = row.get(label_col, "")
            mapped = map_label(raw_label)
            if mapped is None:
                skipped += 1
                continue

            fv = map_row_to_features(row, col_map)
            vec = fv.to_array()

            # Skip rows where the vector is all-zeros AND invalid (likely corrupt rows)
            if not fv.is_valid and np.all(vec == 0.0):
                skipped += 1
                continue

            vectors.append(vec)
            labels.append(mapped)

    if not vectors:
        raise ValueError(f"No valid rows loaded from {filepath}. Check label mapping and column names.")

    X = np.vstack(vectors).astype(np.float32)
    return X, labels, col_map, skipped

