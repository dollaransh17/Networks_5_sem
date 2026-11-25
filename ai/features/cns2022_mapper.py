"""
ai/features/cns2022_mapper.py

Phase 4.2: CNS 2022 / CSE-CIC-IDS2018 / CIC-IDS-2017 Dataset Feature & Label Mapper
References:
  - IEEE CNS 2022: "Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018"
    Authors: Lisa Liu, Gints Engelen, Timothy Lynar, Daryl Essam, Wouter Joosen (DistriNet, KU Leuven)
  - PRD (Section 5, Phase 4), ARCHITECTURE.md, AGENTS.md, DATABASE.md

Crucial Guidelines from DistriNet CNS 2022:
  1. "Attempted" Labels: Flows intended to be part of an attack that do not exhibit malicious
     behavior are labeled with an "- Attempted" modifier or Attempted Category != -1.
     The authors explicitly state: Under NO circumstances should "Attempted" flows be treated
     as a separate standalone attack class. In this mapper, attempted flows are cleanly mapped
     to 'benign' to prevent artificial label noise and classification collapse.
  2. Decision-Time Validity: Uses ONLY mid-flow features available during active flow polling.
     Contract features:
       - packet_rate (pkts/sec)
       - byte_rate (bytes/sec)
       - avg_packet_size (bytes/packet)
       - packet_count (total observed packets)
       - byte_count (total observed bytes)
       - flow_duration_sec (duration in seconds)
  3. Sanitization: Replaces 'Infinity', 'inf', 'NaN', and negative rate values with valid numbers.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any
import numpy as np

from ai.features.feature_contract import FlowFeatureVector, FEATURE_NAMES

# ---------------------------------------------------------------------------
# Column variants across CICFlowMeter, CNS 2022, CSE-CIC-IDS2018, CIC-IDS-2017
# ---------------------------------------------------------------------------
COLUMN_CANDIDATES_CNS: Dict[str, List[str]] = {
    "packet_rate": [
        "flow pkts/s",
        "flow packets/s",
        "flow_pkts_s",
        "flow_packets_s",
        "packets/s",
        "fwd pkts/s",
    ],
    "byte_rate": [
        "flow byts/s",
        "flow bytes/s",
        "flow_byts_s",
        "flow_bytes_s",
        "bytes/s",
        "fwd byts/s",
    ],
    "avg_packet_size": [
        "pkt len mean",
        "packet length mean",
        "pkt_len_mean",
        "average packet size",
        "avg pkt size",
        "avg packet size",
        "pkt size avg",
        "fwd pkt len mean",
    ],
    "packet_count": [
        "tot fwd pkts",
        "total fwd packets",
        "total forward packets",
        "tot_fwd_pkts",
        "total fwd pkts",
        "subflow fwd pkts",
        "total packets",
    ],
    "byte_count": [
        "totlen fwd pkts",
        "total length of fwd packets",
        "total fwd bytes",
        "totlen_fwd_pkts",
        "subflow fwd bytes",
        "fwd packets bytes",
    ],
    "flow_duration_sec": [
        "flow duration",
        "flow_duration",
        "duration",
    ],
}

# ---------------------------------------------------------------------------
# CNS 2022 & CSE-CIC-IDS2018 Multi-class Attack Categorization
# Target 4 classes: 'benign', 'dos', 'portscan', 'bruteforce'
# ---------------------------------------------------------------------------
LABEL_MAP_CNS: Dict[str, str] = {
    # Benign variants
    "benign": "benign",
    "normal": "benign",
    
    # CNS 2022 Attempted flows (must be mapped to benign per publication guidelines)
    "attempted": "benign",
    "dos goldeneye - attempted": "benign",
    "dos slowloris - attempted": "benign",
    "dos slowhttptest - attempted": "benign",
    "dos hulk - attempted": "benign",
    "ddos loic-udp - attempted": "benign",
    "ddos hoic - attempted": "benign",
    "ddos attacks-loic-http - attempted": "benign",
    "ftp-patator - attempted": "benign",
    "ssh-patator - attempted": "benign",
    "ftp-bruteforce - attempted": "benign",
    "ssh-bruteforce - attempted": "benign",

    # DoS / DDoS attacks
    "dos": "dos",
    "ddos": "dos",
    "dos attacks-goldeneye": "dos",
    "dos attacks-slowloris": "dos",
    "dos attacks-slowhttptest": "dos",
    "dos attacks-hulk": "dos",
    "dos goldeneye": "dos",
    "dos slowloris": "dos",
    "dos slowhttptest": "dos",
    "dos hulk": "dos",
    "ddos attack-loic-udp": "dos",
    "ddos attack-hoic": "dos",
    "ddos attacks-loic-http": "dos",
    "ddos loic-http": "dos",
    "ddos loic-udp": "dos",
    "ddos hoic": "dos",
    "heartbleed": "dos",

    # Portscan / Recon / Botnet / Infiltration
    "portscan": "portscan",
    "port scan": "portscan",
    "infilteration": "portscan",
    "infiltration": "portscan",
    "bot": "portscan",
    "botnet": "portscan",
    "botnet ares": "portscan",

    # Brute Force / Web Attacks / Privilege Escalation
    "bruteforce": "bruteforce",
    "brute force": "bruteforce",
    "ftp-patator": "bruteforce",
    "ssh-patator": "bruteforce",
    "ftp-bruteforce": "bruteforce",
    "ssh-bruteforce": "bruteforce",
    "web attack": "bruteforce",
    "web attack - brute force": "bruteforce",
    "web attack - xss": "bruteforce",
    "web attack - sql injection": "bruteforce",
    "brute force -web": "bruteforce",
    "brute force -xss": "bruteforce",
    "sql injection": "bruteforce",
}

SUPPORTED_LABELS = ["benign", "dos", "portscan", "bruteforce"]


@dataclass
class CNSColumnMap:
    """Resolved column headers for CNS2022 / CSE-CIC-IDS2018 datasets."""
    resolved: Dict[str, str]        # contract_name -> raw csv column header
    unresolved: List[str]           # features that could not be matched
    label_column: Optional[str] = None
    attempted_column: Optional[str] = None


def resolve_cns_columns(csv_headers: List[str]) -> CNSColumnMap:
    """
    Scans CSV headers and maps them to the frozen 6-feature contract
    and identifies the ground-truth label and attempted-category columns.
    """
    norm_map: Dict[str, str] = {h.strip().lower(): h for h in csv_headers}

    resolved: Dict[str, str] = {}
    unresolved: List[str] = []

    for feature in FEATURE_NAMES:
        candidates = COLUMN_CANDIDATES_CNS.get(feature, [])
        found = None
        for cand in candidates:
            cand_norm = cand.strip().lower()
            if cand_norm in norm_map:
                found = norm_map[cand_norm]
                break
        if found is not None:
            resolved[feature] = found
        else:
            unresolved.append(feature)

    # Detect label column
    label_col = None
    for cand in ["label", "class", "attack", "attack type", "category"]:
        if cand in norm_map:
            label_col = norm_map[cand]
            break

    # Detect CNS2022 attempted category column if present
    attempted_col = None
    for cand in ["attempted category", "attempted_category", "attempted", "is_attempted"]:
        if cand in norm_map:
            attempted_col = norm_map[cand]
            break

    return CNSColumnMap(
        resolved=resolved,
        unresolved=unresolved,
        label_column=label_col,
        attempted_column=attempted_col,
    )


def map_cns_label(raw_label: str, attempted_val: Optional[Any] = None) -> Optional[str]:
    """
    Maps a raw CNS2022 / CSE-CIC-IDS2018 label string to one of the 4 benchmark classes:
    'benign', 'dos', 'portscan', 'bruteforce'.

    If 'attempted_val' indicates an attempted attack flow (e.g. Attempted Category != -1
    or label contains 'attempted'), maps to 'benign' per DistriNet CNS 2022 guidelines.
    """
    if raw_label is None:
        return None

    cleaned = str(raw_label).strip().lower()

    # If explicit attempted flag is provided (CNS2022 format: -1 means not attempted, >= 0 means attempted)
    if attempted_val is not None:
        try:
            att_int = int(attempted_val)
            if att_int != -1:
                return "benign"
        except (ValueError, TypeError):
            pass

    # Check for "attempted" suffix or substring
    if "attempted" in cleaned:
        return "benign"

    # Direct dictionary lookup
    if cleaned in LABEL_MAP_CNS:
        return LABEL_MAP_CNS[cleaned]

    # Partial substring matching for variations
    if any(k in cleaned for k in ["dos", "ddos", "goldeneye", "slowloris", "slowhttp", "hulk", "loic", "hoic"]):
        return "dos"
    if any(k in cleaned for k in ["portscan", "port scan", "infilt", "bot"]):
        return "portscan"
    if any(k in cleaned for k in ["brute", "patator", "sql", "xss", "web attack"]):
        return "bruteforce"
    if "benign" in cleaned or "normal" in cleaned:
        return "benign"

    return None


def sanitize_float(val: Any, default: float = 0.0) -> float:
    """Safely converts input to a finite, non-negative float."""
    try:
        f = float(val)
        if not np.isfinite(f) or f < 0.0:
            return default
        return f
    except (ValueError, TypeError):
        return default
