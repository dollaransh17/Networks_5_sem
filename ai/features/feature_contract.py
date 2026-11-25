"""
ai/features/feature_contract.py

Phase 4: Behavioral Feature Contract & Extractor
References: PRD (Section 5, Phase 4.1), PDF Section 5 & 6, AGENTS.md, ARCHITECTURE.md

Rules & Constraints:
1. Decision-Time Validity: ONLY uses measurements available during an active flow sample.
   Does NOT use future measurements (e.g. total completed flow duration or bidirectional
   fin/rst flag counts that only appear when a connection closes).
2. Explicit Feature Contract:
   - packet_rate (pkts/sec over actual elapsed Delta t)
   - byte_rate (bytes/sec over actual elapsed Delta t)
   - avg_packet_size (bytes/packet = delta_bytes / delta_packets)
   - packet_count (cumulative switch observation)
   - byte_count (cumulative switch observation)
   - flow_duration_sec (switch duration_sec + duration_nsec * 1e-9)
3. Deterministic Order & Missing Value Handling:
   - Strict feature vector order defined in FEATURE_NAMES.
   - Missing or zero-delta intervals handled cleanly without division by zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import numpy as np

from ai.features.counter_rates import FlowCounterSample, calculate_flow_rates, FlowRateMetrics

# Frozen feature contract list (strictly ordered)
FEATURE_NAMES: List[str] = [
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "packet_count",
    "byte_count",
    "flow_duration_sec",
]


@dataclass(frozen=True)
class FlowFeatureVector:
    """Represents a frozen extracted feature vector for AI model inference."""
    features: Dict[str, float]
    is_valid: bool
    reset_detected: bool = False

    def to_array(self) -> np.ndarray:
        """Returns 1D numpy array in the strict feature contract order."""
        import numpy as np

        return np.array([self.features.get(f, 0.0) for f in FEATURE_NAMES], dtype=np.float32)

    def to_dict(self) -> Dict[str, float]:
        return dict(self.features)


class FeatureExtractor:
    """
    Extracts tabular features from sequential OVS flow samples.
    """

    def extract(
        self,
        prev: Optional[FlowCounterSample],
        curr: FlowCounterSample,
        flow_duration_sec: float = 0.0,
    ) -> FlowFeatureVector:
        """
        Extracts features between two consecutive observations.
        """
        # If no previous sample exists, provide default baseline
        if prev is None:
            avg_size = (curr.byte_count / curr.packet_count) if curr.packet_count > 0 else 0.0
            feat_dict = {
                "packet_rate": 0.0,
                "byte_rate": 0.0,
                "avg_packet_size": float(avg_size),
                "packet_count": float(curr.packet_count),
                "byte_count": float(curr.byte_count),
                "flow_duration_sec": float(flow_duration_sec),
            }
            return FlowFeatureVector(features=feat_dict, is_valid=False, reset_detected=False)

        # Calculate differential rates over actual elapsed time (Delta t)
        rates: FlowRateMetrics = calculate_flow_rates(prev, curr)

        if rates.reset_detected or not rates.is_valid:
            feat_dict = {f: 0.0 for f in FEATURE_NAMES}
            feat_dict["packet_count"] = float(curr.packet_count)
            feat_dict["byte_count"] = float(curr.byte_count)
            feat_dict["flow_duration_sec"] = float(flow_duration_sec)
            return FlowFeatureVector(
                features=feat_dict,
                is_valid=False,
                reset_detected=rates.reset_detected
            )

        delta_packets = curr.packet_count - prev.packet_count
        delta_bytes = curr.byte_count - prev.byte_count

        avg_packet_size = (delta_bytes / delta_packets) if delta_packets > 0 else 0.0

        feat_dict = {
            "packet_rate": float(rates.packet_rate),
            "byte_rate": float(rates.byte_rate),
            "avg_packet_size": float(avg_packet_size),
            "packet_count": float(curr.packet_count),
            "byte_count": float(curr.byte_count),
            "flow_duration_sec": float(flow_duration_sec),
        }

        return FlowFeatureVector(
            features=feat_dict,
            is_valid=True,
            reset_detected=False
        )

