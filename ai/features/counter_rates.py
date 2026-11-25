"""
ai/features/counter_rates.py

Calculates flow statistics rates (packet_rate, byte_rate) from OVS FlowStats
observations over actual elapsed time (Delta t), handling counter resets, switch
restarts, and missing sample intervals.

Complies with PRD Section 5.2 and PDF Section 5 (Worked Example).
"""

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class FlowCounterSample:
    """A single snapshot of switch flow counters with timestamp."""
    timestamp_s: float
    packet_count: int
    byte_count: int


@dataclass(frozen=True)
class FlowRateMetrics:
    """Calculated rates over actual elapsed time."""
    elapsed_time_s: float
    packet_rate: float
    byte_rate: float
    is_valid: bool
    reset_detected: bool = False


def calculate_flow_rates(
    prev: Optional[FlowCounterSample],
    curr: FlowCounterSample,
    min_elapsed_s: float = 0.001
) -> FlowRateMetrics:
    """
    Computes packet_rate and byte_rate between two successive samples.

    Rules:
    - Uses actual elapsed time (curr.timestamp_s - prev.timestamp_s), NEVER a hardcoded interval.
    - If elapsed time <= 0 or < min_elapsed_s, marks sample as invalid to avoid division by zero.
    - If counters decreased (curr < prev), detects switch restart / rule replacement / counter reset,
      returns is_valid=False and reset_detected=True (never produces negative rates).
    """
    if prev is None:
        return FlowRateMetrics(
            elapsed_time_s=0.0,
            packet_rate=0.0,
            byte_rate=0.0,
            is_valid=False,
            reset_detected=False
        )

    dt = curr.timestamp_s - prev.timestamp_s
    if dt < min_elapsed_s:
        return FlowRateMetrics(
            elapsed_time_s=dt,
            packet_rate=0.0,
            byte_rate=0.0,
            is_valid=False,
            reset_detected=False
        )

    delta_packets = curr.packet_count - prev.packet_count
    delta_bytes = curr.byte_count - prev.byte_count

    # Check for counter reset / switch restart
    if delta_packets < 0 or delta_bytes < 0:
        return FlowRateMetrics(
            elapsed_time_s=dt,
            packet_rate=0.0,
            byte_rate=0.0,
            is_valid=False,
            reset_detected=True
        )

    packet_rate = delta_packets / dt
    byte_rate = delta_bytes / dt

    return FlowRateMetrics(
        elapsed_time_s=dt,
        packet_rate=packet_rate,
        byte_rate=byte_rate,
        is_valid=True,
        reset_detected=False
    )

