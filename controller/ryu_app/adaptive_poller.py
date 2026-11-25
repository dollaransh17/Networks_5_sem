"""
controller/ryu_app/adaptive_poller.py

Phase 6.3: Adaptive Telemetry Polling Controller
References: PRD (Section 5, Phase 6.3), PLAN.md, AGENTS.md

Key Rules (AGENTS.md & PRD):
1. Normal Baseline Polling: 2.0 seconds between FlowStatsRequest probes.
2. Surge / Attack Polling: 0.5 seconds (500 ms) when anomaly or high packet rate (> 1,000 pkt/s) is detected.
3. Cooldown: Returns gracefully to 2.0 seconds after 3 consecutive calm sample cycles.
4. Backpressure Protection: If datapath reply latency exceeds 300 ms, clamps poll rate
   and logs backpressure event to prevent controller queue overload.
5. Lost coverage logging: Explicitly records lost samples if interval was throttled.
"""

import time
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class PollingState:
    current_interval_s: float
    is_surge_mode: bool
    consecutive_calm_cycles: int
    backpressure_active: bool
    last_rtt_s: float
    total_samples: int
    throttled_samples: int


class AdaptivePoller:
    """
    Dynamically modulates OpenFlow FlowStatsRequest polling frequency.
    """

    def __init__(
        self,
        base_interval_s: float = 2.0,
        surge_interval_s: float = 0.5,
        rate_surge_threshold_pkts_s: float = 1000.0,
        rtt_backpressure_threshold_s: float = 0.300,
        calm_cycles_needed: int = 3,
    ):
        self.base_interval_s = base_interval_s
        self.surge_interval_s = surge_interval_s
        self.rate_surge_threshold_pkts_s = rate_surge_threshold_pkts_s
        self.rtt_backpressure_threshold_s = rtt_backpressure_threshold_s
        self.calm_cycles_needed = calm_cycles_needed

        self._current_interval = base_interval_s
        self._is_surge_mode = False
        self._consecutive_calm = 0
        self._backpressure_active = False
        self._total_samples = 0
        self._throttled_samples = 0

    def evaluate_cycle(
        self,
        observed_packet_rate: float,
        is_ai_anomaly: bool,
        last_request_rtt_s: float,
    ) -> float:
        """
        Evaluates current flow rates and switch RTT to determine the next polling sleep interval.

        Args:
            observed_packet_rate: Current flow packet rate (pkts/sec) over actual elapsed time.
            is_ai_anomaly: True if Isolation Forest or XGBoost flagged an anomaly.
            last_request_rtt_s: Measured round-trip time between FlowStatsRequest and FlowStatsReply.

        Returns:
            next_sleep_interval_s: Float seconds to sleep until next poll.
        """
        self._total_samples += 1

        # Check for backpressure: switch is struggling to reply in time
        if last_request_rtt_s > self.rtt_backpressure_threshold_s:
            self._backpressure_active = True
            self._throttled_samples += 1
            # Back off to protect switch and controller event loop
            self._current_interval = max(self.base_interval_s, last_request_rtt_s * 2.0)
            return self._current_interval

        self._backpressure_active = False

        # Check if threat or traffic surge is present
        threat_detected = (observed_packet_rate >= self.rate_surge_threshold_pkts_s) or is_ai_anomaly

        if threat_detected:
            # Enter surge mode immediately
            self._is_surge_mode = True
            self._consecutive_calm = 0
            self._current_interval = self.surge_interval_s
        else:
            if self._is_surge_mode:
                self._consecutive_calm += 1
                if self._consecutive_calm >= self.calm_cycles_needed:
                    # Return to base interval
                    self._is_surge_mode = False
                    self._consecutive_calm = 0
            # Recompute after backpressure so its interval cannot persist on a healthy reply.
            self._current_interval = self.surge_interval_s if self._is_surge_mode else self.base_interval_s

        return self._current_interval

    def get_state(self, last_rtt_s: float = 0.0) -> PollingState:
        return PollingState(
            current_interval_s=self._current_interval,
            is_surge_mode=self._is_surge_mode,
            consecutive_calm_cycles=self._consecutive_calm,
            backpressure_active=self._backpressure_active,
            last_rtt_s=last_rtt_s,
            total_samples=self._total_samples,
            throttled_samples=self._throttled_samples,
        )

