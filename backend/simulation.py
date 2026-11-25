"""Deterministic polling experiments using synthetic counter observations."""

from dataclasses import dataclass

from ai.features.counter_rates import FlowCounterSample, calculate_flow_rates
from controller.ryu_app.adaptive_poller import AdaptivePoller


@dataclass(frozen=True)
class Segment:
    start_ms: int
    packets_per_second: int
    reply_ms: int = 40
    reset_counters: bool = False


@dataclass(frozen=True)
class Scenario:
    title: str
    description: str
    duration_ms: int
    segments: tuple[Segment, ...]

    def sample(self, at_ms: int) -> tuple[FlowCounterSample, int]:
        # Each strategy reads the same underlying counters on its own schedule.
        total = 0
        reply_ms = self.segments[0].reply_ms
        for index, segment in enumerate(self.segments):
            if at_ms < segment.start_ms:
                break
            if segment.reset_counters:
                total = 0
            end = self.duration_ms
            if index + 1 < len(self.segments):
                end = self.segments[index + 1].start_ms
            total += segment.packets_per_second * (min(at_ms, end) - segment.start_ms)
            reply_ms = segment.reply_ms
        packets = total // 1000
        return FlowCounterSample(at_ms / 1000, packets, packets * 600), reply_ms


SCENARIOS = {
    "workload-burst": Scenario(
        "Workload burst", "Watch adaptive polling speed up during a demand spike and cool down as traffic settles.",
        14_000,
        (Segment(0, 120), Segment(4_000, 2_400), Segment(8_000, 120)),
    ),
    "steady-load": Scenario(
        "Steady load", "Compare both strategies while traffic and switch response times stay stable.",
        14_000, (Segment(0, 120),),
    ),
    "slow-switch": Scenario(
        "Slow switch", "See how slow replies interrupt rapid polling and how the adaptive strategy recovers.",
        16_000,
        (Segment(0, 1_800), Segment(3_000, 1_800, 1_400), Segment(8_000, 1_800), Segment(11_000, 120)),
    ),
    "counter-restart": Scenario(
        "Counter restart", "See how a counter reset discards one rate measurement before a new baseline forms.",
        14_000, (Segment(0, 180), Segment(5_000, 90, reset_counters=True)),
    ),
}


def describe_scenario(key: str, scenario: Scenario):
    return {
        "id": key,
        "title": scenario.title,
        "description": scenario.description,
        "duration_s": scenario.duration_ms / 1000,
    }


def _replay(scenario: Scenario, adaptive: bool):
    poller = AdaptivePoller()
    interval = poller.base_interval_s
    previous = None
    steps = []
    at_ms = 0
    while at_ms < scenario.duration_ms:
        sample, reply_ms = scenario.sample(at_ms)
        reply_at_ms = at_ms + reply_ms
        if reply_at_ms > scenario.duration_ms:
            break
        rates = calculate_flow_rates(previous, sample)
        mode = "fixed"
        if adaptive:
            interval = poller.evaluate_cycle(rates.packet_rate, False, reply_ms / 1000)
            state = poller.get_state()
            if state.backpressure_active:
                mode = "backpressure"
            elif state.consecutive_calm_cycles:
                mode = "cooldown"
            else:
                mode = "surge" if state.is_surge_mode else "baseline"
        steps.append({
            "sample_at_s": sample.timestamp_s,
            "reply_at_s": reply_at_ms / 1000,
            "rtt_ms": reply_ms,
            "packet_rate": round(rates.packet_rate, 2) if rates.is_valid else None,
            "reset_detected": rates.reset_detected,
            "next_interval_s": interval,
            "mode": mode,
        })
        previous = sample
        at_ms = reply_at_ms + round(interval * 1000)

    return {
        "completed_polls": len(steps),
        "valid_rate_samples": sum(step["packet_rate"] is not None for step in steps),
        "backpressure_cycles": sum(step["mode"] == "backpressure" for step in steps),
        "steps": steps,
    }


def run_scenario(key: str):
    scenario = SCENARIOS[key]
    return {
        **describe_scenario(key, scenario),
        "source": "synthetic",
        "fixed": _replay(scenario, adaptive=False),
        "adaptive": _replay(scenario, adaptive=True),
    }
