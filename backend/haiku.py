"""Ask one Claude Haiku instance for three illustrative flow assessments."""

import json
from http.client import HTTPSConnection, HTTPException
from threading import Lock

from backend.models import MODELS


class HaikuRequestError(RuntimeError):
    """An upstream failure suitable for a credential-free console response."""


class InvalidAssessment(HaikuRequestError):
    """The provider returned an incomplete or malformed assessment."""


class HaikuModels:
    def __init__(self, model, key):
        if not key or not key.isascii() or any(not 33 <= ord(char) <= 126 for char in key):
            raise ValueError("Set a valid ANTHROPIC_API_KEY before enabling Haiku mode.")
        if model not in {"claude-haiku-4-5", "claude-haiku-4-5-20251001"}:
            raise ValueError("ANTHROPIC_MODEL must identify Claude Haiku 4.5.")
        self.model = model
        self.key = key
        self.lock = Lock()
        self.status = {
            name: {"name": f"{label} · Haiku simulation", "ready": True, "version": model, "provider": "haiku"}
            for name, (label, *_) in MODELS.items()
        }

    def check(self, features):
        try:
            return self._check(features)
        except InvalidAssessment:
            return self._check(features)

    def _check(self, features):
        measurements = features.features
        # Match the steady preset, service rate, and queue limit in the 3D room.
        baseline_rate = 5
        gateway_rate = 10
        queue_limit = 80
        rate = measurements["packet_rate"]
        count = measurements["packet_count"]
        labels = {
            "xgboost": "above_capacity" if rate > gateway_rate else "within_capacity",
            "bilstm": "queue_overflow_risk" if count > queue_limit else "fits_empty_queue",
            "isolation_forest": "above_baseline" if rate > baseline_rate else (
                "below_baseline" if rate < baseline_rate else "matches_baseline"
            ),
        }
        facts = {
            "xgboost": f"Offered rate: {rate:g} packets/s. Gateway capacity: {gateway_rate} packets/s.",
            "bilstm": (
                f"With background traffic off, {min(count, queue_limit):g} of {count:g} packets "
                f"fit in the initially empty {queue_limit}-packet queue."
            ),
            "isolation_forest": f"Offered rate: {rate:g} packets/s. Steady preset: {baseline_rate} packets/s.",
        }
        context = {
            "measurements": measurements,
            "steady_simulation_preset_packets_per_second": baseline_rate,
            "gateway_capacity_packets_per_second": gateway_rate,
            "empty_gateway_queue_limit_packets": queue_limit,
            "packets_queued_immediately_if_empty": min(count, queue_limit),
            "seconds_to_drain_admitted_burst_at_capacity": min(count, queue_limit) / gateway_rate,
            "demo_labels": labels,
        }
        prompt = (
            "Score and explain a burst from three perspectives in a 3D traffic demo. The keys "
            "name illustrative perspectives only. Submit one report_demo_scores tool call with xgboost, "
            "bilstm, and isolation_forest. For each key return an object with an integer score "
            "from 0 to 100 and a one-sentence qualitative rationale. The UI shows exact measurements separately. Do not include any digits, numbers, counts, or computations in the rationale. "
            "For xgboost, compare the selected window's average offered packet rate with "
            "the gateway capacity. For bilstm, describe queuing over time for a single burst "
            "with an initially empty queue and background traffic off. All admitted packets arrive "
            "at once. The selected measurement window does not pace the 3D animation. Use only "
            "the supplied initial occupancy, queue limit, and drain "
            "time, which excludes travel to the destination. For isolation_forest, compare the "
            "average rate against the simulator's steady preset. Explain each supplied label. "
            "Score gateway pressure for xgboost, empty-queue occupancy and overflow pressure "
            "for bilstm, and the size of the departure from the steady rate for isolation_forest. "
            "Use 0 for no pressure or deviation, around 50 for moderate pressure or deviation, "
            "and 100 for extreme pressure or deviation. These are illustrative severity "
            "estimates, never probabilities. Use packets/s for rates and compare the provided values directly. Avoid percentages and multipliers in the explanations. Do not claim these are "
            "trained-model predictions, infer an attack type, or claim an observed drop count. "
            + json.dumps(context)
        )
        assessment_schema = {
            "type": "object",
            "properties": {"score": {"type": "integer", "minimum": 0, "maximum": 100},
                           "rationale": {"type": "string"}},
            "required": ["score", "rationale"],
        }
        body = {
            "model": self.model,
            "max_tokens": 800,
            "messages": [{"role": "user", "content": prompt}],
            "tools": [{
                "name": "report_demo_scores",
                "description": "Report the three demo scores and their explanations.",
                "input_schema": {
                    "type": "object",
                    "properties": {name: assessment_schema for name in MODELS},
                    "required": list(MODELS),
                },
            }],
            "tool_choice": {"type": "tool", "name": "report_demo_scores"},
        }
        connection = HTTPSConnection("api.anthropic.com", timeout=20)
        try:
            connection.request("POST", "/v1/messages", body=json.dumps(body).encode(), headers={
                "content-type": "application/json",
                "anthropic-version": "2023-06-01",
                "x-api-key": self.key,
            })
            reply = connection.getresponse()
            if reply.status != 200:
                raise HaikuRequestError(f"Claude Haiku returned HTTP {reply.status}.")
            message = json.load(reply)
            reports = [
                block["input"] for block in message["content"]
                if block.get("type") == "tool_use" and block.get("name") == "report_demo_scores"
            ]
            if len(reports) != 1:
                raise ValueError("Expected one scoring report")
            assessments = reports[0]
            if not isinstance(assessments, dict) or set(assessments) != set(MODELS):
                raise ValueError("Unexpected assessment names")
            results = {}
            for name, assessment in assessments.items():
                score = assessment["score"]
                rationale = assessment["rationale"]
                if (type(score) not in (int, float) or not 0 <= score <= 100
                        or int(score) != score):
                    raise ValueError("Invalid demo score")
                if not isinstance(rationale, str) or not rationale.strip():
                    raise ValueError("Missing assessment rationale")
                rationale = rationale.strip()
                explanation = facts[name]
                if not any(char.isdigit() for char in rationale):
                    explanation += " " + rationale[:250]
                results[name] = {
                    "label": labels[name], "demo_score": int(score),
                    "rationale": explanation, "version": self.model,
                }
            return results
        except (OSError, HTTPException):
            raise HaikuRequestError("Could not reach Claude Haiku.") from None
        except (ValueError, KeyError, TypeError):
            raise InvalidAssessment("The scoring service returned an incomplete assessment. Try checking the same burst again.") from None
        finally:
            connection.close()
