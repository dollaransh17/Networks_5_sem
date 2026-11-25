"""
controller/ryu_app/enforcement_types.py

Data structures and validation for OpenFlow enforcement requests and rule lifecycle.
Enforces the mandatory rule properties:
- Unique rule cookie
- Scoped match (rejects broad single src_ip rules)
- Priority
- Hard timeout (expiry)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List


class ActionState(str, Enum):
    DECISION_CREATED = "decision_created"
    ACTION_REQUESTED = "action_requested"
    CONTROLLER_ACCEPTED = "controller_accepted"
    RULE_PROCESSED = "rule_processed"
    EFFECT_OBSERVED = "effect_observed"
    EXPIRED = "expired"
    REVERTED = "reverted"
    FAILED = "failed"
    REJECTED = "rejected"


@dataclass
class EnforcementMatch:
    """
    Scoped match specification.
    Rule: Never block on src_ip alone (AGENTS.md).
    Must specify target_ip or port/protocol alongside subject.
    """
    ipv4_src: str
    ipv4_dst: Optional[str] = None
    ip_proto: Optional[int] = None
    tcp_src: Optional[int] = None
    tcp_dst: Optional[int] = None
    udp_src: Optional[int] = None
    udp_dst: Optional[int] = None
    ingress_port: Optional[int] = None

    def validate_scope(self) -> bool:
        """
        Validates that match is sufficiently scoped.
        Rejects rules that specify ONLY ipv4_src without any destination,
        port, or ingress attachment.
        """
        has_specifics = any([
            self.ipv4_dst is not None,
            self.ip_proto is not None,
            self.tcp_dst is not None,
            self.udp_dst is not None,
            self.ingress_port is not None
        ])
        return has_specifics


@dataclass
class EnforcementActionRequest:
    incident_id: str
    action_id: str
    switch_id: str
    match: EnforcementMatch
    action_type: str = "temporary_drop"   # temporary_drop, rate_limit, quarantine
    priority: int = 200
    ttl_s: int = 60                       # Default hard timeout
    rule_cookie: int = 1
    policy_version: str = "p1"
    evidence_refs: List[str] = field(default_factory=list)

    def validate(self) -> List[str]:
        errors = []
        if not self.incident_id:
            errors.append("incident_id is required")
        if not self.action_id:
            errors.append("action_id is required")
        if not self.switch_id:
            errors.append("switch_id is required")
        if not self.rule_cookie or self.rule_cookie <= 0:
            errors.append("Valid non-zero rule_cookie is required")
        if self.ttl_s <= 0:
            errors.append("ttl_s (hard_timeout) must be greater than 0")
        if not self.match.validate_scope():
            errors.append("Match scope too broad: cannot block on src_ip alone")
        return errors

