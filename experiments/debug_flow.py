import sys
import os

_proj_root = "/home/rajnish/acnproject"
if _proj_root not in sys.path:
    sys.path.insert(0, _proj_root)

from sensors.alert_listener.listener import EveAlertListener
from risk.policy_engine.engine import RiskPolicyEngine
from sensors.alert_listener.daemon import execute_flow_mod

listener = EveAlertListener()
engine = RiskPolicyEngine()

raw_line = '{"timestamp":"2026-11-08T06:00:00.000Z","flow_id":123456789,"event_type":"alert","src_ip":"192.0.2.10","src_port":45678,"dest_ip":"198.51.100.20","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":1000001,"rev":1,"signature":"THREAT_ISOLATION_MALICIOUS_PAYLOAD_DETECTED","category":"Attempted Admin Access"}}'

alert = listener.process_line(raw_line)
print("Alert:", alert)
decision = engine.evaluate_suricata_alert(alert, switch_id="s1")
print("Decision:", decision.action_type, decision.approved)
res = execute_flow_mod(decision.action_request)
print("Flow Mod Executed:", res)

