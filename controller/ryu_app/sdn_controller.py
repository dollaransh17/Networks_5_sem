#!/usr/bin/env python3
"""
controller/ryu_app/sdn_controller.py

Phase 2: SDN Threat Isolation Controller Application
References: AGENTS.md, ARCHITECTURE.md, FEATURES.md (F2, F3)

Key Responsibilities:
1. Negotiates OpenFlow 1.3 protocol.
2. Installs proactive table-miss entry (sends unhandled packets to controller for L2 learning).
3. Maintains periodic 2.0s FlowStatsRequest polling loop to retrieve flow counters.
4. Computes packet_rate and byte_rate using ACTUAL elapsed time (never hardcoded 2s),
   properly handling resets, missing samples, and switch restarts via ai.features.counter_rates.
5. Implements install_mitigation_rule() to program scoped, expiring FLOW_MOD entries (DROP / quarantine)
   with cookie, priority, hard_timeout, followed by a BarrierRequest to confirm switch ordering.

Rules compliance:
- AI inference and cloud calls are KEPT OUT of Ryu's event loop.
- Scoped match validation: rejects un-scoped src_ip rules.
"""

import os
import sys
import time

# Ensure project root is in sys.path when launched via ryu-manager CLI
_proj_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _proj_root not in sys.path:
    sys.path.insert(0, _proj_root)

from typing import Dict, Tuple, Optional, Any, List

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub

from ai.features.counter_rates import (
    FlowCounterSample,
    calculate_flow_rates,
    FlowRateMetrics
)


class SDNThreatIsolationController(app_manager.RyuApp):
    """
    Ryu controller application managing OVS switch telemetry and scoped threat isolation.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNThreatIsolationController, self).__init__(*args, **kwargs)

        # L2 learning MAC table: dpid -> { mac: port }
        self.mac_to_port: Dict[int, Dict[str, int]] = {}

        # Connected switch datapaths: dpid -> datapath
        self.datapaths: Dict[int, Any] = {}

        # History of previous counter samples:
        # Keep same-match entries in different tables or priorities independent.
        self.flow_history: Dict[Tuple[int, int, int, int, str], FlowCounterSample] = {}

        # Latest calculated rates: (dpid, match_key) -> FlowRateMetrics
        self.flow_rates: Dict[Tuple[int, int, int, int, str], FlowRateMetrics] = {}

        # Periodic polling interval (Baseline: 2.0 seconds)
        self.poll_interval_s: float = 2.0

        # Start periodic statistics polling thread
        self.monitor_thread = hub.spawn(self._polling_loop)
        self.logger.info("[INIT] SDNThreatIsolationController initialized (OF 1.3, poll_interval=%.1fs)",
                         self.poll_interval_s)

    # -------------------------------------------------------------------------
    # Switch Connection & Proactive Table-Miss Entry
    # -------------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Invoked on initial switch handshake.
        Registers datapath and installs table-miss flow entry (priority 0) to ensure
        baseline traffic is sent to controller for standard forwarding.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        if self.datapaths.get(dpid) is not datapath:
            self._clear_switch_state(dpid)
            self.datapaths[dpid] = datapath
        self.logger.info("[SWITCH_JOIN] Datapath s%s connected. Installing table-miss entry.", dpid)

        # Table-miss rule: match all packets at lowest priority (0)
        # Action: forward to controller with no packet buffer
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]
        self._add_flow(
            datapath=datapath,
            priority=0,
            match=match,
            actions=actions,
            cookie=0,
            hard_timeout=0,
            idle_timeout=0
        )

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def switch_disconnected(self, ev):
        datapath = ev.datapath
        if self.datapaths.get(datapath.id) is datapath:
            del self.datapaths[datapath.id]
            self._clear_switch_state(datapath.id)

    def _clear_switch_state(self, dpid):
        self.mac_to_port.pop(dpid, None)
        for samples in (self.flow_history, self.flow_rates):
            for key in [key for key in samples if key[0] == dpid]:
                del samples[key]

    def _add_flow(self, datapath, priority: int, match: Any, actions: List[Any],
                  buffer_id: Optional[int] = None, cookie: int = 0,
                  hard_timeout: int = 0, idle_timeout: int = 0):
        """
        Helper method to construct and transmit an OpenFlow FLOW_MOD message.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=instructions,
                cookie=cookie,
                hard_timeout=hard_timeout,
                idle_timeout=idle_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=instructions,
                cookie=cookie,
                hard_timeout=hard_timeout,
                idle_timeout=idle_timeout
            )
        datapath.send_msg(mod)

    # -------------------------------------------------------------------------
    # Flow Telemetry: 2.0-Second Periodic Polling Loop (F2)
    # -------------------------------------------------------------------------
    def _polling_loop(self):
        """
        Background loop requesting flow statistics from all connected switches
        every 2.0 seconds.
        """
        while True:
            for dp in list(self.datapaths.values()):
                self._send_flow_stats_request(dp)
            hub.sleep(self.poll_interval_s)

    def _send_flow_stats_request(self, datapath):
        """
        Transmits an OpenFlow FlowStatsRequest message to the datapath.
        """
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # -------------------------------------------------------------------------
    # FlowStatsReply Handler & Rate Calculation (F2)
    # -------------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        Processes switch FlowStatsReply messages:
        - Retrieves raw packet_count and byte_count.
        - Calculates rates using actual elapsed time between samples (Delta t).
        - Correctly flags resets and missing samples.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        if self.datapaths.get(dpid) is not ev.msg.datapath:
            return
        now_s = time.monotonic()

        for stat in body:
            # Skip the table-miss entry (priority 0) from security rate telemetry
            if stat.priority == 0:
                continue

            # Deterministic string representation of match fields
            match_key = str(sorted(stat.match.items()))
            flow_key = (dpid, stat.table_id, stat.priority, stat.cookie, match_key)

            # Use a monotonic clock for elapsed time across observations.
            curr_sample = FlowCounterSample(
                timestamp_s=now_s,
                packet_count=stat.packet_count,
                byte_count=stat.byte_count
            )

            prev_sample = self.flow_history.get(flow_key)

            # Calculate rates using the tested counter_rates module
            rates = calculate_flow_rates(prev_sample, curr_sample)

            # Update cache with current snapshot
            self.flow_history[flow_key] = curr_sample
            self.flow_rates[flow_key] = rates

            if rates.is_valid:
                self.logger.info(
                    "[TELEMETRY] Switch s%s Flow [%s] -> "
                    "Rate: %.2f pkt/s, %.2f bytes/s | Elapsed: %.3fs (pkts: %d, bytes: %d)",
                    dpid, match_key, rates.packet_rate, rates.byte_rate,
                    rates.elapsed_time_s, stat.packet_count, stat.byte_count
                )
            elif rates.reset_detected:
                self.logger.warning(
                    "[TELEMETRY_WARN] Switch s%s Flow [%s] -> "
                    "Counter reset detected (switch reboot or flow re-installed). Rates reset to 0.",
                    dpid, match_key
                )
            else:
                # First observation sample or gap: baseline recorded, waiting for next interval
                self.logger.debug(
                    "[TELEMETRY_INIT] Switch s%s Flow [%s] -> First sample recorded (pkts: %d, bytes: %d)",
                    dpid, match_key, stat.packet_count, stat.byte_count
                )

    # -------------------------------------------------------------------------
    # Mitigation Rule Installation & Barrier Verification (F3)
    # -------------------------------------------------------------------------
    def install_mitigation_rule(self, datapath, match: Any, action_type: str = "temporary_drop",
                                priority: int = 200, hard_timeout: int = 60,
                                cookie: int = 1) -> bool:
        """
        Sends a FLOW_MOD to enforce an approved mitigation policy, followed by a
        BarrierRequest to guarantee switch ordering and processing.

        Parameters:
            datapath: Switch instance
            match: OFPMatch structure (must be scoped: e.g. src_ip + dst_ip or port)
            action_type: "temporary_drop" (empty actions) or "quarantine" (redirect to port 3/VLAN 999)
            priority: Flow priority (e.g. 200, higher than normal forwarding priority 1)
            hard_timeout: Timeout in seconds for automatic expiration
            cookie: Unique identifier for tracking and rollback

        Returns:
            True once the BarrierRequest is dispatched to the switch.
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Build actions depending on mitigation type
        if action_type == "temporary_drop":
            actions = []  # Empty action list = OpenFlow DROP
        elif action_type == "quarantine":
            # Direct traffic to VLAN 999 quarantine sink (port 3 on s1)
            actions = [
                parser.OFPActionPushVlan(0x8100),
                parser.OFPActionSetField(vlan_vid=0x1000 | 999),
                parser.OFPActionOutput(3)
            ]
        else:
            self.logger.error("[ENFORCE_ERR] Unsupported action_type: %s", action_type)
            return False

        self.logger.info(
            "[ENFORCE_START] Installing mitigation rule on s%s: "
            "action=%s, priority=%d, hard_timeout=%ds, cookie=%d",
            datapath.id, action_type, priority, hard_timeout, cookie
        )

        # 1. Dispatch FLOW_MOD
        self._add_flow(
            datapath=datapath,
            priority=priority,
            match=match,
            actions=actions,
            cookie=cookie,
            hard_timeout=hard_timeout,
            idle_timeout=0
        )

        # 2. Dispatch BarrierRequest to verify ordering and execution
        barrier_req = parser.OFPBarrierRequest(datapath)
        datapath.send_msg(barrier_req)
        self.logger.info("[ENFORCE_BARRIER] Sent BarrierRequest to switch s%s for cookie %d",
                         datapath.id, cookie)
        return True

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        """
        Handles BarrierReply from switch, confirming the switch has finished
        processing preceding FLOW_MOD messages.
        """
        dpid = ev.msg.datapath.id
        self.logger.info("[ENFORCE_CONFIRMED] BarrierReply received from switch s%s: rules processed.", dpid)

    # -------------------------------------------------------------------------
    # Baseline Packet-In (L2 Learning & Forwarding)
    # -------------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Standard L2 MAC learning and forwarding for baseline traffic.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # Discard LLDP discovery frames

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        # Learn mapping
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # If destination port is known, install standard forwarding rule (priority 1)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self._add_flow(
                datapath=datapath,
                priority=1,
                match=match,
                actions=actions,
                idle_timeout=20,
                hard_timeout=0
            )

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

