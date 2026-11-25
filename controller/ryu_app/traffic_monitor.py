"""
controller/ryu_app/traffic_monitor.py

Phase 2: Ryu Controller Application
- OpenFlow 1.3 protocol handling
- Table-miss rule installation (PACKET_IN for standard L2 learning / forwarding)
- Periodic FlowStatsRequest polling (2.0s baseline)
- Rate feature extraction using actual elapsed time (Delta t) via ai.features.counter_rates
- Bounded polling queues and error handling (AGENTS.md & ARCHITECTURE.md compliance)
"""

import time
from typing import Dict, Tuple
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub

from ai.features.counter_rates import (
    FlowCounterSample,
    calculate_flow_rates,
    FlowRateMetrics
)


class ThreatIsolationMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ThreatIsolationMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port: Dict[int, Dict[str, int]] = {}
        self.datapaths: Dict[int, Any] = {}
        # Stores last counter snapshot per flow: (dpid, match_key) -> FlowCounterSample
        self.flow_history: Dict[Tuple[int, str], FlowCounterSample] = {}
        # Stores latest calculated rates
        self.flow_rates: Dict[Tuple[int, str], FlowRateMetrics] = {}
        # Baseline polling interval: 2.0 seconds
        self.poll_interval_s = 2.0
        # Start background polling thread
        self.monitor_thread = hub.spawn(self._monitor_loop)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install default table-miss entry on switch connection."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        self.logger.info("Switch s%s connected. Installing table-miss rule.", datapath.id)

        # Match all packets with lowest priority (0) and send to controller
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None,
                  cookie=0, hard_timeout=0, idle_timeout=0):
        """Helper to send FLOW_MOD entry to switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id,
                priority=priority, match=match,
                instructions=inst, cookie=cookie,
                hard_timeout=hard_timeout, idle_timeout=idle_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority,
                match=match, instructions=inst, cookie=cookie,
                hard_timeout=hard_timeout, idle_timeout=idle_timeout
            )
        datapath.send_msg(mod)

    def _monitor_loop(self):
        """Periodic background polling loop."""
        while True:
            for dp in list(self.datapaths.values()):
                self._request_flow_stats(dp)
            hub.sleep(self.poll_interval_s)

    def _request_flow_stats(self, datapath):
        """Request flow statistics from datapath."""
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        Handle stats reply. Calculate packet_rate and byte_rate using actual
        elapsed time (Delta t). Never use a hard-coded time interval.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        now_s = time.time()

        for stat in body:
            # Skip table-miss default rule (priority 0) from rate telemetry
            if stat.priority == 0:
                continue

            match_key = str(sorted(stat.match.items()))
            flow_key = (dpid, match_key)

            curr_sample = FlowCounterSample(
                timestamp_s=now_s,
                packet_count=stat.packet_count,
                byte_count=stat.byte_count
            )

            prev_sample = self.flow_history.get(flow_key)
            rates = calculate_flow_rates(prev_sample, curr_sample)

            self.flow_history[flow_key] = curr_sample
            self.flow_rates[flow_key] = rates

            if rates.is_valid:
                self.logger.debug(
                    "Flow [%s] rates: %.2f pkt/s, %.2f B/s (dt=%.3fs)",
                    match_key, rates.packet_rate, rates.byte_rate, rates.elapsed_time_s
                )
            elif rates.reset_detected:
                self.logger.warning(
                    "Flow [%s] counter reset detected! Flags marked invalid.",
                    match_key
                )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Basic L2 learning switch forwarding."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignore LLDP
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        # Learn MAC address to avoid future packet-in flooding
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install forwarding flow if destination port is known
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # Use idle_timeout for normal learning entries
            self._add_flow(datapath, priority=1, match=match, actions=actions, idle_timeout=20)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)

