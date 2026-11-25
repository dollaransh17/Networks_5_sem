#!/usr/bin/env python3
"""
lab/topology/mininet_topo.py

Phase 1 Foundation: Mininet Topology Definition
Builds the physical nodes, linear links, and predictable static IP assignments
per ARCHITECTURE.md and Figure 4 of the project guide:

Linear Forwarding Chain:
  Client (h1) -> Gateway (gw) -> Suricata (ips) -> OVS (s1) -> Server (srv)
                                                 -> Quarantine (quar)

Node breakdown:
  1. Test Client (h1): 192.0.2.10/24 (gw: 192.0.2.1)
  2. Gateway (gw):
       - gw-eth0: 192.0.2.1/24 (faces client)
       - gw-eth1: 10.0.1.1/24  (faces suricata)
  3. Suricata (ips):
       - ips-eth0: 10.0.1.2/24 (faces gateway)
       - ips-eth1: 10.0.2.1/24 (faces OVS switch s1)
       (Acts as transparent layer-3 router / bridge in this stage)
  4. OVS Switch (s1): Open vSwitch instance forwarding packets between Suricata, Server, and Quarantine
  5. Protected Test Server (srv): 198.51.100.20/24 (connected to s1)
  6. VLAN 999 Quarantine (quar): 192.168.99.2/24 (restricted quarantine host connected to s1)

Note: No Ryu controller configuration or Suricata inspection logic is added yet.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, Host, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class ThreatIsolationTopology(Topo):
    """
    Mininet topology implementing the exact 6 nodes and linear connectivity.
    """

    def build(self):
        # 1. Test Client
        client = self.addHost(
            'h1',
            ip='192.0.2.10/24',
            defaultRoute='via 192.0.2.1'
        )

        # 2. Access Gateway (Multi-homed router)
        gateway = self.addHost(
            'gw',
            ip='192.0.2.1/24'
        )

        # 3. Suricata (Transparent forwarder / inline bridge between GW and OVS)
        suricata = self.addHost(
            'ips',
            ip='10.0.1.2/24'
        )

        # 4. Open vSwitch (s1)
        s1 = self.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')

        # 5. Protected Test Server
        server = self.addHost(
            'srv',
            ip='198.51.100.20/24'
        )

        # 6. VLAN 999 Quarantine Host (Restricted destination)
        quarantine = self.addHost(
            'quar',
            ip='192.168.99.2/24'
        )

        # Linear links: Client -> Gateway -> Suricata -> OVS -> Server
        # Link 1: Client to Gateway
        self.addLink(client, gateway, intfName1='h1-eth0', intfName2='gw-eth0')

        # Link 2: Gateway to Suricata
        self.addLink(gateway, suricata, intfName1='gw-eth1', intfName2='ips-eth0')

        # Link 3: Suricata to OVS Switch (s1)
        self.addLink(suricata, s1, intfName1='ips-eth1', intfName2='s1-eth1')

        # Link 4: OVS Switch (s1) to Protected Server
        self.addLink(s1, server, intfName1='s1-eth2', intfName2='srv-eth0')

        # Link 5: OVS Switch (s1) to VLAN 999 Quarantine Host
        self.addLink(s1, quarantine, intfName1='s1-eth3', intfName2='quar-eth0')


def setup_routes(net):
    """
    Configure interface addresses and static routing tables on multi-homed nodes
    so packets flow across the linear chain:
      Client (192.0.2.10) <-> Gateway <-> Suricata <-> OVS (s1) <-> Server (198.51.100.20)
    """
    gw = net.get('gw')
    ips = net.get('ips')
    srv = net.get('srv')
    quar = net.get('quar')

    # Gateway routing configuration
    # Enable IP forwarding
    gw.cmd('sysctl -w net.ipv4.ip_forward=1')
    # Assign IP on the interface facing Suricata
    gw.cmd('ip addr add 10.0.1.1/24 dev gw-eth1')
    # Route to protected server network via Suricata
    gw.cmd('ip route add 198.51.100.0/24 via 10.0.1.2')
    # Route to quarantine network via Suricata
    gw.cmd('ip route add 192.168.99.0/24 via 10.0.1.2')

    # Suricata node routing configuration (acting as transparent forwarding node)
    # Enable IP forwarding
    ips.cmd('sysctl -w net.ipv4.ip_forward=1')
    # Assign IP on interface facing OVS s1
    ips.cmd('ip addr add 10.0.2.1/24 dev ips-eth1')
    # Route to client network via Gateway
    ips.cmd('ip route add 192.0.2.0/24 via 10.0.1.1')
    # Route to server network directly reachable over s1
    ips.cmd('ip route add 198.51.100.0/24 dev ips-eth1')
    # Route to quarantine network directly reachable over s1
    ips.cmd('ip route add 192.168.99.0/24 dev ips-eth1')

    # Protected Server route back to client network via Suricata
    srv.cmd('ip route replace default via 10.0.2.1 dev srv-eth0 onlink')

    # Quarantine Host route back to client network via Suricata
    quar.cmd('ip route replace default via 10.0.2.1 dev quar-eth0 onlink')


def main():
    setLogLevel('info')
    topo = ThreatIsolationTopology()

    # Connect OVS switch s1 to local Ryu controller on 127.0.0.1:6653
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        build=True,
        autoSetMacs=True
    )

    info('*** Starting Network\n')
    net.start()

    info('*** Configuring Static IP Routing across nodes\n')
    setup_routes(net)

    info('*** Network Topology ready.\n')
    info('*** Nodes:\n')
    info('  - Client: h1 (192.0.2.10)\n')
    info('  - Gateway: gw (gw-eth0: 192.0.2.1, gw-eth1: 10.0.1.1)\n')
    info('  - Suricata: ips (ips-eth0: 10.0.1.2, ips-eth1: 10.0.2.1)\n')
    info('  - Switch: s1 (OVS)\n')
    info('  - Server: srv (198.51.100.20)\n')
    info('  - Quarantine: quar (192.168.99.2)\n')

    # CLI prompt for interactive exploration
    CLI(net)

    info('*** Stopping Network\n')
    net.stop()


if __name__ == '__main__':
    main()
