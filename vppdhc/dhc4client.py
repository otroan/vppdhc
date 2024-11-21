"""DHCPv4 Client."""

import asyncio
import logging
import random
from typing import Any

import asyncio_dgram
from scapy.layers.dhcp import BOOTP, DHCP, DHCPOptions
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.volatile import RandInt

from vppdhc.datamodel import DHCP4ClientEvent, DHCP4ClientStateMachine, IPv4Interface
from vppdhc.vpppunt import Actions, VPPPunt

logger = logging.getLogger(__name__)
packet_logger = logging.getLogger(f"{__name__}.packet")

PRL = [1, 3, 108, 121] # router, subnetmask, ipv6 only, classless static route

# DHCPv4 client
def options2dict(options: list) -> dict:
    """Get DHCP message type."""
    # Return all options in a dictionary
    # Using a dict comprehension
    o= {}
    for op in options:
        o[op[0]] = op[1]
    return o
class DHCPClient:
    """DHCPv4 Client."""

    def __init__(self, receive_socket, send_socket, vpp, conf, event_queue: asyncio.Queue) -> None:
        """DHCPv4 Client."""
        self.receive_socket = receive_socket
        self.send_socket = send_socket
        self.vpp = vpp
        self.if_name = conf.interface
        self.if_index = self.vpp.vpp_interface_name2index(self.if_name)
        self.event_queue = event_queue
        self.client_set_state(DHCP4ClientStateMachine.INIT)

    def client_set_state(self, newstate: DHCP4ClientStateMachine) -> None:
        """Set the client state."""
        if self.event_queue:
            self.event_queue.put_nowait(DHCP4ClientEvent(state=newstate))
        self.state = newstate

    async def client(self) -> None:
        """DHCPv4 Client."""
        interface_info = self.vpp.vpp_interface_info(self.if_index)
        logger.debug("Interface info: %s", interface_info)
        reader = await asyncio_dgram.bind(self.receive_socket)
        writer = await asyncio_dgram.connect(self.send_socket)

        reply = None
        rt = 1 # SOL_TIMEOUT
        rc = 0

        chaddr = interface_info.mac

        xid = RandInt()
        server_id = None
        client_ip = None
        server_mac = None

        while True:
            if self.state == DHCP4ClientStateMachine.INIT:
                # Send DHCPDISCOVER
                discover = (Ether(src=interface_info.mac, dst="ff:ff:ff:ff:ff:ff") /
                            IP(src="0.0.0.0", dst="255.255.255.255") /  # noqa: S104
                            UDP(sport=68, dport=67) /
                            BOOTP(chaddr=chaddr, xid=xid) /
                            DHCP(options=[("message-type", "discover"),
                                          ("max_dhcp_size", 1500),
                                          ("param_req_list", PRL),
                                          ("client_id", b"\x01" + chaddr), "end"])
                            )
                discover = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / discover
                packet_logger.debug("Sending DISCOVER: %s", discover.show2(dump=True))
                await writer.send(bytes(discover))

                rt = 2*rt + random.uniform(-0.1, 0.1)*rt
                rt = min(rt, 3600) # MAX_SOL_TIMEOUT
            elif self.state == DHCP4ClientStateMachine.REQUESTING:
                requested_addr = reply[BOOTP].yiaddr
                dhcp_options = [("message-type", "request"),
                                ("server_id", server_id),
                                ("client_id", b"\x01" + chaddr),
                                ("max_dhcp_size", 1500),
                                ("param_req_list", PRL),
                                ("requested_addr", requested_addr), "end",
                ]

                # Send DHCP request
                request = (Ether(src=interface_info.mac, dst="ff:ff:ff:ff:ff:ff") /
                            IP(src="0.0.0.0", dst="255.255.255.255") /  # noqa: S104
                            UDP(sport=68, dport=67) /
                            BOOTP(chaddr=chaddr, xid=xid) /
                            DHCP(options=dhcp_options)
                            )
                request = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / request
                rc += 1
                packet_logger.debug("Sending REQUEST: %s", request.show2(dump=True))
                await writer.send(bytes(request))

                rt = 2*rt + random.uniform(-0.1, 0.1)*rt  # noqa: S311
                rt = min(rt, 30) # REQ_MAX_RT
                if rc > 10:
                    self.client_set_state(DHCP4ClientStateMachine.INIT)
                    logger.warning("REQUEST timeout")
            elif self.state == DHCP4ClientStateMachine.RENEWING:
                # Renew lease
                dhcp_options = [("message-type", "request"),
                                ("client_id", b"\x01" + chaddr), "end"
                ]

                renew = (Ether(src=interface_info.mac, dst=server_mac) /
                           IP(src=client_ip, dst=server_id) /
                           UDP(sport=68, dport=67) /
                           BOOTP(chaddr=chaddr, xid=xid, ciaddr=client_ip) /
                           DHCP(options=dhcp_options)
                           )
                renew = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / renew

                rc += 1

                packet_logger.debug("Sending RENEW: %s", renew.show2(dump=True))
                await writer.send(bytes(renew))

                rt = 2*rt + random.uniform(-0.1, 0.1)*rt
                rt = min(rt, 30) # REQ_MAX_RT
                if rc > 10:
                    self.client_set_state(DHCP4ClientStateMachine.INIT)
                    logger.warning("REQUEST timeout")

            # Receive on uds socket
            try:
                reply, _ = await asyncio.wait_for(reader.recv(), timeout=rt)
            except asyncio.TimeoutError:
                if self.state == DHCP4ClientStateMachine.BOUND:
                    self.client_set_state(DHCP4ClientStateMachine.RENEWING)
                logger.warning("Timeout")
                continue

            # Decode packet with scapy
            reply = VPPPunt(reply)
            packet_logger.debug("Received from server: %s", reply.show2(dump=True))

            dhcp = reply[DHCP]
            options = options2dict(dhcp.options)
            server_id = options.get("server_id", None)
            if options["message-type"] == 2:    # DHCPOFFER
                logger.debug("Received DHCPOFFER")
                self.client_set_state(DHCP4ClientStateMachine.REQUESTING)
                rc = 0
            elif options["message-type"] == 5: # DHCPACK
                logger.debug("Received DHCPACK")
                # Is it sufficient to just set rt to T1?
                lease_time = options.get("lease_time", 0)
                client_ip = reply[BOOTP].yiaddr
                server_mac = reply[Ether].src
                rt = 0.5 * lease_time
                prefix = IPv4Interface(f'{client_ip}/{options["subnet_mask"]}')
                self.event_queue.put_nowait(DHCP4ClientEvent(ip=prefix))
                self.client_set_state(DHCP4ClientStateMachine.BOUND)
