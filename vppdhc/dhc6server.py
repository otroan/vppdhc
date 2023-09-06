#!/usr/bin/env python3

import logging
import asyncio
import random
import hashlib
from typing import Any
from scapy.layers.l2 import Ether
from scapy.layers.dhcp6 import (DHCP6, DHCP6_Solicit, DHCP6_Release, DHCP6_Decline, DHCP6_Rebind,
                                DHCP6_Request, DHCP6_Advertise, DHCP6_Confirm,
                                DHCP6_Reply, DHCP6_Renew, DHCP6OptClientId, DHCP6OptServerId,
                                DHCP6OptIA_NA, DHCP6OptIAAddress, DHCP6OptStatusCode, DUID_LL)
from scapy.layers.inet6 import IPv6, UDP
import asyncio_dgram
from ipaddress import IPv6Address, IPv6Network
from vppdhc.vpppunt import VPPPunt, Actions
from enum import IntEnum

logger = logging.getLogger(__name__)

class DHCPv6Server():
    def __init__(self, receive_socket, send_socket, vpp, if_name, prefix, preflft, validlft):
        self.receive_socket = receive_socket
        self.send_socket = send_socket
        self.vpp = vpp
        self.if_name = if_name

        self.if_index = self.vpp.vpp_interface_name2index(if_name)
        logger.debug(f'Getting interface index for: {if_name} {self.if_index}')
        self.prefix = IPv6Network(prefix)
        self.preflft = preflft
        self.validlft = validlft

        self.interface_info = self.vpp.vpp_interface_info(self.if_index)
        logger.debug(f"Interface info: {self.interface_info}")

        # Create a DUID-LL with the MAC address
        self.duid = DUID_LL(lladdr=self.interface_info.mac)

        # Add a route in the MFIB for the all DHCP servers and relays address
        self.vpp.vpp_ip6_mreceive('ff02::1:2/128')

    def process_solicit(self, solicit):
        '''Process a DHCPv6 solicit/request packet'''

        # Create an interface identifier from the client's DUID
        clientid = solicit[DHCP6OptClientId]
        clientduid = clientid.duid
        interface_id = hashlib.sha256(bytes(clientduid)).digest()[:8]
        # interface_int = int.from_bytes(interface_id, 'big')
        logger.debug(f'Interface ID: {interface_id.hex()}')
        # Concatenate self.prefix and interface_id to create the IPv6 address
        ipv6 = IPv6Address(int(self.prefix.network_address) + int.from_bytes(interface_id, 'big'))

        t1 = int(0.5 * self.preflft)
        t2 = int(0.875 * self.preflft)

        advertise = (Ether(src=self.interface_info.mac, dst=solicit[Ether].src) /
                    IPv6(src=self.interface_info.ip6, dst=solicit[IPv6].src) /
                    UDP(sport=547, dport=546) /
                    DHCP6_Advertise(trid=solicit[DHCP6_Solicit].trid) /
                    DHCP6OptServerId(duid=self.duid) /
                    DHCP6OptClientId(duid=clientduid) /
                    DHCP6OptIA_NA(iaid=solicit[DHCP6OptIA_NA].iaid, T1=t1, T2=t2,
                                  ianaopts = DHCP6OptIAAddress(addr=ipv6, preflft=self.preflft, validlft=self.validlft)
                    )
        )

        advertise = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / advertise
        advertise.show2()
        return advertise

    def process_request(self, request, trid):
        '''Process a DHCPv6 solicit/request packet'''

        # Create an interface identifier from the client's DUID
        clientid = request[DHCP6OptClientId]
        clientduid = clientid.duid
        interface_id = hashlib.sha256(bytes(clientduid)).digest()[:8]
        # interface_int = int.from_bytes(interface_id, 'big')
        logger.debug(f'Interface ID: {interface_id.hex()}')
        # Concatenate self.prefix and interface_id to create the IPv6 address
        ipv6 = IPv6Address(int(self.prefix.network_address) + int.from_bytes(interface_id, 'big'))

        t1 = int(0.5 * self.preflft)
        t2 = int(0.875 * self.preflft)

        reply = (Ether(src=self.interface_info.mac, dst=request[Ether].src) /
                    IPv6(src=self.interface_info.ip6, dst=request[IPv6].src) /
                    UDP(sport=547, dport=546) /
                    DHCP6_Reply(trid=trid) /
                    DHCP6OptServerId(duid=self.duid) /
                    DHCP6OptClientId(duid=clientduid) /
                    DHCP6OptIA_NA(iaid=request[DHCP6OptIA_NA].iaid, T1=t1, T2=t2,
                                  ianaopts = DHCP6OptIAAddress(addr=ipv6, preflft=self.preflft, validlft=self.validlft)
                    )
        )

        reply = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / reply
        reply.show2()
        return reply


    async def listen(self):
        '''DHCPv6 Server'''

        reader = await asyncio_dgram.bind(self.receive_socket)
        writer = await asyncio_dgram.connect(self.send_socket)

        while True:
            # Receive on uds socket
            (request, _) = await reader.recv()

            # Decode packet with scapy
            request = VPPPunt(request)
            logger.debug(f'Received from client {request.show2(dump=True)}')
            request.show2()

            p = request[IPv6].payload
            p = p.payload
            if not isinstance(p, DHCP6):
                print('NO IDEA WHAT THIS IS')
                continue

            trid = p.trid

            if request.haslayer(DHCP6_Solicit):
                logger.debug('Received DHCPv6 Solicit')
                reply = self.process_solicit(request)
            elif (request.haslayer(DHCP6_Request) or request.haslayer(DHCP6_Confirm) or
                request.haslayer(DHCP6_Renew) or request.haslayer(DHCP6_Rebind)):
                logger.debug('Received DHCPv6 Request, Renew, Rebind')
                reply = self.process_request(request, trid)
            elif request.haslayer(DHCP6_Release):
                reply = self.process_release(request, trid)
            elif request.haslayer(DHCP_Decline):
                reply = self.process_decline(request, trid)
            else:
                logger.debug('Received DHCPv6 Unknown')
                continue

            if reply:
                await writer.send(bytes(reply))

    def __call__(self, *args: Any, **kwds: Any) -> Any:
        return asyncio.create_task(self.listen())
