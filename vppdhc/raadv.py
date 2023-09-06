#!/usr/bin/env python3

import logging
import asyncio
import random
from typing import Any
from enum import IntEnum
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo
import asyncio_dgram
from vppdhc.vpppunt import VPPPunt, Actions

logger = logging.getLogger(__name__)
# logger = logging.getLogger("scapy")
class StateMachine(IntEnum):
    '''DHCPv6 PD Client states'''
    INIT = 0
    SELECTING = 1
    REQUESTING = 2
    BOUND = 3
    RENEWING = 4
    RELEASING = 5

class IP6NDRA():
    def __init__(self, receive_socket, send_socket, vpp, if_name, prefix):
        self.receive_socket = receive_socket
        self.send_socket = send_socket
        self.vpp = vpp
        self.if_name = if_name

        self.if_index = self.vpp.vpp_interface_name2index(if_name)
        logger.debug(f'Getting interface index for: {if_name} {self.if_index}')
        self.prefix = prefix

    async def listen(self):
        '''IP6 ND RA'''

        interface_info = self.vpp.vpp_interface_info(self.if_index)
        logger.debug(f"Interface info: {interface_info}")

        reader = await asyncio_dgram.bind(self.receive_socket)
        # reader = asyncio_dgram.from_socket(receive_socket)
        writer = await asyncio_dgram.connect(self.send_socket)
        rt = 30

        while True:
            # Send periodic RA
            ra = (Ether(src=interface_info.mac, dst='33:33:00:00:00:01') /
                  IPv6(src=interface_info.ip6, dst='ff02::1') / ICMPv6ND_RA(M=1, O=1) /
                    ICMPv6NDOptSrcLLAddr(lladdr=interface_info.mac)
                    )

            ra = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / ra
            ra.show2()
            await writer.send(bytes(ra))

            # Receive on uds socket
            try:
                solicit, _ = await asyncio.wait_for(reader.recv(), timeout=rt)
            except asyncio.TimeoutError:
                logger.warning('Timeout')
                continue

            # Decode packet with scapy
            solicit = VPPPunt(solicit)
            logger.debug(f'Received from server {solicit.show2(dump=True)}')

            solicit.show2()


    def __call__(self, *args: Any, **kwds: Any) -> Any:
        return asyncio.create_task(self.listen())
