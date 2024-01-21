# pylint: disable=import-error, invalid-name, logging-fstring-interpolation

import time
import logging
import asyncio
from typing import Any
from enum import IntEnum
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import (IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo,
                                ICMPv6NDOptPREF64)

import asyncio_dgram
from vppdhc.vpppunt import VPPPunt, Actions


# TODO: Add support for sending on multiple interfaces
# TODO: Support SLAAC. Pick up prefix from interface

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
    def __init__(self, receive_socket, send_socket, vpp, configuration):
        self.receive_socket = receive_socket
        self.send_socket = send_socket
        self.vpp = vpp
        if_names = configuration.interfaces
        self.if_names = if_names
        self.if_name = if_names[0]
        self.pio = configuration.pio
        if self.pio:
            self.pio_prefix = self.pio.prefix
            self.pio_L = self.pio.L
            self.pio_A = self.pio.A
        self.rt = configuration.maxrtradvinterval
        self.pref64 = configuration.pref64
        self.if_index = self.vpp.vpp_interface_name2index(self.if_name)
        logger.debug(f'Getting interface index for: {self.if_name} {self.if_index}')

    async def listen(self):
        '''IP6 ND RA'''

        interface_info = self.vpp.vpp_interface_info(self.if_index)
        logger.debug(f"Interface info: {interface_info}")

        reader = await asyncio_dgram.bind(self.receive_socket)
        writer = await asyncio_dgram.connect(self.send_socket)

        rt = self.rt
        solicit = None
        next_periodic = rt

        while True:
            # Send periodic or solicted RA
            if solicit and next_periodic > 5:
                # If there is longer than 5 seconds until the next periodic RA send RS
                dstmac = solicit[Ether].src # pylint: disable=unsubscriptable-object
                dstip = solicit[IPv6].src # pylint: disable=unsubscriptable-object
                logger.debug(f'Sending solicited RA to {dstip} {self.if_name} from'
                              ' {interface_info.ip6ll} {dstmac}')

            else:
                dstmac = '33:33:00:00:00:01'
                dstip = 'ff02::1'
                logger.debug(f'Sending periodic RA on {self.if_name} from {interface_info.ip6ll}')

            ra = (Ether(src=interface_info.mac, dst=dstmac) /
                  IPv6(src=interface_info.ip6ll, dst=dstip) / ICMPv6ND_RA(M=1, O=1) /
                    ICMPv6NDOptSrcLLAddr(lladdr=interface_info.mac)
                    )
            if self.pio:
                ra /= ICMPv6NDOptPrefixInfo(prefix=self.pio_prefix.network_address, prefixlen=self.pio_prefix.prefixlen,
                                            L=self.pio_L, A=self.pio_A)
            if self.pref64:
                ra /= ICMPv6NDOptPREF64(prefix=self.pref64.network_address, scaledlifetime=8191)
            ra = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / ra
            # ra.show2()
            await writer.send(bytes(ra))

            # Receive on uds socket
            waited = rt
            try:
                now = time.time()
                solicit, _ = await asyncio.wait_for(reader.recv(), timeout=next_periodic)
                logger.debug(f'WAITED in receive {time.time() - now}')
                next_periodic  -= (time.time() - now)
            except asyncio.TimeoutError:
                logger.info(f'Timeout {waited}')
                solicit = None
                next_periodic = self.rt
                continue

            # Decode packet with scapy
            solicit = VPPPunt(solicit)

            # logger.debug(f'Received from server {solicit.show2(dump=True)}')
            # solicit.show2()

    def __call__(self, *args: Any, **kwds: Any) -> Any:
        return asyncio.create_task(self.listen())
