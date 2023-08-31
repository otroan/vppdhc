#!/usr/bin/env python3

import logging
import asyncio
import random
from typing import Any
from scapy.layers.l2 import Ether
from scapy.layers.dhcp6 import (DUID_LL, DHCP6OptClientId, DHCP6OptIA_PD,
                                DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request,
                                DHCP6_Reply, DHCP6OptServerId, DHCP6_Renew,
                                DHCP6OptIAPrefix, DHCP6OptStatusCode)
from scapy.layers.inet6 import IPv6, UDP
import asyncio_dgram
from vppdhc.vpppunt import VPPPunt, Actions
from enum import IntEnum

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

class DHCPv6PDClient():
    def __init__(self, receive_socket, send_socket, vpp, if_name, internal_prefix):
        self.receive_socket = receive_socket
        self.send_socket = send_socket
        self.vpp = vpp

        self.if_index = self.vpp.vpp_interface_name2index(if_name)
        logger.debug(f'Getting interface index for: {if_name} {self.if_index}')
        self.internal_prefix = internal_prefix

        self.bindings = {}

    def process_reply(self, reply):
        '''Process a DHCPv6 reply packet'''
        # from vpp_papi import VppEnum
        # enum = VppEnum.vl_api_ip_neighbor_event_flags_t
        # Install blackhole route for the delegated prefix
        iapd = reply[DHCP6OptIA_PD]
        if iapd.haslayer(DHCP6OptStatusCode):
            logger.error('DHCPv6 error: ', iapd.getlayer(DHCP6OptStatusCode))
            raise Exception('DHCPv6 error')
        iapdopt = iapd[DHCP6OptIAPrefix]
        # iapdopt.show2()
        rv = self.vpp.api.npt66_binding_add_del(is_add=True, sw_if_index=self.if_index,
                                                internal=self.internal_prefix,
                                                external=f'{iapdopt.prefix}/{iapdopt.plen}')
        logger.info(f"Setting up new NAT binding {iapdopt.prefix}/{iapdopt.plen}  ->  {self.internal_prefix} {rv}")

        # Install default route
        nexthop = reply[IPv6].src
        rv = self.vpp.api.cli_inband(cmd=f'ip route add ::/0 via {nexthop}')
        logger.debug(f'Adding route {rv}')

        # print('PREFIX: ', iapdopt.prefix, iapdopt.plen)
        # paths = [{'sw_if_index': self.if_index, 'table_id': 0}]
        # drop_nh = VppRoutePath("::1", 0xFFFFFFFF, type=FibPathType.FIB_PATH_TYPE_DROP)
        # route = {'prefix': f'{iapdopt.prefix}/{iapdopt.plen}','n_paths': 1, 'paths': paths}
        # rv = self.vpp.api.ip_route_add_del_v2(route=route)
        # self.vpp.api.ip_add_del_route(dst_address=prefix.prefix, dst_address_length=prefix.prefixlen,
        #                                 table_id=0, classify_table_index=0, is_ipv6=1, is_local=0,
        #                                 is_drop=1, is_unreach=0, is_prohibit=0, is_resolve_host=0,
        #                                 is_resolve_attached=0, is_interface_rx=0, is_classify=0,
        #                                 is_multipath=0, is_dvr=0, is_source_lookup=0, is_rpf_id=0,
        #                                 is_udp_encap=0, is_ip4_nh=0, is_add=1)

    async def client(self):
        '''DHCPv6 PD Client'''

        interface_info = self.vpp.vpp_interface_info(self.if_index)
        logger.debug(f"Interface info: {interface_info}")

        # Create a DUID-LL with the MAC address
        duid = DUID_LL(lladdr=interface_info.mac)

        reader = await asyncio_dgram.bind(self.receive_socket)
        # reader = asyncio_dgram.from_socket(receive_socket)
        writer = await asyncio_dgram.connect(self.send_socket)
        state = StateMachine.INIT
        reply = None
        rt = 1 # SOL_TIMEOUT
        rc = 0
        while True:
            if state == StateMachine.INIT:

                # Send DHCPv6 PD solicit scapy
                solicit = (Ether(src=interface_info.mac, dst='33:33:00:01:00:02') /
                        IPv6(src=interface_info.ip6, dst='ff02::1:2') / UDP(sport=546, dport=547) /
                        DHCP6_Solicit() / DHCP6OptClientId(duid=duid) / DHCP6OptIA_PD())

                solicit = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / solicit

                logger.debug(f'Sending SOLICIT: {solicit.show2(dump=True)}')
                await writer.send(bytes(solicit))

                rt = 2*rt + random.uniform(-0.1, 0.1)*rt
                rt = min(rt, 3600) # MAX_SOL_TIMEOUT
            elif state == StateMachine.REQUESTING:
                # Send DHCPv6 PD request
                iapd = reply[DHCP6OptIA_PD]
                serverid = reply[DHCP6OptServerId]
                request = (Ether(src=interface_info.mac, dst=reply[Ether].src) /
                        IPv6(src=interface_info.ip6, dst='ff02::1:2') / UDP(sport=546, dport=547) /
                        DHCP6_Request() / DHCP6OptClientId(duid=duid) / serverid / iapd)
                request = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / request
                rc += 1

                logger.debug(f'Sending REQUEST {request.show2(dump=True)}')
                await writer.send(bytes(request))

                rt = 2*rt + random.uniform(-0.1, 0.1)*rt
                rt = min(rt, 30) # REQ_MAX_RT
                if rc > 10:
                    state = StateMachine.INIT
                    logger.warning('REQUEST timeout')
            elif state == StateMachine.RENEWING:
                # Renew lease
                renew = (Ether(src=interface_info.mac, dst=reply[Ether].src) /
                        IPv6(src=interface_info.ip6, dst='ff02::1:2') / UDP(sport=546, dport=547) /
                        DHCP6_Renew() / DHCP6OptClientId(duid=duid) / DHCP6OptServerId(duid=serverid) / iapd)
                renew = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / renew
                # renew.show2()
                rc += 1
                await writer.send(bytes(renew))

                rt = 2*rt + random.uniform(-0.1, 0.1)*rt
                rt = min(rt, 30) # REQ_MAX_RT
                if rc > 10:
                    state = StateMachine.INIT
                    logger.warning('REQUEST timeout')

            # Receive on uds socket
            try:
                reply, _ = await asyncio.wait_for(reader.recv(), timeout=rt)
            except asyncio.TimeoutError:
                if state == StateMachine.BOUND:
                    state = StateMachine.RENEWING
                logger.warning('Timeout')
                continue

            # Decode packet with scapy
            reply = VPPPunt(reply)
            logger.debug(f'Received from server {reply.show2(dump=True)}')

            if reply.haslayer(DHCP6_Advertise):
                logger.debug('Received DHCPv6 Advertise')
                state = StateMachine.REQUESTING
                rc = 0
            elif reply.haslayer(DHCP6_Reply):
                logger.debug('Received DHCPv6 Reply')
                state = StateMachine.BOUND
                # Is it sufficient to just set rt to T1?
                rt = reply[DHCP6OptIA_PD].T1
                self.process_reply(reply)

            # reply.show2()

    def __call__(self, *args: Any, **kwds: Any) -> Any:
        return asyncio.create_task(self.client())


    ## NOT USED
    async def handle_timer(self):
        '''Handle a timer'''
        while True:
            print('Timer fired')
            await asyncio.sleep(1)
