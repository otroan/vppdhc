import logging
import asyncio
from typing import Any
import asyncio_dgram
import random

from enum import IntEnum
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import DHCP, BOOTP, DHCPOptions
from scapy.volatile import RandInt
from ipaddress import IPv4Interface
from vppdhc.vpppunt import VPPPunt, Actions

logger = logging.getLogger(__name__)

# DHCPv4 client
class StateMachine(IntEnum):
    '''DHCPv4 Client states'''
    INIT = 0
    SELECTING = 1
    REQUESTING = 2
    BOUND = 3
    RENEWING = 4
    RELEASING = 5

def options2dict(options):
    '''Get DHCP message type'''
    # Return all options in a dictionary
    # Using a dict comprehension
    o= {}
    for op in options:
        o[op[0]] = op[1]
    return o

class DHCPClient():
    def __init__(self, receive_socket, send_socket, vpp, conf) -> None:
        self.receive_socket = receive_socket
        self.send_socket = send_socket
        self.vpp = vpp
        self.if_name = conf.interface
        self.if_index = self.vpp.vpp_interface_name2index(self.if_name)
        self.nat = conf.nat
        self.tenant_id = conf.tenant

    def process_reply(self, reply, options):
        reply.show2()

        # Add address to the interface
        client_ip = reply[BOOTP].yiaddr
        prefix = IPv4Interface(f'{client_ip}/{options["subnet_mask"]}')
        rv = self.vpp.vpp_ip_address(self.if_index, prefix)
        print('RV', rv)
        # Create a NAT instance with that address as the NAT pool

        if self.nat:
            print('CONFIGURING NAT INSTANCE', self.nat, client_ip)
            rv = self.vpp.vpp_vcdp_nat_add(self.nat, [client_ip])
            print('RV', rv)
            rv = self.vpp.vpp_vcdp_nat_bind_set_unset(self.tenant_id, self.nat)
            print('RV', rv)

    async def client(self):
        '''DHCPv4 Client'''

        interface_info = self.vpp.vpp_interface_info(self.if_index)
        logger.debug(f"Interface info: {interface_info}")

        reader = await asyncio_dgram.bind(self.receive_socket)
        # reader = asyncio_dgram.from_socket(receive_socket)
        writer = await asyncio_dgram.connect(self.send_socket)
        state = StateMachine.INIT
        reply = None
        rt = 1 # SOL_TIMEOUT
        rc = 0

        chaddr = interface_info.mac.packed
        xid = RandInt()
        self.vpp.vpp_dhcp_client_detect(self.if_index)
        server_id = None
        client_ip = None
        server_mac = None
        while True:
            if state == StateMachine.INIT:

                # Send DHCPDISCOVER
                discover = (Ether(src=interface_info.mac, dst='ff:ff:ff:ff:ff:ff') /
                            IP(src='0.0.0.0', dst='255.255.255.255') /
                            UDP(sport=68, dport=67) /
                            BOOTP(chaddr=chaddr, xid=xid) /
                            DHCP(options=[('message-type', 'discover'),
                                          ('client_id', b'\x01' + chaddr), 'end'])
                            )
                discover = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / discover

                logger.debug(f'Sending DISCOVER: {discover.show2(dump=True)}')
                await writer.send(bytes(discover))

                rt = 2*rt + random.uniform(-0.1, 0.1)*rt
                rt = min(rt, 3600) # MAX_SOL_TIMEOUT
            elif state == StateMachine.REQUESTING:
                requested_addr = reply[BOOTP].yiaddr
                dhcp_options = [('message-type', 'request'),
                                ('server_id', server_id),
                                ('client_id', b'\x01' + chaddr),
                                ('requested_addr', requested_addr), 'end'
                ]

                # Send DHCP request
                request = (Ether(src=interface_info.mac, dst='ff:ff:ff:ff:ff:ff') /
                            IP(src='0.0.0.0', dst='255.255.255.255') /
                            UDP(sport=68, dport=67) /
                            BOOTP(chaddr=chaddr, xid=xid) /
                            DHCP(options=dhcp_options)
                            )
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
                dhcp_options = [('message-type', 'request'),
                                ('client_id', b'\x01' + chaddr), 'end'
                ]

                renew = (Ether(src=interface_info.mac, dst=server_mac) /
                           IP(src=client_ip, dst=server_id) /
                           UDP(sport=68, dport=67) /
                           BOOTP(chaddr=chaddr, xid=xid, ciaddr=client_ip) /
                           DHCP(options=dhcp_options)
                           )
                renew = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / renew

                renew.show2()
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


            dhcp = reply[DHCP]
            options = options2dict(dhcp.options)
            server_id = options.get('server_id', None)
            if options['message-type'] == 2:    # DHCPOFFER
                logger.debug('Received DHCPOFFER')
                state = StateMachine.REQUESTING
                rc = 0
            elif options['message-type'] == 5: # DHCPACK
                logger.debug('Received DHCPACK')
                state = StateMachine.BOUND
                # Is it sufficient to just set rt to T1?
                lease_time = options.get('lease_time', 0)
                client_ip = reply[BOOTP].yiaddr
                server_mac = reply[Ether].src
                rt = 0.5 * lease_time
                self.process_reply(reply, options)


    def __call__(self, *args: Any, **kwds: Any) -> Any:
        return asyncio.create_task(self.client())
