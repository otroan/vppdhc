# pylint: disable=import-error, invalid-name, logging-fstring-interpolation

'''
Stateless DHCPv6 IA_NA Server
'''

import logging
import asyncio
import hashlib
from typing import Any
from ipaddress import IPv6Address
from scapy.layers.l2 import Ether
from scapy.layers.dhcp6 import (DHCP6, DHCP6_Solicit, DHCP6_Release, DHCP6_Decline, DHCP6_Rebind,
                                DHCP6_Request, DHCP6_Advertise, DHCP6_Confirm,
                                DHCP6_Reply, DHCP6_Renew, DHCP6OptClientId, DHCP6OptServerId,
                                DHCP6OptIA_NA, DHCP6OptIAAddress, DUID_LL,
                                DHCP6OptDNSServers, DHCP6OptStatusCode)
from scapy.layers.inet6 import IPv6, UDP
import asyncio_dgram
from vppdhc.vpppunt import VPPPunt, Actions

# Configuration
# If no configuration is given, the DHCPv6 server will find the prefix(es) configured
# on the interface and serve addresses from those prefixes.
# If one or more interfaces are configured, the DHCPv6 server will only respond
# to requests on those interfaces.

logger = logging.getLogger(__name__)

class DHCPv6Server(): # pylint: disable=too-many-instance-attributes
    '''DHCPv6 Server'''
    def __init__(self, receive_socket, send_socket, vpp, conf):
        self.receive_socket = receive_socket
        self.send_socket = send_socket
        self.vpp = vpp

        self.if_names = conf.interfaces
        self.if_name = self.if_names[0]

        self.if_index = self.vpp.vpp_interface_name2index(self.if_name)
        logger.debug(f'Getting interface index for: {self.if_name} {self.if_index}')

        self.preflft = conf.preflft
        self.validlft = conf.validlft
        self.dns = conf.dns

        self.interface_info = self.vpp.vpp_interface_info(self.if_index)

        # Give out addresses from the first prefix configured on the interface
        self.prefix = self.interface_info.ip6[0].network

        logger.debug(f"Interface info: {self.interface_info}")
        logger.debug(f'Serving, prefix: {self.prefix} on interface {self.if_name}')

        # Create a DUID-LL with the MAC address
        self.duid = DUID_LL(lladdr=self.interface_info.mac)

        # Add a route in the MFIB for the all DHCP servers and relays address
        self.vpp.vpp_ip_multicast_group_join('ff02::1:2')

    def mk_address(self, clientduid, iaid):
        '''Create an IPv6 address from the client's DUID and IAID'''
        interface_id = hashlib.sha256(bytes(clientduid) + iaid.to_bytes(4, 'big')).digest()[:8]

        # Concatenate self.prefix and interface_id to create the IPv6 address
        return IPv6Address(int(self.prefix.network_address) + int.from_bytes(interface_id, 'big'))

    def process_solicit(self, solicit):
        '''Process a DHCPv6 solicit/request packet'''

        # Create an interface identifier from the client's DUID
        clientid = solicit[DHCP6OptClientId]
        clientduid = clientid.duid
        iaid = solicit[DHCP6OptIA_NA].iaid

        ipv6 = self.mk_address(clientduid, iaid)
        logger.debug(f'Allocating IPv6 address {ipv6} to client {clientduid} '
                      'from {solicit[IPv6].src}')
        t1 = int(0.5 * self.preflft)
        t2 = int(0.875 * self.preflft)

        advertise = (Ether(src=self.interface_info.mac, dst=solicit[Ether].src) /
                    IPv6(src=self.interface_info.ip6ll, dst=solicit[IPv6].src) /
                    UDP(sport=547, dport=546) /
                    DHCP6_Advertise(trid=solicit[DHCP6_Solicit].trid) /
                    DHCP6OptServerId(duid=self.duid) /
                    DHCP6OptClientId(duid=clientduid))

        if self.dns:
            advertise /= DHCP6OptDNSServers(dnsservers=self.dns)

        advertise /=  (DHCP6OptIA_NA(iaid=solicit[DHCP6OptIA_NA].iaid, T1=t1, T2=t2,
                                  ianaopts = DHCP6OptIAAddress(addr=ipv6,
                                                               preflft=self.preflft,
                                                               validlft=self.validlft))
                    )

        advertise = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / advertise
        # advertise.show2()
        return advertise

    def process_request(self, request, trid, msgtype):
        '''Process a DHCPv6 solicit/request packet'''

        # Create an interface identifier from the client's DUID
        clientid = request[DHCP6OptClientId]
        clientduid = clientid.duid
        iaid = request[DHCP6OptIA_NA].iaid

        ipv6 = self.mk_address(clientduid, iaid)
        if msgtype == 3:
            logger.debug(f'Allocating IPv6 address {ipv6} to client '
                          '{clientduid} from {request[IPv6].src}')
        else:
            logger.debug(f'Refreshing IPv6 address {ipv6} to client '
                          '{clientduid} from {request[IPv6].src}')

        t1 = int(0.5 * self.preflft)
        t2 = int(0.875 * self.preflft)

        reply = (Ether(src=self.interface_info.mac, dst=request[Ether].src) /
                    IPv6(src=self.interface_info.ip6ll, dst=request[IPv6].src) /
                    UDP(sport=547, dport=546) /
                    DHCP6_Reply(trid=trid) /
                    DHCP6OptServerId(duid=self.duid) /
                    DHCP6OptClientId(duid=clientduid) /
                    DHCP6OptIA_NA(iaid=request[DHCP6OptIA_NA].iaid, T1=t1, T2=t2,
                                  ianaopts = DHCP6OptIAAddress(addr=ipv6,
                                                               preflft=self.preflft,
                                                               validlft=self.validlft)
                    )
        )
        if self.dns:
            reply /= DHCP6OptDNSServers(dnsservers=self.dns)

        reply = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / reply
        # reply.show2()
        return reply

    def process_release(self, release, trid):
        '''Process a DHCPv6 Release packet'''
        logger.error('Received DHCPv6 Release %s', release.show2(dump=True))
        clientid = release[DHCP6OptClientId]
        clientduid = clientid.duid

        reply = (Ether(src=self.interface_info.mac, dst=release[Ether].src) /
            IPv6(src=self.interface_info.ip6ll, dst=release[IPv6].src) /
            UDP(sport=547, dport=546) /
            DHCP6_Reply(trid=trid) /
            DHCP6OptServerId(duid=self.duid) /
            DHCP6OptClientId(duid=clientduid) /
            DHCP6OptStatusCode(statuscode=0, statusmsg='Success')
            )
        return reply

    def process_decline(self, decline, trid):
        '''Process a DHCPv6 Decline packet'''
        logger.error('Received DHCPv6 Decline %s', decline.show2(dump=True))
        clientid = decline[DHCP6OptClientId]
        clientduid = clientid.duid

        reply = (Ether(src=self.interface_info.mac, dst=decline[Ether].src) /
            IPv6(src=self.interface_info.ip6ll, dst=decline[IPv6].src) /
            UDP(sport=547, dport=546) /
            DHCP6_Reply(trid=trid) /
            DHCP6OptServerId(duid=self.duid) /
            DHCP6OptClientId(duid=clientduid) /
            DHCP6OptStatusCode(statuscode=0, statusmsg='Success')
            )
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
            if request[VPPPunt].iface_index != self.if_index:
                logger.error('Received packet on wrong interface %s', request.show2(dump=True))
                continue

            # logger.debug(f'Received from client {request.show2(dump=True)}')
            # request.show2()

            p = request[IPv6].payload
            p = p.payload
            if not isinstance(p, DHCP6):
                logger.warning('Unknown packet received, not DHCPv6 %s', p.__class__.__name__)
                continue
            msgtype = p.msgtype
            trid = p.trid

            if request.haslayer(DHCP6_Solicit):
                logger.debug('Received DHCPv6 Solicit')
                reply = self.process_solicit(request)
            elif (request.haslayer(DHCP6_Request) or request.haslayer(DHCP6_Confirm) or
                request.haslayer(DHCP6_Renew) or request.haslayer(DHCP6_Rebind)):
                logger.debug('Received DHCPv6 Request, Renew, Rebind')
                reply = self.process_request(request, trid, msgtype)
            elif request.haslayer(DHCP6_Release):
                reply = self.process_release(request, trid)
            elif request.haslayer(DHCP6_Decline):
                reply = self.process_decline(request, trid)
            else:
                logger.debug('Received DHCPv6 Unknown')
                continue

            if reply:
                await writer.send(bytes(reply))

    def __call__(self, *args: Any, **kwds: Any) -> Any:
        return asyncio.create_task(self.listen())
