# pylint: disable=import-error, invalid-name, logging-fstring-interpolation

"""
Stateless DHCPv6 IA_NA Server
"""

# TODO
# Don't use interface information in configuration.
# Dynamically create a pool for any interface
#
import random
import hashlib
import logging
from ipaddress import IPv6Address, IPv6Network

import asyncio_dgram  # type: ignore
from scapy.all import Packet  # type: ignore
from scapy.layers.dhcp6 import (  # type: ignore
    DHCP6,
    DUID_LL,
    DHCP6_Advertise,
    DHCP6_Confirm,
    DHCP6_Decline,
    DHCP6_InfoRequest,
    DHCP6_Rebind,
    DHCP6_Release,
    DHCP6_Renew,
    DHCP6_Reply,
    DHCP6_Request,
    DHCP6_Solicit,
    DHCP6OptClientId,
    DHCP6OptDNSServers,
    DHCP6OptIA_NA,
    DHCP6OptIA_PD,
    DHCP6OptIAAddress,
    DHCP6OptIAPrefix,
    DHCP6OptServerId,
    DHCP6OptStatusCode,
)
from scapy.layers.inet6 import UDP, IPv6  # type: ignore
from scapy.layers.l2 import Ether  # type: ignore

from vppdhc.vppdhcdctl import register_command
from vppdhc.vpppunt import Actions, VPPPunt

# Configuration
# If no configuration is given, the DHCPv6 server will find the prefix(es) configured
# on the interface and serve addresses from those prefixes.
# If one or more interfaces are configured, the DHCPv6 server will only respond
# to requests on those interfaces.

logger = logging.getLogger(__name__)
packet_logger = logging.getLogger(f"{__name__}.packet")


@register_command("dhcp6", "bindings")
def command_dhcp6_binding(args=None) -> str:
    """Show DHCP bindings."""
    if args:
        return f"Binding command with args: {args}"
    # Get DHCPServer singleton instance
    return "NOT IMPLEMENTED"
    # dhcp = DHCPv6Server.get_instance()
    # s = ""
    # for v in dhcp.dbs.values():
    #     s += v.model_dump_json(indent=4, exclude_none=True)
    # return s


class DHC6Server:  # pylint: disable=too-many-instance-attributes
    """DHCPv6 Server."""

    def __init__(self, receive_socket, send_socket, vpp, conf):
        self.receive_socket = receive_socket
        self.send_socket = send_socket
        self.vpp = vpp

        self.if_names = conf.interfaces
        self.if_name = self.if_names[0]

        self.preflft = conf.preflft
        self.validlft = conf.validlft
        self.dns = conf.dns
        self.ia_pd = bool(conf.ia_prefix)
        self.ia_prefix = conf.ia_prefix[0]
        self.pd_allocate_length = conf.ia_allocate_length
        self.ia_na = conf.ia_na
        self.prefix_leases = {}

    def mk_address(self, clientduid, iaid):
        """Create an IPv6 address from the client's DUID and IAID."""
        interface_id = hashlib.sha256(bytes(clientduid) + iaid.to_bytes(4, "big")).digest()[:8]

        # Concatenate self.prefix and interface_id to create the IPv6 address
        return IPv6Address(int(self.prefix.network_address) + int.from_bytes(interface_id, "big"))

    def mk_prefix(self, clientduid, iaid):
        """Allocate an IPv6 prefix from the client's DUID and IAID."""
        for subnet in self.ia_prefix.subnets(new_prefix=self.pd_allocate_length):
            if subnet not in self.prefix_leases:
                self.prefix_leases[subnet] = clientduid
                return subnet
        raise ValueError("No free prefixes available!")

    def process_request(self, request: Packet, trid, msgtype) -> Packet:
        """Process a DHCPv6 solicit/request packet."""
        clientid = request[DHCP6OptClientId]
        clientduid = clientid.duid
        reply_msg = DHCP6_Advertise(trid=trid) if msgtype == 1 else DHCP6_Reply(trid=trid)
        reply = (
            Ether(src=self.interface_info.mac, dst=request[Ether].src)
            / IPv6(src=self.interface_info.ip6ll, dst=request[IPv6].src)
            / UDP(sport=547, dport=546)
            / reply_msg
            / DHCP6OptServerId(duid=self.duid)
            / DHCP6OptClientId(duid=clientduid)
        )

        if self.dns:
            reply /= DHCP6OptDNSServers(dnsservers=self.dns)

        if self.ia_na:
            if request.haslayer(DHCP6OptIA_NA):
                iaid = request[DHCP6OptIA_NA].iaid
                ipv6 = self.mk_address(clientduid, iaid)
                logger.debug("Allocating IPv6 address %s to client %s from %s", ipv6, clientduid, request[IPv6].src)
                t1 = int(0.5 * self.preflft)
                t2 = int(0.875 * self.preflft)
                reply /= DHCP6OptIA_NA(
                    iaid=iaid,
                    T1=t1,
                    T2=t2,
                    ianaopts=DHCP6OptIAAddress(addr=ipv6, preflft=self.preflft, validlft=self.validlft),
                )
            else:
                packet_logger.error("Received DHCPv6 solicit with IA_NA %s", request.show(dump=True))
                reply /= DHCP6OptIA_NA(
                    ianaopts=DHCP6OptStatusCode(statuscode=2, statusmsg="Why do you think we support IA_NA here?")
                )

        if self.ia_pd:
            if request.haslayer(DHCP6OptIA_PD):
                iaid = request[DHCP6OptIA_PD].iaid
                ipv6 = self.mk_prefix(clientduid, iaid)
                logger.debug("Allocating IPv6 prefix %s to client %s from %s", ipv6, clientduid, request[IPv6].src)
                t1 = int(0.5 * self.preflft)
                t2 = int(0.875 * self.preflft)
                reply /= DHCP6OptIA_PD(
                    iaid=iaid,
                    T1=t1,
                    T2=t2,
                    iapdopt=DHCP6OptIAPrefix(prefix=ipv6.network_address,
                                             plen=ipv6.prefixlen,
                                             preflft=self.preflft, validlft=self.validlft),
                )
            else:
                packet_logger.error("Received DHCPv6 solicit with IA_PD %s", request.show(dump=True))
                reply /= DHCP6OptIA_PD(
                    iapdopt=DHCP6OptStatusCode(statuscode=6, statusmsg="Why do you think we support PD here?")
                )

        return VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / reply

    # def process_request(self, request: Packet, trid: int, msgtype: int) -> Packet:
    #     """Process a DHCPv6 solicit/request packet."""
    #     # Create an interface identifier from the client's DUID
    #     clientid = request[DHCP6OptClientId]
    #     clientduid = clientid.duid

    #     reply = (
    #         Ether(src=self.interface_info.mac, dst=request[Ether].src)
    #         / IPv6(src=self.interface_info.ip6ll, dst=request[IPv6].src)
    #         / UDP(sport=547, dport=546)
    #         / DHCP6_Reply(trid=trid)
    #         / DHCP6OptServerId(duid=self.duid)
    #         / DHCP6OptClientId(duid=clientduid)
    #     )

    #     if request.haslayer(DHCP6OptIA_NA):
    #         iaid = request[DHCP6OptIA_NA].iaid
    #         ipv6 = self.mk_address(clientduid, iaid)
    #         if msgtype == 3:
    #             logger.debug("Allocating IPv6 address %s to client %s from %s", ipv6, clientduid, request[IPv6].src)
    #         else:
    #             logger.debug("Refreshing IPv6 address %s to client %s from %s", ipv6, clientduid, request[IPv6].src)

    #         t1 = int(0.5 * self.preflft)
    #         t2 = int(0.875 * self.preflft)

    #         reply /= DHCP6OptIA_NA(
    #             iaid=request[DHCP6OptIA_NA].iaid,
    #             T1=t1,
    #             T2=t2,
    #             ianaopts=DHCP6OptIAAddress(addr=ipv6, preflft=self.preflft, validlft=self.validlft),
    #         )

    #     if request.haslayer(DHCP6OptIA_PD):
    #         packet_logger.error("Received DHCPv6 request with IA_PD %s", request.show(dump=True))
    #         reply /= DHCP6OptIA_PD(
    #             iapdopt=DHCP6OptStatusCode(statuscode=6, statusmsg="Why do you think we support PD here?")
    #         )

    #     if self.dns:
    #         reply /= DHCP6OptDNSServers(dnsservers=self.dns)

    #     return VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / reply

    def process_release(self, release: Packet, trid: int) -> Packet:
        """Process a DHCPv6 Release packet."""
        logger.error("Received DHCPv6 Release %s", release.show2(dump=True))
        clientid = release[DHCP6OptClientId]
        clientduid = clientid.duid

        reply = (
            Ether(src=self.interface_info.mac, dst=release[Ether].src)
            / IPv6(src=self.interface_info.ip6ll, dst=release[IPv6].src)
            / UDP(sport=547, dport=546)
            / DHCP6_Reply(trid=trid)
            / DHCP6OptServerId(duid=self.duid)
            / DHCP6OptClientId(duid=clientduid)
            / DHCP6OptStatusCode(statuscode=0, statusmsg="Success")
        )
        return reply

    def process_decline(self, decline: Packet, trid: int) -> Packet:
        """Process a DHCPv6 Decline packet."""
        logger.error("Received DHCPv6 Decline %s", decline.show2(dump=True))
        clientid = decline[DHCP6OptClientId]
        clientduid = clientid.duid

        return (
            Ether(src=self.interface_info.mac, dst=decline[Ether].src)
            / IPv6(src=self.interface_info.ip6ll, dst=decline[IPv6].src)
            / UDP(sport=547, dport=546)
            / DHCP6_Reply(trid=trid)
            / DHCP6OptServerId(duid=self.duid)
            / DHCP6OptClientId(duid=clientduid)
            / DHCP6OptStatusCode(statuscode=0, statusmsg="Success")
        )

    async def listen(self) -> None:
        """DHCPv6 Server."""

        self.if_index = await self.vpp.vpp_interface_name2index(self.if_name)
        logger.debug("Getting interface index for: %s %s", self.if_name, self.if_index)

        self.interface_info = await self.vpp.vpp_interface_info(self.if_index)

        # Give out addresses from the first prefix configured on the interface
        self.prefix = self.interface_info.ip6[0].network

        logger.debug("Interface info: %s", self.interface_info)
        logger.debug("Serving, prefix: %s on interface %s", self.prefix, self.if_name)

        # Create a DUID-LL with the MAC address
        self.duid = DUID_LL(lladdr=self.interface_info.mac)

        # Add a route in the MFIB for the all DHCP servers and relays address
        await self.vpp.vpp_ip_multicast_group_join("ff02::1:2")

        reader = await asyncio_dgram.bind(self.receive_socket)
        writer = await asyncio_dgram.connect(self.send_socket)

        while True:
            # Receive on uds socket
            (packet, _) = await reader.recv()

            # Decode packet with scapy
            packet = VPPPunt(packet)
            if packet[VPPPunt].iface_index != self.if_index:
                logger.error("Received packet on wrong interface %s", packet.show2(dump=True))
                continue

            p = packet[IPv6].payload
            p = p.payload
            if not isinstance(p, DHCP6):
                logger.warning("Unknown packet received, not DHCPv6 %s", p.__class__.__name__)
                continue
            msgtype = p.msgtype
            trid = p.trid

            if packet.haslayer(DHCP6_Solicit):
                logger.debug("Received DHCPv6 Solicit")
                reply = self.process_request(packet, trid, msgtype)
                # reply = self.process_solicit(packet)
            elif (
                packet.haslayer(DHCP6_Request)
                or packet.haslayer(DHCP6_Confirm)
                or packet.haslayer(DHCP6_Renew)
                or packet.haslayer(DHCP6_Rebind)
            ):
                logger.debug("Received DHCPv6 Request, Renew, Rebind")
                reply = self.process_request(packet, trid, msgtype)
            elif packet.haslayer(DHCP6_Release):
                reply = self.process_release(packet, trid)
            elif packet.haslayer(DHCP6_Decline):
                reply = self.process_decline(packet, trid)
            elif packet.haslayer(DHCP6_InfoRequest):
                logger.info("Received DHCPv6 Information Request")
                continue
            else:
                logger.error("Received DHCPv6 Unknown: %s", msgtype)
                packet_logger.debug(packet.show2(dump=True))
                continue

            if reply:
                await writer.send(bytes(reply))
