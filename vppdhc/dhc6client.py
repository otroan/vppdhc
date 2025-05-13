# pylint: disable=import-error, invalid-name, logging-fstring-interpolation

"""DHCPv6 IA_PD client"""

import asyncio
import logging
import random
from enum import IntEnum
from ipaddress import IPv6Address, IPv6Network

import asyncio_dgram
from pydantic import BaseModel, ConfigDict
from scapy.layers.dhcp6 import (
    DUID_LL,
    DHCP6_Advertise,
    DHCP6_Renew,
    DHCP6_Reply,
    DHCP6_Request,
    DHCP6_Solicit,
    DHCP6OptClientId,
    DHCP6OptIA_NA,
    DHCP6OptIA_PD,
    DHCP6OptIAAddress,
    DHCP6OptIAPrefix,
    DHCP6OptServerId,
    DHCP6OptStatusCode,
)
from scapy.layers.inet6 import UDP, IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from vppdhc.datamodel import (
    DHC6_IANA,
    DHC6_IAPD,
    DHC6_IAAddr,
    DHC6_IAPrefix,
    DHC6ClientBinding,
)
from vppdhc.vppdb import VPPDB, register_vppdb_model
from vppdhc.vpppunt import Actions, VPPPunt

logger = logging.getLogger(__name__)
packet_logger = logging.getLogger(f"{__name__}.packet")


@register_vppdb_model("dhc6client")
class ConfDHC6Client(BaseModel):
    """DHCPv6 PD client configuration."""

    model_config = ConfigDict(populate_by_name=True)
    interface: str
    ia_pd: bool = True
    ia_na: bool = False


class StateMachine(IntEnum):
    """DHCPv6 PD Client states."""

    INIT = 0
    SELECTING = 1
    REQUESTING = 2
    BOUND = 3
    RENEWING = 4
    RELEASING = 5


class DHC6Client:
    """DHCPv6 Client."""

    def __init__(self, receive_socket, send_socket, vpp, conf: VPPDB):
        self.receive_socket = receive_socket
        self.send_socket = send_socket
        self.vpp = vpp
        self.cdb = conf

        dhc6_conf = conf.get("/dhc6client")
        sys_conf = conf.get("/system")
        print("DHCP6 CLIENT CONFIG", dhc6_conf)
        self.if_name = dhc6_conf.interface
        self.tenant_id = sys_conf.bypass_tenant
        self.state = StateMachine.INIT
        self.binding = None

        self.ia_pd = dhc6_conf.ia_pd
        self.ia_na = dhc6_conf.ia_na

        self.bindings = {}

    async def validate_reply(self, reply: Packet) -> bool:
        """Validate a DHCPv6 reply packet."""
        if self.ia_pd:
            if reply.haslayer(DHCP6OptIA_PD):
                iapd = reply[DHCP6OptIA_PD]
                if iapd.haslayer(DHCP6OptStatusCode):
                    logger.error("DHCPv6 error: %s", iapd.getlayer(DHCP6OptStatusCode))
                    return False
            else:
                return False
        if self.ia_na:
            if reply.haslayer(DHCP6OptIA_NA):
                iana = reply[DHCP6OptIA_NA]
                if iana.haslayer(DHCP6OptStatusCode):
                    logger.error("DHCPv6 error: %s", iana.getlayer(DHCP6OptStatusCode))
                    return False
            else:
                return False
        return True

    async def on_lease(self, bindings: DHC6ClientBinding) -> None:
        """Send event."""
        try:
            self.cdb.set("/ops/dhc6c/lease", bindings)
        except Exception as e:
            logger.exception("Error setting lease: %s", e)
            raise

    async def process_reply(self, reply: Packet) -> None:
        """Process a DHCPv6 reply packet."""
        rt = 1  # SOL_TIMEOUT
        nexthop = reply[IPv6].src
        macsrc = reply[Ether].src
        iana = iapd = None
        if reply.haslayer(DHCP6OptIA_PD):
            iapd_opt = reply[DHCP6OptIA_PD]
            iaprefix = iapd_opt[DHCP6OptIAPrefix]
            pdprefix = IPv6Network(f"{iaprefix.prefix}/{iaprefix.plen}")
            rt = iapd_opt.T1
            iapd = DHC6_IAPD(
                prefixes=[DHC6_IAPrefix(prefix=pdprefix, preferred=iaprefix.preflft, valid=iaprefix.validlft)],
                T1=iapd_opt.T1,
                T2=iapd_opt.T2,
                iaid=iapd_opt.iaid,
            )
        if reply.haslayer(DHCP6OptIA_NA):
            iana_opt = reply[DHCP6OptIA_NA]
            iaaddr = iana_opt[DHCP6OptIAAddress]
            address = IPv6Address(iaaddr.addr)
            rt = iana_opt.T1

            iana = DHC6_IANA(
                addresses=[DHC6_IAAddr(address=address, preferred=iaaddr.preflft, valid=iaaddr.validlft)],
                T1=iana_opt.T1,
                T2=iana_opt.T2,
                iaid=iana_opt.iaid,
            )

        self.bindings = DHC6ClientBinding(ia_pd=[iapd], ia_na=[iana], macsrc=macsrc, nexthop=nexthop)
        await self.on_lease(self.bindings)

        return rt

    async def client(self):
        """DHCPv6 Client."""
        self.if_index = await self.vpp.vpp_interface_name2index(self.if_name)
        logger.debug("Getting interface index for: %s %s", self.if_name, self.if_index)

        interface_info = await self.vpp.vpp_interface_info(self.if_index)
        logger.debug("Interface info: %s", interface_info)

        # Create a DUID-LL with the MAC address
        duid = DUID_LL(lladdr=interface_info.mac)

        reader = await asyncio_dgram.bind(self.receive_socket)
        writer = await asyncio_dgram.connect(self.send_socket)
        self.state = StateMachine.INIT
        reply = None
        rt = 1  # SOL_TIMEOUT
        rc = 0
        while True:
            if self.state == StateMachine.INIT:
                # Send DHCPv6 PD solicit scapy
                solicit = (
                    Ether(src=interface_info.mac, dst="33:33:00:01:00:02")
                    / IPv6(src=interface_info.ip6ll, dst="ff02::1:2")
                    / UDP(sport=546, dport=547)
                    / DHCP6_Solicit()
                    / DHCP6OptClientId(duid=duid)
                )

                if self.ia_pd:
                    solicit = solicit / DHCP6OptIA_PD()
                if self.ia_na:
                    solicit = solicit / DHCP6OptIA_NA()
                solicit = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / solicit

                packet_logger.debug("Sending SOLICIT: %s", solicit.show2(dump=True))
                await writer.send(bytes(solicit))

                rt = 2 * rt + random.uniform(-0.1, 0.1) * rt  # noqa: S311
                rt = min(rt, 3600)  # MAX_SOL_TIMEOUT
            elif self.state == StateMachine.REQUESTING:
                # Send DHCPv6 request
                serverid = reply[DHCP6OptServerId]
                request = (
                    Ether(src=interface_info.mac, dst=reply[Ether].src)
                    / IPv6(src=interface_info.ip6ll, dst="ff02::1:2")
                    / UDP(sport=546, dport=547)
                    / DHCP6_Request()
                    / DHCP6OptClientId(duid=duid)
                    / serverid
                )
                if self.ia_pd and reply.haslayer(DHCP6OptIA_PD):
                    request /= reply[DHCP6OptIA_PD]
                if self.ia_na and reply.haslayer(DHCP6OptIA_NA):
                    request /= reply[DHCP6OptIA_NA]

                request = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / request
                rc += 1

                packet_logger.debug("Sending REQUEST %s", request.show2(dump=True))
                await writer.send(bytes(request))

                rt = 2 * rt + random.uniform(-0.1, 0.1) * rt  # noqa: S311
                rt = min(rt, 30)  # REQ_MAX_RT
                if rc > 10:
                    self.state = StateMachine.INIT
                    logger.warning("REQUEST timeout")
            elif self.state == StateMachine.RENEWING:
                # Renew lease
                renew = (
                    Ether(src=interface_info.mac, dst=reply[Ether].src)
                    / IPv6(src=interface_info.ip6ll, dst="ff02::1:2")
                    / UDP(sport=546, dport=547)
                    / DHCP6_Renew()
                    / DHCP6OptClientId(duid=duid)
                    / DHCP6OptServerId(duid=serverid)
                    / self.bindings
                )
                renew = VPPPunt(iface_index=self.if_index, action=Actions.PUNT_L2) / renew
                packet_logger.debug("Sending RENEW %s", renew.show2(dump=True))
                rc += 1
                await writer.send(bytes(renew))

                rt = 2 * rt + random.uniform(-0.1, 0.1) * rt  # noqa: S311
                rt = min(rt, 30)  # REQ_MAX_RT
                if rc > 10:
                    self.state = StateMachine.INIT
                    logger.warning("REQUEST timeout")

            # Receive on uds socket
            try:
                reply, _ = await asyncio.wait_for(reader.recv(), timeout=rt)
            except TimeoutError:
                if self.state == StateMachine.BOUND:
                    self.state = StateMachine.RENEWING
                logger.warning("Timeout")
                continue

            # Decode packet with scapy
            reply = VPPPunt(reply)
            packet_logger.debug("Received from server %s", reply.show2(dump=True))

            if reply.haslayer(DHCP6_Advertise):
                logger.debug("Received DHCPv6 Advertise")
                if not await self.validate_reply(reply):
                    logger.error("Invalid DHCPv6 Advertise")
                    self.state = StateMachine.INIT
                    await asyncio.sleep(rt)
                else:
                    self.state = StateMachine.REQUESTING
                    rc = 0
            elif reply.haslayer(DHCP6_Reply):
                logger.debug("Received DHCPv6 Reply")
                self.state = StateMachine.BOUND
                # Is it sufficient to just set rt to T1?
                # Process reply failed, wait for a RT before retrying
                if not await self.validate_reply(reply):
                    logger.error("Invalid DHCPv6 Reply")
                    self.state = StateMachine.INIT
                    await asyncio.sleep(rt)
                else:
                    try:
                        rt = await self.process_reply(reply)
                    except Exception:
                        logger.exception("Error processing reply")
                        await asyncio.sleep(rt)

    async def cleanup(self) -> None:
        """Clean up resources."""
        if hasattr(self, "_reader"):
            self._reader.close()
        if hasattr(self, "_writer"):
            self._writer.close()

    async def __aenter__(self) -> "DHC6Client":
        """Enter async context."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit async context."""
        await self.cleanup()
