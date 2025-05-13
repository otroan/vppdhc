#!/usr/bin/env python3
"""DHCPv4 server."""

# TODO
# Clean up probed duplicates after timeout
# Clean up expired leases

import hashlib
import logging
import time
from enum import Enum
from ipaddress import IPv4Address, IPv4Network

import asyncio_dgram
from pydantic import BaseModel, ConfigDict, Field, conint, field_serializer
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import str2mac

from vppdhc.vppdb import VPPDB, register_vppdb_model
from vppdhc.vppdhcdctl import register_command
from vppdhc.vpppunt import Actions, VPPPunt

logger = logging.getLogger(__name__)
packet_logger = logging.getLogger(f"{__name__}.packet")


@register_vppdb_model("dhc4server")
class ConfDHC4Server(BaseModel):
    """DHCPv4 server configuration."""

    model_config = ConfigDict(populate_by_name=True)
    lease_time: int = Field(alias="lease-time")
    renewal_time: int = Field(alias="renewal-time")
    dns: list[IPv4Address]
    ipv6_only_preferred: bool = Field(alias="ipv6-only-preferred", default=False)


class DHC4ServerNoIPaddrAvailableError(Exception):
    """No IP address available."""


##### DHCP Binding database #####


@register_command("dhcp", "bindings")
def command_dhcp_binding(args=None) -> str:
    """Show DHCP bindings."""
    if args:
        return f"Binding command with args: {args}"
    # Get DHCPServer singleton instance

    dhcp = DHC4Server.get_instance()
    s = ""
    for v in dhcp.dbs.values():
        s += v.model_dump_json(indent=4, exclude_none=True)
    return s


def options2dict(packet) -> dict:
    """Get DHCP message type."""
    # Return all options in a dictionary
    # Using a dict comprehension
    options = {}
    for op in packet[DHCP].options:
        options[op[0]] = op[1]
    return options


def get_ip_index(ip: str, network: str) -> int:
    """Get the index of an IP address in a network."""
    ip_address = IPv4Address(ip)
    network_address = IPv4Network(network)

    # Check if the IP is in the network
    if ip_address in network_address:
        # Calculate the index
        return int(ip_address) - int(network_address.network_address)
    raise ValueError


def get_epoch() -> int:
    """Get the current epoch time."""
    return int(time.time())


class DHC4BindingState(Enum):
    """State of the binding."""

    BOUND = "BOUND"
    DECLINED = "DECLINED"
    IN_USE = "IN_USE"
    RESERVED = "RESERVED"
    OFFERED = "OFFERED"


class DHC4Lease(BaseModel):
    """DHCPv4 Lease information."""

    ip_address: IPv4Address  # The IPv4 address assigned to the client
    mac_address: bytes
    hostname: str | None  # Hostname, if provided by the client
    last_updated: int  # Timestamp for when the lease was first issued
    status: DHC4BindingState
    client_id: bytes | None  # DHCP client identifier (if used by the client)

    @field_serializer("mac_address")
    def serialize_mac_address(self, value: bytes) -> str:
        # Serialize `bytes` to Base64-encoded string
        return str2mac(value)

    @field_serializer("client_id")
    def serialize_client_id(self, value: bytes) -> str:
        # Serialize `bytes` to Base64-encoded string
        if value is None:
            return ""
        return value.hex()


class DHC4ServerNoIPaddrAvailableError(Exception):
    pass


class DHC4BindingDatabase(BaseModel):
    """DHCPv4 Binding database."""

    ifindex: int
    interface: str
    mac_address: bytes
    server_ip: IPv4Address
    leases: list[DHC4Lease | None]  # List of DHCP leases (each representing a client binding)
    network: IPv4Network  # The network the DHCP server is serving, e.g., "192.168.1.0/24"
    dns_servers: list[IPv4Address] | None  # List of DNS servers provided by DHCP
    lease_time_default: conint(gt=0) = 86400  # Default lease time in seconds (e.g., 24 hours)
    lease_by_client_id: dict[bytes, int]  # Index of bindings by MAC address
    model_config = ConfigDict(extra="allow")

    @field_serializer("mac_address")
    def serialize_mac_address(self, value: bytes) -> str:
        return str2mac(value)

    @field_serializer("lease_by_client_id")
    def serialize_lease_by_client_id(self, value: bytes) -> str:
        return None

    @field_serializer("leases")
    def serialize_leases(self, value: list[DHC4Lease | None]) -> list[DHC4Lease]:
        """Filter out None values from leases list."""
        return [lease for lease in value if lease is not None]

    def static_ip(self, ip: IPv4Address) -> None:
        """Reserve an IP address."""
        index = get_ip_index(ip, self.network)
        self.leases[index] = DHC4Lease(
            ip_address=ip,
            mac_address=b"",
            hostname=None,
            last_updated=0,
            status=DHC4BindingState.RESERVED,
            client_id=None,
            renew_time=None,
            rebind_time=None,
        )

    def __init__(self, **data):
        """Initialize the DHCPv4 binding database."""
        super().__init__(**data)
        self.__post_init__()

    def __post_init__(self) -> "DHC4BindingDatabase":
        """Post-init hook."""
        # Extend the list with None to accommodate the new index
        self.leases.extend([None] * (self.network.num_addresses))
        # Reserve the first 10% of a prefix to manually configured addresses up to 256 addresses
        reserved = min(int(self.network.num_addresses / 10), 256)
        logger.debug(
            "Creating new DHCP binding database for: %s %s reserved %d",
            self.interface,
            self.network,
            reserved,
        )
        reserved_addresses = list(self.network)[:reserved]
        for ip in reserved_addresses:
            # Set a lease for the reserved addresses at given index
            self.static_ip(ip)
        self.static_ip(self.server_ip)  # Reserve the router address
        self.probed_duplicates = {}  # Probed duplicates

    def get_next_free(self, client_id: bytes, reqip=None) -> IPv4Address:
        """Get the next free IP address."""
        if client_id in self.lease_by_client_id:
            # Client already has an address. Return the same
            index = self.lease_by_client_id[client_id]
            return self.leases[index].ip_address
        if reqip is not None:
            ip = reqip
        else:
            # Require a new address
            # Hash the client identifier (or MAC address) to generate a unique identifier
            uid = hashlib.sha256(client_id).digest()
            uid_int = int.from_bytes(uid[:4], byteorder="big")

            ip = IPv4Address(self.network.network_address + uid_int % self.network.num_addresses)

        # Check if IP address is in pool
        if self.in_use(ip) or ip in self.probed_duplicates:
            # IP address is in use, pick another one
            for ip in self.network.hosts():
                # Check if ip is in bindings
                if not self.in_use(ip) and ip not in self.probed_duplicates:
                    break
            else:
                raise DHC4ServerNoIPaddrAvailableError
        logger.debug("Next free IP address: %s to %s", ip, client_id)
        return ip

    def in_use(self, ip) -> bool:
        """Is the IP address in use."""
        try:
            index = get_ip_index(ip, self.network)
        except ValueError:
            return False
        lease = self.leases[index]
        if lease is None:
            return False
        if lease.status == DHC4BindingState.RESERVED or lease.last_updated == 0:
            return True
        if lease.last_updated + self.lease_time_default < get_epoch():
            # Lease expired
            logger.debug("Lease expired: %s", ip)
            self.leases[index] = None
            try:
                del self.lease_by_client_id[lease.client_id]
                del self.leases[index]
            except KeyError:
                pass
            self.leases[index] = None
            return False

        return self.leases[index] is not None

    def broadcast_address(self) -> IPv4Address:
        """Return broadcast address."""
        return self.prefix.broadcast_address

    def subnet_mask(self) -> IPv4Address:
        """Return subnet mask."""
        return self.network.netmask

    def reserve(self, mac_address: bytes, client_id: bytes, hostname: str, reqip=None) -> IPv4Address:
        """Reserve a new IP address."""
        ip = self.get_next_free(client_id, reqip)

        lease = DHC4Lease(
            ip_address=ip,
            mac_address=mac_address,
            hostname=hostname,
            last_updated=get_epoch(),
            status=DHC4BindingState.OFFERED,
            client_id=client_id,
            renew_time=None,
            rebind_time=None,
        )

        index = get_ip_index(ip, self.network)
        self.leases[index] = lease
        self.lease_by_client_id[client_id] = index

        logger.debug("Reservering IP address: %s to %s", ip, mac_address)

        return ip

    async def reserve_with_probe(self, vpp, mac_address, clientid, hostname) -> IPv4Address:
        """Reserve an IP address with probe (OFFER)."""
        while True:
            ip = self.reserve(mac_address, clientid, hostname)

            logger.debug("Probing address: %s", ip)
            r = await vpp.vpp_probe_is_duplicate_async(self.ifindex, clientid, ip)
            if not r:
                break

            logger.error("***Already in use: %s %s", ip, clientid)
            self.probed_duplicates[ip] = get_epoch()
        return ip

    def release(self, client_id: bytes, ip: IPv4Address) -> None:
        """Release an IP address."""
        try:
            index = self.lease_by_client_id[client_id]
        except KeyError:
            logger.error("Release with unknown client_id %s", client_id)
            return

        logger.debug("Releasing IP address: %s from %s", ip, client_id)
        del self.lease_by_client_id[client_id]
        del self.leases[index]

    def decline(self, client_id: bytes, ip: IPv4Address) -> None:
        """Mark an IP address as declined."""
        try:
            index = self.lease_by_client_id[client_id]
        except KeyError:
            logger.error("Release with unknown client_id %s", client_id)
            return
        logger.error("Releasing IP address: %s from %s", ip, client_id)
        del self.lease_by_client_id[client_id]
        del self.leases[index]
        self.probed_duplicates[ip] = get_epoch()

    def confirm_offer(self, client_id: bytes, ip: IPv4Address) -> IPv4Address:
        """Confirm an offer."""
        try:
            index = self.lease_by_client_id[client_id]
        except KeyError:
            logger.error("Confirm offer with unknown client_id %s", client_id)
            return None
        lease = self.leases[index]
        if ip != lease.ip_address:
            logger.error("Confirm offer with wrong ip address %s != %s", ip, lease.ip_address)
            return None
        lease.status = DHC4BindingState.BOUND
        lease.last_updated = get_epoch()
        return lease.ip_address

    def verify_or_extend_lease(self, client_id: bytes, reqip: IPv4Address) -> IPv4Address:
        """Verify or extend a lease."""
        print("*** REQIP ***", reqip)
        index = get_ip_index(reqip, self.network)
        lease = self.leases[index]

        if lease.ip_address != reqip or lease.client_id != client_id:
            logger.error("Verify or extend lease with wrong IP %s != %s", lease.ip_address, reqip)
            return None
        lease.last_updated = get_epoch()
        return lease.ip_address

    def nak(self, dst_ip, req):
        """Create a NAK packet."""
        mac = req[Ether].src
        repb = req.getlayer(BOOTP).copy()
        repb.op = "BOOTREPLY"
        repb.yiaddr = 0
        repb.siaddr = 0
        repb.ciaddr = 0  # Client address
        repb.giaddr = req[BOOTP].giaddr  # Relay agent IP
        repb.chaddr = req[BOOTP].chaddr  # Client hardware address
        repb.sname = "vppdhcpd"  # Server name not given
        del repb.payload
        resp = (
            Ether(src=self.mac_address, dst=mac)
            / IP(src=self.server_ip, dst=dst_ip)
            / UDP(sport=req.dport, dport=req.sport)
            / repb
        )

        dhcp_options = [("message-type", "nak")]
        dhcp_options.append("end")
        resp /= DHCP(options=dhcp_options)
        return resp

    def free_lease(self, client_id: bytes) -> None:
        index = self.lease_by_client_id[client_id]
        del self.lease_by_client_id[client_id]
        del self.leases[index]


class DHC4Server:
    """DHCPv4 Server. Singleton class."""

    _instance = None

    def __new__(cls, *args, **kwargs) -> "DHC4Server":
        """DHCPv4 Server."""
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, receive_socket, send_socket, vpp, conf: VPPDB) -> None:
        """DHCPv4 Server."""
        self.receive_socket = receive_socket
        self.send_socket = send_socket
        self.vpp = vpp

        dhc4server_conf = conf.get("/dhc4server")
        system_conf = conf.get("/system")
        self.renewal_time = dhc4server_conf.renewal_time
        self.lease_time = dhc4server_conf.lease_time
        self.name_server = dhc4server_conf.dns
        self.tenant_id = system_conf.bypass_tenant
        self.ipv6_only_preferred = dhc4server_conf.ipv6_only_preferred

        self.dbs = {}  # DHCPv4 Binding databases

    @classmethod
    def get_instance(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = cls(*args, **kwargs)
        return cls._instance

    async def process_packet(self, db: DHC4BindingDatabase, req: Packet):  # pylint: disable=too-many-locals
        """Process a DHCP packet."""
        dhcp_server_ip = db.server_ip

        if req[BOOTP].giaddr != "0.0.0.0":  # noqa: S104
            # Client must be on-link
            logger.error("**Ignoring request from non on-link client: %s", req[Ether].src)
            return None

        options = options2dict(req)
        reqip = options.get("requested_addr", None)
        hostname = options.get("hostname", "")
        params = options.get("param_req_list", [])
        server_id = options.get("server_id", None)
        client_id = options.get("client_id", None)
        include_108 = None

        msgtype = options["message-type"]

        # This DHCP server is always on-link with the client, let's just use the MAC address.
        mac_address = req[Ether].src

        client_id = b"0x1" + mac_address if client_id is None else client_id

        reqip = IPv4Address(reqip) if reqip else req[IP].src

        if msgtype == 1:  # discover
            # Reserve a new address
            dst_ip = "255.255.255.255"
            try:
                ip = await db.reserve_with_probe(self.vpp, mac_address, client_id, hostname)
                logger.debug("DISCOVER: %s: %s", mac_address, ip)
            except DHC4ServerNoIPaddrAvailableError:
                logger.exception("*** ERROR No IP address available for: %s ***", mac_address)
                return db.nak(dst_ip, req)

        elif msgtype == 3:  # request
            if server_id:
                if IPv4Address(server_id) != dhcp_server_ip:
                    # Someone else won
                    db.free_lease(client_id)
                    logger.error(
                        "*** ERROR Unknown server id %s expected %s from %s ***",
                        server_id,
                        dhcp_server_ip,
                        chaddrstr,
                    )
                    return None

                # In response to a previous offer. Create a new lease.
                ip = db.confirm_offer(client_id, reqip)
                if not ip:
                    return db.nak("255.255.255.255", req)
                logger.debug("REQUEST: %s: %s", mac_address, ip)
                dst_ip = "255.255.255.255"
            else:
                # Verifying or extending an existing lease
                ip = db.verify_or_extend_lease(client_id, reqip)
                if not ip:
                    return db.nak(ip, req)
                logger.debug("RENEW/REBIND: %s: %s", mac_address, ip)
                dst_ip = ip
        elif msgtype == 4:  # decline
            # Address declined, like duplicate
            db.decline(client_id, reqip)
            logger.error("DECLINE: %s: %s", mac_address, reqip)
            return None
        elif msgtype == 7:  # release
            db.release(client_id, reqip)
            logger.debug("RELEASE: %s: %s", mac_address, reqip)
            return None
        else:
            logger.error("*** ERROR Unknown message type %s from %s ***", msgtype, mac_address)
            return None

        mac = req[Ether].src

        if 108 in params and self.ipv6_only_preferred and msgtype in (1, 3):
            include_108 = 0  # Default wait time

        repb = req.getlayer(BOOTP).copy()
        repb.op = "BOOTREPLY"
        repb.yiaddr = ip  # Your client address
        repb.siaddr = dhcp_server_ip  # Next server
        repb.ciaddr = 0  # Client address
        repb.giaddr = req[BOOTP].giaddr  # Relay agent IP
        repb.chaddr = req[BOOTP].chaddr  # Client hardware address
        repb.sname = "vppdhcpd"  # Server name not given
        del repb.payload

        resp = (
            Ether(src=db.mac_address, dst=mac)
            / IP(src=dhcp_server_ip, dst=dst_ip)
            / UDP(sport=req.dport, dport=req.sport)
            / repb
        )

        dhcp_options = [
            (op[0], {1: 2, 3: 5}.get(op[1], op[1]))
            for op in req[DHCP].options
            if isinstance(op, tuple) and op[0] == "message-type"
        ]

        dhcp_options += [
            x
            for x in [
                ("server_id", dhcp_server_ip),
                ("router", dhcp_server_ip),
                ("name_server", self.name_server[0]),
                # ("broadcast_address", pool.broadcast_address()),
                ("subnet_mask", db.subnet_mask()),
                # ("renewal_time", self.renewal_time),
                ("lease_time", self.lease_time),
                ("ipv6-only-preferred", include_108),
            ]
            if x[1] is not None
        ]
        dhcp_options.append("end")
        resp /= DHCP(options=dhcp_options)
        return resp

    async def listen(self) -> None:
        """Listen for DHCP requests."""
        # Clients send from their unicast address to 255.255.255.255:67
        primary_key = {
            "context_id": 0,
            "src": "0.0.0.0",
            "dst": "255.255.255.255",
            "sport": 0,
            "dport": 67,
            "proto": 17,
        }
        rv = await self.vpp.vpp_vcdp_session_add(self.tenant_id, primary_key=primary_key)
        logger.debug("VCDP session add: %s", rv)
        print(f"Receive SOCKET NAME {self.receive_socket}")

        try:
            self._reader = await asyncio_dgram.bind(self.receive_socket)
            self._writer = await asyncio_dgram.connect(self.send_socket)

            while True:
                # Receive on uds socket
                (packet, _) = await self._reader.recv()

                # Decode packet with scapy
                packet = VPPPunt(packet)
                packet_logger.debug("Received from client: %s", packet.show2(dump=True))

                if not packet.haslayer(BOOTP):
                    packet_logger.error("Packet without bootp %s", packet.show2(dump=True))
                    continue

                reqb = packet.getlayer(BOOTP)
                if reqb.op != 1:  # BOOTPREQUEST
                    continue

                ifindex = packet[VPPPunt].iface_index
                db = self.dbs.get(ifindex)
                if db is None:
                    # Create a pool on a given interface
                    interface_info = await self.vpp.vpp_interface_info(ifindex)

                    # Create a new DHCPv4 pool based on the interface IP address/subnet
                    db = self.dbs[ifindex] = DHC4BindingDatabase(
                        ifindex=ifindex,
                        interface=interface_info.name,
                        mac_address=interface_info.mac,
                        server_ip=interface_info.ip4[0].ip,
                        leases=[],
                        network=interface_info.ip4[0].network,
                        dns_servers=self.name_server,
                        lease_by_client_id={},
                    )

                    # Add a 3-tuple session so to get DHCP unicast packets
                    await self.vpp.vpp_vcdp_session_add(self.tenant_id, 0, interface_info.ip4[0].ip, 17, 0, 67)

                reply = await self.process_packet(db, packet)
                if not reply:
                    logger.notice("Process packet failed. No reply")
                    continue

                reply = VPPPunt(iface_index=ifindex, action=Actions.PUNT_L2) / reply
                packet_logger.debug("Sending to %s: %s", interface_info.mac, reply.show2(dump=True))

                await self._writer.send(bytes(reply))
        except asyncio.CancelledError:
            # Handle cancellation
            raise
        finally:
            # Always clean up resources
            await self.cleanup()

    async def cleanup(self):
        """Clean up resources."""
        if hasattr(self, "_reader"):
            self._reader.close()
        if hasattr(self, "_writer"):
            self._writer.close()

    async def __aenter__(self):
        """Enter async context."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context."""
        await self.cleanup()
