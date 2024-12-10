"""
This provides a wrapper around the VPP API for punt sockets and multicast
It implements the VPP Punt protocol.
"""

# pylint: disable=import-error, invalid-name, logging-fstring-interpolation

import time
import logging
import asyncio
from enum import IntEnum
from collections import namedtuple
from scapy.packet import Packet, bind_layers
from scapy.fields import IntEnumField, LEIntField
from scapy.layers.l2 import Ether
from vpp_papi.vpp_papi_async import VPPApiClient, VppEnum
from vppdhc.datamodel import VPPInterfaceInfo
from ipaddress import IPv6Network, IPv4Address, IPv6Address, ip_address

logger = logging.getLogger(__name__)
logging.getLogger("vpp_papi").setLevel(logging.ERROR)


class VPPDHCException(Exception):
    """VPP DHC Exception"""

    pass


# Define the action enumeration
class Actions(IntEnum):
    """VPP Punt actions."""

    PUNT_L2 = 0
    ROUTED_IP4 = 1
    ROUTED_IP6 = 2


# Define the custom header
class VPPPunt(Packet):  # pylint: disable=too-few-public-methods
    """VPP Punt header."""

    name = "VPPPunt"
    fields_desc = [
        LEIntField("iface_index", 0),
        IntEnumField("action", 0, Actions),
    ]


# Always ethernet after the VPP Punt header
bind_layers(VPPPunt, Ether)

##### VPP PUNT Protocol #####


class VPP:
    """VPP API wrapper"""

    def __init__(self):
        # VPP API socket
        self.event_queue = asyncio.Queue()
        self.vpp = VPPApiClient()
        self.interface_info = {}

    @classmethod
    async def create(cls):
        # Perform async operations here
        instance = cls()
        logger.debug("Connecting to VPP")
        rv = await instance.vpp.connect("vppdhc", instance.event_queue)
        if rv < 0:
            raise IOError(f"Error connecting to VPP: {rv}")
        logger.debug("Connected to VPP")
        rv = await instance.vpp.api.show_version()
        logger.debug(f"VPP version: {rv}")
        return instance

    async def vpp_interface_name2index(self, ifname: str) -> int:
        """Returns the interface index for the given interface name."""
        r, interface_details = await self.vpp.api.sw_interface_dump(name_filter_valid=1, name_filter=ifname)
        if len(interface_details) != 1:
            raise VPPDHCException(f"Interface {ifname} not found")
        return interface_details[0].sw_if_index

    async def vpp_interface_info(self, ifindex: int) -> VPPInterfaceInfo:
        """Returns the interface info for the given interface index."""
        # Define a named tuple
        if ifindex in self.interface_info:
            return self.interface_info[ifindex]

        r, interface_details = await self.vpp.api.sw_interface_dump(sw_if_index=ifindex)
        r, address_details4 = await self.vpp.api.ip_address_dump(sw_if_index=ifindex, is_ipv6=False)
        r, address_details6 = await self.vpp.api.ip_address_dump(sw_if_index=ifindex, is_ipv6=True)
        link_local = await self.vpp.api.sw_interface_ip6_get_link_local_address(sw_if_index=ifindex)

        v4addrs = [x.prefix for x in address_details4]
        v6addrs = [x.prefix for x in address_details6]

        interfaceinfo = VPPInterfaceInfo(
            ifindex=ifindex,
            name=interface_details[0].interface_name,
            mac=interface_details[0].l2_address.packed,
            ip4=v4addrs,
            ip6=v6addrs,
            ip6ll=link_local.ip,
        )
        self.interface_info[ifindex] = interfaceinfo
        logger.debug("Interface info: %s", interfaceinfo)
        return interfaceinfo

    async def vpp_probe_is_duplicate(self, ifindex, mac, neighbor) -> bool:
        """Returns true if this is a likely duplicate."""
        rv = await self.vpp.api.arping_acd(address=neighbor, sw_if_index=ifindex, is_garp=False)
        if rv.retval != 0:
            logger.error("Error arping_acd: %s", rv)
        return bool(rv.reply_count > 0 and rv.mac_address != mac)

    async def vpp_socket_register(self, af, proto, port: int) -> tuple[str, str]:
        """Register the punt socket with VPP."""
        punt = {
            "type": VppEnum.vl_api_punt_type_t.PUNT_API_TYPE_L4,
            "punt": {"l4": {"af": af, "protocol": proto, "port": port}},
        }
        pathname = f"/tmp/vpp-punt-{af}-{proto}-{port}"
        rv = await self.vpp.api.punt_socket_register(punt=punt, header_version=1, pathname=pathname)
        assert rv.retval == 0
        logger.info(f"Punt socket register: {rv}")
        return pathname, rv.pathname

    async def vpp_ip_route_add(self, prefix, nexthop: ip_address, nh_ifindex=0xFFFFFFFF, table_id=0, src=0):
        """Adds an IPv4|v6 route"""

        # Path
        if isinstance(nexthop, IPv6Address):
            proto = VppEnum.vl_api_fib_path_nh_proto_t.FIB_API_PATH_NH_PROTO_IP6
            nh = {"address": {"ip6": nexthop}}
        else:
            proto = VppEnum.vl_api_fib_path_nh_proto_t.FIB_API_PATH_NH_PROTO_IP4
            nh = {"address": {"ip4": nexthop}}
        path = {
            "weight": 1,
            "preference": 0,
            "table_id": 0,
            "nh": nh,
            "next_hop_id": 0xFFFFFFFF,
            "sw_if_index": nh_ifindex,
            "rpf_id": 0,
            "proto": proto,
            "type": 0,  # FIB_PATH_TYPE_NORMAL
            "flags": 0,  # FIB_PATH_FLAG_NONE
            "n_labels": 0,
            "label_stack": [0] * 16,
        }

        rv = await self.vpp.api.ip_route_add_del_v2(
            route={
                "table_id": table_id,
                "prefix": prefix,
                "n_paths": 1,
                "paths": [path],
                "src": src,
            },
            is_add=1,
            is_multipath=0,
        )
        assert rv.retval == 0
        logger.debug(f"Adding route {prefix} {nexthop} {nh_ifindex} {rv}")

    async def vpp_ip6_route_del2(self, prefix, table_id=0, src=0):
        r = await self.vpp.api.ip_route_add_del_v2(
            route={
                "table_id": table_id,
                "prefix": prefix,
                "src": src,
                "n_paths": 0,
            },
            is_add=0,
            is_multipath=0,
        )

    async def vpp_ip6_mreceive(self, group_prefix, table_id=0):
        # _paths = self.encoded_paths if paths is None else paths
        proto = 1  # IPv6
        nh_ifindex = 0xFFFFFFFF
        # nh_i_flags = 0
        e_flags = 0
        nh = {"address": {"ip6": "::"}}
        prefix = IPv6Network(group_prefix)
        prefix = {
            "af": 1,  # IP6
            "grp_address": {"ip6": prefix.network_address},
            "src_address": {"ip6": "::"},
            "grp_address_length": prefix.prefixlen,
        }

        path = {
            "weight": 1,
            "preference": 0,
            "table_id": 0,
            "nh": nh,
            "next_hop_id": 0xFFFFFFFF,
            "sw_if_index": nh_ifindex,
            "rpf_id": 0,
            "proto": proto,
            "type": 0,  # FIB_PATH_TYPE_NORMAL
            "flags": 0,  # FIB_PATH_FLAG_NONE
            "n_labels": 0,
            "label_stack": [0] * 16,
        }
        mpath = {
            "itf_flags": 4,
            "path": path,
        }
        route = {
            "table_id": table_id,
            "entry_flags": e_flags,
            "rpf_id": 0,
            "prefix": prefix,
            "n_paths": 1,
            "paths": [mpath],
        }

        return await self.vpp.api.ip_mroute_add_del(route=route, is_multipath=0, is_add=1)

    # def vpp_dhcp_client_detect(self, ifindex, enable=True):
    #     r = self.vpp.api.dhcp_client_detect_enable_disable(
    #         sw_if_index=ifindex,
    #         enable=enable,
    #     )
    #     assert r.retval == 0

    async def vpp_ip_address(self, ifindex, prefix, add=True):
        return await self.vpp.api.sw_interface_add_del_address(
            sw_if_index=ifindex, is_add=add, del_all=False, prefix=prefix
        )

    async def vpp_vcdp_nat_add(self, nat_id, addresses):
        return await self.vpp.api.vcdp_nat_add(nat_id=nat_id, n_addr=len(addresses), addr=addresses)

    async def vpp_vcdp_nat_bind_set_unset(self, tenant_id, nat_id, is_set=True):
        return await self.vpp.api.vcdp_nat_bind_set_unset(tenant_id=tenant_id, nat_id=nat_id, is_set=is_set)

    async def vpp_vcdp_session_add(self, tenant_id, primary_key, secondary_key=None):
        return await self.vpp.api.vcdp_session_add(tenant_id=tenant_id,
                                                   primary_key=primary_key,
                                                   secondary_key=secondary_key)

    async def vpp_ip_multicast_group_join(self, group):
        return await self.vpp.api.ip_multicast_group_join(grp_address=group)
