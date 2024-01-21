'''
This provides a wrapper around the VPP API for punt sockets and multicast
It implements the VPP Punt protocol.
'''

# pylint: disable=import-error, invalid-name, logging-fstring-interpolation

import time
import logging
from enum import IntEnum
from collections import namedtuple
from scapy.packet import Packet, bind_layers
from scapy.fields import IntEnumField, LEIntField
from scapy.layers.l2 import Ether
from vpp_papi import VPPApiClient, VppEnum
from ipaddress import IPv6Network

logger = logging.getLogger(__name__)
logging.getLogger('vpp_papi').setLevel(logging.ERROR)

class VPPDHCException(Exception):
    '''VPP DHC Exception'''
    pass

# Define the action enumeration
class Actions(IntEnum):
    '''VPP Punt actions'''
    PUNT_L2 = 0
    ROUTED_IP4 = 1
    ROUTED_IP6 = 2

# Define the custom header
class VPPPunt(Packet): # pylint: disable=too-few-public-methods
    '''VPP Punt header'''
    name = "VPPPunt"
    fields_desc = [
        LEIntField("iface_index", 0),
        IntEnumField("action", 0, Actions),
    ]

# Always ethernet after the VPP Punt header
bind_layers(VPPPunt, Ether)

##### VPP PUNT Protocol #####

def vpp_callback_default(msg):
    '''VPP callback function'''
    logger.debug(f"Received VPP message: {msg}")

class VPP():
    '''VPP API wrapper'''

    def __init__(self, apidir, vpp_callback=vpp_callback_default):
        # VPP API socket
        VPPApiClient.apidir = apidir
        vpp = VPPApiClient()
        vpp.register_event_callback(vpp_callback)

        # Give VPP 5 seconds to come up
        time.sleep(3)

        logger.debug('Connecting to VPP')
        rv = vpp.connect("vpp")
        assert rv == 0
        logger.debug("Connected to VPP")
        self.vpp = vpp
        self.api = vpp.api
        self.interface_info = {}

        rv = self.vpp.api.show_version()
        logger.debug(f"VPP version: {rv}")

    def vpp_interface_name2index(self, ifname):
        '''Returns the interface index for the given interface name'''
        interface_details = self.vpp.api.sw_interface_dump(name_filter_valid=1, name_filter=ifname)
        if len(interface_details) != 1:
            raise VPPDHCException(f'Interface {ifname} not found')
        return interface_details[0].sw_if_index

    def vpp_interface_info(self, ifindex):
        '''Returns the interface info for the given interface index'''
        # Define a named tuple
        if ifindex in self.interface_info:
            return self.interface_info[ifindex]
        Interface = namedtuple('Interface', ['ifindex', 'name', 'mac', 'ip4', 'ip6', 'ip6ll'])

        interface_details = self.vpp.api.sw_interface_dump(sw_if_index=ifindex)
        address_details4 = self.vpp.api.ip_address_dump(sw_if_index=ifindex, is_ipv6=False)
        address_details6 = self.vpp.api.ip_address_dump(sw_if_index=ifindex, is_ipv6=True)
        link_local = self.vpp.api.sw_interface_ip6_get_link_local_address(sw_if_index=ifindex)

        v4addrs = [x.prefix for x in address_details4]
        v6addrs = [x.prefix for x in address_details6]

        interfaceinfo =  Interface(ifindex,
                         interface_details[0].interface_name,
                         interface_details[0].l2_address,
                         v4addrs,
                         v6addrs,
                         link_local.ip)
        self.interface_info[ifindex] = interfaceinfo
        logger.debug('Interface info: %s', interfaceinfo)
        return interfaceinfo

    def vpp_probe_is_duplicate(self, ifindex, mac, neighbor):
        '''Returns true if this is a likely duplciate'''
        rv = self.vpp.api.arping_acd(address=neighbor, sw_if_index=ifindex, is_garp=False)
        if rv.retval != 0:
            logger.error(f"Error arping_acd: {rv}")
        if rv.reply_count > 0 and rv.mac_address != mac:
            return True
        return False

    def vpp_socket_register(self, af, proto, port):
        '''Registers a punt socket with VPP'''
        punt = {"type": VppEnum.vl_api_punt_type_t.PUNT_API_TYPE_L4,
                   "punt": {
                       "l4": {
                           "af": af, "protocol": proto,
                           "port": port
                           }
                    }
                }
        pathname = f'/tmp/vpp-punt-{af}-{proto}-{port}'
        rv = self.vpp.api.punt_socket_register(punt=punt, header_version=1, pathname=pathname)
        assert rv.retval == 0
        logger.info(f'Punt socket register: {rv}')
        return pathname, rv.pathname

    def vpp_ip6_route_add(self, prefix, nexthop, nh_ifindex=0xFFFFFFFF, table_id=0, src=0):
        '''Adds an IPv6 route'''

        # Path
        proto = 1 # IPv6
        nh = {"address": {"ip6": nexthop}}
        path = {
            "weight": 1,
            "preference": 0,
            "table_id": 0,
            "nh": nh,
            "next_hop_id": 0xFFFFFFFF,
            "sw_if_index": nh_ifindex,
            "rpf_id": 0,
            "proto": proto,
            "type": 0, # FIB_PATH_TYPE_NORMAL
            "flags": 0, # FIB_PATH_FLAG_NONE
            "n_labels": 0,
            "label_stack": [0]*16
        }

        rv = self.vpp.api.ip_route_add_del_v2(
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
        logger.debug(f'Adding route {prefix} {nexthop} {nh_ifindex} {rv}')


    def vpp_ip6_route_del2(self, prefix, table_id=0, src=0):
        r = self.vpp.api.ip_route_add_del_v2(
            route={
                "table_id": table_id,
                "prefix": prefix,
                "src": src,
                "n_paths": 0,
            },
            is_add=0,
            is_multipath=0,
        )

    def vpp_ip6_mreceive(self, group_prefix, table_id=0):
        # _paths = self.encoded_paths if paths is None else paths
        proto = 1 # IPv6
        nh_ifindex = 0xFFFFFFFF
        # nh_i_flags = 0
        e_flags = 0
        nh = {"address": {"ip6": '::'}}
        prefix = IPv6Network(group_prefix)
        prefix = {
            "af": 1, # IP6
            "grp_address": {"ip6": prefix.network_address},
            "src_address": {"ip6": '::'},
            "grp_address_length": prefix.prefixlen
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
            "type": 0, # FIB_PATH_TYPE_NORMAL
            "flags": 0, # FIB_PATH_FLAG_NONE
            "n_labels": 0,
            "label_stack": [0]*16
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

        rv = self.vpp.api.ip_mroute_add_del(
            route=route, is_multipath=0, is_add=1
        )
        print(f'Tried to add an mreceive entry {rv}')

    def vpp_dhcp_client_detect(self, ifindex, enable=True):
        r = self.vpp.api.dhcp_client_detect_enable_disable(
            sw_if_index=ifindex,
            enable=enable,
        )
        assert r.retval == 0

    def vpp_ip_address(self, ifindex, prefix, add=True):
        r = self.vpp.api.sw_interface_add_del_address(
            sw_if_index=ifindex,
            is_add=add,
            del_all=False,
            prefix=prefix
        )
        return r

    def vpp_vcdp_nat_add(self, nat_id, addresses):
        r = self.vpp.api.vcdp_nat_add(nat_id=nat_id,
                                      n_addr=len(addresses),
                                      addr=addresses)
        print('RV', r)

    def vpp_vcdp_nat_bind_set_unset(self, tenant_id, nat_id, is_set=True):
        r = self.vpp.api.vcdp_nat_bind_set_unset(tenant_id=tenant_id,
                                                 nat_id=nat_id,
                                                 is_set=is_set)

    def vpp_vcdp_session_add(self, tenant_id, src, dst, protocol, sport, dport):
        r = self.vpp.api.vcdp_session_add(tenant_id=tenant_id,
                                          context_id=0,
                                          src=src,
                                          dst=dst,
                                          protocol=protocol,
                                          sport=sport,
                                          dport=dport)
        print('RV', r)

    def vpp_ip_multicast_group_join(self, group):
        r = self.vpp.api.ip_multicast_group_join(grp_address=group)
        print('RV', r)
