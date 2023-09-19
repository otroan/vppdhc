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

logger = logging.getLogger(__name__)
logging.getLogger('vpp_papi').setLevel(logging.ERROR)

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
        assert len(interface_details) == 1
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

    def vpp_ip6_mreceive(self, group_prefix):
        '''Adds an IPv6 multicast receive address'''
        rv = self.vpp.api.ip6_mreceive_add_del(group_address=group_prefix)
        assert rv.retval == 0
        logger.debug('Adding multicast receive {rv}')

    def vpp_ip6_route_add(self, prefix, nexthop, ifindex):
        '''Adds an IPv6 route'''
        rv = self.vpp.api.ip_route_simple_add_del(prefix=prefix,
                                                  next_hop_address=nexthop,
                                                  next_hop_sw_if_index=ifindex)
        assert rv.retval == 0
        logger.debug(f'Adding route {prefix} {nexthop} {ifindex} {rv}')
