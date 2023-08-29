##### VPP PUNT Protocol #####
from enum import IntEnum
from scapy.packet import Packet, bind_layers
from scapy.fields import IntEnumField, LEIntField
from scapy.layers.l2 import Ether
from vpp_papi import VPPApiClient
from collections import namedtuple

# Define the action enumeration
class Actions(IntEnum):
    '''VPP Punt actions'''
    PUNT_L2 = 0
    ROUTED_IP4 = 1
    ROUTED_IP6 = 2

# Define the custom header
class VPPPunt(Packet):
    '''VPP Punt header'''
    name = "VPPPunt"
    fields_desc = [
        LEIntField("iface_index", 0),
        IntEnumField("action", 0, Actions),
    ]

# Always ethernet after the VPP Punt header
bind_layers(VPPPunt, Ether)

##### VPP PUNT Protocol #####

def vpp_callback(msg):
    '''VPP callback function'''
    print(f"Received VPP message: {msg}")

class VPP():

    def __init__(self, vpp_callback):
        # VPP API socket
        VPPApiClient.apidir = '/home/otroan/vpp/api'
        vpp = VPPApiClient()
        vpp.register_event_callback(vpp_callback)

        print('Trying to connect to VPP')
        rv = vpp.connect("vpp")
        assert rv == 0
        print(f"Connected to VPP")
        self.vpp = vpp
        self.api = vpp.api

    def vpp_interface_name2index(self, ifname):
        interface_details = self.vpp.api.sw_interface_dump(name_filter_valid=1, name_filter=ifname)
        assert len(interface_details) == 1
        return interface_details[0].sw_if_index

    def vpp_interface_info(self, ifindex):
        # Define a named tuple
        Interface = namedtuple('Interface', ['ifindex', 'name', 'mac', 'ip4', 'ip6'])

        interface_details = self.vpp.api.sw_interface_dump(sw_if_index=ifindex)
        address_details = self.vpp.api.ip_address_dump(sw_if_index=ifindex)

        link_local = self.vpp.api.sw_interface_ip6_get_link_local_address(sw_if_index=ifindex)

        # TOOD: Cache this
        return Interface(ifindex,
                         interface_details[0].interface_name,
                         interface_details[0].l2_address,
                         address_details[0].prefix,
                         link_local.ip)

    def vpp_probe(self, ifindex, neighbor):
        # Watch changes for this neighbor
        # rv = self.vpp.api.want_ip_neighbor_events_v2(enable=True, ip=neighbor, sw_if_index=ifindex)
        # print('RV', rv)
        # rv = self.vpp.api.ip_neighbor_probe(sw_if_index=ifindex, ip=neighbor)
        # print('RV: ', rv)

        rv = self.vpp.api.arping(address=neighbor, sw_if_index=ifindex, is_garp=False)
        print('RV: ', rv)
        if rv.reply_count > 0:
            return True
        return False
