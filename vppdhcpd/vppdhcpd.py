#!/usr/bin/env python3

import os
import sys
import socket
from enum import IntEnum
from typing import Any
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.packet import Packet, bind_layers
from scapy.fields import IntEnumField, LEIntField
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.utils import atol, itom, ltoa, sane, str2mac

from collections import namedtuple

##### VPP PUNT Protocol #####
from vpp_papi import VPPApiClient

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


##### DHCP Binding database #####
class DHCPBinding():
    '''DHCP Binding database'''
    def __init__(self, prefix):
        self.prefix = prefix
        self.bindings = {}
        self.pool = {}
        self.pool[prefix.ip] = 'router'

    def allocate(self, chaddr):
        ''' find next free ip address'''
        # Iterate over ip address in IPv4Prefix
        if chaddr in self.bindings:
            return self.bindings[chaddr]
        for ip in self.prefix.network.hosts():
            # Check if ip is in bindings
            if ip not in self.pool:
                self.bindings[chaddr] = ip
                self.pool[ip] = chaddr
                return ip
        #
        raise Exception("No more IP addresses available")

    def release(self, chaddr):
        '''Release an IP address'''
        ip = self.bindings[chaddr]
        del self.bindings[chaddr]
        del self.pool[ip]

    def broadcast_address(self):
        '''Return broadcast address'''
        return self.prefix.network.broadcast_address

    def subnet_mask(self):
        '''Return subnet mask'''
        return self.prefix.netmask

def punt_connect(send_path, receive_path):
    ''' Connect to VPP punt sockets '''
    send_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    receive_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    receive_socket.bind(receive_path)
    send_socket.connect(send_path)
    return send_socket, receive_socket


def vpp_callback(msg):
    '''VPP callback function'''
    print(f"Received VPP message: {msg}")

class VPP():

    def __init__(self):
        # VPP API socket
        VPPApiClient.apidir = '/home/otroan/vpp/api'
        vpp = VPPApiClient()
        vpp.register_event_callback(vpp_callback)

        print('Trying to connect to VPP')
        rv = vpp.connect("vpp")
        assert rv == 0
        print(f"Connected to VPP")
        self.vpp = vpp

    def vpp_interface_info(self, ifindex):
        # Define a named tuple
        Interface = namedtuple('Interface', ['name', 'mac', 'ip4'])

        interface_details = self.vpp.api.sw_interface_dump(sw_if_index=ifindex)
        address_details = self.vpp.api.ip_address_dump(sw_if_index=ifindex)
        # TOOD: Cache this
        return Interface(interface_details[0].interface_name,
                         interface_details[0].l2_address,
                         address_details[0].prefix)



class DHCPServer():
    def __init__(self, receive_socket, send_socket, vpp, renewal_time=600, lease_time=3600, name_server='8.8.8.8'):
        self.receive_socket = receive_socket
        self.send_socket = send_socket
        self.vpp = vpp

        self.renewal_time = renewal_time
        self.lease_time = lease_time
        self.name_server = name_server

        self.bindings = {}

    def process_packet(self, interface_info, pool, req):
        '''Process a DHCP packet'''

        # Allocate new address
        ip = pool.allocate(req[BOOTP].chaddr)

        mac = req[Ether].src
        dhcp_server_ip = interface_info.ip4.ip
        repb = req.getlayer(BOOTP).copy()
        repb.op = "BOOTREPLY"
        repb.yiaddr = ip                # Your client address
        repb.siaddr = 0                 # Next server
        repb.ciaddr = 0                 # Client address
        repb.giaddr = req[BOOTP].giaddr # Relay agent IP
        repb.chaddr = req[BOOTP].chaddr # Client hardware address
        del repb.payload
        resp = Ether(src=interface_info.mac, dst=mac) / IP(src=dhcp_server_ip, dst=ip) / UDP(sport=req.dport, dport=req.sport) / repb  # noqa: E501

        dhcp_options = [
                (op[0], {1: 2, 3: 5}.get(op[1], op[1]))
                for op in req[DHCP].options
                if isinstance(op, tuple) and op[0] == "message-type"
            ]
        dhcp_options += [
            x for x in [
                ("server_id", dhcp_server_ip),
                ("router", dhcp_server_ip),
                ("name_server", self.name_server),
                ("broadcast_address", pool.broadcast_address()),
                ("subnet_mask", pool.subnet_mask()),
                ("renewal_time", self.renewal_time),
                ("lease_time", self.lease_time),
                # ('classless_static_routes', ['12.0.0.0/8:169.254.1.1']),
            ]
            if x[1] is not None
        ]
        dhcp_options.append("end")
        resp /= DHCP(options=dhcp_options)
        return resp

    def listen(self):
        '''Listen for DHCP requests'''
        while True:
            # Receive on uds socket
            packet = self.receive_socket.recv(10000)

            # Decode packet with scapy
            packet = VPPPunt(packet)
            packet.show2()

            if not packet.haslayer(BOOTP):
                continue
            reqb = packet.getlayer(BOOTP)
            if reqb.op != 1:
                continue

            sw_if_index = packet[VPPPunt].iface_index
            print(f"Interface index: {sw_if_index}")
            interface_info = self.vpp.vpp_interface_info(sw_if_index)
            print(f"Interface info: {interface_info}")

            # Check if pool for the IP prefix on the interface exists
            # If not create one
            try:
                pool = self.bindings[sw_if_index]
            except KeyError:
                # Create a pool
                pool = self.bindings[sw_if_index] = DHCPBinding(interface_info.ip4)

            reply = self.process_packet(interface_info, pool, packet)
            print('SENDING REPLY')
            reply = VPPPunt(iface_index=sw_if_index, action=Actions.PUNT_L2) / reply
            reply.show2()

            self.send_socket.send(bytes(reply))



    def __call__(self, *args: Any, **kwds: Any) -> Any:
        self.listen()

def main():
    '''Main function'''

    RECEIVE_SOCK_PATH = "/tmp/vpp-punt2.sock"
    # Delete socket file if exists
    if os.path.exists(RECEIVE_SOCK_PATH):
        os.remove(RECEIVE_SOCK_PATH)
    try:
        uds_send_socket, uds_receive_socket = punt_connect("/tmp/vpp-punt.sock", RECEIVE_SOCK_PATH)
    except socket.error as e:
        print(f"Socket error: {e}")
        sys.exit(1)

    vpp = VPP()

    dhcp_server = DHCPServer(uds_receive_socket, uds_send_socket, vpp, renewal_time=30, lease_time=60)
    dhcp_server()

    # Cleanup (delete the bound socket file)
    uds_receive_socket.close()
    uds_send_socket.close()
    os.remove(RECEIVE_SOCK_PATH)

if __name__ == "__main__":
    main()