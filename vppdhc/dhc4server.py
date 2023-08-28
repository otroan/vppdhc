#!/usr/bin/env python3

import asyncio
from typing import Any
from scapy.layers.l2 import Ether
from scapy.layers.dhcp import DHCP, BOOTP, DHCPOptionsField, DHCPTypes
from scapy.layers.inet import IP, UDP
import asyncio_dgram
from vppdhc.vpppunt import VPPPunt, Actions


##### DHCP Binding database #####
class DHCPBinding():
    '''DHCP Binding database'''
    def __init__(self, prefix):
        self.prefix = prefix
        self.bindings = {}
        self.pool = {}
        self.pool[prefix.ip] = 'router'

    def allocate(self, chaddr, reqip=None):
        ''' find next free ip address'''
        # Iterate over ip address in IPv4Prefix
        if chaddr in self.bindings:
            return self.bindings[chaddr]
        if reqip in self.pool and self.pool[reqip] == chaddr:
            return reqip
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

    def declined(self, chaddr, ip):
        '''Mark an IP address as declined'''
        self.pool[ip] = 'declined'

        del self.bindings[chaddr]

    def broadcast_address(self):
        '''Return broadcast address'''
        return self.prefix.network.broadcast_address

    def subnet_mask(self):
        '''Return subnet mask'''
        return self.prefix.netmask


def vpp_callback(msg):
    '''VPP callback function'''
    print(f"Received VPP message: {msg}")

def options2dict(packet):
    '''Get DHCP message type'''
    # Return all options in a dictionary
    # Using a dict comprehension
    options = {}
    for op in packet[DHCP].options:
        options[op[0]] = op[1]
    return options

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

        options = options2dict(req)
        reqip = None
        if 'requested_addr' in options:
            reqip = options['requested_addr']

        print('MESSAGE TYPE', options)
        msgtype = options['message-type']
        if msgtype == 1: # discover
            # Reserve a new address
            ip = pool.allocate(req[BOOTP].chaddr)
        elif msgtype == 3: # request
            # Allocate new address
            ip = pool.allocate(req[BOOTP].chaddr, reqip)
            print('ALLOCATING NEW ADDRESS: ', ip)
        elif msgtype == 4: # decline
            # Address declined, like duplicate
            pool.declined(req[BOOTP].chaddr, reqip)
        elif msgtype == 7:  # release
            pool.release(req[BOOTP].chaddr)
            return None
        else:
            print('Unknown message type')
            return None

        mac = req[Ether].src
        dhcp_server_ip = interface_info.ip4.ip
        print('SERVER IP', dhcp_server_ip, self.name_server, pool.subnet_mask(), pool.broadcast_address())

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
                ("name_server", self.name_server[0]),
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

    async def listen(self):
        '''Listen for DHCP requests'''

        reader = await asyncio_dgram.bind(self.receive_socket)
        writer = await asyncio_dgram.connect(self.send_socket)

        while True:
            # Receive on uds socket
            (packet, _) = await reader.recv()

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
            if not reply:
                continue
            reply = VPPPunt(iface_index=sw_if_index, action=Actions.PUNT_L2) / reply
            reply.show2()

            await writer.send(bytes(reply))

    def __call__(self, *args: Any, **kwds: Any) -> Any:
        return asyncio.create_task(self.listen())


    async def handle_timer(self):
        '''Handle a timer'''
        while True:
            print('Timer fired')
            await asyncio.sleep(1)
