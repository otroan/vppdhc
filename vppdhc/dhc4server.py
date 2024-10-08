#!/usr/bin/env python3
'''
DHCPv4 server
'''

import logging
import unittest
from unittest.mock import patch, AsyncMock
from datetime import datetime
import asyncio
import hashlib
from typing import Any
from ipaddress import IPv4Address, IPv4Network
from scapy.layers.l2 import Ether
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.utils import str2mac
import asyncio_dgram
from vppdhc.vpppunt import VPPPunt, Actions
from vppdhc.vppdhcdctl import register_command
from pydantic import BaseModel
from enum import Enum
from typing import Dict

logger = logging.getLogger(__name__)

class DHC4ServerNoIPaddrAvailable(Exception):
    '''No IP address available'''


##### DHCP Binding database #####

@register_command('dhcp', 'bindings')
def command_dhcp_binding(args=None):
    '''Show DHCP bindings'''
    if args:
        return f'Binding command with args: {args}'
    # Get DHCPServer singleton instance

    dhcp = DHCPServer.get_instance()
    s = ''
    for k,v in dhcp.bindings.items():
        s += f'DHCPv4 Bindings interface: {k}\n'
        s += v.dump()
    return s

class BindingState(Enum):
    BOUND = 'BOUND'
    DECLINED = 'DECLINED'
    IN_USE = 'IN_USE'
    RESERVED = 'RESERVED'

class Chaddr():
    def __init__(self, chaddr):
        self.chaddr = chaddr

class Binding(BaseModel):
    ip: IPv4Address
    chaddr: Chaddr
    state: BindingState
    created: datetime
    meta: dict

class Bindings(BaseModel):
    interface: str
    prefix: IPv4Network
    bindings: Dict[str, Binding]

class DHCPPool(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for key in list(self.keys()):
            self._normalize_key(key)

    def __setitem__(self, key, value):
        normalized_key = self._normalize_key(key)
        super().__setitem__(normalized_key, value)

    def __getitem__(self, key):
        normalized_key = self._normalize_key(key)
        return super().__getitem__(normalized_key)

    def __contains__(self, key):
        normalized_key = self._normalize_key(key)
        return super().__contains__(normalized_key)

    def _normalize_key(self, key):
        if isinstance(key, IPv4Address):
            normalized_key = str(key)
        elif isinstance(key, str):
            normalized_key = key
        else:
            raise TypeError("Key must be a str or IPv4Address")
        return normalized_key

    def get(self, key, default=None):
        normalized_key = self._normalize_key(key)
        return super().get(normalized_key, default)

    def pop(self, key, *args):
        normalized_key = self._normalize_key(key)
        return super().pop(normalized_key, *args)


class DHCPBinding():
    '''DHCP Binding database'''
    def __init__(self, prefix: IPv4Network):
        self.prefix = prefix
        self.bindings = {}
        self.pool = DHCPPool()

        # List of all available IP addresses
        # self.pool = [ip for ip in prefix.hosts()]

        # Create a dictionary of all available IP addresses
        # for ip in self.prefix.hosts():
        #     self.bindings[ip] = None

        # Reserve the first 10% of a prefix to manually configured addresses
        reserved = int(self.prefix.num_addresses / 10)
        i = 0
        for ip in prefix:
            if i >= reserved:
                break
            self.reserve_ip(ip)
            i += 1

    def reserve_ip(self, ip):
        '''Reserve an IP address'''
        self.pool[ip] = BindingState.RESERVED

    def pool_add(self, ip: IPv4Address, binding: dict):
        '''Add an IP address to the pool'''
        self.pool[ip] = binding

    def in_use(self, ip):
        return False if ip in self.pool and self.pool[ip] == BindingState.DECLINED else ip in self.pool

    def get_next_free(self, chaddr, reqip=None) -> IPv4Address:
        if chaddr in self.bindings:
            # Client already has an address. Return the same
            return self.bindings[chaddr]['ip']

        if reqip:
            ip = reqip
        else:
            # Require a new address
            # Hash the client's MAC address to generate a unique identifier
            uid = hashlib.sha256(chaddr.encode('utf-8')).digest()
            uid_int = int.from_bytes(uid[:4], byteorder='big')
            ip = IPv4Address(self.prefix.network_address + uid_int % self.prefix.num_addresses)

        # Check if IP address is in pool
        if self.in_use(ip):
            # IP address is in use, pick another one
            for ip in self.prefix.hosts():
                # Check if ip is in bindings
                if not self.in_use(ip):
                    break
            else:
                raise DHC4ServerNoIPaddrAvailable('No free IP addresses available')
        logger.debug(f'Next free IP address: {ip} to {chaddr}')
        return ip

    def reserve(self, chaddr, reqip=None, meta=None) -> IPv4Address:
        '''Reserve a new IP address'''
        # if chaddr in self.bindings:
        #     # Client already has an address. Renew
        #     self.bindings[chaddr].refreshed = datetime.now()
        #     return self.bindings[chaddr].ip, True

        ip = self.get_next_free(chaddr, reqip)

        # How to get a timestamp in python
        binding = Binding(ip=ip, chaddr=chaddr, state=BindingState.OFFERED,
                          created=datetime.now(), meta=meta)
        self.bindings[chaddr] = binding
        self.pool[ip] = self.bindings[chaddr]

        logger.debug(f'Reservering IP address: {ip} to {chaddr}')
        return ip


    def release(self, chaddr):
        '''Release an IP address'''
        try:
            binding = self.bindings[chaddr]
            del self.bindings[chaddr]
            del self.pool[binding['ip']]
        except KeyError:
            pass

    def declined(self, chaddr, ip):
        '''Mark an IP address as declined'''
        self.pool[ip] = BindingState.DECLINED
        try:
            del self.bindings[chaddr]
        except KeyError:
            logger.info(f'Decline with no binding for {chaddr}')

    def mark_as_in_use(self, chaddr, ip):
        '''Mark an IP address as in use'''
        self.pool[ip] = BindingState.IN_USE

    def broadcast_address(self):
        '''Return broadcast address'''
        return self.prefix.broadcast_address

    def subnet_mask(self):
        '''Return subnet mask'''
        return self.prefix.netmask

    def dump(self):
        '''Dump the bindings'''
        s = f'Bindings for {self.prefix}\n'
        for k,v in self.bindings.items():
            s += f'{k}: {v["ip"]} {v["state"]} {str(v["created"])}\n'
        return s

def options2dict(packet):
    '''Get DHCP message type'''
    # Return all options in a dictionary
    # Using a dict comprehension
    options = {}
    for op in packet[DHCP].options:
        options[op[0]] = op[1]
    return options

def chaddr2str(v):
    '''Convert a chaddr to a string'''
    if v[6:] == b"\x00" * 10:  # Default padding
        return f"{str2mac(v[:6])} (+ 10 nul pad)"
    return f"{str2mac(v[:6])} (pad: {v[6:]})"


def nak(interface_info, dhcp_server_ip, dst_ip, req):
    '''Create a NAK packet'''
    mac = req[Ether].src
    repb = req.getlayer(BOOTP).copy()
    repb.op = "BOOTREPLY"
    repb.yiaddr = 0
    repb.siaddr = 0
    repb.ciaddr = 0                 # Client address
    repb.giaddr = req[BOOTP].giaddr # Relay agent IP
    repb.chaddr = req[BOOTP].chaddr # Client hardware address
    repb.sname = "vppdhcpd"         # Server name not given
    del repb.payload
    resp = (Ether(src=interface_info.mac, dst=mac) /
            IP(src=dhcp_server_ip, dst=dst_ip) /
            UDP(sport=req.dport, dport=req.sport) / repb)  # noqa: E501

    dhcp_options = [("message-type", 'nak')]
    dhcp_options.append("end")
    resp /= DHCP(options=dhcp_options)
    return resp


class DHCPServer():
    '''DHCPv4 Server'''
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, receive_socket, send_socket, vpp, conf):
        '''DHCPv4 Server'''
        self.receive_socket = receive_socket
        self.send_socket = send_socket
        self.vpp = vpp

        self.renewal_time = conf.renewal_time
        self.lease_time = conf.lease_time
        self.name_server = conf.dns
        self.tenant_id = conf.bypass_tenant
        self.ipv6_only_preferred = conf.ipv6_only_preferred

        self.bindings = {}
        self.interface_info = {}

        # Clients send from their unicast address to 255.255.255.255:67
        self.vpp.vpp_vcdp_session_add(self.tenant_id, 0, '255.255.255.255', 17, 0, 67)

    @classmethod
    def get_instance(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = cls(*args, **kwargs)
        return cls._instance

    def reserve_with_probe(self, chaddr, pool, ifindex, meta=None):
        '''Reserve an IP address with probe (OFFER)'''
        while True:
            ip = pool.reserve(chaddr, meta=meta)
            logger.debug(f'Probing address: {ip}')
            if not self.vpp.vpp_probe_is_duplicate(ifindex, chaddr, ip):
                break
            logger.warning(f'***Already in use: {ip} {chaddr}')
            pool.mark_as_in_use(chaddr, ip)
        return ip

    def process_packet(self, interface_info, pool, req): # pylint: disable=too-many-locals
        '''Process a DHCP packet'''
        dhcp_server_ip = interface_info.ip4[0].ip

        if req[BOOTP].giaddr != '0.0.0.0':
            # Client must be on-link
            logger.error(f'**Ignoring request from non on-link client {req[Ether].src}')
            return None
        options = options2dict(req)

        reqip = options.get('requested_addr', None)
        hostname = options.get('hostname', '')
        params = options.get('param_req_list', [])
        server_id = options.get('server_id', None)
        include_108 = None

        metainfo = {'hostname': hostname}

        msgtype = options['message-type']

        # This DHCP server is always on-link with the client, let's just use the MAC address.
        # chaddr = req[BOOTP].chaddr
        chaddr = req[Ether].src
        chaddrstr = str(chaddr)
        # chaddrstr = chaddr2str(chaddr)
        if msgtype == 1: # discover
            # Reserve a new address
            dst_ip = '255.255.255.255'
            try:
                ip = self.reserve_with_probe(chaddr, pool, interface_info.ifindex, meta=metainfo)
                logger.debug(f'DISCOVER: {chaddrstr}: {ip}')
            except DHC4ServerNoIPaddrAvailable:
                logger.error(f'*** ERROR No IP address available for {chaddrstr} ***')
                return nak(interface_info, dhcp_server_ip, dst_ip, req)
        elif msgtype == 3: # request
            if server_id:
                if server_id != dhcp_server_ip:
                    # Someone else won
                    pool.free_lease(chaddr)
                    logger.error(f'*** ERROR Unknown server id {server_id} from {chaddrstr} ***')
                    return None
                # In response to a previous offer. Create a new lease.
                ip = pool.confirm_offer(chaddr)
                if not ip:
                    return nak(interface_info, dhcp_server_ip, '255.255.255.255', req)
                logger.debug(f'CONFIRM: {chaddrstr}: {ip}')
            else:
                # Verifying or extending an existing lease
                ip = pool.verify_or_extend_lease(chaddr, reqip, meta=metainfo)
                if not ip:
                    return nak(interface_info, dhcp_server_ip, ip, req)
            logger.debug(f'REQUEST/RENEW: {chaddrstr}: {ip}')
            dst_ip = ip
        elif msgtype == 4: # decline
            # Address declined, like duplicate
            pool.declined(chaddr, reqip)
            logger.warning(f'DECLINE: {chaddrstr}: {reqip}')
            return None
        elif msgtype == 7:  # release
            pool.release(chaddr)
            logger.debug(f'RELEASE: {chaddrstr}: {reqip}')
            return None
        else:
            logger.error(f'*** ERROR Unknown message type {msgtype} from {chaddrstr} ***')
            return None

        mac = req[Ether].src

        if 108 in params and self.ipv6_only_preferred and msgtype in (1, 3):
            include_108 = 0 # Default wait time

        repb = req.getlayer(BOOTP).copy()
        repb.op = "BOOTREPLY"
        repb.yiaddr = ip                # Your client address
        repb.siaddr = 0 # dhcp_server_ip    # Next server
        repb.ciaddr = 0                 # Client address
        repb.giaddr = req[BOOTP].giaddr # Relay agent IP
        repb.chaddr = req[BOOTP].chaddr # Client hardware address
        repb.sname = "vppdhcpd"         # Server name not given
        del repb.payload
        resp = (Ether(src=interface_info.mac, dst=mac) /
                IP(src=dhcp_server_ip, dst=dst_ip) /
                UDP(sport=req.dport, dport=req.sport) / repb)  # noqa: E501

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
                # ("broadcast_address", pool.broadcast_address()),
                ("subnet_mask", pool.subnet_mask()),
                # ("renewal_time", self.renewal_time),
                ("lease_time", self.lease_time),
                ("ipv6-only-preferred", include_108),
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
            # packet.show2()

            if not packet.haslayer(BOOTP):
                logger.error(f'Packet without bootp {packet.show2(dump=True)}')
                continue
            reqb = packet.getlayer(BOOTP)
            if reqb.op != 1:
                continue


            # Check if pool for the IP prefix on the interface exists
            # If not create one
            ifindex = packet[VPPPunt].iface_index
            try:
                pool = self.bindings[ifindex]
                interface_info = self.interface_info[ifindex]
            except KeyError:
                # Create a pool on a given interface
                interface_info = self.vpp.vpp_interface_info(ifindex)
                self.interface_info[ifindex] = interface_info

                # Create a new DHCPv4 pool based on the interface IP address/subnet
                pool = self.bindings[ifindex] = DHCPBinding(interface_info.ip4[0].network)
                pool.reserve_ip(interface_info.ip4[0].ip) # Reserve the router address

                # Add a 3-tuple session so to get DHCP unicast packets
                self.vpp.vpp_vcdp_session_add(self.tenant_id, 0, interface_info.ip4[0].ip, 17, 0, 67)
            reply = self.process_packet(interface_info, pool, packet)
            if not reply:
                continue
            reply = VPPPunt(iface_index=ifindex, action=Actions.PUNT_L2) / reply
            # reply.sho w2()

            await writer.send(bytes(reply))
            # pool.dump()

    def __call__(self, *args: Any, **kwds: Any) -> Any:
        return asyncio.create_task(self.listen())

# class TestDHCPMessageHandler(unittest.TestCase):

#     def setUp(self):
#         self.loop = asyncio.get_event_loop()

#     @patch('dhc4server.DHCPServer.allocate_with_probe', new_callable=AsyncMock)
#     # @patch('dhc4server.DHCPPool.allocate', new_callable=AsyncMock)
#     # @patch('dhc4server.DHCPPool.declined', new_callable=AsyncMock)
#     # @patch('dhc4server.DHCPPool.release', new_callable=AsyncMock)
#     def test_handle_dhcp_message_discover(self, mock_allocate_with_probe):
#         # Setup the mocks
#         mock_allocate_with_probe.return_value = '192.168.1.10'

#         # Create a mock request
#         req = {'msgtype': 1, 'chaddr': '00:11:22:33:44:55'}
#         interface_info = AsyncMock()
#         interface_info.ifindex = 1
#         pool = AsyncMock()
#         metainfo = {}

#         # Run the asyncio task
#         result = self.loop.run_until_complete(process_packet(req, interface_info, pool, metainfo))

#         # Assertions
#         self.assertEqual(result, '192.168.1.10')
#         mock_allocate_with_probe.assert_called_once_with('00:11:22:33:44:55', 1, meta={})


class TestDHCPBinding(unittest.TestCase):

    def setUp(self):
        self.prefix = IPv4Network('192.168.1.0/24')
        self.dhcp_binding = DHCPBinding(self.prefix)

    def tearDown(self):
        # Print the binding database
        print(self.dhcp_binding.dump())

    def test_initialization(self):
        # Check if the prefix is set correctly
        self.assertEqual(self.dhcp_binding.prefix, self.prefix)
        # Check if the first 10% of IP addresses are reserved
        reserved_count = int(self.prefix.num_addresses / 10)
        reserved_ips = [ip for ip in self.prefix][:reserved_count]
        for ip in reserved_ips:
            self.assertEqual(self.dhcp_binding.pool[ip], 'reserved')

    def test_reserve_ip(self):
        ip = IPv4Address('192.168.1.10')
        self.dhcp_binding.reserve_ip(ip)
        self.assertEqual(self.dhcp_binding.pool[ip], 'reserved')

    def test_pool_add(self):
        ip = IPv4Address('192.168.1.20')
        binding = {'chaddr': '00:11:22:33:44:55'}
        self.dhcp_binding.pool_add(ip, binding)
        self.assertEqual(self.dhcp_binding.pool[ip], binding)

    def test_in_use(self):
        ip = IPv4Address('192.168.1.30')
        self.dhcp_binding.pool_add(ip, {'chaddr': '00:11:22:33:44:55'})
        self.assertTrue(self.dhcp_binding.in_use(ip))
        self.dhcp_binding.pool[ip] = 'declined'
        self.assertFalse(self.dhcp_binding.in_use(ip))

    def test_get_next_free(self):
        chaddr = '00:11:22:33:44:55'
        ip = IPv4Address('192.168.1.40')
        self.dhcp_binding.pool_add(ip, {'chaddr': chaddr, 'ip': ip})
        self.dhcp_binding.bindings[chaddr] = {'ip': ip}
        self.assertEqual(self.dhcp_binding.get_next_free(chaddr), ip)

        # Test requesting a new IP
        new_chaddr = '00:11:22:33:44:66'
        next_free_ip = self.dhcp_binding.get_next_free(new_chaddr)
        self.assertIsInstance(next_free_ip, IPv4Address)
        self.assertNotIn(next_free_ip, self.dhcp_binding.pool)

if __name__ == '__main__':
    unittest.main()
