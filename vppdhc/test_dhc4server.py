import unittest
from ipaddress import IPv4Address, IPv4Network
from vppdhc.dhc4server import DHCPBinding, BindingState

class TestDHCPBinding(unittest.TestCase):

    def setUp(self):
        self.prefix = IPv4Network('192.168.1.0/24')
        self.dhcp_binding = DHCPBinding(self.prefix)

    def test_initialization(self):
        # Check if the prefix is set correctly
        self.assertEqual(self.dhcp_binding.prefix, self.prefix)
        # Check if the first 10% of IP addresses are reserved
        reserved_count = int(self.prefix.num_addresses / 10)
        reserved_ips = [ip for ip in self.prefix][:reserved_count]
        for ip in reserved_ips:
            self.assertEqual(self.dhcp_binding.pool[ip], BindingState.RESERVED)

    def test_reserve_ip(self):
        ip = IPv4Address('192.168.1.10')
        self.dhcp_binding.reserve_ip(ip)
        self.assertEqual(self.dhcp_binding.pool[ip], BindingState.RESERVED)

    def test_pool_add(self):
        ip = IPv4Address('192.168.1.20')
        binding = {'chaddr': '00:11:22:33:44:55'}
        self.dhcp_binding.pool_add(ip, binding)
        self.assertEqual(self.dhcp_binding.pool[ip], binding)

    def test_in_use(self):
        ip = IPv4Address('192.168.1.30')
        self.dhcp_binding.pool_add(ip, {'chaddr': '00:11:22:33:44:55'})
        self.assertTrue(self.dhcp_binding.in_use(ip))
        self.dhcp_binding.pool[ip] = BindingState.DECLINED
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
