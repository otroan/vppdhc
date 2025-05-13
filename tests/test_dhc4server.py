"""Tests for DHCv4 server module."""

from ipaddress import IPv4Address, IPv4Network

import pytest
from pydantic import ValidationError

from vppdhc.dhc4server import (
    DHC4BindingDatabase,
    DHC4BindingState,
    DHC4ServerNoIPaddrAvailableError,
    get_ip_index,
)


def test_ip_in_network():
    assert get_ip_index("192.168.1.10", "192.168.1.0/24") == 10
    assert get_ip_index("192.168.1.1", "192.168.1.0/24") == 1
    assert get_ip_index("192.168.1.255", "192.168.1.0/24") == 255


def test_ip_not_in_network():
    with pytest.raises(ValueError):
        get_ip_index("192.168.2.10", "192.168.1.0/24")


def test_ip_at_network_boundary():
    assert get_ip_index("192.168.1.0", "192.168.1.0/24") == 0
    assert get_ip_index("192.168.1.255", "192.168.1.0/24") == 255


def test_invalid_ip():
    with pytest.raises(ValueError):
        get_ip_index("invalid_ip", "192.168.1.0/24")


def test_invalid_network():
    with pytest.raises(ValueError):
        get_ip_index("192.168.1.10", "invalid_network")


def test_ip_not_ipv4():
    with pytest.raises(ValueError):
        get_ip_index("2001:db8::1", "192.168.1.0/24")


def test_network_not_ipv4():
    with pytest.raises(ValueError):
        get_ip_index("192.168.1.10", "2001:db8::/32")


@pytest.fixture
def dhcp_binding_db():
    return DHC4BindingDatabase(
        ifindex=1,
        interface="eth0",
        mac_address=bytes.fromhex("001122334455"),
        server_ip=IPv4Address("192.168.1.1"),
        leases=[],  # Initialize with 256 empty leases
        network=IPv4Network("192.168.1.0/24"),
        dns_servers=[IPv4Address("8.8.8.8")],
        lease_time_default=86400,
        lease_time_max=172800,
        lease_by_client_id={},
    )


def test_initialization(dhcp_binding_db):
    assert dhcp_binding_db.ifindex == 1
    assert dhcp_binding_db.interface == "eth0"
    assert dhcp_binding_db.server_ip == IPv4Address("192.168.1.1")
    assert len(dhcp_binding_db.leases) == 256
    assert dhcp_binding_db.network == IPv4Network("192.168.1.0/24")
    assert dhcp_binding_db.dns_servers == [IPv4Address("8.8.8.8")]
    assert dhcp_binding_db.lease_time_default == 86400
    assert dhcp_binding_db.lease_time_max == 172800
    assert dhcp_binding_db.lease_by_client_id == {}


def test_static_ip(dhcp_binding_db):
    ip = IPv4Address("192.168.1.10")
    dhcp_binding_db.static_ip(ip)
    index = get_ip_index(ip, "192.168.1.0/24")
    lease = dhcp_binding_db.leases[index]
    assert lease.ip_address == ip
    assert lease.status == DHC4BindingState.RESERVED


def test_static_ip_outside_network(dhcp_binding_db):
    ip = IPv4Address("192.168.2.10")
    with pytest.raises(ValueError):
        dhcp_binding_db.static_ip(ip)


def test_invalid_initialization():
    with pytest.raises(ValidationError):
        DHC4BindingDatabase(
            ifindex=1,
            interface="eth0",
            mac_address=bytes.fromhex("001122334455"),
            server_ip=IPv4Address("192.168.1.1"),
            leases=[None] * 256,
            network="invalid_network",
            dns_servers=[IPv4Address("8.8.8.8")],
            lease_time_default=86400,
            lease_time_max=172800,
            lease_by_client_id={},
        )


def test_post_init_hook(dhcp_binding_db):
    reserved = min(int(dhcp_binding_db.network.num_addresses / 10), 256)
    reserved_addresses = list(dhcp_binding_db.network)[:reserved]
    for ip in reserved_addresses:
        index = get_ip_index(ip, "192.168.1.0/24")
        lease = dhcp_binding_db.leases[index]
        assert lease.ip_address == ip, f"IP address {ip} is not reserved"
        assert lease.status == DHC4BindingState.RESERVED


def test_reserve_new_client(dhcp_binding_db):
    client_id = b"client1"
    ip = dhcp_binding_db.reserve(client_id, client_id, "host1")
    assert ip is not None
    assert dhcp_binding_db.in_use(ip)


def test_get_next_free_existing_client(dhcp_binding_db):
    client_id = b"client1"
    ip = dhcp_binding_db.reserve(client_id, client_id, "host1")
    dhcp_binding_db.lease_by_client_id[client_id] = get_ip_index(ip, "192.168.1.0/24")
    ip2 = dhcp_binding_db.reserve(client_id, client_id, "host1")
    assert ip == ip2


def test_reserve_requested_ip(dhcp_binding_db):
    client_id = b"client1"
    requested_ip = IPv4Address("192.168.1.50")
    ip = dhcp_binding_db.reserve(client_id, client_id, "host", reqip=requested_ip)
    assert ip == requested_ip


def test_reserve_no_available_ip(dhcp_binding_db):
    client_id = b"client1"
    with pytest.raises(DHC4ServerNoIPaddrAvailableError):
        for i in range(256):
            ip = dhcp_binding_db.reserve(client_id + i.to_bytes(), client_id + i.to_bytes(), "host")


def test_confirm_offer_new_client(dhcp_binding_db):
    mac_address = b"00:11:22:33:44:55"
    client_id = b"client1"
    hostname = "client1-host"
    ip = dhcp_binding_db.reserve(mac_address, client_id, hostname)
    confirmed_ip = dhcp_binding_db.confirm_offer(client_id, ip)
    assert confirmed_ip == ip
    index = get_ip_index(ip, "192.168.1.0/24")
    lease = dhcp_binding_db.leases[index]
    assert lease.status == DHC4BindingState.BOUND


def test_confirm_offer_existing_client(dhcp_binding_db):
    mac_address = b"00:11:22:33:44:55"
    client_id = b"client1"
    hostname = "client1-host"
    ip = dhcp_binding_db.reserve(mac_address, client_id, hostname)
    confirmed_ip = dhcp_binding_db.confirm_offer(client_id, ip)
    assert confirmed_ip == ip
    index = get_ip_index(ip, "192.168.1.0/24")
    lease = dhcp_binding_db.leases[index]
    assert lease.status == DHC4BindingState.BOUND


def test_release(dhcp_binding_db):
    mac_address = b"00:11:22:33:44:55"
    client_id = b"client1"
    hostname = "client1-host"
    ip = dhcp_binding_db.reserve(mac_address, client_id, hostname)
    dhcp_binding_db.release(client_id, ip)
    index = get_ip_index(ip, dhcp_binding_db.network)
    lease = dhcp_binding_db.leases[index]
    assert lease == None


def test_decline(dhcp_binding_db):
    mac_address = b"00:11:22:33:44:55"
    client_id = b"client1"
    hostname = "client1-host"
    ip = dhcp_binding_db.reserve(mac_address, client_id, hostname)
    dhcp_binding_db.decline(client_id, ip)
    ip2 = dhcp_binding_db.reserve(mac_address, client_id, hostname)
    assert ip != ip2
