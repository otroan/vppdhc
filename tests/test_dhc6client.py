import asyncio
import asyncio_dgram
import pytest
import logging
from ipaddress import IPv6Network
from scapy.all import Ether, IP, UDP, BOOTP, DHCP
from random import randint
from vppdhc.dhc6client import DHC6Client
from vppdhc.dhc6server import DHC6Server, command_dhcp6_binding
from unittest.mock import MagicMock, Mock, AsyncMock
from vppdhc.vpppunt import VPPPunt, Actions
from vppdhc.datamodel import IPv6Interface, VPPInterfaceInfo, IPv6Address, ConfDHC6Client, ConfDHC6Server
from vppdhc.event_manager import EventManager
import vppdhc.businesslogic

def pytest_configure(config):
    # Set the asyncio loop scope for this test file only
    config.option.asyncio_default_fixture_loop_scope = "session"  # Options: function, module, or session


# state = DHCP4ClientStateMachine.INIT
# expected_state = DHCP4ClientStateMachine.REQUESTING
async def on_lease(event):
    print(f"Lease event: {event}")


async def state(event):
    print(f"Client state: {event}")


async def dhcp_core_test(event_manager, client_task, server_task):
    event_manager.subscribe("/dhc6client/on_lease", on_lease)
    event_manager.subscribe("/dhc6client/state", state)
    await asyncio.sleep(7)

    s = command_dhcp6_binding()
    print("BINDINGS", s)

    print("SHUTTING DOWN    ")
    server_task.cancel()
    client_task.cancel()


@pytest.mark.asyncio
async def test_dhc6client() -> None:
    """Define temporary paths for sockets."""
    import tempfile

    client_socket = tempfile.NamedTemporaryFile(delete=True)
    server_socket = tempfile.NamedTemporaryFile(delete=True)
    client_socket_path = "\0" + client_socket.name
    server_socket_path = "\0" + server_socket.name

    event_manager = EventManager()
    vppdhc.businesslogic.init(event_manager)
    client_config = ConfDHC6Client(interface="eth0", ia_pd=True, ia_na=True,
                                   internal_prefix="fd00::/64", npt66=True)
    server_config = ConfDHC6Server(
        interfaces=["eth0"],
        dns=["1::1"],
        ia_na=True,
        ia_prefix=[IPv6Network("2001:DB8::/56")],
        ia_allocate_length=64,
    )

    vpp = Mock()
    vpp.vpp_interface_name2index = AsyncMock(return_value=42)
    vpp.vpp_probe_is_duplicate = AsyncMock(return_value=False)
    vpp.vpp_ip_multicast_group_join = AsyncMock(return_value=None)

    interfaceinfo = VPPInterfaceInfo(
        ifindex=42,
        name="eth0",
        mac=b"\xaa\xbb\xcc\xdd\xee\xff",
        ip6=[IPv6Interface("1::1/128")],
        ip4=[],
        ip6ll=IPv6Address("fe80::1"),
    )

    logging.getLogger("vppdhc.dhc6client.packet").setLevel(logging.INFO)

    vpp.vpp_interface_info = AsyncMock(return_value=interfaceinfo)

    client = DHC6Client(client_socket_path, server_socket_path, vpp, client_config, event_manager)
    server = DHC6Server(server_socket_path, client_socket_path, vpp, server_config)

    logging.getLogger("vppdhc.dhc4client.packet").setLevel(logging.INFO)
    logging.getLogger("vppdhc.dhc4server.packet").setLevel(logging.INFO)

    async with asyncio.TaskGroup() as tg:
        server_task = tg.create_task(server.listen())
        client_task = tg.create_task(client.client())
        test_task = tg.create_task(dhcp_core_test(event_manager, client_task, server_task))


if __name__ == "__main__":
    pytest.main()
