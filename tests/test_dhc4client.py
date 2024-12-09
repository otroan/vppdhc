import asyncio
import asyncio_dgram
import pytest
import logging
from scapy.all import Ether, IP, UDP, BOOTP, DHCP
from random import randint
from vppdhc.dhc4client import DHC4Client, DHC4ClientStateMachine
from vppdhc.dhc4server import DHC4Server, command_dhcp_binding
from vppdhc.datamodel import ConfDHC4Client, ConfDHC4Server
from unittest.mock import MagicMock, Mock, AsyncMock
from vppdhc.vpppunt import VPPPunt, Actions
from vppdhc.datamodel import IPv4Interface, VPPInterfaceInfo, IPv6Address, DHC4ClientEvent
from vppdhc.event_manager import EventManager

def pytest_configure(config):
    # Set the asyncio loop scope for this test file only
    config.option.asyncio_default_fixture_loop_scope = "session"  # Options: function, module, or session

state = DHC4ClientStateMachine.INIT
expected_state = DHC4ClientStateMachine.REQUESTING
async def on_lease(event):
    print(f"Lease event: {event}")

async def state(event):
    global state, expected_state
    print(f"Client state: {event}")
    state = event.state
    # assert state == expected_state

    expected_state = DHC4ClientStateMachine.BOUND

async def dhcp_core_test(event_manager, client_task, server_task):

    event_manager.subscribe("/dhc4client/on_lease", on_lease)
    event_manager.subscribe("/dhc4client/state", state)
    await asyncio.sleep(7)

    s = command_dhcp_binding()
    print('BINDINGS', s)

    print('SHUTTING DOWN    ')
    server_task.cancel()
    client_task.cancel()


@pytest.mark.asyncio
async def test_dhc4client() -> None:
    """Define temporary paths for sockets."""
    import tempfile

    client_socket = tempfile.NamedTemporaryFile(delete=True)
    server_socket = tempfile.NamedTemporaryFile(delete=True)
    client_socket_path = '\0'+client_socket.name
    server_socket_path = '\0'+server_socket.name

    event_manager = EventManager()

    client_config = ConfDHC4Client(interface="eth0")
    server_config = ConfDHC4Server(dns=["8.8.8.8"],
                                    renewal_time=5,
                                    lease_time=10,
                                    bypass_tenant=2000)

    vpp = Mock()
    vpp.vpp_interface_name2index = AsyncMock(return_value=42)
    vpp.vpp_probe_is_duplicate_async = AsyncMock(return_value=False)
    vpp.vpp_vcdp_session_add = AsyncMock(return_value=0)
    interfaceinfo =  VPPInterfaceInfo(ifindex=42,
                                      name="eth0",
                                      mac=b"\xaa\xbb\xcc\xdd\xee\xff",
                                      ip4=[IPv4Interface("192.168.1.0/24")],
                                      ip6=[],
                                      ip6ll=IPv6Address("fe80::1"))

    logging.getLogger("vppdhc.dhc4client.packet").setLevel(logging.INFO)

    vpp.vpp_interface_info = AsyncMock(return_value=interfaceinfo)

    client = DHC4Client(client_socket_path, server_socket_path, vpp, client_config, event_manager)
    server = DHC4Server(server_socket_path, client_socket_path, vpp, server_config)

    logging.getLogger("vppdhc.dhc4client.packet").setLevel(logging.INFO)
    logging.getLogger("vppdhc.dhc4server.packet").setLevel(logging.INFO)

    async with asyncio.TaskGroup() as tg:
        server_task = tg.create_task(server.listen())
        client_task = tg.create_task(client.client())
        test_task = tg.create_task(dhcp_core_test(event_manager, client_task, server_task))


if __name__ == "__main__":
    pytest.main()
