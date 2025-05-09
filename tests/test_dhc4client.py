import asyncio
import pytest
import logging
from vppdhc.dhc4client import DHC4Client, DHC4ClientStateMachine, ConfDHC4Client
from vppdhc.dhc4server import DHC4Server, command_dhcp_binding, ConfDHC4Server
from unittest.mock import Mock, AsyncMock
from vppdhc.datamodel import IPv4Interface, VPPInterfaceInfo, IPv6Address, Configuration, ConfSystem
from vppdhc.event_manager import EventManager
from vppdhc.vppdb import VPPDB


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

async def dhcp_core_test(client_task, server_task):
    # Just wait for the client and server to run
    await asyncio.sleep(7)

    s = command_dhcp_binding()
    print('BINDINGS', s)

    print('SHUTTING DOWN')
    # Don't cancel tasks here, let the test function handle it
    # server_task.cancel()
    # client_task.cancel()


@pytest.mark.asyncio
async def test_dhc4client() -> None:
    """Define temporary paths for sockets."""
    import tempfile

    client_socket = tempfile.NamedTemporaryFile(delete=True)
    server_socket = tempfile.NamedTemporaryFile(delete=True)
    client_socket_path = '\0'+client_socket.name
    server_socket_path = '\0'+server_socket.name

    # Create configurations
    dhc4_config = ConfDHC4Client(interface="eth0")
    server_config = ConfDHC4Server(dns=["8.8.8.8"],
                                   renewal_time=5,
                                   lease_time=10,
                                   ipv6_only_preferred=False)
    system_config = ConfSystem(log_level="DEBUG", bypass_tenant=2000)

    # Set up the configuration database
    cdb = VPPDB()
    cdb.set("/system", system_config)
    cdb.set("/dhc4client", dhc4_config)
    cdb.set("/dhc4server", server_config)
    print('CLIENT CONFIG', cdb.store)

    # Subscribe to events using VPPDB
    cdb.subscribe("/dhc4c/on_lease", on_lease)
    cdb.subscribe("/dhc4client/state", state)

    vpp = Mock()
    vpp.vpp_interface_name2index = AsyncMock(return_value=42)
    vpp.vpp_probe_is_duplicate_async = AsyncMock(return_value=False)
    vpp.vpp_vcdp_session_add = AsyncMock(return_value=0)
    interfaceinfo = VPPInterfaceInfo(ifindex=42,
                                    name="eth0",
                                    mac=b"\xaa\xbb\xcc\xdd\xee\xff",
                                    ip4=[IPv4Interface("192.168.1.0/24")],
                                    ip6=[],
                                    ip6ll=IPv6Address("fe80::1"))

    logging.getLogger("vppdhc.dhc4client.packet").setLevel(logging.INFO)

    vpp.vpp_interface_info = AsyncMock(return_value=interfaceinfo)

    # Modified test to properly handle task cancellation and resource cleanup
    async with DHC4Client(client_socket_path, server_socket_path, vpp, cdb) as client, \
             DHC4Server(server_socket_path, client_socket_path, vpp, cdb) as server:

        # Create tasks outside the TaskGroup
        server_task = asyncio.create_task(server.listen())
        client_task = asyncio.create_task(client.client())

        try:
            # Wait for the test to complete
            await dhcp_core_test(client_task, server_task)
        finally:
            # Ensure tasks are cancelled and awaited
            server_task.cancel()
            client_task.cancel()

            # Wait for tasks to complete cancellation
            try:
                await asyncio.gather(server_task, client_task, return_exceptions=True)
            except asyncio.CancelledError:
                pass  # Expected


if __name__ == "__main__":
    pytest.main()
