import asyncio
import logging
from unittest.mock import AsyncMock, Mock

import pytest

from vppdhc.datamodel import ConfSystem, IPv4Interface, IPv6Address, VPPInterfaceInfo
from vppdhc.dhc4client import ConfDHC4Client, DHC4Client, DHC4ClientStateMachine
from vppdhc.dhc4server import ConfDHC4Server, DHC4Server
from vppdhc.vppdb import VPPDB


def pytest_configure(config):
    # Set the asyncio loop scope for this test file only
    config.option.asyncio_default_fixture_loop_scope = "session"  # Options: function, module, or session


state = DHC4ClientStateMachine.INIT
expected_state = DHC4ClientStateMachine.REQUESTING

# Create an asyncio.Event to signal when the lease is received
lease_event = asyncio.Event()


def on_lease(key, event):
    print(f"*****Lease event: {key} : {event}")
    lease_event.set()  # Signal that the lease has been received


def state(key, event):
    print(f"Client state: {key} : {event}")
    global state, expected_state
    expected_state = DHC4ClientStateMachine.BOUND


async def dhcp_core_test(client, server):
    # Wait for the lease event to be set
    await lease_event.wait()
    # await asyncio.sleep(3)  # Allow some time for the lease to be processed

    # Check if we received a lease event
    # s = command_dhcp_binding()
    # print("BINDINGS", s)

    # Add a check to see if the lease was received
    if not hasattr(client, "binding") or client.binding is None:
        print("WARNING: No lease received during test!")
    else:
        print(f"Lease received: {client.binding}")

    print("SHUTTING DOWN")


@pytest.mark.asyncio
async def test_dhc4client() -> None:
    """Define temporary paths for sockets."""
    import tempfile

    client_socket = tempfile.NamedTemporaryFile(delete=True)
    server_socket = tempfile.NamedTemporaryFile(delete=True)
    client_socket_path = "\0" + client_socket.name
    server_socket_path = "\0" + server_socket.name

    # Create configurations
    dhc4_config = ConfDHC4Client(interface="eth0")
    server_config = ConfDHC4Server(dns=["8.8.8.8"], renewal_time=5, lease_time=10, ipv6_only_preferred=False)
    system_config = ConfSystem(log_level="DEBUG", bypass_tenant=2000)

    # Set up the configuration database
    cdb = VPPDB()
    cdb.set("/system", system_config)
    cdb.set("/dhc4client", dhc4_config)
    cdb.set("/dhc4server", server_config)
    print("CLIENT CONFIG", cdb.store)

    # Subscribe to events using VPPDB
    cdb.subscribe("/ops/dhc4c/lease", on_lease)
    cdb.subscribe("/ops/dhc4c/state", state)

    vpp = Mock()
    vpp.vpp_interface_name2index = AsyncMock(return_value=42)
    vpp.vpp_probe_is_duplicate_async = AsyncMock(return_value=False)
    vpp.vpp_vcdp_session_add = AsyncMock(return_value=0)
    interfaceinfo = VPPInterfaceInfo(
        ifindex=42,
        name="eth0",
        mac=b"\xaa\xbb\xcc\xdd\xee\xff",
        ip4=[IPv4Interface("192.168.1.0/24")],
        ip6=[],
        ip6ll=IPv6Address("fe80::1"),
    )

    logging.getLogger("vppdhc.dhc4client.packet").setLevel(logging.INFO)

    vpp.vpp_interface_info = AsyncMock(return_value=interfaceinfo)

    # Modified test to properly handle task cancellation and resource cleanup
    async with (
        DHC4Client(client_socket_path, server_socket_path, vpp, cdb) as client,
        DHC4Server(server_socket_path, client_socket_path, vpp, cdb) as server,
    ):
        # Create tasks outside the TaskGroup
        server_task = asyncio.create_task(server.listen())
        client_task = asyncio.create_task(client.client())

        try:
            # Wait for the test to complete
            await dhcp_core_test(client, server)
        finally:
            # Ensure tasks are cancelled and awaited
            server_task.cancel()
            client_task.cancel()

            # Wait for tasks to complete cancellation
            try:
                await asyncio.gather(server_task, client_task, return_exceptions=True)
            except asyncio.CancelledError:
                pass  # Expected

    cdb.dump()


if __name__ == "__main__":
    pytest.main()
