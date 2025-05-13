import asyncio
import logging
from ipaddress import IPv6Network
from unittest.mock import AsyncMock, Mock

import pytest
from pydantic.networks import IPv6Interface

from vppdhc.datamodel import (
    ConfSystem,
    IPv6Address,
    VPPInterfaceInfo,
)
from vppdhc.dhc6client import ConfDHC6Client, DHC6Client
from vppdhc.dhc6server import ConfDHC6Server, DHC6Server, command_dhcp6_binding
from vppdhc.vppdb import VPPDB


def pytest_configure(config):
    # Set the asyncio loop scope for this test file only
    config.option.asyncio_default_fixture_loop_scope = "session"  # Options: function, module, or session


# Create an asyncio.Event to signal when the lease is received
lease_event = asyncio.Event()


# state = DHCP4ClientStateMachine.INIT
# expected_state = DHCP4ClientStateMachine.REQUESTING
def on_lease(key, event):
    print(f"Lease event: {event}")
    lease_event.set()  # Signal that the lease has been received


def state(event):
    print(f"Client state: {event}")


async def dhcp_core_test(client_task, server_task):
    await lease_event.wait()

    s = command_dhcp6_binding()
    print("BINDINGS", s)


interfaceinfo = {}
interfaceinfo[42] = VPPInterfaceInfo(
    ifindex=42,
    name="eth0",
    mac=b"\xaa\xbb\xcc\xdd\xee\xff",
    ip6=[IPv6Interface("1::1/128"), IPv6Interface("fd00::1/64")],
    ip4=[],
    ip6ll=IPv6Address("fe80::1"),
)
interfaceinfo[43] = VPPInterfaceInfo(
    ifindex=43,
    name="eth1",
    mac=b"\xaa\xbb\xcc\xdd\xee\xff",
    ip6=[IPv6Interface("2::1/128")],
    ip4=[],
    ip6ll=IPv6Address("fe80::2"),
)


def mock_interface_info(ifindex):
    return interfaceinfo[ifindex]


def mock_name2index(name):
    return 42 if name == "eth0" else 43


@pytest.mark.asyncio
async def test_dhc6client() -> None:
    """Define temporary paths for sockets."""
    import tempfile

    client_socket = tempfile.NamedTemporaryFile(delete=True)
    server_socket = tempfile.NamedTemporaryFile(delete=True)
    client_socket_path = "\0" + client_socket.name
    server_socket_path = "\0" + server_socket.name

    client_config = ConfDHC6Client(interface="eth0", ia_pd=True, ia_na=True, internal_prefix="fd00::/64", npt66=True)
    server_config = ConfDHC6Server(
        interfaces=["eth0", "eth1"],
        dns=["1::1"],
        ia_na=True,
        ia_prefix=[IPv6Network("2001:DB8::/56")],
        ia_allocate_length=64,
    )
    system_config = ConfSystem(log_level="DEBUG", bypass_tenant=2000)

    cdb = VPPDB()
    cdb.set("/dhc6client", client_config)
    cdb.set("/dhc6server", server_config)
    cdb.set("/system", system_config)

    vpp = Mock()
    vpp.vpp_interface_name2index = AsyncMock(side_effect=mock_name2index)
    vpp.vpp_probe_is_duplicate = AsyncMock(return_value=False)
    vpp.vpp_ip_multicast_group_join = AsyncMock(return_value=None)
    # _ = BusinessLogic(event_manager, vpp)

    logging.getLogger("vppdhc.dhc6client.packet").setLevel(logging.INFO)
    logging.getLogger("vppdhc.dhc6server.packet").setLevel(logging.INFO)

    vpp.vpp_interface_info = AsyncMock(side_effect=mock_interface_info)

    # Subscribe to events using VPPDB
    cdb.subscribe("/ops/dhc6c/lease", on_lease)
    cdb.subscribe("/ops/dhc6c/state", state)

    # Modified test to properly handle task cancellation and resource cleanup
    async with (
        DHC6Client(client_socket_path, server_socket_path, vpp, cdb) as client,
        DHC6Server(server_socket_path, client_socket_path, vpp, cdb) as server,
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

    print("*** DATA STORE ****")
    cdb.dump()


if __name__ == "__main__":
    pytest.main()
