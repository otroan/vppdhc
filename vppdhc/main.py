#!/usr/bin/env python3

import os
import asyncio
import typer
from vppdhc.dhc4server import DHCPServer
from vppdhc.dhc6pdclient import DHCPv6PDClient
from vppdhc.vpppunt import VPP

app = typer.Typer()

from vppdhc._version import __version__
def version_callback(value: bool):
    if value:
        typer.echo(f"vppdhcpd version: {__version__}")
        raise typer.Exit()

async def setup_tasks(dhc4serversock, dhc6pdclientsock, vppsock, vpp):
    # DHCPv4 server
    dhcp_server = DHCPServer(dhc4serversock, vppsock, vpp, renewal_time=30, lease_time=60)

    # DHCPv6 PD client
    pd_client = DHCPv6PDClient(dhc6pdclientsock, vppsock, vpp, if_index=1, internal_prefix='fd00::/48')

    await asyncio.gather(dhcp_server(), pd_client())

@app.command()
def main(dhc4serversock: str,
         dhc6pdclientsock: str,
         vppsock: str,
         verbose: bool = False,
         version: bool = typer.Option(None, "--version", callback=version_callback, is_eager=True),
         ):

    # Delete socket file if exists
    if os.path.exists(dhc4serversock):
        os.remove(dhc4serversock)
    if os.path.exists(dhc6pdclientsock):
        os.remove(dhc6pdclientsock)

    vpp = VPP(None)

    tasks = setup_tasks(dhc4serversock, dhc6pdclientsock, vppsock, vpp)
    asyncio.run(tasks)

    # # Cleanup (delete the bound socket file)
    # uds_receive_socket.close()
    # uds_send_socket.close()
    # os.remove(RECEIVE_SOCK_PATH)

if __name__ == '__main__':
    app()
