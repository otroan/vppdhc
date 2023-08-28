#!/usr/bin/env python3

import os
import sys
import json
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

async def setup_tasks(conf, vpp):
    # DHCPv4 server
    c = conf['dhc4server']
    if os.path.exists(c['socket']):
        os.remove(c['socket'])

    dhcp_server = DHCPServer(c['socket'], conf['vpp']['socket'], vpp,
                             c['renewal-time'], c['lease-time'], c['name-server'])

    # DHCPv6 PD client
    c = conf['dhc6pdclient']
    if os.path.exists(c['socket']):
        os.remove(c['socket'])
    pd_client = DHCPv6PDClient(c['socket'], conf['vpp']['socket'],
                               vpp,
                               c['interface'], c['internal-prefix'])

    await asyncio.gather(dhcp_server(), pd_client())

@app.command()
def main(config: typer.FileText,
         verbose: bool = False,
         version: bool = typer.Option(None, "--version", callback=version_callback, is_eager=True),
         ):

    conf = json.loads(config.read())
    print('CONF', conf)

    vpp = VPP(None)

    tasks = setup_tasks(conf, vpp)
    asyncio.run(tasks)

    # # Cleanup (delete the bound socket file)
    # uds_receive_socket.close()
    # uds_send_socket.close()
    # os.remove(RECEIVE_SOCK_PATH)

if __name__ == '__main__':
    app()
