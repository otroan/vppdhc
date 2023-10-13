#!/usr/bin/env python3

'''
The main module for the VPPDHC daemon.
'''

# pylint: disable=import-error, invalid-name, logging-fstring-interpolation

import sys
import logging
import json
import asyncio
import typer
from vppdhc.dhc4server import DHCPServer
from vppdhc.dhc6pdclient import DHCPv6PDClient
from vppdhc.dhc6server import DHCPv6Server
from vppdhc.raadv import IP6NDRA
from vppdhc.vpppunt import VPP, VppEnum
from vppdhc._version import __version__

app = typer.Typer()
logger = logging.getLogger(__name__)

def version_callback(value: bool):
    '''Print the version and exit'''
    if value:
        typer.echo(f"vppdhcpd version: {__version__}")
        raise typer.Exit()

async def setup_tasks(conf, vpp):
    '''Setup the tasks'''
    tasks = []

    # # DHCPv4 client
    # if 'dhc4client' in conf:
    #     logger.debug('Setting up DHCPv4 client')
    #     c = conf['dhc4client']
    #     socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP4,
    #                             VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
    #                             68)

    #     dhcp_client = DHCPClient(socket, vpp_socket, vpp,
    #                             c['renewal-time'], c['lease-time'], c['name-server'])
    #     tasks.append(dhcp_client())

    # DHCPv4 server
    if 'dhc4server' in conf:
        logger.debug('Setting up DHCPv4 server')
        c = conf['dhc4server']
        socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP4,
                                VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                                67)

        dhcp_server = DHCPServer(socket, vpp_socket, vpp, c)
        tasks.append(dhcp_server())

    # DHCPv6 PD client
    if 'dhc6pdclient' in conf:
        logger.debug('Setting up DHCPv6 PD client')
        c = conf['dhc6pdclient']
        socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP6,
                                VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                                546) # pylint: disable=no-member

        npt66 = c.get('npt66', False)
        pd_client = DHCPv6PDClient(socket, vpp_socket, vpp,
                                c['interface'], c['internal-prefix'], npt66)

        tasks.append(pd_client())

    # DHCPv6 server
    if 'dhc6server' in conf:
        logger.debug('Setting up DHCPv6 server')
        c = conf['dhc6server']
        socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP6,
                                VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                                547) # pylint: disable=no-member
        server = DHCPv6Server(socket, vpp_socket, vpp, c)
        tasks.append(server())

    # RA advertisement
    if 'ip6ndra' in conf:
        logger.debug('Setting up RA advertisement daemon')
        c = conf['ip6ndra']
        # Get router solicitations
        socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP6,
                                VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP6,
                                133) # pylint: disable=no-member
        server = IP6NDRA(socket, vpp_socket, vpp, c)
        tasks.append(server())

    await asyncio.gather(*tasks)

@app.command()
def main(config: typer.FileText,
         apidir: str,
         log: str = None,
         logfile: str = None,
         version: bool = typer.Option(None, "--version", callback=version_callback, is_eager=True), # pylint: disable=unused-argument
         ):
    '''The main entry point for the VPPDHC daemon'''
    numeric_level = logging.INFO
    if log:
        numeric_level = getattr(logging, log.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {log}')
    if logfile:
        logging.basicConfig(filename=logfile, encoding='utf-8',
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        level=numeric_level)
    else:
        logging.basicConfig(stream=sys.stdout, encoding='utf-8',
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        level=numeric_level)
    conf = json.loads(config.read())
    logger.debug('Configuration %s', conf)

    vpp = VPP(apidir, None)

    tasks = setup_tasks(conf, vpp)

    logger.debug('Running main loop')
    asyncio.run(tasks)

    # # Cleanup (delete the bound socket file)
    # uds_receive_socket.close()
    # uds_send_socket.close()
    # os.remove(RECEIVE_SOCK_PATH)

if __name__ == '__main__':
    app()
