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
from vppdhc.dhc4client import DHCPClient
from vppdhc.dhc4server import DHCPServer
from vppdhc.dhc6pdclient import DHCPv6PDClient
from vppdhc.dhc6server import DHCPv6Server
from vppdhc.raadv import IP6NDRA
from vppdhc.vpppunt import VPP, VppEnum
from vppdhc._version import __version__

app = typer.Typer()
logger = logging.getLogger(__name__)


# Validate the configuration file against a Pydantic model
from pydantic import BaseModel, Field
from pydantic.networks import IPvAnyAddress, IPvAnyNetwork, IPv6Address, IPv6Network, IPv4Address

class ConfVPP(BaseModel):
    socket: str

class ConfDHCP4Client(BaseModel):
    interface: str
    nat: str
    tenant: int

class ConfDHCP4Server(BaseModel):
    lease_time: int = Field(alias='lease-time')
    renewal_time: int = Field(alias='renewal-time')
    dns: list[IPv4Address]
    bypass_tenant: int = Field(alias='bypass-tenant')

class ConfDHCP6PDClient(BaseModel):
    interface: str
    internal_prefix: IPv6Network = Field(alias='internal-prefix')
    npt66: bool = False

class ConfDHCP6Server(BaseModel):
    interfaces: list[str]
    preflft: int = 604800
    validlft: int = 2592000
    dns: list[IPv6Address]

class ConfIP6NDPrefix(BaseModel):
    prefix: IPv6Network
    L: bool = True
    A: bool = False
class ConfIP6NDRA(BaseModel):
    interfaces: list[str]
    pio: ConfIP6NDPrefix = None
    maxrtradvinterval: int = 600
    pref64: IPv6Network = None

class Configuration(BaseModel):
    '''Configuration model'''
    vpp: ConfVPP
    dhc4client: ConfDHCP4Client = None
    dhc4server: ConfDHCP4Server = None
    dhc6pdclient: ConfDHCP6PDClient = None
    dhc6server: ConfDHCP6Server = None
    ip6ndra: ConfIP6NDRA = None


def version_callback(value: bool):
    '''Print the version and exit'''
    if value:
        typer.echo(f"vppdhcpd version: {__version__}")
        raise typer.Exit()

async def setup_tasks(conf, vpp):
    '''Setup the tasks'''
    tasks = []

    # DHCPv4 client
    if conf.dhc4client:
        logger.debug('Setting up DHCPv4 client')
        socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP4,
                                VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                                68)

        dhcp_client = DHCPClient(socket, vpp_socket, vpp, conf.dhc4client)
        tasks.append(dhcp_client())

    # DHCPv4 server
    if conf.dhc4server:
        logger.debug('Setting up DHCPv4 server')
        socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP4,
                                VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                                67)

        dhcp_server = DHCPServer(socket, vpp_socket, vpp, conf.dhc4server)
        tasks.append(dhcp_server())

    # DHCPv6 PD client
    if conf.dhc6pdclient:
        logger.debug('Setting up DHCPv6 PD client')
        socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP6,
                                VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                                546) # pylint: disable=no-member

        pd_client = DHCPv6PDClient(socket, vpp_socket, vpp, conf.dhc6pdclient)
        tasks.append(pd_client())

    # DHCPv6 server
    if conf.dhc6server:
        logger.debug('Setting up DHCPv6 server')
        socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP6,
                                VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                                547) # pylint: disable=no-member
        try:
            server = DHCPv6Server(socket, vpp_socket, vpp, conf.dhc6server)
        except Exception as e:
            logger.error(f'Error setting up DHCPv6 server: {e}')
            sys.exit(1)
        tasks.append(server())

    # RA advertisement
    if conf.ip6ndra:
        logger.debug('Setting up RA advertisement daemon')
        # Get router solicitations
        socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP6,
                                VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP6,
                                133) # pylint: disable=no-member
        server = IP6NDRA(socket, vpp_socket, vpp, conf.ip6ndra)
        tasks.append(server())

    await asyncio.gather(*tasks)

@app.command()
def main(config: typer.FileText,
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

    validatedconf = Configuration(**conf)
    print('Validated configuration: ', validatedconf)

    logger.debug('Configuration %s', validatedconf)

    vpp = VPP(None)

    tasks = setup_tasks(validatedconf, vpp)

    logger.debug('Running main loop')
    asyncio.run(tasks)

    # # Cleanup (delete the bound socket file)
    # uds_receive_socket.close()
    # uds_send_socket.close()
    # os.remove(RECEIVE_SOCK_PATH)

if __name__ == '__main__':
    app()
