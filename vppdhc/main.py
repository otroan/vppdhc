"""
The main module for the VPPDHC daemon.
"""

# pylint: disable=import-error, invalid-name, logging-fstring-interpolation

import asyncio
import json
import logging
import sys

import typer

from vppdhc._version import __version__

from vppdhc.dhc4client import DHCPClient
from vppdhc.dhc4server import DHCPServer
from vppdhc.dhc6pdclient import DHCPv6PDClient
from vppdhc.dhc6server import DHCPv6Server
from vppdhc.raadv import IP6NDRA
from vppdhc.vppdhcdctl import VPPDHCD
from vppdhc.vpppunt import VPP, VppEnum
from vppdhc.datamodel import DHCP4ClientEvent, DHCP4ServerEvent, Configuration

app = typer.Typer()
logger = logging.getLogger(__name__)


def version_callback(value: bool):
    """Print the version and exit."""
    if value:
        typer.echo(f"vppdhcpd version: {__version__}")
        raise typer.Exit()

def setup_tasks(tg, conf, vpp, event_queue: asyncio.Queue):
    """Setup the tasks."""
    tasks = []
    # Initialise the control socket
    try:
        vppdhcdctl = VPPDHCD("/tmp/vppdhcd.sock")
        t = tg.create_task(vppdhcdctl.start_control_server())
        tasks.append(t)
    except Exception as e:
        logger.error(f"***Error setting up control socket: {e}")

    # DHCPv4 client
    if conf.dhc4client:
        logger.debug("Setting up DHCPv4 client")
        socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP4,
                                VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                                68)

        dhcp_client = DHCPClient(socket, vpp_socket, vpp, conf.dhc4client, event_queue)
        t = tg.create_task(dhcp_client.client())
        tasks.append(t)

    # DHCPv4 server
    if conf.dhc4server:
        logger.debug("Setting up DHCPv4 server")
        socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP4,
                                VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                                67)

        dhcp_server = DHCPServer(socket, vpp_socket, vpp, conf.dhc4server)
        t = tg.create_task(dhcp_server())
        tasks.append(t)

    # DHCPv6 PD client
    if conf.dhc6pdclient:
        logger.debug("Setting up DHCPv6 PD client")
        socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP6,
                                VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                                546) # pylint: disable=no-member

        pd_client = DHCPv6PDClient(socket, vpp_socket, vpp, conf.dhc6pdclient)
        t = tg.create_task(pd_client())
        tasks.append(t)

    # DHCPv6 server
    if conf.dhc6server:
        logger.debug("Setting up DHCPv6 server")
        socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP6,
                                VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                                547) # pylint: disable=no-member
        try:
            server = DHCPv6Server(socket, vpp_socket, vpp, conf.dhc6server)
        except Exception as e:
            logger.error(f"Error setting up DHCPv6 server: {e}")
            sys.exit(1)
        t = tg.create_task(server())
        tasks.append(t)

    # RA advertisement
    if conf.ip6ndra:
        logger.debug("Setting up RA advertisement daemon")
        # Get router solicitations
        socket, vpp_socket = vpp.vpp_socket_register(VppEnum.vl_api_address_family_t.ADDRESS_IP6,
                                VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP6,
                                133) # pylint: disable=no-member
        server = IP6NDRA(socket, vpp_socket, vpp, conf.ip6ndra)
        t = tg.create_task(server())
        tasks.append(t)

    return tasks

def dhcp4clientevent(event):
    print('RECEIVED AN EVENT', event)
    # rv = self.vpp.vpp_ip_address(self.if_index, prefix)
    # print('RV', rv)
    # Create a NAT instance with that address as the NAT pool

    # if self.nat:
    #     print('CONFIGURING NAT INSTANCE', self.nat, client_ip)
    #     rv = self.vpp.vpp_vcdp_nat_add(self.nat, [client_ip])
    #     print('RV', rv)
    #     rv = self.vpp.vpp_vcdp_nat_bind_set_unset(self.tenant_id, self.nat)
    #     print('RV', rv)

async def handle_events(event_queue: asyncio.Queue):
    while True:
        event = await event_queue.get()
        if isinstance(event, DHCP4ClientEvent):
            dhcp4clientevent(event)
        # Process the event
        print(f"Handling event: {event}")

async def main_coroutine(validatedconf, vpp) -> None:
    import traceback
    event_queue = asyncio.Queue()
    try:
        async with asyncio.TaskGroup() as tg:
            tasks = setup_tasks(tg, validatedconf, vpp, event_queue)
            events = tg.create_task(handle_events(event_queue))
    except ExceptionGroup as eg:
        print(f"ExceptionGroup caught: {eg}")
        for exc in eg.exceptions:
            print(f"Task exception: {exc}")
            print("Traceback:")
            traceback.print_exception(type(exc), exc, exc.__traceback__)

@app.command()
def main(config: typer.FileText,
         log: str = None,
         logfile: str = None,
         logpacket: bool = False,
         version: bool = typer.Option(None, "--version", callback=version_callback, is_eager=True), # pylint: disable=unused-argument
         ) -> None:
    """The main entry point for the VPPDHC daemon."""
    numeric_level = logging.INFO
    if log:
        numeric_level = getattr(logging, log.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log}")
    if logfile:
        logging.basicConfig(filename=logfile, encoding='utf-8',
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        level=numeric_level)
    else:
        logging.basicConfig(stream=sys.stdout, encoding='utf-8',
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        level=numeric_level)
    packetloglevel = logging.DEBUG if logpacket else logging.INFO
    logging.getLogger("vppdhc.dhc4client.packet").setLevel(packetloglevel)
    logging.getLogger("vppdhc.dhc4server.packet").setLevel(packetloglevel)
    logging.getLogger("vppdhc.dhc6pdclient.packet").setLevel(packetloglevel)
    logging.getLogger("vppdhc.dhc6server.packet").setLevel(packetloglevel)
    logging.getLogger("vppdhc.raadv.packet").setLevel(packetloglevel)

    conf = json.loads(config.read())

    validatedconf = Configuration(**conf)

    logger.debug("Configuration %s", validatedconf)

    vpp = None
    if validatedconf.vpp:
        vpp = VPP(None)


    logger.debug("Running main loop")
    try:
        asyncio.run(main_coroutine(validatedconf, vpp))
    except KeyboardInterrupt:
        print("Exiting application...")


    # # Cleanup (delete the bound socket file)
    # uds_receive_socket.close()
    # uds_send_socket.close()
    # os.remove(RECEIVE_SOCK_PATH)

if __name__ == '__main__':
    app()
