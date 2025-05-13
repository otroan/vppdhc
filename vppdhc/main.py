"""The main module for the VPPDHC daemon."""

# pylint: disable=import-error, invalid-name, logging-fstring-interpolation

import asyncio
import json
import logging
import sys

import typer

from vppdhc._version import __version__
from vppdhc.businesslogic import BusinessLogic
from vppdhc.datamodel import Configuration
from vppdhc.dhc4client import DHC4Client
from vppdhc.dhc4server import DHC4Server
from vppdhc.dhc6client import DHC6Client
from vppdhc.dhc6server import DHC6Server
from vppdhc.raadv import IP6NDRA
from vppdhc.vppdhcdctl import VPPDHCD
from vppdhc.vpppunt import VPP, VppEnum

app = typer.Typer()
logger = logging.getLogger(__name__)


def version_callback(value: bool):
    """Print the version and exit."""
    if value:
        typer.echo(f"vppdhcpd version: {__version__}")
        raise typer.Exit


async def setup_tasks(tg, conf, vpp) -> list:
    """Set up the tasks."""
    tasks = []
    # Initialise the control socket
    try:
        vppdhcdctl = VPPDHCD("/tmp/vppdhcd.sock")
        logger.debug("Starting VPPDHC Control server")

        t = tg.create_task(vppdhcdctl.start_control_server())
        tasks.append(t)
    except Exception as e:
        logger.exception("***Error setting up control socket: %s", e)

    # DHCPv4 client
    if conf.dhc4client:
        logger.debug("Starting DHCPv4 client")
        socket, vpp_socket = await vpp.vpp_socket_register(
            VppEnum.vl_api_address_family_t.ADDRESS_IP4,
            VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
            68,
        )

        dhc4_client = DHC4Client(socket, vpp_socket, vpp, conf)
        t = tg.create_task(dhc4_client.client())
        tasks.append(t)

    # DHCPv4 server
    if conf.dhc4server:
        logger.debug("Starting DHCPv4 server")
        socket, vpp_socket = await vpp.vpp_socket_register(
            VppEnum.vl_api_address_family_t.ADDRESS_IP4,
            VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
            67,
        )

        dhc4_server = DHC4Server(socket, vpp_socket, vpp, conf)
        t = tg.create_task(dhc4_server.listen())
        tasks.append(t)

    # DHCPv6 client
    if conf.dhc6client:
        logger.debug("Starting DHCPv6 client")
        socket, vpp_socket = await vpp.vpp_socket_register(
            VppEnum.vl_api_address_family_t.ADDRESS_IP6,
            VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
            546,
        )  # pylint: disable=no-member

        dhc6_client = DHC6Client(socket, vpp_socket, vpp, conf)
        t = tg.create_task(dhc6_client.client())
        tasks.append(t)

    # DHCPv6 server
    if conf.dhc6server:
        logger.debug("Starting DHCPv6 server")
        socket, vpp_socket = await vpp.vpp_socket_register(
            VppEnum.vl_api_address_family_t.ADDRESS_IP6,
            VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
            547,
        )  # pylint: disable=no-member
        try:
            dhc6_server = DHC6Server(socket, vpp_socket, vpp, conf.dhc6server)
        except Exception as e:
            logger.exception("Error setting up DHCPv6 server: %s", e)
            sys.exit(1)
        t = tg.create_task(dhc6_server.listen())
        tasks.append(t)

    # RA advertisement
    if conf.ip6ndra:
        logger.debug("Starting RA advertisement daemon")
        # Get router solicitations
        socket, vpp_socket = await vpp.vpp_socket_register(
            VppEnum.vl_api_address_family_t.ADDRESS_IP6,
            VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP6,
            133,
        )  # pylint: disable=no-member
        ra_server = IP6NDRA(socket, vpp_socket, vpp, conf.ip6ndra)
        t = tg.create_task(ra_server.listen())
        tasks.append(t)

    return tasks


async def main_coroutine(validatedconf) -> None:
    import traceback

    vpp = None
    if validatedconf.vpp:
        vpp = await VPP.create()

    _ = BusinessLogic(vpp, validatedconf)

    try:
        async with asyncio.TaskGroup() as tg:
            tasks = await setup_tasks(tg, validatedconf, vpp)
    except ExceptionGroup as eg:
        print(f"ExceptionGroup caught: {eg}")
        for exc in eg.exceptions:
            print(f"Task exception: {exc}")
            print("Traceback:")
            traceback.print_exception(type(exc), exc, exc.__traceback__)


@app.command()
def main(
    config: typer.FileText,
    log: str = None,
    logfile: str = None,
    logpacket: bool = False,
    version: bool = typer.Option(None, "--version", callback=version_callback, is_eager=True),  # pylint: disable=unused-argument
) -> None:
    """The main entry point for the VPPDHC daemon."""
    numeric_level = logging.INFO
    if log:
        numeric_level = getattr(logging, log.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log}")
    if logfile:
        logging.basicConfig(
            filename=logfile,
            encoding="utf-8",
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            level=numeric_level,
        )
    else:
        logging.basicConfig(
            stream=sys.stdout,
            encoding="utf-8",
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            level=numeric_level,
        )
    packetloglevel = logging.DEBUG if logpacket else logging.INFO
    logging.getLogger("vppdhc.dhc4client.packet").setLevel(packetloglevel)
    logging.getLogger("vppdhc.dhc4server.packet").setLevel(packetloglevel)
    logging.getLogger("vppdhc.dhc6client.packet").setLevel(packetloglevel)
    logging.getLogger("vppdhc.dhc6server.packet").setLevel(packetloglevel)
    logging.getLogger("vppdhc.raadv.packet").setLevel(packetloglevel)

    conf = json.loads(config.read())

    validatedconf = Configuration(**conf)

    logger.debug("Configuration %s", validatedconf)

    logger.debug("Running main loop")
    try:
        asyncio.run(main_coroutine(validatedconf))
    except KeyboardInterrupt:
        print("Exiting application...")

    # # Cleanup (delete the bound socket file)
    # uds_receive_socket.close()
    # uds_send_socket.close()
    # os.remove(RECEIVE_SOCK_PATH)


if __name__ == "__main__":
    app()
