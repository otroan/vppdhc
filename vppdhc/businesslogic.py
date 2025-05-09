import logging
from vppdhc.event_manager import EventManager
from vppdhc.datamodel import DHC4ClientEvent, Configuration

logger = logging.getLogger(__name__)

class BusinessLogic:
    def __init__(self, event_manager: EventManager, vpp, conf: Configuration):
        logger.info("Initializing business logic")
        self.vpp = vpp
        self.event_manager = event_manager
        self.event_manager.subscribe("/dhc4c/on_lease", self.dhc4_on_lease)
        self.event_manager.subscribe("/dhc6c/on_lease", self.dhc6_on_lease)

    async def dhc6_on_lease(self, data):
        """DHCPv6 on lease event."""
        logger.info("DHCPv6 on lease: %s", data)

        '''
                        # Delete old binding if it exists
                        rv = self.vpp.api.npt66_binding_add_del(
                            is_add=False,
                            sw_if_index=self.if_index,
                            internal=self.internal_prefix,
                            external=self.bindings["prefix"],
                        )
                        logger.info(f"Deleting old NAT binding {self.bindings['prefix']}  ->  {self.internal_prefix} {rv}")


                if self.npt66:
                    rv = self.vpp.api.npt66_binding_add_del(
                        is_add=True, sw_if_index=self.if_index, internal=self.internal_prefix, external=pdprefix
                    )
                    logger.info(f"Setting up new NAT binding {pdprefix}  ->  {self.internal_prefix} {rv}")

                # Install default route. TODO: Might be replaced by router discovery at some point
                # rv = self.vpp.api.cli_inband(cmd=f'ip route add ::/0 via {nexthop} {self.if_name}')
                rv = self.vpp.vpp_ip6_route_add("::/0", nexthop, self.if_index)

                # Normally with DHCPv6 PD one would install a blackhole route for the delegated prefix.
                # With NPT66 we don't need to do that, since the prefix is translated to the internal prefix
                # and we have a blackhole route for the internal prefix instead.
                if not self.npt66:
                    rv = self.vpp.vpp_ip6_route_add(pdprefix, "::")
        '''

    async def dhc4_on_lease(self, data: DHC4ClientEvent) -> None:
        """DHCPv4 on lease event."""
        logger.info("DHCPv4 on lease: %s", data)

        # Configure interface IP address? Or just NAT pool?
        address = data.ip
        rv = await self.vpp.vpp_ip_address(data.ifindex, data.ip, add=True)
        logger.info("Setting up IP address %s on interface %s %s", address, data.ifindex, rv)

        # Set up route to the default gateway
        rv = await self.vpp.vpp_ip_route_add("0.0.0.0/0", data.options["router"])
        logger.info("Adding default route via %s", data.options["router"])

        # Set up NAT?
        # rv =