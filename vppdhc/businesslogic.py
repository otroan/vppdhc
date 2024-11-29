import logging
from vppdhc.event_manager import EventManager

logger = logging.getLogger(__name__)

async def dhc6_on_lease(data):
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

def init(event_manager: EventManager) -> None:
    """Initialize the business logic."""
    event_manager.subscribe("/dhc6c/on_lease", dhc6_on_lease)
