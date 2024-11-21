"""VPPDHC Configuration Model."""

from enum import IntEnum
from vpp_papi.macaddress import MACAddress
from pydantic import BaseModel, ConfigDict, Field
from pydantic.networks import IPv4Address, IPv4Interface, IPv6Address, IPv6Network


class VPPInterfaceInfo(BaseModel):
        """VPP Interface information."""

        ifindex: int
        name: str
        mac: bytes
        ip4: list[IPv4Interface]
        ip6: list[IPv6Address]
        ip6ll: IPv6Address

class ConfVPP(BaseModel):
    """Configuration for VPP."""

    socket: str

class ConfDHCP4Client(BaseModel):
    """DHCPv4 client configuration."""

    interface: str

class DHCP4ClientStateMachine(IntEnum):
    """DHCPv4 Client states."""

    INIT = 0
    SELECTING = 1
    REQUESTING = 2
    BOUND = 3
    RENEWING = 4
    RELEASING = 5

class DHCP4ClientEvent(BaseModel):
    """DHCPv4 client event."""

    ip: IPv4Interface = None
    state: DHCP4ClientStateMachine = None

class DHCP4ServerEvent(BaseModel):
    """DHCPv4 server event."""

    event: str

class ConfDHCP4Server(BaseModel):
    """DHCPv4 server configuration."""

    model_config = ConfigDict(populate_by_name=True)
    lease_time: int = Field(alias="lease-time")
    renewal_time: int = Field(alias="renewal-time")
    dns: list[IPv4Address]
    ipv6_only_preferred: bool = Field(alias="ipv6-only-preferred", default=False)
    bypass_tenant: int = Field(alias="bypass-tenant")

class ConfDHCP6PDClient(BaseModel):
    """DHCPv6 PD client configuration."""

    interface: str
    internal_prefix: IPv6Network = Field(alias="internal-prefix")
    npt66: bool = False

class ConfDHCP6Server(BaseModel):
    """DHCPv6 server configuration."""

    interfaces: list[str]
    preflft: int = 604800
    validlft: int = 2592000
    dns: list[IPv6Address]

class ConfIP6NDPrefix(BaseModel):
    """IPv6 ND prefix information."""

    prefix: IPv6Network
    L: bool = True
    A: bool = False
class ConfIP6NDRA(BaseModel):
    """IPv6 ND RA configuration."""

    interfaces: list[str]
    pio: ConfIP6NDPrefix = None
    maxrtradvinterval: int = 600
    pref64: IPv6Network = None

class Configuration(BaseModel):
    """Configuration model."""

    vpp: ConfVPP = None
    dhc4client: ConfDHCP4Client = None
    dhc4server: ConfDHCP4Server = None
    dhc6pdclient: ConfDHCP6PDClient = None
    dhc6server: ConfDHCP6Server = None
    ip6ndra: ConfIP6NDRA = None


