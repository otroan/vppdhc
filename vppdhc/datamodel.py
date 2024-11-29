"""VPPDHC Configuration Model."""

from enum import IntEnum

from pydantic import BaseModel, ConfigDict, Field
from pydantic.networks import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface, IPv6Network
from vpp_papi.macaddress import MACAddress # type: ignore


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

class ConfDHC4Client(BaseModel):
    """DHCPv4 client configuration."""

    interface: str

class DHC4ClientStateMachine(IntEnum):
    """DHCPv4 Client states."""

    INIT = 0
    SELECTING = 1
    REQUESTING = 2
    BOUND = 3
    RENEWING = 4
    RELEASING = 5

class DHC4ClientEvent(BaseModel):
    """DHCPv4 client event."""

    ip: IPv4Interface = None
    state: DHC4ClientStateMachine = None
    options: dict = None

class ConfDHC4Server(BaseModel):
    """DHCPv4 server configuration."""

    model_config = ConfigDict(populate_by_name=True)
    lease_time: int = Field(alias="lease-time")
    renewal_time: int = Field(alias="renewal-time")
    dns: list[IPv4Address]
    ipv6_only_preferred: bool = Field(alias="ipv6-only-preferred", default=False)
    bypass_tenant: int = Field(alias="bypass-tenant")

class ConfDHC6Client(BaseModel):
    """DHCPv6 PD client configuration."""

    model_config = ConfigDict(populate_by_name=True)
    interface: str
    ia_pd: bool = True
    ia_na: bool = False


    internal_prefix: IPv6Network = Field(alias="internal-prefix") # Move to "business logic"
    npt66: bool = False # Move to "business logic"

class ConfDHC6Server(BaseModel):
    """DHCPv6 server configuration."""

    interfaces: list[str]
    preflft: int = 604800
    validlft: int = 2592000
    dns: list[IPv6Address]
    ia_na: bool = True
    ia_prefix: list[IPv6Network] | None = None
    ia_allocate_length: int | None = None

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
    dhc4client: ConfDHC4Client = None
    dhc4server: ConfDHC4Server = None
    dhc6client: ConfDHC6Client = None
    dhc6server: ConfDHC6Server = None
    ip6ndra: ConfIP6NDRA = None


class DHC6_IAAddr(BaseModel):
    """OPTION_IAADDR."""

    address: IPv6Address
    preferred: int
    valid: int

class DHC6_IANA(BaseModel):
    """OPTION_IA_NA."""

    iaid: int
    T1: int
    T2: int
    addresses: list[DHC6_IAAddr]

class DHC6_IAPrefix(BaseModel):
    """OPTION_IAPREFIX."""

    prefix: IPv6Network
    preferred: int
    valid: int
class DHC6_IAPD(BaseModel):
    """OPTION_IA_PD."""

    iaid: int
    T1: int
    T2: int
    prefixes: list[DHC6_IAPrefix]
class DHC6ClientBinding(BaseModel):
    """DHCPv6 client binding."""

    ia_pd: list[DHC6_IAPD]|None
    ia_na: list[DHC6_IANA]|None
    macsrc: bytes
    nexthop: IPv6Address
