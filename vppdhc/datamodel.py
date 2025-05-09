"""VPPDHC Configuration Model."""

from enum import IntEnum

from pydantic import BaseModel, ConfigDict, Field
from pydantic.networks import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface, IPv6Network
from vpp_papi.macaddress import MACAddress # type: ignore
from vppdhc.vppdb import VPPDB, register_vppdb_model

class VPPInterfaceInfo(BaseModel):
        """VPP Interface information."""

        ifindex: int
        name: str
        mac: bytes
        ip4: list[IPv4Interface]
        ip6: list[IPv6Address]
        ip6ll: IPv6Address
        duid: bytes = None

@register_vppdb_model("system")
class ConfSystem(BaseModel):
    """Global configuration."""

    model_config = ConfigDict(populate_by_name=True)
    bypass_tenant: int = Field(alias="bypass-tenant")
    log_level: str = Field(alias="log-level")
    log_file: str = Field(alias="log-file", default=None)


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

    ifindex: int = None
    ip: IPv4Interface = None
    state: DHC4ClientStateMachine = None
    options: dict = None




class Configuration(BaseModel):
    """Configuration model."""

    system: ConfSystem = None


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
