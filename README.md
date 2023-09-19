# VPP DHCP4, DHCPv6, RA daemon

VPP supports a punt infrastructure. This daemon registers with VPP to receive DHCPv4, DHCPv6 and
ICMPv6 router solicitations. The daemon connects to VPP via a Unix Domain Socket, where it receives
the packet it is interested in on a separate socket, and where it can send packets outbound on
a given interface.

VPPDHC is a single process, that uses Python asyncio to implement the various functions.

## DHCPv4 server
The DHCP server is set up to receive all DHCP packets from VPP.
It will service any interface, by querying VPP for it's interface addressing, and create a pool
based on that. E.g. if the interface IP address is 192.168.10.1/24. It will create a pool
of 192.168.10.0/24, with the first 10% reserved for static addressing.

The allocation strategy is to take a hash of the host Ethernet mac address and use the bottom
bits of the hash, plus the pool prefix to create an address.
Collissions are handled by probing using the arpping VPP plugin, or handling decline messages from the client.
Using a larger number of host bits limits the probability of collision. E.g. using all of 192.168/16 for the pool.
Or even the whole of 10/8.

## DHCPv4 client
Not yet implemented.

## DHCPv6 PD client


## DHCPv6 server

## RA Advertisement daemon
The RA advertisement daemon is very simple. For the interface(s) it is enabled on, it will advertise an RA
with the M-flag and the O-flag enabled, and with an empty PIO.

In the future it can be extended to include the prefix configured on the interface in the PIO and set the A-flag
if SLAAC is desired.

## Configuration example

```
{
    "dhc6pdclient": {
        "interface": "tap0",
        "internal-prefix": "fd00::/48",
        "npt66": true
    },
    "dhc6server": {
        "interfaces": ["tap1"],
        "dns": ["2001:4860:4860::8888"]
    },
    "ip6ndra": {
        "interfaces": ["tap1"]
    },
    "dhc4server": {
        "name-server": ["8.8.8.8"],
        "renewal-time": 600,
        "lease-time": 3600
    },
}
```
