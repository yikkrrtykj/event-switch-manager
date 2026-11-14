import re

from .types import usable
from .validation import Validation, pairs

MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)


def check_addressing(v: Validation) -> None:
    p = v.plan
    vlans = v.index("vlans", p.vlans, lambda x: x.id)
    v.index("vlans", p.vlans, lambda x: x.name.casefold())
    if vlans:
        v.require(p.management_vlan in vlans, "management_vlan", "vlan_reference",
                  "Management VLAN must be defined")
    subnets = v.index("subnets", p.subnets, lambda x: x.id)
    svis = {x.id: x for x in p.logical_interfaces if x.kind == "svi"}
    for i, subnet in enumerate(p.subnets):
        v.require(subnet.vlan in vlans, f"subnets.{i}.vlan", "vlan_reference", "Unknown VLAN")
    for i, j in pairs(len(p.subnets)):
        first, second = p.subnets[i], p.subnets[j]
        v.require(not first.network.overlaps(second.network), f"subnets.{j}.network",
                  "subnet_overlap", f"{second.network} overlaps subnets.{i} ({first.network})")
    gateways = v.index("gateways", p.gateways, lambda x: x.subnet_id)
    v.index("gateways", p.gateways, lambda x: x.address)
    v.index("gateways", p.gateways, lambda x: x.svi_id)
    for i, gateway in enumerate(p.gateways):
        path = f"gateways.{i}"
        subnet = subnets.get(gateway.subnet_id)
        svi = svis.get(gateway.svi_id)
        v.require(subnet and usable(gateway.address, subnet.network), f"{path}.address",
                  "gateway_address", "Gateway must be usable in its subnet")
        v.require(subnet and svi and svi.vlan == subnet.vlan and svi.address
                  and svi.address.ip == gateway.address and svi.address.network == subnet.network,
                  f"{path}.svi_id", "gateway_svi", "SVI VLAN, IP and prefix must match the gateway")
    v.index("dhcp_pools", p.dhcp_pools, lambda x: x.id)
    for i, pool in enumerate(p.dhcp_pools):
        path = f"dhcp_pools.{i}"
        subnet = subnets.get(pool.subnet_id)
        v.require(subnet and subnet.network.prefixlen < 31 and pool.start <= pool.end
                  and usable(pool.start, subnet.network) and usable(pool.end, subnet.network),
                  path, "dhcp_bounds", "Pool requires a valid range inside the usable subnet")
        gateway = gateways.get(pool.subnet_id)
        v.require(not gateway or not pool.start <= gateway.address <= pool.end, path,
                  "dhcp_gateway", "Pool includes its gateway")
    for i, j in pairs(len(p.dhcp_pools)):
        first, second = p.dhcp_pools[i], p.dhcp_pools[j]
        v.require(first.subnet_id != second.subnet_id
                  or first.end < second.start or second.end < first.start,
                  f"dhcp_pools.{j}", "dhcp_overlap", f"Pool overlaps dhcp_pools.{i}")
    v.index("dhcp_reservations", p.dhcp_reservations, lambda x: x.id)
    v.index("dhcp_reservations", p.dhcp_reservations, lambda x: x.address)
    v.index("dhcp_reservations", p.dhcp_reservations,
            lambda x: (x.subnet_id, x.client_mac.casefold()))
    for i, reservation in enumerate(p.dhcp_reservations):
        path = f"dhcp_reservations.{i}"
        subnet = subnets.get(reservation.subnet_id)
        gateway = gateways.get(reservation.subnet_id)
        v.require(MAC.fullmatch(reservation.client_mac), f"{path}.client_mac", "mac_address",
                  "Use a six-octet colon-separated MAC address")
        v.require(subnet and subnet.network.prefixlen < 31
                  and usable(reservation.address, subnet.network)
                  and (not gateway or reservation.address != gateway.address),
                  f"{path}.address", "dhcp_reservation", "Use a usable non-gateway IP")
        for pool in p.dhcp_pools:
            if pool.subnet_id == reservation.subnet_id:
                v.require(not pool.start <= reservation.address <= pool.end, f"{path}.address",
                          "dhcp_reservation_pool", f"Reservation conflicts with pool {pool.id}")
    v.index("dhcp_relays", p.dhcp_relays, lambda x: x.subnet_id)
    for i, relay in enumerate(p.dhcp_relays):
        path = f"dhcp_relays.{i}"
        gateway = gateways.get(relay.subnet_id)
        v.require(gateway and gateway.svi_id == relay.svi_id, f"{path}.svi_id",
                  "dhcp_relay_svi", "Relay must reference the subnet gateway SVI")
        v.require(relay.servers and len(relay.servers) == len(set(relay.servers)),
                  f"{path}.servers", "dhcp_relay_servers", "Specify distinct relay server IPs")
        for j, server in enumerate(relay.servers):
            v.require(not (server.is_unspecified or server.is_multicast
                          or server.is_loopback or server.is_reserved)
                      and (not gateway or server != gateway.address),
                      f"{path}.servers.{j}", "dhcp_relay_server", "Invalid relay destination")
    v.index("vlan_access_policies", p.vlan_access_policies, lambda x: x.id)
    v.index("vlan_access_policies", p.vlan_access_policies,
            lambda x: (x.source_vlan, x.destination_vlan, x.priority))
    for i, policy in enumerate(p.vlan_access_policies):
        v.require(policy.source_vlan in vlans and policy.destination_vlan in vlans
                  and policy.source_vlan != policy.destination_vlan,
                  f"vlan_access_policies.{i}", "vlan_reference", "Use two distinct existing VLANs")
