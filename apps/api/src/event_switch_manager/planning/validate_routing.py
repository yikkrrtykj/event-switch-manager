from collections import defaultdict
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from uuid import UUID

from event_switch_manager.domain import DeviceRole

from .plan import EventPlan
from .routing import IpNextHop, NatExemption, PolicyBasedRoute, StaticRoute, TrackActive
from .validate_vpn import check_vpn_paths
from .types import usable
from .validation import Validation, pairs


def check_transit(v: Validation) -> None:
    p = v.plan
    transit = p.transit
    if transit is None:
        return
    assignments = {a.id: a for a in p.assignments}
    assets = {a.id: a for a in p.physical_devices}
    ports = {a.id: a for a in p.physical_interfaces}
    svis = {a.id: a for a in p.logical_interfaces}
    core = assignments.get(transit.core_assignment_id)
    firewall = assignments.get(transit.hillstone_assignment_id)
    core_port = ports.get(transit.core_port_id)
    fw_port = ports.get(transit.hillstone_port_id)
    core_asset = assets.get(core_port.physical_device_id) if core_port else None
    fw_asset = assets.get(fw_port.physical_device_id) if fw_port else None
    v.require(core and core.role == DeviceRole.CORE and core_asset and core_asset.vendor == "cisco",
              "transit.core_assignment_id", "transit_core", "Transit needs a Cisco Core assignment")
    v.require(firewall and fw_asset and fw_asset.vendor == "hillstone",
              "transit.hillstone_assignment_id", "transit_firewall",
              "Transit needs a planned Hillstone chassis assignment")
    v.require(transit.vlan != p.management_vlan, "transit.vlan", "transit_management",
              "Transit and management VLANs must differ")
    v.require(transit.core_ip != transit.hillstone_ip
              and usable(transit.core_ip, transit.network)
              and usable(transit.hillstone_ip, transit.network),
              "transit.network", "transit_address", "Both peers need distinct usable transit IPs")
    for field, port_id, owner in (
        ("core_port_id", transit.core_port_id, transit.core_assignment_id),
        ("hillstone_port_id", transit.hillstone_port_id, transit.hillstone_assignment_id),
    ):
        port = ports.get(port_id)
        v.require(port and port.assignment_id == owner and port.settings.mode == "access"
                  and port.settings.access_vlan == transit.vlan, f"transit.{field}", "transit_port",
                  "Transit ports must be access ports on their designated assignments and VLAN")
    endpoints = {transit.core_port_id, transit.hillstone_port_id}
    v.require(any(set(link.endpoints) == endpoints for link in p.links), "transit",
              "transit_link", "Add a topology link between the transit ports")
    svi = svis.get(transit.core_svi_id)
    v.require(svi and svi.assignment_id == transit.core_assignment_id and svi.kind == "svi"
              and svi.vlan == transit.vlan and svi.address
              and svi.address.ip == transit.core_ip and svi.address.network == transit.network,
              "transit.core_svi_id", "transit_svi", "Core SVI must match transit VLAN, IP and CIDR")
    core_default = min(
        (route for route in p.default_routes if route.assignment_id == transit.core_assignment_id),
        key=lambda route: route.preference,
        default=None,
    )
    v.require(core_default and core_default.next_hop.address == transit.hillstone_ip,
              "transit", "core_default", "Preferred Cisco Core default must use Hillstone")
    for i, gateway in enumerate(p.gateways):
        interface = svis.get(gateway.svi_id)
        v.require(interface and interface.assignment_id == transit.core_assignment_id,
                  f"gateways.{i}.svi_id", "core_gateway", "Cisco Core owns VLAN gateways")
    firewall_routes = [(i, route) for i, route in enumerate(p.static_routes)
                       if route.assignment_id == transit.hillstone_assignment_id]
    for i, subnet in enumerate(p.subnets):
        v.require(subnet.vlan == transit.vlan if subnet.network == transit.network
                  else subnet.vlan != transit.vlan and not subnet.network.overlaps(transit.network),
                  f"subnets.{i}.network", "transit_overlap", "Subnet conflicts with transit CIDR")
        if subnet.vlan != transit.vlan:
            _check_core_return(v, subnet.network, transit.core_ip, firewall_routes,
                               f"subnets.{i}.network")


def _via_core(route: StaticRoute, address: IPv4Address) -> bool:
    return isinstance(route.next_hop, IpNextHop) and route.next_hop.address == address


def _check_core_return(
    v: Validation,
    network: IPv4Network,
    core_ip: IPv4Address,
    routes: list[tuple[int, StaticRoute]],
    path: str,
) -> None:
    covering = min(
        (route for _, route in routes if network.subnet_of(route.destination)),
        key=lambda route: (-route.destination.prefixlen, route.preference),
        default=None,
    )
    v.require(covering and _via_core(covering, core_ip)
              and not isinstance(covering.activation, TrackActive), path, "return_route",
              f"Hillstone needs a preferred return route via Core for {network}")
    best_by_prefix: dict[IPv4Network, tuple[int, StaticRoute]] = {}
    for index, route in routes:
        if route.destination != network and route.destination.subnet_of(network):
            current = best_by_prefix.get(route.destination)
            if current is None or route.preference < current[1].preference:
                best_by_prefix[route.destination] = (index, route)
    for index, winner in best_by_prefix.values():
        v.require(_via_core(winner, core_ip), f"static_routes.{index}", "return_route",
                  f"More-specific route {winner.destination} diverts {network} from Core")


def check_routes(v: Validation) -> None:
    p = v.plan
    vlans = {x.id for x in p.vlans}
    assignments = {x.id for x in p.assignments}
    ports = {x.id: x for x in p.physical_interfaces}
    logical = {x.id: x for x in p.logical_interfaces}
    tracks = v.index("tracks", p.tracks, lambda x: x.id)
    isps = v.index("isps", p.isps, lambda x: x.id)
    tunnels = v.index("ipsec_tunnels", p.ipsec_tunnels, lambda x: x.id)
    connected: dict[UUID, set[IPv4Interface]] = defaultdict(set)
    for port in p.physical_interfaces:
        if port.settings.address is not None:
            connected[port.assignment_id].add(port.settings.address)
    for interface in p.logical_interfaces:
        if interface.address is not None:
            connected[interface.assignment_id].add(interface.address)
    for channel in p.port_channels:
        aggregate = logical.get(channel.interface_id)
        if aggregate and channel.settings.address:
            connected[aggregate.assignment_id].add(channel.settings.address)
    if p.transit:
        transit = p.transit
        connected[transit.hillstone_assignment_id].add(
            IPv4Interface((transit.hillstone_ip, transit.network.prefixlen))
        )
    v.index("isps", p.isps, lambda x: (x.assignment_id, x.interface_id))
    for i, isp in enumerate(p.isps):
        path = f"isps.{i}"
        wan = ports.get(isp.interface_id)
        v.require(isp.assignment_id in assignments and wan
                  and wan.assignment_id == isp.assignment_id and wan.settings.mode == "routed"
                  and wan.settings.address == isp.address,
                  f"{path}.interface_id", "isp_port", "ISP needs a matching routed interface")
        v.require(usable(isp.address.ip, isp.address.network)
                  and usable(isp.gateway, isp.address.network) and isp.gateway != isp.address.ip,
                  f"{path}.gateway", "next_hop", "ISP gateway must be an on-link peer")
        if isp.track_id:
            tracker = tracks.get(isp.track_id)
            v.require(tracker and tracker.tunnel_id is None, f"{path}.track_id", "isp_track",
                      "ISP Track must exist and be independent of Tunnel health")
        v.index(f"{path}.routed_public_blocks", isp.routed_public_blocks, lambda x: x.network)
        for j, block in enumerate(isp.routed_public_blocks):
            v.require(block.network.prefixlen > 0, f"{path}.routed_public_blocks.{j}",
                      "routed_public_block", "A routed public block cannot be the default route")
    for i, tunnel in enumerate(p.ipsec_tunnels):
        path = f"ipsec_tunnels.{i}"
        uplink = isps.get(tunnel.isp_id)
        v.require(uplink and uplink.assignment_id == tunnel.assignment_id
                  and tunnel.track_id in tracks
                  and tracks[tunnel.track_id].tunnel_id in (None, tunnel.id),
                  path, "tunnel_reference", "Tunnel requires an ISP on its owner and a Track")
        v.require(usable(tunnel.inside.ip, tunnel.inside.network)
                  and usable(tunnel.remote_gateway, tunnel.inside.network)
                  and tunnel.remote_gateway != tunnel.inside.ip,
                  f"{path}.remote_gateway", "next_hop", "Tunnel gateway must be an on-link peer")
    for i, tracker in enumerate(p.tracks):
        if tracker.tunnel_id is not None:
            bound_tunnel = tunnels.get(tracker.tunnel_id)
            v.require(bound_tunnel and bound_tunnel.track_id == tracker.id,
                      f"tracks.{i}.tunnel_id", "tunnel_track_binding",
                      "Tunnel-bound Track must be referenced by that Tunnel")
    v.index("vpn_remote_prefixes", p.vpn_remote_prefixes, lambda x: (x.tunnel_id, x.network))
    for i, prefix in enumerate(p.vpn_remote_prefixes):
        path = f"vpn_remote_prefixes.{i}"
        remote_tunnel = tunnels.get(prefix.tunnel_id)
        v.require(remote_tunnel and prefix.network.prefixlen > 0, path, "vpn_prefix",
                  "VPN prefix requires a tunnel and a non-default remote network")
        for j, subnet in enumerate(p.subnets):
            v.require(not prefix.network.overlaps(subnet.network), path, "vpn_local_overlap",
                      f"{prefix.network} overlaps subnets.{j} ({subnet.network})")
        if remote_tunnel:
            owner = remote_tunnel.assignment_id
            check_vpn_paths(v, remote_tunnel, prefix.network, path)
            for address in connected[owner]:
                v.require(not prefix.network.overlaps(address.network), path,
                          "vpn_connected_overlap",
                          f"{prefix.network} overlaps connected network {address.network}")
    for i, j in pairs(len(p.vpn_remote_prefixes)):
        a, b = p.vpn_remote_prefixes[i], p.vpn_remote_prefixes[j]
        owner_a, owner_b = tunnels.get(a.tunnel_id), tunnels.get(b.tunnel_id)
        v.require(not (owner_a and owner_b and owner_a.assignment_id == owner_b.assignment_id
                       and a.tunnel_id != b.tunnel_id and a.network.overlaps(b.network)),
                  f"vpn_remote_prefixes.{j}", "vpn_prefix_overlap",
                  f"Remote prefix overlaps a different tunnel at vpn_remote_prefixes.{i}")
    v.index("static_routes", p.static_routes, lambda x: x.id)
    v.index("static_routes", p.static_routes,
            lambda x: (x.assignment_id, x.destination, x.preference))
    for i, route in enumerate(p.static_routes):
        path = f"static_routes.{i}"
        v.require(route.assignment_id in assignments and route.destination.prefixlen > 0,
                  path, "static_route", "Use an existing assignment and a non-default prefix")
        if route.next_hop.kind == "tunnel":
            route_tunnel = tunnels.get(route.next_hop.tunnel_id)
            v.require(route_tunnel and route_tunnel.assignment_id == route.assignment_id,
                      f"{path}.next_hop", "tunnel_reference", "Tunnel belongs to another owner")
            if isinstance(route.activation, TrackActive) and route_tunnel:
                v.require(route.activation.track_id == route_tunnel.track_id
                          and route.activation.state == "up",
                          f"{path}.activation.track_id", "tunnel_route_track",
                          "Tunnel route must follow its own health Track in the up state")
        elif isinstance(route.next_hop, IpNextHop):
            _check_ip(v, connected[route.assignment_id], route.next_hop.address, f"{path}.next_hop")
        if isinstance(route.activation, TrackActive):
            tracker = tracks.get(route.activation.track_id)
            v.require(tracker and (
                any(isp.track_id == tracker.id and isp.assignment_id == route.assignment_id
                    for isp in p.isps)
                or any(tunnel.track_id == tracker.id and tunnel.assignment_id == route.assignment_id
                       for tunnel in p.ipsec_tunnels)
            ), f"{path}.activation.track_id", "route_track_reference",
                "Static route needs a Track associated with its owner")
    v.index("default_routes", p.default_routes, lambda x: x.id)
    v.index("default_routes", p.default_routes, lambda x: (x.assignment_id, x.preference))
    for i, default in enumerate(p.default_routes):
        v.require(default.assignment_id in assignments, f"default_routes.{i}", "reference",
                  "Unknown route owner")
        _check_ip(v, connected[default.assignment_id], default.next_hop.address,
                  f"default_routes.{i}.next_hop")
    _check_policies(v, vlans)


def _check_ip(
    v: Validation, interfaces: set[IPv4Interface], address: IPv4Address, path: str
) -> None:
    v.require(address not in {x.ip for x in interfaces}
              and any(usable(address, x.network) for x in interfaces),
              path, "next_hop", "IP next hop must be an on-link peer of the route owner")


def _check_policies(v: Validation, vlans: set[int]) -> None:
    p = v.plan
    tunnels = {x.id: x for x in p.ipsec_tunnels}
    _check_source_egress(v, vlans)
    v.index("policy_routes", p.policy_routes, lambda x: x.id)
    v.index("policy_routes", p.policy_routes, lambda x: (x.assignment_id, x.priority))
    v.index("nat_exemptions", p.nat_exemptions, lambda x: x.id)
    v.index("nat_exemptions", p.nat_exemptions,
            lambda x: (x.assignment_id, x.source_vlan, x.destination, x.tunnel_id))
    vpn_rules: tuple[tuple[str, tuple[PolicyBasedRoute | NatExemption, ...]], ...] = (
        ("policy_routes", p.policy_routes), ("nat_exemptions", p.nat_exemptions),
    )
    for group, rules in vpn_rules:
        for i, rule in enumerate(rules):
            tunnel = tunnels.get(rule.tunnel_id)
            v.require(rule.source_vlan in vlans and tunnel
                      and tunnel.assignment_id == rule.assignment_id
                      and _covered(p, rule.tunnel_id, rule.destination),
                      f"{group}.{i}", "vpn_policy", "Rule must target a prefix on its tunnel")
    for i, policy in enumerate(p.policy_routes):
        has_exemption = any(
            rule.assignment_id == policy.assignment_id
            and rule.source_vlan == policy.source_vlan
            and rule.tunnel_id == policy.tunnel_id
            and policy.destination.subnet_of(rule.destination)
            for rule in p.nat_exemptions
        )
        v.require(has_exemption, f"policy_routes.{i}", "nat_exemption",
                  "VPN policy needs a matching NAT exemption")

def _check_source_egress(v: Validation, vlans: set[int]) -> None:
    p = v.plan
    isps = {x.id: x for x in p.isps}
    tracks = {x.id: x for x in p.tracks}
    v.index("snat", p.snat, lambda x: x.id)
    by_egress = v.index("snat", p.snat, lambda x: (x.assignment_id, x.source_vlan, x.isp_id))
    for i, nat in enumerate(p.snat):
        path = f"snat.{i}"
        isp = isps.get(nat.isp_id)
        v.require(nat.source_vlan in vlans and isp and isp.assignment_id == nat.assignment_id,
                  path, "snat_reference", "SNAT requires an existing VLAN and local ISP")
        if isp:
            belongs_to_isp = usable(nat.translated_ip, isp.address.network) or any(
                usable(nat.translated_ip, block.network) for block in isp.routed_public_blocks
            )
            other_uplink = any(
                other.id != isp.id and other.assignment_id == nat.assignment_id
                and nat.translated_ip in (other.address.ip, other.gateway)
                for other in p.isps
            )
            v.require(belongs_to_isp and nat.translated_ip != isp.gateway and not other_uplink,
                      f"{path}.translated_ip", "snat_egress_address",
                      f"SNAT address must belong to ISP {isp.name} or its declared routed block")
    v.index("source_routes", p.source_routes, lambda x: x.id)
    v.index("source_routes", p.source_routes, lambda x: (x.assignment_id, x.source_vlan))
    for i, source in enumerate(p.source_routes):
        path = f"source_routes.{i}"
        v.require(source.source_vlan in vlans, f"{path}.source_vlan",
                  "vlan_reference", "Unknown VLAN")
        v.require(source.isp_priority and len(source.isp_priority) == len(set(source.isp_priority)),
                  f"{path}.isp_priority", "isp_priority", "Specify distinct ISPs in failover order")
        no_nat = v.index(f"{path}.no_nat", source.no_nat, lambda x: x.isp_id)
        for j, exception in enumerate(source.no_nat):
            v.require(exception.isp_id in source.isp_priority, f"{path}.no_nat.{j}.isp_id",
                      "sbr_no_nat_reference", "No-NAT exception must identify a listed ISP")
        used_tracks: set[UUID] = set()
        for j, isp_id in enumerate(source.isp_priority):
            hop = f"{path}.isp_priority.{j}"
            isp = isps.get(isp_id)
            if not isp or isp.assignment_id != source.assignment_id:
                v.error(hop, "sbr_isp_reference", "SBR must reference an ISP on the same device")
                continue
            tracker = tracks.get(isp.track_id) if isp.track_id is not None else None
            v.require(tracker and tracker.tunnel_id is None and tracker.id not in used_tracks,
                      hop, "isp_track", f"SBR ISP {isp.name} needs its own valid egress Track")
            if tracker:
                used_tracks.add(tracker.id)
            has_snat = (source.assignment_id, source.source_vlan, isp_id) in by_egress
            exempt = isp_id in no_nat
            position = "Primary" if j == 0 else f"Backup #{j}"
            v.require(has_snat or exempt, hop, "missing_sbr_snat",
                      f"{position} ISP {isp.name} needs SNAT for VLAN {source.source_vlan} "
                      "or a documented no-NAT exception")
            v.require(not (has_snat and exempt), hop, "sbr_nat_conflict",
                      f"ISP {isp.name} has both SNAT and a no-NAT exception for this VLAN")


def _covered(plan: EventPlan, tunnel_id: UUID, destination: IPv4Network) -> bool:
    return any(x.tunnel_id == tunnel_id and destination.subnet_of(x.network)
               for x in plan.vpn_remote_prefixes)
