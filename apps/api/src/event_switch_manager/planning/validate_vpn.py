from ipaddress import IPv4Address, IPv4Network
from typing import Literal
from uuid import UUID

from .routing import AlwaysActive, IpsecTunnel, StaticRoute, TrackActive
from .validation import Validation

TunnelState = Literal["up", "down"]


def check_vpn_paths(
    v: Validation, tunnel: IpsecTunnel, prefix: IPv4Network, path: str
) -> None:
    plan = v.plan
    routes = [route for route in plan.static_routes
              if route.assignment_id == tunnel.assignment_id and route.destination.overlaps(prefix)]
    routes.sort(key=lambda route: (-route.destination.prefixlen, route.preference))
    transit = plan.transit
    core_ip = (
        transit.core_ip if transit and transit.hillstone_assignment_id == tunnel.assignment_id
        else None
    )
    return_prefixes = sorted({
        str(route.destination) for route in routes
        if route.next_hop.kind == "ip" and route.next_hop.address == core_ip
    })
    overlap = f"{prefix} overlaps Core return routes {', '.join(return_prefixes)}"
    default = min(
        (route for route in plan.default_routes if route.assignment_id == tunnel.assignment_id),
        key=lambda route: route.preference,
        default=None,
    )
    fallback = _ip_path(default.next_hop.address, core_ip) if default else "no route"
    track_bound = any(
        track.id == tunnel.track_id and track.tunnel_id == tunnel.id for track in plan.tracks
    )
    exact_route = any(
        route.destination == prefix and route.next_hop.kind == "tunnel"
        and route.next_hop.tunnel_id == tunnel.id for route in routes
    )
    if not exact_route:
        v.error(path, "vpn_tunnel_route", f"{prefix} requires an exact route via {tunnel.name}")
    uncertain = not track_bound
    unsafe = not exact_route
    up_target = f"Tunnel {tunnel.id}"
    checks: tuple[tuple[TunnelState, str, str], ...] = (
        ("up", up_target, "vpn_tunnel_route"),
        ("down", "discard", "vpn_down_route"),
    )
    for state, expected, code in checks:
        wrong_paths: set[str] = set()
        possible_paths: set[str] = set()
        for address in _route_boundaries(prefix, routes):
            outcomes = _next_hops(address, routes, tunnel, state, track_bound, core_ip, fallback)
            if expected not in outcomes:
                wrong_paths.update(outcomes)
            elif outcomes != {expected}:
                possible_paths.update(outcomes - {expected})
        if wrong_paths:
            unsafe = True
            v.error(path, code,
                    f"{prefix} has traffic that cannot select the required {state} next hop "
                    f"({tunnel.name if state == 'up' else expected}). "
                    f"Possible next hops: {', '.join(sorted(wrong_paths))}.")
        if possible_paths:
            uncertain = True
            v.warning(path, f"{code}_unverified",
                      f"{prefix} when {state} can also select "
                      f"{', '.join(sorted(possible_paths))}. Specify or verify route activation.")
    for i, rule in enumerate(plan.policy_routes):
        if (rule.assignment_id == tunnel.assignment_id and rule.tunnel_id == tunnel.id
                and rule.destination.overlaps(prefix)):
            rule_path = f"policy_routes.{i}.on_tunnel_down"
            if rule.on_tunnel_down == "unknown":
                uncertain = True
                v.warning(rule_path, "vpn_pbr_down_unverified",
                          "Specify whether PBR discards or uses the destination route table")
            elif rule.on_tunnel_down == "use-sbr":
                unsafe = True
                v.error(rule_path, "vpn_pbr_down_unsafe",
                        "PBR must not send failed VPN traffic to ordinary ISP egress selection")
    if return_prefixes:
        if unsafe:
            v.error(path, "vpn_return_overlap_risk",
                    f"{overlap} and has an unsafe forwarding plan")
        elif uncertain:
            v.warning(path, "vpn_return_overlap_unverified",
                      f"{overlap}; fault protection is unverified")
        else:
            v.warning(path, "vpn_return_overlap",
                      f"{overlap}; modeled Tunnel and fail-closed "
                      "discard paths take precedence")
    v.warning(path, "vpn_failover_not_verified",
              "NOT VERIFIED on hardware: confirm Tunnel Track, route withdrawal, active discard "
              "and VPN PBR/NAT behavior during Console Deployment Preflight")


def _route_boundaries(prefix: IPv4Network, routes: list[StaticRoute]) -> list[IPv4Address]:
    # One representative per interval with the same covering route candidates.
    start = int(prefix.network_address)
    end = int(prefix.broadcast_address)
    boundaries = {start}
    for route in routes:
        for point in (int(route.destination.network_address),
                      int(route.destination.broadcast_address) + 1):
            if start < point <= end:
                boundaries.add(point)
    return [IPv4Address(point) for point in sorted(boundaries)]


def _next_hops(
    address: IPv4Address, routes: list[StaticRoute], tunnel: IpsecTunnel,
    state: TunnelState, track_bound: bool, core_ip: IPv4Address | None, fallback: str,
) -> set[str]:
    outcomes: set[str] = set()
    tracks_if_skipped: dict[UUID, TunnelState] = {}
    for route in routes:
        if address not in route.destination:
            continue
        active = _active(route, tunnel, state, track_bound)
        condition = route.activation
        if active is None and isinstance(condition, TrackActive):
            assumed_state = tracks_if_skipped.get(condition.track_id)
            if assumed_state is None:
                # Reaching a lower priority route requires this condition to be false.
                tracks_if_skipped[condition.track_id] = "down" if condition.state == "up" else "up"
            else:
                active = assumed_state == condition.state
        if active is False:
            continue
        hop = route.next_hop
        if hop.kind == "ip":
            outcomes.add(_ip_path(hop.address, core_ip))
        elif hop.kind == "tunnel":
            outcomes.add(f"Tunnel {hop.tunnel_id}")
        else:
            outcomes.add("discard")
        if active is True:
            return outcomes
    return outcomes | {fallback}


def _active(
    route: StaticRoute, tunnel: IpsecTunnel, state: TunnelState, track_bound: bool,
) -> bool | None:
    condition = route.activation
    if isinstance(condition, AlwaysActive):
        return True
    if condition is None:
        return True if route.next_hop.kind == "ip" else None
    if track_bound and condition.track_id == tunnel.track_id:
        return condition.state == state
    return None


def _ip_path(address: IPv4Address, core_ip: IPv4Address | None) -> str:
    return f"Core ({address})" if address == core_ip else str(address)
