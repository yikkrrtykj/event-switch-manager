import re
from collections.abc import Mapping
from uuid import UUID

from .addressing import Vlan
from .inventory import LogicalInterface, PhysicalInterface, PortSettings
from .validation import Validation

STACK_PORT = re.compile(r"^[A-Za-z]+(\d+)/\d+/\d+(?:[:.]\d+)?$")


def check_port(v: Validation, settings: PortSettings, path: str, vlans: Mapping[int, Vlan]) -> None:
    access = settings.access_vlan
    native = settings.native_vlan
    allowed = settings.allowed_vlans
    if settings.mode == "access":
        valid = access is not None and native is None and not allowed and settings.address is None
    elif settings.mode == "trunk":
        valid = access is None and bool(allowed) and settings.address is None
        valid = valid and (native is None or native in allowed)
    else:
        valid = access is None and native is None and not allowed
    v.require(valid, path, "port_mode", "VLAN and address fields must match the port mode")
    v.require(len(allowed) == len(set(allowed)), path, "duplicate", "Repeated allowed VLAN")
    for vlan in (access, native, *allowed):
        if vlan is not None:
            v.require(vlan in vlans, path, "vlan_reference", f"Unknown VLAN {vlan}")


def check_inventory(v: Validation) -> None:
    p = v.plan
    devices = v.index("physical_devices", p.physical_devices, lambda x: x.id)
    v.index("physical_devices", p.physical_devices, lambda x: (x.vendor, x.verified_serial.upper()))
    assignments = v.index("assignments", p.assignments, lambda x: x.id)
    v.index("assignments", p.assignments, lambda x: x.hostname.casefold())
    v.index("assignments", (a for a in p.assignments if a.management_ip), lambda x: x.management_ip)
    vlans = {x.id: x for x in p.vlans}
    stacks: dict[UUID, dict[int, UUID]] = {}
    used_chassis: dict[UUID, UUID] = {}
    for i, entry in enumerate(p.assignments):
        path = f"assignments.{i}"
        chassis = entry.physical_device_id
        if chassis:
            v.require(chassis in devices, f"{path}.physical_device_id",
                      "reference", "Unknown chassis")
            owner = used_chassis.setdefault(chassis, entry.id)
            v.require(owner == entry.id, path, "duplicate", "Chassis is already assigned")
        if entry.software:
            v.index(f"{path}.software.capabilities", entry.software.capabilities,
                    lambda x: x.capability)
    v.index("stacks", p.stacks, lambda x: x.assignment_id)
    for i, stack in enumerate(p.stacks):
        path = f"stacks.{i}"
        assignment = assignments.get(stack.assignment_id)
        v.require(assignment, path, "reference", "Stack assignment is missing")
        v.require(stack.members, f"{path}.members", "stack_members", "Stack has no members")
        v.index(f"{path}.members", stack.members, lambda x: x.number)
        v.index(f"{path}.members", stack.members, lambda x: x.physical_device_id)
        members = {x.number: x.physical_device_id for x in stack.members}
        stacks[stack.assignment_id] = members
        if assignment and assignment.physical_device_id:
            v.require(assignment.physical_device_id in members.values(), path, "stack_chassis",
                      "The assignment chassis must be a member of the Stack")
        for j, member in enumerate(stack.members):
            chassis = member.physical_device_id
            owner = used_chassis.setdefault(chassis, stack.assignment_id)
            v.require(chassis in devices and owner == stack.assignment_id,
                      f"{path}.members.{j}", "stack_chassis", "Invalid or already assigned chassis")
    ports = v.index("physical_interfaces", p.physical_interfaces, lambda x: x.id)
    logical = v.index("logical_interfaces", p.logical_interfaces, lambda x: x.id)
    interfaces: tuple[PhysicalInterface | LogicalInterface, ...] = (
        *p.physical_interfaces, *p.logical_interfaces,
    )
    v.index("interfaces", interfaces, lambda x: x.id)
    v.index("interfaces", interfaces, lambda x: (x.assignment_id, x.name.casefold()))
    for i, port in enumerate(p.physical_interfaces):
        path = f"physical_interfaces.{i}"
        assignment = assignments.get(port.assignment_id)
        stack_members = stacks.get(port.assignment_id)
        v.require(assignment and port.physical_device_id in devices, path, "reference",
                  "Port requires an existing assignment and chassis")
        if stack_members is not None:
            parsed = STACK_PORT.fullmatch(port.name)
            v.require(port.stack_member is not None
                      and stack_members.get(port.stack_member) == port.physical_device_id
                      and parsed and int(parsed[1]) == port.stack_member,
                      f"{path}.stack_member", "stack_port", "Port name must match Stack chassis")
        else:
            v.require(port.stack_member is None and assignment
                      and assignment.physical_device_id == port.physical_device_id,
                      f"{path}.physical_device_id", "port_chassis",
                      "Port must belong to its chassis")
        check_port(v, port.settings, f"{path}.settings", vlans)
    for i, interface in enumerate(p.logical_interfaces):
        path = f"logical_interfaces.{i}"
        v.require(interface.assignment_id in assignments, path, "reference", "Unknown assignment")
        if interface.kind == "svi":
            v.require(interface.vlan in vlans and interface.address is not None, path, "svi",
                      "SVI requires an existing VLAN and an IPv4 interface address")
        else:
            v.require(interface.vlan is None, path, "svi", "Only an SVI declares its VLAN here")
    channels = v.index("port_channels", p.port_channels, lambda x: x.interface_id)
    member_owner: set[UUID] = set()
    numbers: set[tuple[UUID, int]] = set()
    for i, channel in enumerate(p.port_channels):
        path = f"port_channels.{i}"
        aggregate = logical.get(channel.interface_id)
        v.require(aggregate and aggregate.kind == "port-channel", path, "port_channel_interface",
                  "Port-Channel requires a matching logical interface")
        if aggregate:
            key = (aggregate.assignment_id, channel.number)
            v.require(key not in numbers, f"{path}.number", "duplicate", "Repeated channel number")
            numbers.add(key)
            v.require(aggregate.address is None, path, "port_channel_address",
                      "Set the aggregate address in its port settings")
        check_port(v, channel.settings, f"{path}.settings", vlans)
        v.require(channel.member_ids, f"{path}.member_ids", "empty", "Port-Channel needs members")
        for j, port_id in enumerate(channel.member_ids):
            member_port = ports.get(port_id)
            v.require(member_port and aggregate
                      and member_port.assignment_id == aggregate.assignment_id
                      and member_port.settings.mode == channel.settings.mode
                      and member_port.settings.access_vlan == channel.settings.access_vlan
                      and member_port.settings.native_vlan == channel.settings.native_vlan
                      and set(member_port.settings.allowed_vlans)
                      == set(channel.settings.allowed_vlans)
                      and member_port.settings.address is None,
                      f"{path}.member_ids.{j}", "port_channel_member",
                      "Member must share the assignment and aggregate settings")
            v.require(port_id not in member_owner, f"{path}.member_ids.{j}", "duplicate",
                      "Physical port may join only one aggregate")
            member_owner.add(port_id)
    for i, interface in enumerate(p.logical_interfaces):
        if interface.kind == "port-channel":
            v.require(interface.id in channels, f"logical_interfaces.{i}", "port_channel_interface",
                      "Logical Port-Channel requires an aggregate record")
    v.index("links", p.links, lambda x: x.id)
    linked_ports: set[UUID] = set()
    for i, link in enumerate(p.links):
        first, second = link.endpoints
        a, b = ports.get(first), ports.get(second)
        v.require(first != second and a and b and a.assignment_id != b.assignment_id,
                  f"links.{i}.endpoints", "topology_endpoints",
                  "A link connects two physical ports on different assignments")
        for j, endpoint in enumerate(link.endpoints):
            v.require(endpoint not in linked_ports, f"links.{i}.endpoints.{j}", "duplicate",
                      "A physical port has only one link")
            linked_ports.add(endpoint)
