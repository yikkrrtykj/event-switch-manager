"""CIS-03-02A read-only Layer 3 intent tests."""

from __future__ import annotations

import copy
from typing import Any

from layer3_helpers import assignment_id, make_l3_plan, revision_for

from event_switch_manager.domain import DeviceRole
from event_switch_manager.planning.layer3_intent import (
    CONTRACT_ID,
    INTENT_SCHEMA_VERSION,
    Layer3Intent,
    build_layer3_intent,
)


def _intent(**overrides: Any) -> Layer3Intent:
    revision = revision_for(make_l3_plan("00000000-0000-0000-0000-000000000099", **overrides))
    return build_layer3_intent(revision)


def _core(intent: Layer3Intent) -> Any:
    return next(device for device in intent.devices if device.identity.hostname == "L3-Core")


def _access(intent: Layer3Intent) -> Any:
    return next(device for device in intent.devices if device.identity.hostname == "L3-Access")


def test_positive_intent_binds_identity_and_allows_core_forwarding() -> None:
    result = _intent()
    core = _core(result)
    assert result.contract_id == CONTRACT_ID
    assert result.l3_intent_schema_version == INTENT_SCHEMA_VERSION
    assert result.source == "saved-revision"
    assert result.baseline.source == "planning-baseline-unavailable"
    assert result.before_state_evidence == "planning-baseline-unavailable"
    assert core.identity.role is DeviceRole.CORE
    assert core.identity.exact_pid == "C9300L-24P-4X"
    assert core.identity.pid_evidence == "exact-verified-pid"
    assert core.identity.serial_verified is True
    assert core.identity.software_image == "17.12.4"
    assert core.identity.software_license == "Network Advantage"
    assert core.readiness.allowed is True
    assert core.readiness.ip_routing.value == "enable"
    assert core.readiness.documentation.value == "supported"
    assert core.readiness.runtime_prerequisite.value == "satisfied"
    assert core.readiness.hardware_verified is False
    assert core.readiness.deployment_allowed is False
    assert core.blockers == ()
    assert result.readiness.forwarding_ready is True
    assert result.readiness.core_devices == 1
    assert result.readiness.blocked_core_devices == 0
    assert result.readiness.hardware_verified is False
    assert result.readiness.deployment_allowed is False


def test_access_with_management_ip_is_not_a_router() -> None:
    result = _intent()
    access = _access(result)
    assert access.identity.role is DeviceRole.ACCESS
    assert access.readiness.allowed is False
    assert access.readiness.ip_routing.value == "not-applicable"
    assert access.blockers == ()
    assert access.interfaces == ()
    assert access.routes == ()


def test_firewall_records_are_not_treated_as_core_l3() -> None:
    result = _intent()
    firewall = next(
        device for device in result.devices if device.identity.hostname == "L3-FW"
    )
    assert firewall.identity.role is DeviceRole.EXTERNAL_DISTRIBUTION
    assert firewall.readiness.allowed is False
    assert firewall.blockers == ()
    assert firewall.routes == ()


def test_transit_svi_routes_and_relay_are_desired_state_only() -> None:
    result = _intent()
    core = _core(result)
    assert result.transit is not None
    assert result.transit.vlan == 9
    assert result.transit.vlan_declared is True
    assert result.transit.core_ip == core.transit.core_ip
    assert core.transit is not None
    assert core.transit.hillstone_ip == core.routes[0].next_hop
    assert core.routes == (core.routes[0],)
    assert core.routes[0].kind == "default"
    assert core.routes[0].transit_bound is True
    assert core.routes[0].distance == 1
    assert {interface.name for interface in core.interfaces} == {"Vlan9", "Vlan10", "Vlan20"}
    assert all(interface.line_protocol == "unknown-not-read" for interface in core.interfaces)
    assert all(interface.carrier.value == "planned-up" for interface in core.interfaces)
    assert len(core.dhcp_relays) == 1
    relay = core.dhcp_relays[0]
    assert relay.allowed is True
    assert relay.server_ownership == "external-unspecified"
    assert relay.cisco_server_intent is False
    assert relay.associated_pool_ids
    assert str(relay.servers[0]) == "192.168.10.5"
    assert core.dhcp_server_observations == ()
    assert core.service_blockers == ()


def test_no_cli_or_deployment_artifact_is_emitted() -> None:
    result = _intent()
    payload = result.model_dump(mode="json")
    assert result.cli is None
    assert result.executable is False
    assert result.device_writes_enabled is False
    assert result.deployment_status == "blocked"
    forbidden = {
        "commands", "command_lines", "configuration", "config", "cli_commands",
        "script", "execution_order", "sequence", "paste_ready", "deployment_script",
    }
    assert forbidden.isdisjoint(payload)


def test_fingerprint_is_deterministic_and_changes_with_intent() -> None:
    revision = revision_for(make_l3_plan("00000000-0000-0000-0000-000000000099"))
    first = build_layer3_intent(revision)
    second = build_layer3_intent(revision)
    assert first.intent_fingerprint == second.intent_fingerprint
    assert first.model_dump() == second.model_dump()
    changed_payload = make_l3_plan(
        "00000000-0000-0000-0000-000000000099", deny_policy=True,
    )
    changed = build_layer3_intent(revision_for(changed_payload))
    assert changed.intent_fingerprint != first.intent_fingerprint


def test_deny_policy_blocks_global_core_forwarding() -> None:
    result = _intent(deny_policy=True)
    core = _core(result)
    assert core.readiness.allowed is False
    assert core.readiness.ip_routing.value == "blocked"
    assert "l3-policy-acl-not-implemented" in core.blockers
    assert "l3-vlan-access-policy-not-implemented" in {
        conflict.code for conflict in core.conflicts
    }
    assert {operation.operation for operation in core.blocked_operations} >= {
        "policy-acl", "ip-routing",
    }
    assert "l3-policy-acl-not-implemented" in result.deployment_blockers
    assert result.readiness.forwarding_ready is False


def test_routing_enabled_false_conflicts_with_l3_records() -> None:
    result = _intent(routing_enabled=False)
    core = _core(result)
    assert core.readiness.allowed is False
    assert "l3-routing-disabled-conflict" in core.blockers
    assert "l3-routing-disabled-conflict" in {
        conflict.code for conflict in core.conflicts
    }


def test_routing_enabled_true_on_access_is_rejected() -> None:
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    access = next(
        item for item in payload["assignments"] if item["hostname"] == "L3-Access"
    )
    access["routing_enabled"] = True
    result = build_layer3_intent(revision_for(payload))
    access_intent = _access(result)
    assert access_intent.readiness.allowed is False
    assert "l3-routing-enabled-on-non-core" in access_intent.blockers
    assert "l3-routing-enabled-on-non-core" in {
        conflict.code for conflict in access_intent.conflicts
    }


def test_9200_default_and_relay_are_unknown_and_blocked() -> None:
    result = _intent(
        core_pid="C9200L-24P-4X", core_family="catalyst-9200",
    )
    core = _core(result)
    assert core.readiness.allowed is False
    assert core.readiness.documentation.value == "unknown"
    assert "l3-evidence-missing" in core.blockers
    assert len(core.dhcp_relays) == 1
    assert core.dhcp_relays[0].allowed is False
    assert core.dhcp_relays[0].blockers == ("l3-evidence-missing",)
    assert "l3-evidence-missing" in core.service_blockers


def test_2960x_lanbase_is_conditional_and_blocked() -> None:
    result = _intent(
        core_pid="WS-C2960X-24TS-L", core_family="catalyst-2960x",
        core_image="15.2(7)E", core_license="LAN Base",
    )
    core = _core(result)
    assert core.readiness.allowed is False
    assert core.readiness.documentation.value == "conditional"
    assert core.readiness.runtime_prerequisite.value == "unobserved"
    assert "l3-runtime-prerequisite-unobserved" in core.blockers
    assert "l3-documentation-conditional" in core.blockers


def test_3850_ipbase_and_c1000_can_be_ready() -> None:
    ipbase = _intent(
        core_pid="WS-C3850-24P", core_family="catalyst-3850",
        core_image="16.12.12", core_license="IP Base",
    )
    assert _core(ipbase).readiness.allowed is True
    c1000 = _intent(
        core_pid="C1000-24P-4G-L", core_family="catalyst-c1000",
        core_image="15.2(7)E1", core_license=None,
    )
    assert _core(c1000).readiness.allowed is True


def test_pool_without_relay_does_not_claim_cisco_dhcp_server() -> None:
    result = _intent(with_relay=False)
    core = _core(result)
    assert core.readiness.allowed is True
    assert core.dhcp_relays == ()
    assert len(core.dhcp_server_observations) == 1
    observation = core.dhcp_server_observations[0]
    assert observation.cisco_server_intent is False
    assert observation.server_ownership == "unspecified"
    assert observation.blocker == "cisco-dhcp-server-ownership-unresolved"
    assert "cisco-dhcp-server-ownership-unresolved" in core.service_blockers
    assert "cisco-dhcp-server-ownership-unresolved" in result.deployment_blockers
    assert core.readiness.allowed is True


def test_kea_pool_and_relay_coexist_without_server_claim() -> None:
    result = _intent(with_pool=True, with_relay=True)
    core = _core(result)
    assert len(core.dhcp_relays) == 1
    assert core.dhcp_relays[0].associated_pool_ids
    assert core.dhcp_relays[0].cisco_server_intent is False
    assert core.dhcp_server_observations == ()


def test_svi_without_planned_carrier_blocks_forwarding() -> None:
    result = _intent(no_carrier=True)
    core = _core(result)
    assert core.readiness.allowed is False
    assert "l3-svi-no-planned-carrier" in core.blockers
    assert core.readiness.ip_routing.value == "blocked"


def test_multi_subnet_and_duplicate_svi_block() -> None:
    multi = _intent(second_subnet=True)
    core = _core(multi)
    assert core.readiness.allowed is False
    codes = {conflict.code for conflict in core.conflicts}
    assert "l3-multiple-subnets-per-vlan" in codes
    assert "l3-duplicate-svi-vlan" in codes
    duplicate = _intent(duplicate_svi=True)
    assert "l3-duplicate-svi-vlan" in {
        conflict.code for conflict in _core(duplicate).conflicts
    }


def test_invalid_distance_blocks_route_and_forwarding() -> None:
    result = _intent(default_distance=999)
    core = _core(result)
    assert core.readiness.allowed is False
    assert "l3-route-distance-out-of-range" in core.blockers
    assert core.routes == ()


def test_default_route_must_match_transit() -> None:
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    payload["default_routes"][0]["next_hop"]["address"] = "10.0.0.3"
    result = build_layer3_intent(revision_for(payload))
    core = _core(result)
    assert core.readiness.allowed is False
    assert "l3-default-route-not-transit" in {
        conflict.code for conflict in core.conflicts
    }
    assert "l3-core-default-route-mismatch" in core.blockers


def test_transit_vlan_must_be_declared() -> None:
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    payload["vlans"] = [vlan for vlan in payload["vlans"] if vlan["id"] != 9]
    result = build_layer3_intent(revision_for(payload))
    core = _core(result)
    assert core.readiness.allowed is False
    assert "l3-transit-vlan-undefined" in core.blockers
    assert result.transit is not None
    assert result.transit.vlan_declared is False


def test_invalid_revision_blocks_core_forwarding() -> None:
    revision = revision_for(make_l3_plan("00000000-0000-0000-0000-000000000099"))
    invalid = revision.model_copy(update={"validation_status": "INVALID"})
    result = build_layer3_intent(invalid)
    core = _core(result)
    assert core.readiness.allowed is False
    assert "l3-plan-invalid" in core.blockers


def test_baseline_svi_removal_is_blocked_and_traced() -> None:
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    baseline_payload = copy.deepcopy(payload)
    extra_svi = "00000000-0000-0000-0000-0000000000aa"
    baseline_payload["logical_interfaces"].append({
        "id": extra_svi,
        "assignment_id": assignment_id(payload, "L3-Core"),
        "name": "Vlan99",
        "kind": "svi",
        "vlan": 20,
        "address": "192.168.99.1/24",
    })
    baseline = revision_for(baseline_payload)
    result = build_layer3_intent(revision_for(payload), baseline)
    core = _core(result)
    assert result.baseline.source == "previous-saved-revision"
    assert result.before_state_evidence == "planning-baseline"
    assert str(extra_svi) in {str(item) for item in core.removed_svi_ids}
    operations = {operation.operation for operation in core.blocked_operations}
    assert "svi-removal" in operations
    assert "cleanup" in operations
    assert "svi-removal" in {
        operation.operation for operation in core.blocked_operations
        if operation.reason_code == "svi-removal-not-rendered"
    }


def test_svi_gateway_mismatch_blocks_forwarding() -> None:
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    payload["gateways"][0]["address"] = "192.168.10.254"
    result = build_layer3_intent(revision_for(payload))
    core = _core(result)
    assert core.readiness.allowed is False
    assert "l3-svi-gateway-mismatch" in {
        conflict.code for conflict in core.conflicts
    }


def test_routed_port_requires_field_verification_and_blocks() -> None:
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    core_assignment = assignment_id(payload, "L3-Core")
    payload["physical_interfaces"].append({
        "id": "00000000-0000-0000-0000-0000000000bb",
        "assignment_id": core_assignment,
        "physical_device_id": payload["assignments"][0]["physical_device_id"],
        "name": "Gi1/0/3",
        "settings": {"mode": "routed", "address": "10.10.10.1/30"},
    })
    result = build_layer3_intent(revision_for(payload))
    core = _core(result)
    assert core.readiness.allowed is False
    assert "routed-port-transition-requires-field-verification" in core.blockers
    assert "routed-port-transition" in {
        operation.operation for operation in core.blocked_operations
    }


def test_explicit_routing_enabled_keeps_core_ready() -> None:
    result = _intent(routing_enabled=True)
    assert _core(result).readiness.allowed is True


def test_unknown_pid_and_missing_software_fail_closed() -> None:
    unknown = _intent(core_pid="C9300L-48T-4G")
    assert _core(unknown).readiness.allowed is False
    assert "l3-pid-unlisted" in _core(unknown).blockers
    missing = _intent(core_image=None)
    assert _core(missing).readiness.allowed is False
    assert "l3-software-missing" in _core(missing).blockers
