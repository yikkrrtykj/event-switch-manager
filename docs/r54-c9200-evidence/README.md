# R55 — Catalyst 9200 L3 Command Evidence Corrections

## Executive Summary

This document contains the revised **evidence-review candidates** for four Catalyst 9200 L3 command topics at Cisco IOS XE Dublin 17.12.4.

R55/R56 content was accepted by independent AI read-only documentation review recorded in the R56 Issue #4 acceptance comment. R57 converts that review into digest-bound attestations and registers a production C9200 Registry for the exact reviewed scope. The original draft rows remain PENDING and non-production:

```text
Draft Registry ID: cis-03-c9200-l3-command-evidence-draft-v1
Production: false
Rows: 4
Renderable: 0
Fingerprint: d90c0bfe4a177eab8def5fc3e6e4b0349702fbbed1c5cb1c1d58600cfede555e
```

Reviewed production Registry:

```text
Registry ID: cis-03-c9200-l3-command-evidence-v1
Production: true
Rows: 4
Fingerprint: 2c73c8b39100622360c6bfab935d995d8fb884dd999b6df0ae744a7be7cec876
Review provenance: https://github.com/yikkrrtykj/event-switch-manager/issues/4#issuecomment-7099400033
Reviewer: ChatGPT GPT-6 (AI independent read-only document reviewer)
Reviewed at: 2026-11-23
```

Unreviewed C9200 identities (unknown PID, release or License) still resolve to:

```text
Registry ID: cis-03-l1-command-evidence-unreviewed-v1
Rows: 0
```

The AI review is not human engineering approval, Cisco TAC validation, hardware verification or deployment authorization.

## Exact Scope

| Field | Scope |
| --- | --- |
| Platform | Catalyst 9200 / 9200L |
| Software | Cisco IOS XE Dublin 17.12.4 |
| Base licenses | Network Essentials, Network Advantage |
| Family | `catalyst-9200` |
| Topics | IP Routing, SVI Interface, SVI Address, Static Route |
| Default Route | Excluded |
| DHCP Helper | Excluded |
| Routed Port Transition | Excluded |
| VRF / dynamic routing | Excluded |
| Complete scripts / deployment | Excluded |

## PID / Ordering SKU / Default License

The Evidence module owns its PID scope explicitly. It does **not** import the Capability whitelist.

### Hardware model PIDs

```text
C9200-24T
C9200-24P
C9200L-24T-4G
C9200L-24P-4X
```

These are the hardware model designations represented in the C9200/C9200L datasheet and platform documentation.

### Ordering SKUs

```text
C9200L-24T-4G-E
C9200L-24P-4X-A
```

Official default-license mapping:

| Ordering SKU | Default Network Stack License |
| --- | --- |
| `C9200L-24T-4G-E` | Network Essentials |
| `C9200L-24P-4X-A` | Network Advantage |

The `-E` and `-A` suffixes are **ordering tier suffixes**, not additional physical hardware models. A default license bundled at order time is also **not proof of the license currently active on a running device**.

The release-notes model table lists the full ordering SKUs such as `C9200-24T-A`/`-E`, `C9200-24P-A`/`-E`, `C9200L-24T-4G-A`/`-E`, and `C9200L-24P-4X-A`/`-E`. The current evidence scope retains the four base hardware model PIDs plus the two explicitly reviewed ordering SKUs.

### Verified Evidence scope

```text
verified_pids =
  C9200-24T
  C9200-24P
  C9200L-24T-4G
  C9200L-24P-4X
  C9200L-24T-4G-E
  C9200L-24P-4X-A
```

`verified_pids` means “documentation-scoped Evidence applicability”, not “this physical device was tested”.

## Four-topic Evidence Matrix

| Topic | Command | Mode | Official platform source | Command reference | Evidence conclusion |
| --- | --- | --- | --- | --- | --- |
| IP Routing | `ip routing` | global | [Configuration Guidelines for IP Routing / Enabling IP Unicast Routing](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/rtng/b_1712_rtng_9200_cg/configuring_ip_unicast_routing.html) | Platform guide directly documents command and mode | PENDING |
| SVI Interface | `interface Vlan<vlan-id>` | global | [Configuration Guidelines for IP Routing](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/rtng/b_1712_rtng_9200_cg/configuring_ip_unicast_routing.html) and [Switch Virtual Interfaces](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/int_hw/b_1712_int_and_hw_9200_cg/configuring_interface_characteristics.html) | Catalyst 9200 17.12 Interface and Hardware Commands, `interface` | PENDING |
| SVI Address | `ip address <ip-address> <subnet-mask>` | interface | [Assigning IP Addresses to Network Interfaces](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/rtng/b_1712_rtng_9200_cg/configuring_ip_unicast_routing.html) | Catalyst 9200 17.12 IP Addressing Services Commands, `ip address` | PENDING |
| Static Route | `ip route <network> <mask> <next-hop>` | global | [Configuring Static Unicast Routes](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/rtng/b_1712_rtng_9200_cg/protocol_independent_features.html) | Platform guide + [IOS XE protocol-independent `ip route`](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_pi/command/iri-cr-book/iri-cr-a1.html) | PENDING |

## Official Sources

### 17.12.4 release evidence

- Release Notes, Cisco Catalyst 9200 Series Switches, Cisco IOS XE Dublin 17.12.x:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/release_notes/ol-17-12-9200.html>
- What's New in Cisco IOS XE Dublin 17.12.x:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/release_notes/ol-17-12-9200/whats_new_in_cisco_ios_dublin_1712x.html>
  - Contains explicit sections for **Hardware Features in Cisco IOS XE Dublin 17.12.4**, **Software Features in Cisco IOS XE Dublin 17.12.4**, and **Hardware and Software Behavior Changes in Cisco IOS XE Dublin 17.12.4**.
  - Those 17.12.4 sections state there are no new hardware features, no new software features, and no behavior changes in that maintenance release.
- Introduction and supported model/license table:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/release_notes/ol-17-12-9200/introduction.html>

### Routing and interface evidence

- IP Routing Configuration Guide, 17.12, **Configuring IP Unicast Routing**:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/rtng/b_1712_rtng_9200_cg/configuring_ip_unicast_routing.html>
  - Sections: Configuration Guidelines for IP Routing; Enabling IP Unicast Routing; Assigning IP Addresses to Network Interfaces.
- IP Routing Configuration Guide, 17.12, **Protocol-Independent Features**:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/rtng/b_1712_rtng_9200_cg/protocol_independent_features.html>
  - Sections: Static Unicast Routes; Configuring Static Unicast Routes.
- Interface and Hardware Components Configuration Guide, 17.12, **Configuring Interface Characteristics**:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/int_hw/b_1712_int_and_hw_9200_cg/configuring_interface_characteristics.html>
  - Sections: Switch Virtual Interfaces; Interface Connections; Layer 3 Interfaces.

### Command references

- Catalyst 9200 17.12 Command Reference, IP Addressing Services Commands, `ip address`:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/command_reference/b_1712_9200_cr/ip_commands.html#wp1447909228>
- Catalyst 9200 17.12 Command Reference, Interface and Hardware Commands, `interface`:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/command_reference/b_1712_9200_cr/interface_and_hardware_commands.html>
- Cisco IOS XE protocol-independent `ip route` reference:
  <https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_pi/command/iri-cr-book/iri-cr-a1.html>

### Licensing

- Catalyst 9200 17.12 Licensing and Scaling Guidelines:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/release_notes/ol-17-12-9200/licensing_and_scaling_guidelines.html>
- Catalyst 9000 available licenses:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst_9000/cat9000-config-available-licenses.html>
  - Confirms Catalyst 9200 base licenses: Network Essentials and Network Advantage.
- Interface Characteristics Guide, **Interface Connections**:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/int_hw/b_1712_int_and_hw_9200_cg/configuring_interface_characteristics.html>
  - States that with Network Essentials, only basic routing (static routing and RIP) is supported; Network Advantage uses the routing method for forwarding between interfaces.

## Command Grammar, Modes and Restrictions

### IP Routing

```text
ip routing
```

- Mode: global configuration.
- Parameters: none.
- Official platform guide directly documents the command under Enabling IP Unicast Routing.
- Routing is disabled by default; at least one Layer 3 interface is required.
- Excluded: no-form, cleanup, VRF, dynamic routing, complete scripts.

### SVI Interface

Official syntax:

```text
interface vlan vlan-id
```

Renderer canonical spelling:

```text
interface Vlan<vlan-id>
```

- Mode: global configuration.
- `vlan-id`: 1–4094.
- Renderer excludes VLAN 1 and 1002–1005, and requires the canonical `Vlan<vlan>` name.
- One SVI per VLAN per assignment in this evidence batch.
- Excluded: interface range, routed-port, port-channel, VRF.

### SVI Address

```text
ip address ip-address subnet-mask
```

- Mode: interface configuration.
- Only one primary IPv4 address per SVI is modeled.
- The renderer's `/31` and `/32` exclusions are internal safety policy, not a platform limitation claim.
- Address must match the trusted gateway/subnet.
- Excluded: secondary address, DHCP address, unnumbered interface, IPv6.

### Static Route

Official platform-guide syntax:

```text
ip route prefix mask {address | interface} [distance]
```

Project Evidence/Renderer subset:

```text
ip route <network> <mask> <next-hop>
```

- Mode: global configuration.
- Only the IPv4 next-hop form is in this batch.
- Next hop must be on-link in the trusted plan.
- Excluded: interface-only next hop, VRF, name, tag, track, permanent, no-form.
- Default Route is excluded even though the official syntax can express `0.0.0.0/0`.
- Route capacity and hardware limits are not verified in this batch.

## Exclusions

This batch does not include or authorize:

- C9200 Default Route Candidate.
- DHCP Helper Address.
- Routed Port Transition.
- VRF or dynamic routing.
- Full configuration script generation.
- Device connection, configuration push or deployment.
- Any C9200 command in the production Registry.

## Pending Review Digests

Every digest is deterministic SHA-256 of Evidence content, excluding review metadata. These are the revised values:

| Evidence ID | Topic | Pending Content Digest |
| --- | --- | --- |
| `l3-9200-ip-routing-v1` | IP Routing | `84fb338c43bd5584f0797baf9172291973f26720227dc18bbf0fb09a48c4db38` |
| `l3-9200-svi-interface-v1` | SVI Interface | `37223459db80efc3d531a6ccf898c217fc7319893cbee56d3c7ec4eccf2e2193` |
| `l3-9200-svi-address-v1` | SVI Address | `e61264cf0a1b2441f443b8e5213e42ef3b2b6db946619909bd396650ba56c6d9` |
| `l3-9200-static-route-v1` | Static Route | `8206b57a147c5d3a4a3b29506a91ec9f7de1b586ed0fd074f30bae453df55a4a` |

Draft registry fingerprint:

```text
d90c0bfe4a177eab8def5fc3e6e4b0349702fbbed1c5cb1c1d58600cfede555e
```

Digest match is content integrity only; it is not independent approval.

## Blocking Gaps

The remaining blocking gap for every row is:

```text
independent-evidence-review-required
```

The following are recorded as **non-blocking review/safety notes**, not missing official support:

- Ordering-SKU default license is not proof of the actual active license.
- Actual hardware verification was not performed.
- Route capacity and hardware limits are outside this evidence batch.
- Default Route, DHCP Helper, routed-port, VRF and dynamic routing remain excluded.

## `license_evidence` per Topic

All four topics use the official Interface Connections statement that Network Essentials supports basic routing (static routing and RIP), while Network Advantage provides the routing method. Network Advantage support is therefore inherited from the higher license tier and the same official platform guide.

| Topic | `license_evidence` |
| --- | --- |
| IP Routing | VERIFIED |
| SVI Interface | VERIFIED |
| SVI Address | VERIFIED |
| Static Route | VERIFIED |

This is a command-scope conclusion only; it does not mean the actual active license on a physical device was verified.

## 17.12.4 Evidence Chain

```text
Catalyst 9200 17.12.x platform guides
  → Release Notes for 17.12.x
  → What's New in 17.12.x, explicit 17.12.4 sections
  → Evidence rows restricted to release 17.12.4
```

The What's New page explicitly lists 17.12.4 hardware/software/behavior sections and reports no new hardware features, no new software features and no behavior changes for that maintenance release. This establishes the release-page chain; it is not hardware testing.

## Independent Review Checklist

Reviewer must verify and record a real reviewer, date, findings and content digest:

- [ ] Official URL and section support exact command syntax and mode.
- [ ] Hardware model versus ordering SKU classification is correct.
- [ ] `-E` = Network Essentials and `-A` = Network Advantage ordering suffixes are correctly recorded.
- [ ] Default ordering license is not treated as the currently active license.
- [ ] Exact 17.12.4 release chain is accepted.
- [ ] Network Essentials basic-routing statement is applied only to the basic command scope.
- [ ] Network Advantage inheritance is accepted.
- [ ] Static Route platform syntax and renderer safety subset are clearly distinguished.
- [ ] Default Route, DHCP Helper, routed-port, VRF and dynamic routing remain excluded.
- [ ] Content Digest is recomputed from reviewed Evidence content.
- [ ] No fabricated reviewer, reviewed date or findings.
- [ ] Exact reviewed C9200 scope selects the reviewed Registry; unknown scope remains the sentinel.
- [ ] Default Route and DHCP Helper remain BLOCKED with no CLI text.

## Safety State

```text
Hardware: NOT VERIFIED
Deployment: NOT ALLOWED
DHCP Relay License: UNRESOLVED
Reviewed C9200 Registry: cis-03-c9200-l3-command-evidence-v1
Unreviewed C9200 scope: cis-03-l1-command-evidence-unreviewed-v1 (0 rows)
C9200 approved base candidates: candidate-only, no default/DHCP CLI
C9200 Default Route: BLOCKED
C9200 DHCP Helper: BLOCKED
Independent AI documentation review: ACCEPTED (not human/hardware approval)
Draft Registry production registration: NONE
```

## Review Outcome

R56 accepted the four-topic document content after independent AI read-only review. R57 records digest-bound attestations and registers the reviewed C9200 Registry for the exact reviewed scope. The AI review remains non-human, non-hardware, non-deployment approval; actual License and device verification remain pending.
