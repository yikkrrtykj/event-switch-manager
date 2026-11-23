# R54 — Catalyst 9200 L3 Command Evidence Preparation

## Executive Summary

This document prepares **evidence candidates only** for four Catalyst 9200 L3 command topics at Cisco IOS XE Dublin 17.12.4.

No row in this document is approved. All four Evidence rows remain `PENDING` and are held in the non-production registry:

```text
Registry ID: cis-03-c9200-l3-command-evidence-draft-v1
Production: false
Rows: 4
Renderable: 0
```

This registry is **not** registered in production selection and has **not** replaced the C9200 row-less sentinel. C9200 production remains:

```text
Registry ID: cis-03-l1-command-evidence-unreviewed-v1
Rows: 0
```

Independent evidence review is required before any C9200 command can enter a production Registry.

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

The six PID candidates are the project C9200 whitelist:

```text
C9200-24T
C9200-24P
C9200L-24T-4G
C9200L-24T-4G-E
C9200L-24P-4X
C9200L-24P-4X-A
```

The datasheet confirms the C9200/C9200L model families. The `-E` and `-A` ordering variants still need independent PID/SKU confirmation; this is recorded as a review gap rather than silently treated as approved.

## Four-topic Evidence Matrix

| Topic | Command | Mode | Platform source | Command Reference | Evidence conclusion |
| --- | --- | --- | --- | --- | --- |
| IP Routing | `ip routing` | global | Catalyst 9200 17.12 Routing Guide, Configuration Guidelines for IP Routing | No dedicated C9200 command-reference entry located | PENDING REVIEW |
| SVI Interface | `interface Vlan<vlan-id>` | global | Catalyst 9200 17.12 Routing Guide, Configuration Guidelines for IP Routing | Catalyst 9200 17.12 Interface and Hardware Commands, `interface` | PENDING REVIEW |
| SVI Address | `ip address <ip-address> <subnet-mask>` | interface | Catalyst 9200 17.12 Routing Guide, Assigning IP Addresses to Network Interfaces | Catalyst 9200 17.12 IP Addressing Services Commands, `ip address` | PENDING REVIEW |
| Static Route | `ip route <network> <mask> <next-hop>` | global | Catalyst 9200 17.12 Protocol-Independent Features, Configuring Static Unicast Routes | Cisco IOS XE protocol-independent `ip route` reference; no C9200-specific entry located | PENDING REVIEW |

## Official Sources

### Primary platform documentation

- IP Routing Configuration Guide, Cisco IOS XE Dublin 17.12.x (Catalyst 9200 Switches), **Configuring IP Unicast Routing**:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/rtng/b_1712_rtng_9200_cg/configuring_ip_unicast_routing.html>
  - Updated: July 28, 2023.
  - Used sections: Configuration Guidelines for IP Routing; Assigning IP Addresses to Network Interfaces; Enabling IP Unicast Routing.
- IP Routing Configuration Guide, Cisco IOS XE Dublin 17.12.x (Catalyst 9200 Switches), **Protocol-Independent Features**:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/rtng/b_1712_rtng_9200_cg/protocol_independent_features.html>
  - Updated: July 28, 2023.
  - Used sections: Static Unicast Routes; Configuring Static Unicast Routes.

### Command references

- Command Reference, Cisco IOS XE Dublin 17.12.x (Catalyst 9200 Switches), **IP Addressing Services Commands**, `ip address`:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/command_reference/b_1712_9200_cr/ip_commands.html#wp1447909228>
  - Updated: July 31, 2023.
- Command Reference, Cisco IOS XE Dublin 17.12.x (Catalyst 9200 Switches), **Interface and Hardware Commands**, `interface`:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/command_reference/b_1712_9200_cr/interface_and_hardware_commands.html>
  - Updated: July 31, 2023.
- Cisco IOS IP Routing: Protocol-Independent Command Reference, `ip route`:
  <https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_pi/command/iri-cr-book/iri-cr-a1.html>

The generic `ip route` reference is used only because a dedicated C9200 17.12 command-reference entry was not located. This is a recorded evidence gap, not a claim of platform-specific documentation.

### Release, licensing and restrictions

- Release Notes for Cisco Catalyst 9200 Series Switches, Cisco IOS XE Dublin 17.12.x:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/release_notes/ol-17-12-9200.html>
- Licensing and Scaling Guidelines:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/release_notes/ol-17-12-9200/licensing_and_scaling_guidelines.html>
- Configuring Licenses on Cisco Catalyst 9000 Series Switches:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst_9000/cat9000-config-available-licenses.html>
  - Confirms Catalyst 9200 base licenses: Network Essentials and Network Advantage.
- Limitations and Restrictions:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/release_notes/ol-17-12-9200/limitations_and_restrictions.html>
- Cisco Catalyst 9200 Series Switches Data Sheet:
  <https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9200-series-switches/nb-06-cat9200-ser-data-sheet-cte-en.html>

## PID / Release / License Mapping

### PIDs

The draft uses the existing project `_9200_PIDS` list unchanged. The datasheet supports the C9200 and C9200L model families; the review must explicitly confirm the two ordering-variant SKUs before approval.

### Release

The draft target is `17.12.4`. The official pages fetched are for the **17.12.x** documentation set. The exact 17.12.4 build-to-page binding must be confirmed during independent review. No other release is accepted by the draft.

### License

Official source confirms both base license names exist for Catalyst 9200:

```text
Network Essentials
Network Advantage
```

The exact feature-to-license mapping for each command is **not pinned** in this evidence batch. The official license page directs feature mapping to Cisco Feature Navigator, which was not captured as a command-level source. Therefore:

```text
license_evidence = PARTIAL
```

This is intentionally a blocking gap. The draft does not claim `VERIFIED` license approval.

## Command Grammar and Restrictions

### IP Routing

```text
ip routing
```

- Mode: global configuration.
- Parameters: none.
- Restriction: routing is disabled by default; a planned Layer 3 interface is required.
- Excluded: no-form, cleanup, VRF, dynamic routing, complete scripts.
- Documentation gap: no dedicated C9200 command-reference entry was located.

### SVI Interface

```text
interface Vlan<vlan-id>
```

- Mode: global configuration.
- `vlan-id`: 1–4094.
- Renderer policy excludes VLAN 1 and 1002–1005, and requires the exact `Vlan<vlan>` name.
- One SVI per VLAN per assignment in this evidence batch.
- Excluded: interface range, routed-port, port-channel, VRF, fuzzy names.
- Documentation gap: platform-specific SVI command syntax entry remains to be pinned during review.

### SVI Address

```text
ip address <ip-address> <subnet-mask>
```

- Mode: interface configuration.
- Only one primary IPv4 address per SVI is modeled.
- The renderer's `/31` and `/32` exclusions are internal safety policy, not a platform limitation claim.
- Address must match the trusted gateway/subnet.
- Excluded: secondary address, DHCP address, unnumbered interface, IPv6.
- Command reference: Catalyst 9200 17.12 IP Addressing Services Commands, `ip address`.

### Static Route

```text
ip route <network> <mask> <next-hop>
```

- Mode: global configuration.
- Only the IPv4 next-hop form is in this evidence batch.
- The next hop must be on-link in the trusted plan.
- Excluded: interface-only next hop, VRF, name, tag, track, permanent, no-form.
- Default Route is excluded even though the generic `ip route` syntax can express `0.0.0.0/0`.
- Route capacity and hardware limits are not verified in this batch.
- Documentation gap: generic IOS XE command reference is not proof of C9200 platform applicability by itself.

## Exclusions

This batch does **not** include or authorize:

- C9200 Default Route Candidate.
- DHCP Helper Address.
- Routed Port Transition.
- VRF or dynamic routing.
- Full configuration script generation.
- Device connection, configuration push or deployment.
- Any C9200 command in the production Registry.

Static route documentation can express a default destination, but that does not create a separate Default Route candidate or approval.

## Pending Review Digests

Every digest is deterministic SHA-256 of the Evidence content, excluding review metadata. These are the values to review:

| Evidence ID | Topic | Pending Content Digest |
| --- | --- | --- |
| `l3-9200-ip-routing-v1` | IP Routing | `3994bc18808f56bff6f02e60bb9964d680788d4e446de86eaa01d2aea233ecc0` |
| `l3-9200-svi-interface-v1` | SVI Interface | `43db1b686d11ac297c615be7f8ea8bb0fb193c17941cdaec923f9844f642dfc6` |
| `l3-9200-svi-address-v1` | SVI Address | `b0c61e8444d84b4fca71c1792766daf325a446392480ef7adaea0f5d1ff99619` |
| `l3-9200-static-route-v1` | Static Route | `446c9c6df64a33dad0ced5b18ff12db5fd6f6815d3f0325e7dbc47d7ef8255a6` |

Draft registry object fingerprint:

```text
91ed8ecb2cf8b22eada1c9a79c7bd2f005d7c243eddcda47f7161fb743758dc6
```

The digest proves content identity; it does **not** mean the evidence was reviewed or approved.

## Blocking Gaps

All rows are blocked by:

```text
independent-evidence-review-required
official-feature-to-license-mapping-not-pinned
```

Additional gaps:

```text
l3-9200-ip-routing-v1:
  platform-specific-ip-routing-command-reference-not-located

l3-9200-svi-interface-v1:
  platform-specific-svi-command-syntax-gap

l3-9200-static-route-v1:
  platform-specific-static-route-command-reference-not-located
```

## Independent Review Checklist

Reviewer must verify each item and record a real reviewer, date, findings and content digest:

- [ ] Official URL and section support the exact command syntax.
- [ ] Command mode is verified.
- [ ] PID scope is explicitly confirmed, including `-E` and `-A` variants.
- [ ] Exact 17.12.4 release binding is confirmed.
- [ ] Network Essentials / Network Advantage feature mapping is pinned.
- [ ] License source supports each command, or license evidence remains PARTIAL.
- [ ] Static Route command-reference platform applicability is pinned.
- [ ] Restrictions and exclusions match official documentation.
- [ ] The command does not open Default Route, DHCP Helper, routed-port, VRF or dynamic routing.
- [ ] Content Digest is recomputed from the reviewed evidence content.
- [ ] No fabricated reviewer, reviewed date or findings.
- [ ] Production Registry selection is still unchanged and still uses the C9200 sentinel.

## Safety State

```text
Hardware: NOT VERIFIED
Deployment: NOT ALLOWED
DHCP Relay License: UNRESOLVED
C9200 production Registry: cis-03-l1-command-evidence-unreviewed-v1 (0 rows)
C9200 production CLI: BLOCKED
Independent review: PENDING
```

## Review Outcome Expected

A reviewer may approve some or all topics, reject them, or return them for more evidence. No topic is approved by this document. Only after independent review can a later stage register approved C9200 Evidence and verify Renderer/Validator/API/front-end integration.
