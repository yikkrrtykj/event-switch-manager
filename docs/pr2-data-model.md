# PR #2 data model design

Start implementation after the Foundation acceptance gate and the authorized merge of PR #1. Use the merged `main` SHA, the Foundation SQLite schema at revision `0001_event_inventory`, the current event and device API, and the PLN-01 through PLN-03 requirements in [the V1 roadmap](v1-roadmap.md).

## Domain boundaries

| Domain | Records and relationships |
| --- | --- |
| Inventory | Physical Device has a stable chassis UUID, expected vendor and model, and an optional verified serial. Software/License Profile records observed image and capabilities. An Event Device Assignment keeps the existing Device UUID and owns the event role, intended hostname, management IP and location. Hardware binding can be pending. |
| Topology | A Stack membership snapshot maps physical chassis to member numbers. Physical Interface belongs to a chassis. Logical Interface covers SVIs and aggregates. Port-Channel maps physical members to a logical interface. Topology Link connects explicit endpoints within the same event revision. |
| Segmentation and addressing | VLAN, Subnet, Gateway/SVI, DHCP Pool, Reservation and Relay, and VLAN access policy. Port settings carry access VLAN or trunk native and allowed VLANs. Management VLAN defaults to 10 and can be changed per event. |
| Routing and egress | Separate destination routes, source-based routing (SBR), policy-based routing (PBR), ISP Track, SNAT, route-based IPsec Tunnel and VPN NAT Exemption. A VLAN egress policy stores ISP priority and ties eligibility to Track state. Tunnel routes and explicit fallback are modeled separately from ISP selection. |
| Revisions and exchange | Event Plan Revision has a stable ID, schema version and content hash. Import and export exchange a versioned plan. Historical configuration, deployment evidence and approvals reference immutable revisions and target identity. |

Split the domain by these responsibilities as the code grows. Keep persistence and application validation separate from Cisco, Hillstone and other platform adapters.

## Cisco Core and Hillstone transit

Cisco Core owns inter-VLAN routing. The default Core-facing link is an access port in transit VLAN 9. The Core uses the transit SVI (for example, `interface Vlan9`) and points its default route at the Hillstone transit IP. Hillstone uses destination static routes to return the event's internal prefixes to the Core transit IP. The VLAN ID, transit subnet and both peer addresses are configurable. Validate that both IPs are distinct usable addresses in the same subnet.

Model ordinary destination lookup independently from SBR and PBR. Record VPN selectors, tunnel next hops, egress failover and NAT exemption explicitly. Flag VPN remote prefixes that overlap a Core return summary, including a summary such as `192.168.0.0/16`. Report the conflicting prefixes and route owners. Validate both active-tunnel and tunnel-down paths so a broad return route cannot silently send VPN traffic back toward the Core.

## Migration, versioning and acceptance

- Preserve Foundation event and assignment UUIDs across an Alembic upgrade. Treat existing serial values as unverified hints. Backfill only unambiguous associations and keep missing or conflicting identities reviewable. The same chassis must be usable in separate events with independent roles and port settings.
- Validate references inside the event/revision boundary, Stack interface/member mapping, topology endpoints, Port-Channel compatibility, VLAN and subnet conflicts, DHCP pool bounds and overlaps, reservation and gateway exclusions, and route next-hop reachability.
- Serialize a canonical versioned plan for deterministic hashing. Preserve ordering where it is meaningful, such as ISP priority. Normalize CIDRs and map keys. Check unsupported schema versions and reject invalid imports atomically. Verify export/import round trips and equal hashes for equivalent content.
- Bind evidence to a revision, an assignment and the observed hardware/Stack snapshot. Approval evidence can reference the revision hash, artifact hash and operation. Historical links must survive later edits or chassis reuse.

PR #2 delivers domain types, migration, validation, versioned exchange and tests using synthetic fixtures. CLI rendering, device writes, live discovery, hypervisor deployment and production configuration remain future milestones. See [Issue #2](https://github.com/yikkrrtykj/event-switch-manager/issues/2).

## Planning API

All routes are under `/api/v1/events/{event_id}`. The server keeps the existing event and device API.

| Method and path | Result |
| --- | --- |
| GET `/plan/seed` | Create a plan in memory from Foundation inventory. Existing assignment UUIDs are preserved and hardware bindings start empty. |
| POST `/plan/validate` | Return validation issues with paths, stable codes and severity. Structural errors use the API's 422 response. |
| POST `/plan-revisions` | Validate and append a schema version 1 plan. Submitting the same content returns its existing revision. |
| GET `/plan-revisions` | List revision metadata in sequence order. |
| GET `/plan-revisions/{revision_id}` | Read the revision, plan and planning warnings. |
| GET `/plan-revisions/{revision_id}/export` | Export canonical JSON with the SHA-256 content hash as its ETag. |

The document's event UUID must match the URL. Array order is canonicalized for set-like collections. SBR ISP priority retains its order. Revision rows are append-only. SQLite serializes revision imports and the chassis registry enforces verified vendor/serial identity across events.

## Planning and deployment checks

The JSON schema stays at v1. The fields for route activation, tunnel health, egress NAT and
hardware capability are additive. Their defaults preserve existing canonical hashes. Schema
revision `0002_event_plans` already stores plans as JSON, so there is no Alembic migration.
Existing revision exports retain their original bytes and ETags. An exact re-import can return
that historical revision. New or edited content must satisfy the current validation rules.

- Plan validation returns `ERROR` and `WARNING` issues with field paths. Only errors block
  new imports. Imported and read revisions include warnings against the stored plan.
- Chassis records can carry an expected vendor and model with no verified serial. Such records
  describe planned positions and are not registered as verified assets. Planned interfaces and
  Stack members can reference those positions. The same UUIDs can be enriched with observations.
- Tunnel Track can explicitly bind to the tunnel, and routes can be always active or conditional
  on Track up/down. The planner evaluates both states independently of any recorded tunnel state.
  Effective routes use longest prefix first, then lower preference, including more-specific
  routes and fallback to the summary or default. A lower-preference discard without explicit
  activation and tunnel withdrawal is unverified.
- `192.168.141.0/24` may overlap a Hillstone return summary of `192.168.0.0/16` to Cisco
  Core. With the VPN route active on Track up and an eligible winning discard on Track down,
  the plan can save with an overlap warning. Unproven paths get unverified warnings. Clearly
  unsafe paths, including Core fallback and PBR falling through to ordinary ISP selection,
  block import. VPN PBR can discard or use the validated route table on failure and requires
  a matching NAT exemption.
- Every SBR uplink has an ordered, independently tracked ISP and matching SNAT, or a reason
  for omitting SNAT on that specific egress. An off-link translated address requires an ISP
  routed block with a recorded reason.

Actual StoneOS 5.5R11P2-v6 behavior remains **NOT VERIFIED**. Console Deployment Preflight
must independently verify hardware and serials, port presence and capabilities, and the
Stack layout. It must also verify tunnel-bound probing, operational route withdrawal and
discard installation, PBR/NAT exemption behavior, and the forwarding and source address
on each ISP failover path before any device write.
