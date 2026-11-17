# CIS-02A Layer 2 configuration intent

CIS-02A is a read-only planning layer between an immutable saved EventPlan
revision, CIS-01A capability evidence, and a future CLI renderer (CIS-02B). It
produces structured configuration intent and safety diagnostics only.

**CIS-02A does not render Cisco CLI, does not produce a deployment-grade config
preview, does not open Console or SSH, and does not write any device.** Every
result keeps `verification=not-verified`, `deployment_status=blocked`,
`executable=false`, `cli=null` and `device_writes_enabled=false`.
`device_writes_enabled` remains false in the application.

## HTTP contract

`GET /api/v1/events/{event_id}/plan-revisions/{revision_id}/layer2-intent`

The endpoint is read-only and works only from a persisted, immutable revision.
The revision from another event returns 404. The previous revision in the same
event (by revision number) is used as the planning baseline when it exists.

Top-level response:

```json
{
  "intent_schema_version": 1,
  "source": "saved-revision",
  "event_id": "…", "revision_id": "…", "revision_hash": "…",
  "baseline": {
    "source": "previous-saved-revision",
    "revision_id": "…", "revision_hash": "…", "device_state": "unknown"
  },
  "device_state": "unknown",
  "before_state_evidence": "planning-baseline",
  "default_policy_id": "cis-02a-reviewed-defaults-v1",
  "vlans": [ … ],
  "vlan_changes": [ … ],
  "vlan_dependencies": [ … ],
  "devices": [ … ],
  "conflicts": [ … ],
  "validation_findings": [ … ],
  "deployment_blockers": [ … ],
  "readiness": {
    "structured_intent_valid": true,
    "vendor_documentation": "supported",
    "hardware_verified": false,
    "deployment_allowed": false
  },
  "intent_fingerprint": "SHA-256 of the canonical intent document",
  "verification": "not-verified",
  "deployment_status": "blocked",
  "executable": false,
  "cli": null,
  "device_writes_enabled": false
}
```

`before_state_evidence` is `planning-baseline` or
`planning-baseline-unavailable`. The device running-config was not read: all
Before state is explicitly `device_state: "unknown"` and is the previous saved
planning revision, never a claim about the actual device.

### VLAN definition scope

`vlans` at the top level is the event-wide VLAN definition intent. It contains
all VLANs explicitly declared in the EventPlan plus the management VLAN when it
is not declared, each with its planning source. This closes the gap where a
declared-but-not-yet-referenced VLAN was invisible to the intent.

Per-device `desired.vlans` intentionally stays scoped to VLANs referenced by
that device's physical ports and Port-Channels. The engine does not invent
per-device deployment intent for a declared VLAN until the plan references it
from that device. Both scopes are explicit and tested; no VLAN, interface or
Port-Channel outside the EventPlan is created.

## Four separate readiness conclusions

The four conclusions are deliberately independent and are never collapsed into
one PASS:

1. **Structured intent valid** — the plan has no validation ERRORS and the
   engine found no ERROR-severity intent conflict.
2. **Vendor documentation** — aggregate `supported` / `unknown` / `unsupported`
   over the CIS-01A capability checks *required by this intent*.
3. **Hardware verified** — always `false` in this phase. No real device was
   observed.
4. **Deployment allowed** — always `false`. Deployment generation and device
   writes remain blocked.

UNKNOWN and UNSUPPORTED required capabilities still produce a diagnostic intent,
but they add deterministic deployment blockers (`capability-unknown:…`,
`capability-unsupported:…`) and cannot make the result deployment-ready.

## Desired state

Per assignment/device the engine returns:

- exact identity binding: assignment, hostname, role, family, physical device,
  exact verified PID (or model-only/missing evidence), software image, License,
  Stack identity and Stack member list;
- device VLAN intents by ID and name for the VLANs used by this device,
  sourced from the EventPlan (management VLAN is marked with its source);
- event-wide VLAN definitions in the top-level `vlans` field, including declared
  VLANs that are not referenced by interfaces yet;
- Reviewed global defaults, each with `source: "reviewed-default-policy"` and
  the versioned `default_policy_id`:
  - Rapid PVST+ mode `rapid-pvst`;
  - VTP mode `transparent`;
  - root priority from the reviewed role policy: `core=4096`,
    `external-distribution=8192`, `access=32768` (`role-priority-v1`);
  - unused-port shutdown policy: ports not referenced by links, Port-Channels,
    ISPs or Transit are intended `shutdown`. The reviewed policy semantics are
    unchanged; the policy now carries explicit
    `semantics="no-links-port-channels-isps-or-transit"` and
    `requires_field_verification=true`, and each port exposes
    `shutdown_intent_source` (`event-plan` when admin state is explicit,
    `reviewed-default-policy` when the unused-port policy supplied it);
- port intent includes `physical_device_id` so Stack chassis/interface
  ownership is visible and diffable;
- physical ports: interface name, switchport/routed boundary, mode,
  access/native/allowed VLAN, routed address, description, admin state and
  shutdown intent/source, speed, duplex, PoE, PortFast, BPDU Guard,
  Port-Channel membership, physical device and Stack member ownership and
  unused flag;
- Port-Channels: logical interface, number, members, LACP mode
  (`active`/`passive`/`static`), L2 settings including `routed_address`.

The engine never creates a VLAN, interface or Port-Channel beyond what the
EventPlan contains; it only derives intent and diagnostics from the plan.

## ChangeSet and dependencies

Every non-equal target field between the planning baseline and the desired state
produces a `PlannedChange`:

- deterministic `change_id`;
- target kind (`device` / `interface` / `port-channel` / `vlan`), target ID and
  name;
- field, before value, after value;
- `before_source` (`planning-baseline`, `planning-baseline-unavailable` or
  `not-in-baseline`) and `after_source` (`event-plan` or
  `reviewed-default-policy`);
- transition code such as `access-to-trunk`, `trunk-to-access`,
  `switchport-to-routed`, `routed-to-switchport`,
  `independent-to-port-channel-member`,
  `port-channel-member-to-independent`, `lacp-active-to-passive`,
  `native-vlan-change`, `allowed-vlans-change`, `spanning-tree-edge-change`,
  `bpdu-guard-change`, `poe-mode-change`, `speed-change`, `duplex-change`,
  `shutdown-intent-change`, `stack-member-change`, `physical-device-change`,
  `interface-name-change`, `access-vlan-change`,
  `assignment-physical-device-change`, `stack-identity-change`,
  `stack-member-added`, `stack-member-removed`,
  `stack-member-device-change`, `stack-member-pid-change`,
  `vlan-created`, `vlan-removed`, `vlan-renamed`,
  `port-channel-removed`;
- cleanup intent for old settings that must not survive a transition;
- dependency IDs (the same IDs appear in the `IntentDependency` `required_by`
  lists).

VLAN definition changes are structurally distinct:

| Planning change | Change target | Field | Transition |
| --- | --- | --- | --- |
| VLAN added to the plan | `vlan` | `definition` | `vlan-created` |
| VLAN removed from the plan | `vlan` | `definition` | `vlan-removed` |
| VLAN ID kept, name changed | `vlan` | `name` | `vlan-renamed` |
| First revision without a baseline | `vlan` | `definition` | `initial-plan` |

A rename is not a delete/create pair: the VLAN ID and interface references are
preserved, only the name field changes. VLAN definition dependencies
(top-level `vlan_dependencies`) reference the definition change and every
associated interface/Port-Channel/device VLAN-set change that references or
detaches the VLAN: a created/referenced VLAN links its creation and referencing
changes, a removal links the removal and changes that detach the reference, and
an unreferenced declaration links its own definition change. Every associated
`PlannedChange.dependencies` contains the same top-level dependency ID, so the
relation is bidirectional: no dangling dependency IDs, no duplicates, and no
change ID is ever mistaken for a dependency ID.

The relation is an association/ordering-intent record, not proof of an
executable order. Dependency IDs are not change IDs and `required_by` is not a
command sequence; a future renderer must not treat dependency metadata as a
verified execution plan. No self-edge or cycle is created between changes.

Stack identities are separately diffable: assignment physical-device binding
(`physical-device-id`), Stack identity state (`stack-identity`), member
add/remove (`stack-member:<n>:definition`), member chassis replacement
(`stack-member:<n>:physical-device-id`) and member PID change
(`stack-member:<n>:pid`). A physical port also reports its own
`physical_device_id` change. These are planning differences only and add
`device-identity-change-requires-field-verification` /
`stack-identity-change-requires-field-verification` warnings plus
`field-verification-required:…` blockers; the engine never claims a real Stack
replacement/merge/split/renumbering happened.

Port-Channel mode changes reuse the physical-port transition/cleanup logic:
`access-to-trunk`, `trunk-to-access`, `switchport-to-routed`,
`routed-to-switchport`, `mode-change`, with cleanup of old Access/Native/Allowed
VLAN and routed-address fields. Deleting a Port-Channel emits
`port-channel-removed` plus member-detach changes and a
`port-channel-removal` dependency. Its `required_by` is scoped from the
Planning Baseline channel identity and member list: each removed Port-Channel
links only its own removal change and the detach changes of the members that
belonged to it in the baseline. Unrelated member detaches, including detaches
from a retained or separately removed Port-Channel, are never attached by
interface-name guessing. Multiple removed Port-Channels each get a separate
dependency and `required_by` set.

`IntentDependency` entries model ordering intent without commands:
`vlan-definition`, `port-channel-interface`, `port-channel-membership`,
`member-detach`, `mode-cleanup`, `routed-boundary`, `unused-port-policy`,
`stack-member-binding`, `physical-device-binding`, `port-channel-removal`, each
with the change IDs that require it. Device-level dependencies live in
`device.dependencies`; VLAN definition dependencies live in the top-level
`vlan_dependencies`. A change's `dependencies` field is the union of the
device-level and VLAN-level dependency IDs that associate with that change.
Dependency metadata is planning information only; a future Renderer must not
treat it as an already-verified execution order.

## Conflicts and validation findings

`conflicts` are engine findings (`ERROR`/`WARNING`) and remain separate from
CIS-01A capability checks. Examples: a member in two Port-Channels, duplicate
Port-Channel numbers, members outside the plan or assignment, duplicate members,
Port-Channel without a logical interface, access/trunk/routed VLAN-shape
conflicts, Spanning Tree on a routed port, unknown VLAN references, and an
unused port explicitly enabled.

Stack ownership checks are per interface, not per member number: a Stack member
may legitimately own many interfaces. A normal multi-port member produces no
warning. The engine reports `stack-interface-ownership-mismatch` when an
interface's `physical_device_id` differs from its declared member's chassis,
`stack-member-not-in-stack` for an undeclared member number,
`stack-member-without-stack` when a non-Stack assignment declares membership,
and `duplicate-stack-member-number` for an ambiguous layout. Standalone
assignments never produce Stack warnings.

### Unused-port policy boundary

The reviewed policy still treats ports without links, Port-Channels, ISP or
Transit references as unused and intends `shutdown`. That policy was not
silently changed. To avoid presenting this as observed field state, the policy
declares `requires_field_verification=true`, ports expose
`shutdown_intent_source`, and a port that has business VLAN intent but no
topology link receives an `unused-port-policy-inference` WARNING. This makes the
inference auditable and requires field confirmation; it does not assert the port
is physically unused.

`validation_findings` are the saved revision's existing plan validation errors
and warnings. They do not replace capability evidence or hardware verification.

## Capability evidence

CIS-02A calls the existing CIS-01A resolver for the exact revision target:
identity, port layout, VLAN, Rapid PVST+, VTP Transparent, access/trunk/routed
port, PortFast, BPDU Guard, Stack when a Stack exists, Port-Channel and LACP for
aggregates, and per-interface port media/PoE/speed/duplex where the intent uses
them. Each `CapabilityCheck` carries verdict, reason code, reason and evidence
scope. Model names are never used to guess capabilities; missing or unknown
evidence fails closed at the documentation-readiness level.

## Tests

`apps/api/tests/test_layer2_intent.py` covers:

- immutable revision binding, event/revision/hash identity and export/ETag
  immutability;
- 2960X, 3850, 9200, 9300 and C1000 profiles with exact PID/image/License;
- standalone and Stack identity/interface binding;
- access↔trunk, switchport↔routed, channel-member↔independent and LACP
  active/passive transitions with planning baseline and cleanup dependencies;
- review-policy role changes for root priority and Stack member/interface
  ownership changes;
- VLAN/native/allowed, STP defaults, root priority, VTP, PoE, Speed/Duplex,
  description, shutdown intent and unused-port policy;
- fail-closed ROMMON, unknown identity and unknown-optics evidence;
- no baseline → `planning-baseline-unavailable`;
- cross-event isolation and revision immutability;
- deterministic repeated generation and stable intent fingerprint;
- structural conflicts separate from capability evidence;
- invalid revision diagnostics;
- change-set completeness regressions in
  `apps/api/tests/test_layer2_intent_changeset.py`: VLAN create/rename/delete,
  declared-but-unreferenced VLAN scope, Stack chassis replacement/addition/
  removal/renumbering, assignment and interface physical-device changes,
  Port-Channel four-mode transitions with cleanup/dependencies, Port-Channel
  removal/member detach, legal multi-port Stack membership, inconsistent Stack
  ownership, and unused-port policy/source boundaries;
- Port-Channel removal dependency scoping per baseline channel and member list,
  including multiple removals in one revision;
- VLAN dependency backlinks on created, renamed, removed and unreferenced VLAN
  changes, with no duplicate/dangling dependency IDs and no change/dependency ID
  confusion;
- no CLI output and no device write path (`cli=null`, `executable=false`,
  `device_writes_enabled=false`).

### Known boundary observations (not expanded in this change-set fix)

The following are recorded for a future review, not silently expanded here:

- Removing an entire Assignment between revisions currently drops it from
  `devices` without a top-level removed-device ChangeSet record.
- A Stack member `state` change (for example `ready` to `missing`) is visible in
  the desired Stack identity but is not emitted as a `PlannedChange` field.
- Static Port-Channels still receive an LACP capability check because LACP is
  added for every Port-Channel; only PORT-CHANNEL is strictly required for a
  static aggregate. On the reviewed families LACP evidence is supported, so
  this is diagnostic hygiene rather than a current deployment blocker.

They are intentionally not mixed into this dependency remediation; evidence is
kept for a separate scoped fix.

## Out of scope

CIS-02A does not include a Cisco CLI renderer, deployment-grade Cisco config
preview, Console writes, SSH delivery, device clearing, Hillstone writes, Kea
deployment or any real device configuration change. CIS-02B/CIS-03 remain
future milestones. Physical hardware certification remains NOT VERIFIED in
Issue #4.
