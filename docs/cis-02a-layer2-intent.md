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
- desired VLAN intents by ID and name, sourced from the EventPlan (management
  VLAN is marked with its source);
- Reviewed global defaults, each with `source: "reviewed-default-policy"` and
  the versioned `default_policy_id`:
  - Rapid PVST+ mode `rapid-pvst`;
  - VTP mode `transparent`;
  - root priority from the reviewed role policy: `core=4096`,
    `external-distribution=8192`, `access=32768` (`role-priority-v1`);
  - unused-port shutdown policy: ports not referenced by links, Port-Channels,
    ISPs or Transit are intended `shutdown`;
- physical ports: switchport/routed boundary, mode, access/native/allowed VLAN,
  routed address, description, admin state and shutdown intent, speed, duplex,
  PoE, PortFast, BPDU Guard, Port-Channel membership and unused flag;
- Port-Channels: logical interface, number, members, LACP mode
  (`active`/`passive`/`static`), L2 settings.

The engine never creates a VLAN, interface or Port-Channel beyond what the
EventPlan contains; it only derives intent and diagnostics from the plan.

## ChangeSet and dependencies

Every non-equal target field between the planning baseline and the desired state
produces a `PlannedChange`:

- deterministic `change_id`;
- target kind (`device` / `interface` / `port-channel`), target ID and name;
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
  `shutdown-intent-change`;
- cleanup intent for old settings that must not survive a transition;
- dependency IDs.

`IntentDependency` entries model ordering intent without commands:
`vlan-definition`, `port-channel-interface`, `port-channel-membership`,
`member-detach`, `mode-cleanup`, `routed-boundary`, `unused-port-policy`, each
with the change IDs that require it.

## Conflicts and validation findings

`conflicts` are engine findings (`ERROR`/`WARNING`) and remain separate from
CIS-01A capability checks. Examples: a member in two Port-Channels, duplicate
Port-Channel numbers, members outside the plan or assignment, duplicate members,
Port-Channel without a logical interface, access/trunk/routed VLAN-shape
conflicts, Spanning Tree on a routed port, unknown VLAN references, Stack
interface ownership conflicts, and an unused port explicitly enabled.

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
- VLAN/native/allowed, STP defaults, root priority, VTP, PoE, Speed/Duplex,
  description, shutdown intent and unused-port policy;
- fail-closed ROMMON, unknown identity and unknown-optics evidence;
- no baseline → `planning-baseline-unavailable`;
- cross-event isolation and revision immutability;
- deterministic repeated generation and stable intent fingerprint;
- structural conflicts separate from capability evidence;
- invalid revision diagnostics;
- no CLI output and no device write path (`cli=null`, `executable=false`,
  `device_writes_enabled=false`).

## Out of scope

CIS-02A does not include a Cisco CLI renderer, deployment-grade Cisco config
preview, Console writes, SSH delivery, device clearing, Hillstone writes, Kea
deployment or any real device configuration change. CIS-02B/CIS-03 remain
future milestones. Physical hardware certification remains NOT VERIFIED in
Issue #4.
