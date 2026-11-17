# CIS-02B1 Layer 2 configuration preview

CIS-02B1 turns one immutable CIS-02A Layer 2 intent revision into a structured,
per-device **configuration preview** for review. It is the last planning step
before any future renderer: it never renders Cisco CLI, never contacts a device,
never reads or claims a running-config and never writes hardware.

Input contract: [CIS-02A Layer 2 configuration intent](cis-02a-layer2-intent.md)
(`intent_schema_version = 1`). CIS-02B1 does not modify that frozen contract.

Safety invariants are part of the versioned contract:

| Field | Value in CIS-02B1 |
| --- | --- |
| `hardware_verified` | `false` |
| `deployment_allowed` | `false` |
| `verification` | `not-verified` |
| `deployment_status` | `blocked` |
| `executable` | `false` |
| `cli` | `null` |
| `device_writes_enabled` | `false` |
| `running_config_read` | `false` |
| `observed_device_state` | `not-read` |
| `deployability.deployable` (device and item) | `false` |

`preview_schema_version = 1` and
`contract_id = "cis-02b1-layer2-config-preview-v1"`. The preview binds
`intent_schema_version = 1`; any other intent schema version is rejected before
a document is produced.

## HTTP contract

All routes are read-only `GET` requests.

| Route | Result |
| --- | --- |
| `/api/v1/events/{event_id}/plan-revisions/{revision_id}/layer2-config-preview` | One preview document with `devices[]`. |
| `/api/v1/events/{event_id}/plan-revisions/{revision_id}/layer2-config-preview/devices/{assignment_id}` | One self-contained document for a single Assignment. |
| `/api/v1/contracts/layer2-config-preview/schema` | Schema Catalog (`application/json`): contract metadata plus both document schemas. |
| `/api/v1/contracts/layer2-config-preview/schema/aggregate` | Draft 2020-12 JSON Schema for the aggregate document (`application/schema+json`). |
| `/api/v1/contracts/layer2-config-preview/schema/device` | Draft 2020-12 JSON Schema for the single-device document (`application/schema+json`). |

A revision from another event returns `404`. An Assignment outside the revision
intent returns `404`. A revision whose CIS-02A intent cannot be bound to it
returns `409` with one of the reason codes below; this is an internal integrity
failure, not a user input error.

## Revision and intent binding

The preview does not build from a draft. It rebuilds the CIS-02A intent for the
saved revision and validates it before use:

- `intent_schema_version` must be `1`;
- `event_id`, `revision_id` and `revision_hash` must equal the saved revision;
- `intent_fingerprint` is recomputed from the canonical intent document and
  compared with the stored value.

Rejection reasons: `unsupported-intent-schema-version`, `intent-event-mismatch`,
`intent-revision-mismatch`, `intent-revision-hash-mismatch`,
`intent-fingerprint-mismatch`. A tampered intent can therefore never be
previewed as if it were the saved revision.

## Document header

```json
{
  "preview_schema_version": 1,
  "contract_id": "cis-02b1-layer2-config-preview-v1",
  "source": "cis-02a-layer2-intent",
  "event_id": "…",
  "revision_id": "…",
  "revision_number": 2,
  "revision_hash": "…",
  "intent_schema_version": 1,
  "intent_fingerprint": "…",
  "default_policy_id": "cis-02a-reviewed-defaults-v1",
  "baseline": {
    "source": "previous-saved-revision",
    "revision_id": "…", "revision_hash": "…", "device_state": "unknown"
  },
  "device_state": "unknown",
  "before_state_evidence": "planning-baseline",
  "running_config_read": false,
  "observed_device_state": "not-read",
  "dependency_semantics": "association-only-not-an-execution-order",
  "planning_scope": {
    "planned_configuration": "cis-02a-desired-state",
    "planned_difference": "planning-baseline-changeset",
    "device_running_state": "unknown-not-read"
  },
  "readiness": {
    "preview_contract_valid": true,
    "intent_contract_valid": true,
    "structured_intent_valid": true,
    "vendor_documentation": "supported",
    "hardware_verified": false,
    "deployment_allowed": false
  },
  "verification": "not-verified",
  "deployment_status": "blocked",
  "executable": false,
  "cli": null,
  "device_writes_enabled": false,
  "preview_fingerprint": "…"
}
```

`baseline` is a planning baseline only. `before_state_evidence` is
`planning-baseline` or `planning-baseline-unavailable`; the device running state
is never `known`. `deployment_blockers` starts with
`preview-only-no-execution` followed by the CIS-02A blockers and any
preview-specific gate reasons.

### Three separate views

The document keeps three things separate and never merges them:

1. **Planned configuration** — `device.config_items[*].planned`, sourced from
   the EventPlan or the reviewed default policy.
2. **Planned difference** — `device.planned_diff` (the CIS-02A ChangeSet) and
   `device.config_items[*].diff`, sourced from the planning baseline revision.
3. **Real device running state** — `device_state: "unknown"`,
   `running_config_read: false`, `observed_device_state: "not-read"`. No field in
   this contract is an observation of real hardware.

## VLAN scope

`vlan_scope` is the event-wide VLAN definition reference:

- `definitions` lists every declared VLAN plus the management VLAN, with its
  source and the matching definition/rename change;
- `changes` is the CIS-02A `vlan_changes` list (`vlan-created`, `vlan-renamed`,
  `vlan-removed`, `initial-plan`);
- `dependencies` is the event-level `vlan_dependencies` list;
- `fingerprint` is a SHA-256 of the scope content.

Per-device VLAN items stay reference-scoped, exactly as CIS-02A scopes
`desired.vlans`: a device preview only reports VLANs referenced by that device's
ports and Port-Channels. A VLAN declared in the plan but not referenced by a
device appears in `vlan_scope` and never as that device's configuration intent.
This is tested explicitly; the preview does not invent per-device deployment
intent.

`vlan_scope` is event-level reference data in both documents. In a per-device
document its `dependencies[*].required_by` can name change IDs that belong to
other Assignment previews; that is association metadata, not a dangling
device-configuration reference. The device's own configuration never includes
another device's items.

### VLAN definition vs device reference differences

A VLAN definition change and a device reference change are different planning
facts and use different evidence:

| Case | Item `diff.transition` | Change evidence |
| --- | --- | --- |
| Event creates VLAN 40, optionally referenced in the same revision | `vlan-created` | Event `vlan_changes` definition row |
| Event removes VLAN 40, optionally unreferenced in the same revision | `vlan-removed` | Event `vlan_changes` definition row |
| VLAN ID kept, name changed, references unchanged | `vlan-renamed` | Event `vlan_changes` name row |
| First saved revision (no planning baseline) | `initial-plan` | Event `vlan_changes` initial row |
| Existing Assignment newly references an already-declared VLAN | `vlan-referenced` | Device `vlans` set ChangeSet row |
| Existing Assignment stops referencing a still-declared VLAN | `vlan-unreferenced` | Device `vlans` set ChangeSet row |
| New Assignment added in a later revision | no reference change | Device `vlans` initial-plan row, not a reference difference |
| Definition and reference set unchanged | `changed: false` | none |

`vlan-referenced` and `vlan-unreferenced` are emitted only when the Assignment
existed in the previous planning baseline and the device VLAN reference set
changed while no Event-level definition change applies. Their `change_id` is the
real CIS-02A device-level `vlans` set change, never an invented ID and never an
Event definition change. When an Event definition change and a reference change
happen in the same revision, the item keeps the definition transition
(`vlan-created` / `vlan-removed` / `vlan-renamed`). A newly added Assignment's
initial intent is not misreported as `vlan-referenced`; its initial plan is
visible as the device `vlans` initial-plan row in `planned_diff`.

## Per-device preview

```json
{
  "preview_schema_version": 1,
  "contract_id": "cis-02b1-layer2-config-preview-v1",
  "assignment_id": "…",
  "hostname": "L2-Access",
  "identity": {
    "assignment_id": "…", "hostname": "L2-Access", "role": "access",
    "family": "catalyst-9300", "physical_device_id": "…",
    "pid": "C9300L-24P-4X", "pid_evidence": "exact-verified-pid",
    "serial_verified": true, "software_image": "17.12.4",
    "software_license": "Network Advantage",
    "stack_identity": "standalone", "stack_members": []
  },
  "intent_readiness": { "…": "CIS-02A readiness for this device" },
  "deployability": { "…": "see gates below" },
  "config_items": [ "…" ],
  "planned_diff": [ "…" ],
  "dependencies": [ "…" ],
  "conflicts": [ "…" ],
  "capability_checks": [ "…" ],
  "summary": { "…": "deterministic counts" },
  "human_readable": { "display_only": true, "executable": false, "…": "…" },
  "preview_fingerprint": "…"
}
```

`config_items` uses `cis-02a-…`-compatible target IDs (`interface` /
`port-channel` UUIDs, `device` assignment UUID, `vlan` VLAN ID) so a preview item
can always be traced to the intent change that produced it. Categories cover the
required Layer 2 intent set:

`vlan`, `stp`, `vtp`, `root-priority`, `access`, `trunk`, `routed-boundary`,
`port-channel`, `lacp`, `portfast`, `bpdu-guard`, `poe`, `speed`, `duplex`,
`description`, `shutdown`, `unused-port-policy`.

`routed-boundary` is a boundary/cleanup item only; it reports that a port is
planned as routed and which Layer 2 settings must not survive the transition. It
is not an L3 configuration generator.

### Configuration item

```json
{
  "item_id": "cfg-…",
  "category": "access",
  "target_kind": "interface",
  "target_id": "…",
  "target_name": "Gi1/0/1",
  "field": "access_vlan",
  "planned": { "value": 20, "present": true, "source": "event-plan" },
  "baseline": {
    "state": "planning-baseline",
    "value": 20,
    "revision_id": "…",
    "revision_hash": "…"
  },
  "diff": {
    "changed": false,
    "transition": null,
    "cleanup": [],
    "change_id": null,
    "before_source": null,
    "after_source": null
  },
  "capability": {
    "capability": "access",
    "verdict": "supported",
    "reason_code": "feature-documented",
    "reason": "Vendor evidence applies to this profile.",
    "check_id": "cap-…",
    "evidence": [ "…" ]
  },
  "risk": {
    "level": "none",
    "codes": ["execution-not-generated"],
    "requires_field_verification": false
  },
  "deployability": {
    "deployable": false,
    "evidence_gate": "pass",
    "blockers": []
  }
}
```

Every item keeps all six required aspects: **source** (`planned.source`),
**planned value** (`planned.value`), **planning baseline value**
(`baseline.value`/`baseline.state`), **difference** (`diff`), **capability
result** (`capability`), and **risk** (`risk`). `deployable` is always `false`;
`evidence_gate` explains whether the item's evidence would pass, independently
of the phase-wide execution block.

`planned.source` is one of:

| Source | Meaning |
| --- | --- |
| `event-plan` | Explicit value in the saved EventPlan. |
| `management-vlan` | Management VLAN definition supplied by the event. |
| `reviewed-default-policy` | Reviewed default policy `cis-02a-reviewed-defaults-v1`. |
| `platform-default` | No explicit intent and no policy value; device platform default. |
| `not-in-plan` | The current revision expresses no intent for this field (cleanup). |

When a physical interface or Port-Channel is removed from the plan, CIS-02A emits
only a `presence` change for that target. The preview applies that removal change
to the target's baseline-only items, so `diff.changed` is `true`,
`diff.transition` is `interface-removed` or `port-channel-removed`, and
`diff.change_id` points at the presence change. A planned removal is never
reported as "unchanged", and the display text says it has no current planning
intent.

`baseline.state` is `planning-baseline`, `planning-baseline-unavailable` (no
previous saved revision) or `not-in-baseline` (field absent in the previous
revision). An item present only in the baseline reports
`planned.present = false` with `planned.source = "not-in-plan"`; this is cleanup
intent, not authorization to clear a real device.

### Deployability gates

The device `deployability` object holds three independent gates plus one
aggregate evidence gate:

| Gate | Values | Meaning |
| --- | --- | --- |
| `identity_gate` | `pass` / `incomplete` + codes | Exact Cisco PID, serial, software image, License, Stack identity/member readiness, interface/Stack binding. |
| `capability_gate` | `supported` / `unknown` / `unsupported` + lists | Aggregate over the CIS-01A checks CIS-02A requested for this device. |
| `intent_gate` | `valid` / `invalid` | Structured intent valid (no plan ERROR, no ERROR conflict). |
| `evidence_gate` | `pass` / `unknown` / `unsupported` / `identity-incomplete` / `intent-invalid` | Precedence: `intent-invalid` > `identity-incomplete` > `unsupported` > `unknown` > `pass`. |

Identity gate codes include `pid-missing`, `pid-not-verified`, `software-image-missing`,
`license-unverified`, `software-release-unverified`, `pid-unlisted`,
`family-mismatch`, `target-binding-unknown`, `stack-identity-unresolved`,
`stack-member-number-duplicate`, `stack-member-chassis-duplicate`,
`stack-member-pid-missing:<n>`, `stack-member-not-ready:<n>:<state>`,
`serial-not-verified`.

The device-level `evidence_gate` summarizes the whole device and is independent
of each item's gate; an item computes its own gate from its own capability and
the device identity/intent state. For example, a device whose vendor evidence is
UNKNOWN can still show `pass` on a shutdown item that needs no feature evidence,
while every item keeps `deployable: false`. No gate, query parameter or request
body can make an item deployable in CIS-02B1.

`risk.level` adds review severity that does not change the evidence gate:
`none`, `field-verification`, `unknown`, `unsupported`, `identity-incomplete`,
`intent-invalid`. `requires_field_verification` is set for the reviewed
unused-port shutdown policy, inferred unused ports, and CIS-02A field-verification
warnings such as interface/Stack ownership changes.

`human_readable` is display-only prose (`display_only: true`,
`executable: false`). It summarizes the planned defaults, per-port mode changes,
LACP/VLAN differences and the evidence gate. It never contains a multi-line
Cisco command block and is covered by a no-CLI regression test.

## Dependencies are association metadata

`device.dependencies` and `vlan_scope.dependencies` are the CIS-02A
`IntentDependency` lists. Each entry keeps `dependency_id`, `kind`, `target` and
`required_by`, and every document states
`dependency_semantics = "association-only-not-an-execution-order"`.

A dependency is **not** a CLI order, not proof that an operation is safe, and not
a deployment plan. No `execution_order`, `sequence` or command-list field exists
in the contract. Tests assert that every `required_by` entry is a real change ID
and that no ordering field is emitted.

## Determinism and traceability

- `item_id` = `cfg-` + SHA-256 of assignment UUID, category, target kind, target
  ID and field.
- `check_id` = `cap-` + SHA-256 of assignment UUID, check scope, subject and
  capability.
- `preview_fingerprint` = SHA-256 of the canonical document without the
  fingerprint itself (aggregate and per-device documents independently).
- `vlan_scope.fingerprint` = SHA-256 of the scope definitions/changes/dependencies.
- `preview_contract_fingerprint()` hashes the published JSON Schema.

Traceability chain:

```text
saved revision (id, number, hash)
  → CIS-02A intent (intent_schema_version, intent_fingerprint)
    → preview header (revision + intent identity)
      → device preview (assignment UUID, preview_fingerprint)
        → config item (item_id, planned/baseline/diff)
          → planned_diff change (change_id, transition, cleanup)
            → dependency (dependency_id, kind, required_by)
              → capability check (check_id, verdict, evidence)
```

Repeated generation of the same revision returns byte-identical JSON and the
same fingerprints; a later revision never changes an earlier preview.

Fingerprint stability is per contract implementation, not across semantic
corrections. Fixing the VLAN reference-difference semantics changes the
recomputed preview content and therefore `preview_fingerprint` for an affected
already-saved revision. The Saved Revision UUID, canonical revision hash and
ETag remain unchanged, and no stored revision is rewritten. A recomputation
after a code upgrade reflects the corrected semantics; this is not a violation
of determinism.
Cross-assignment isolation is structural: each device preview is built from one
device intent, item IDs include the Assignment UUID, and a same-named interface
on another Assignment can never be merged into it.

## JSON Schema

The contract publishes one Schema Catalog and two document schemas:

| Route | Media type | Purpose |
| --- | --- | --- |
| `/api/v1/contracts/layer2-config-preview/schema` | `application/json` | Catalog: `contract_id`, both schema versions, and the two generated schemas. It is a directory, not a validator schema. |
| `/api/v1/contracts/layer2-config-preview/schema/aggregate` | `application/schema+json` | Aggregate preview document schema, directly usable by a standard validator. |
| `/api/v1/contracts/layer2-config-preview/schema/device` | `application/schema+json` | Single-device preview document schema, directly usable by a standard validator. |

The catalog body is:

```json
{
  "contract_id": "cis-02b1-layer2-config-preview-v1",
  "preview_schema_version": 1,
  "intent_schema_version": 1,
  "aggregate": { "$schema": "https://json-schema.org/draft/2020-12/schema", "…": "…" },
  "device": { "$schema": "https://json-schema.org/draft/2020-12/schema", "…": "…" }
}
```

Both document schemas are generated from the typed Pydantic models (one source,
no hand-written duplicate), declare the Draft 2020-12 `$schema`, set
`additionalProperties: false`, and carry their `$defs` inline so every `$ref`
(`#/$defs/...`) resolves inside the returned document. They encode the safety
constants as `const`/`type: null` constraints: `executable: false`,
`device_writes_enabled: false`, `cli: null`, `preview_schema_version: 1` and the
contract ID. A standard Draft 2020-12 validator accepts real saved-revision,
Stack, Port-Channel and routed-port previews, and rejects `executable: true`,
`device_writes_enabled: true`, a non-null `cli`, a wrong schema version, a wrong
contract ID, missing required fields and wrong field types. Tests use the
independent `jsonschema` package for this; `Pydantic.model_validate` is kept only
as a complementary check, not as a substitute.

## Model examples

Examples use one access port (`Gi1/0/1`, VLAN 20, description "Players desk")
and one trunk port (`Gi1/0/2`, native 10, allowed 10/20), exact PID/image/License
from the reviewed catalog. The description is one of the 14 configuration items:

| Model | PID | Image / License | `vendor_documentation` | Device `evidence_gate` | Deployable items |
| --- | --- | --- | --- | --- | --- |
| Catalyst 2960X | `WS-C2960X-24TS-L` | `15.2(7)E` / LAN Base | `unknown` | `unknown` | 0 of 14 |
| Catalyst 3850 | `WS-C3850-24T` | `16.12.12` / IP Base | `unknown` | `unknown` | 0 of 14 |
| Catalyst 9200L | `C9200L-24T-4G` | `17.12.4` / Network Advantage | `supported` | `pass` | 0 of 14 |
| Catalyst 9300L | `C9300L-24P-4X` | `17.12.4` / Network Advantage | `supported` | `pass` | 0 of 14 |
| Catalyst 1000 | `C1000-24T-4G-L` | `15.2(7)E1` / none | `unknown` | `unknown` | 0 of 14 |

The same example produces these item-level verdicts (`evidence_gate` per item,
followed by the number of items that pass or report UNKNOWN evidence):

| Model | `spanning-tree-mode` | `Gi1/0/1` `mode` | `Gi1/0/1` `access_vlan` | Items pass / unknown |
| --- | --- | --- | --- | --- |
| 2960X | `unknown` / `unknown` | `unknown` / `unknown` | `unknown` / `unknown` | 4 / 10 |
| 3850 | `unknown` / `unknown` | `unknown` / `unknown` | `unknown` / `unknown` | 3 / 11 |
| 9200L | `supported` / `pass` | `supported` / `pass` | `supported` / `pass` | 14 / 0 |
| 9300L | `supported` / `pass` | `supported` / `pass` | `supported` / `pass` | 14 / 0 |
| C1000 | `unknown` / `unknown` | `unknown` / `unknown` | `unknown` / `unknown` | 4 / 10 |

Observed preview verdicts from the model matrix test:

```json
{ "pid": "C9300L-24P-4X", "verdicts": {
  "documented": "supported", "gate": "pass",
  "capability": "supported", "identity_codes": [],
  "summary": { "config_items": 14, "evidence_pass_items": 14,
               "evidence_unknown_items": 0, "deployable_items": 0 } } }
{ "pid": "WS-C2960X-24TS-L", "verdicts": {
  "documented": "unknown", "gate": "unknown",
  "capability": "unknown", "identity_codes": [],
  "summary": { "config_items": 14, "evidence_pass_items": 4,
               "evidence_unknown_items": 10, "deployable_items": 0 } } }
```

A representative item for the 9300L:

```json
{
  "item_id": "cfg-b9f7ae0950f7",
  "category": "access",
  "target_kind": "interface",
  "target_id": "858eca0b-80b9-4a2a-b5b5-671e996dfde3",
  "target_name": "Gi1/0/1",
  "field": "access_vlan",
  "planned": { "value": 20, "present": true, "source": "event-plan" },
  "baseline": { "state": "planning-baseline-unavailable", "value": null,
                "revision_id": null, "revision_hash": null },
  "diff": { "changed": true, "transition": "initial-plan", "cleanup": [],
            "change_id": "chg-276bc224b941",
            "before_source": "planning-baseline-unavailable",
            "after_source": "event-plan" },
  "capability": { "capability": "access", "verdict": "supported",
                  "reason_code": "feature-documented",
                  "reason": "Vendor evidence applies to this profile.",
                  "check_id": "cap-65b623735ecb", "evidence": [ "…" ] },
  "risk": { "level": "none", "codes": ["execution-not-generated"],
            "requires_field_verification": false },
  "deployability": { "deployable": false, "evidence_gate": "pass",
                     "blockers": [] }
}
```

The same item on the 2960X reports `capability.verdict: "unknown"`,
`reason_code: "feature-evidence-missing"`, `evidence_gate: "unknown"` and stays
non-deployable. On a host whose exact PID is not verified it reports
`identity_gate.codes: ["pid-not-verified", "pid-missing",
"serial-not-verified"]`, `evidence_gate:
"identity-incomplete"` and `deployable: false`.

Human-readable excerpt (9300L, first revision):

```text
Review-only Layer 2 configuration preview for L2-Access: C9300L-24P-4X,
image 17.12.4, license Network Advantage, Stack identity standalone.
This preview generates no Cisco command sequence, contacts no device and claims
no running-config; every intent is review information only.
14 configuration intents are reported; 14 differ from the previous saved
revision; 0 do not pass the evidence gate (device gate: pass).
CIS-02A dependency IDs below are association metadata only and are not an
execution order; no command sequence is authorised by this preview.
```

## Stack and Port-Channel examples

- **Stack**: `identity.stack_identity` is `resolved` only when every member has
  an exact PID; member count and ready-member count are reported. A `missing`
  member adds `stack-member-not-ready:<n>:missing`; an unresolved member PID adds
  `stack-member-pid-missing:<n>` and `stack-identity-unresolved`. Every item's
  evidence gate becomes `identity-incomplete`; the device is never deployable.
  Stack identity changes remain planning differences only and are not a claim
  that a real Stack was replaced, merged, split or renumbered.
- **Port-Channel**: `port_channel` items carry the channel number per member;
  `lacp` items carry `active` / `passive` / `static`. `active`/`passive` map to
  the LACP capability check; `static` reports
  `capability: not-required` / `static-channel-requires-no-lacp-evidence` and
  never claims LACP support. Direct member migration between two channels is
  visible as `port-channel-member-migrate` on the member item, with the source
  channel in `baseline.value` and the target channel in `planned.value`.
- **Unused ports**: a port without links, Port-Channels, ISP or Transit
  references reports `shutdown_intent = "shutdown"` from
  `reviewed-default-policy`, `requires_field_verification = true`, and
  `unused-port-policy-inference` when the port still has business VLAN intent.
  An explicit `admin_state` reports `source: "event-plan"` instead, and a
  referenced port with no explicit admin state reports `platform-default`.

## Fail-closed test evidence

The preview suite covers:

- 2960X, 3850, 9200, 9300 and C1000 model matrix with exact PID/image/License;
- standalone and Stack devices, Stack member state `missing` and unresolved
  member PID;
- access↔trunk in both directions, with cleanup intent for old VLAN fields;
- independent interface↔Port-Channel, LACP `active`/`passive`/`static`, and
  direct member migration between two channels;
- VLAN create/rename/delete, declared-but-unreferenced VLAN scope;
- VLAN definition vs device reference boundaries: existing Assignment adds and
  removes a reference to an already-declared VLAN, Event create+reference,
  Event remove+unreference, rename only, first revision without a baseline, a
  new Assignment in a later revision, two Assignments where only one adds the
  reference, a second interface adding an already-referenced VLAN with an
  unchanged device VLAN set, and repeated GET/fingerprint determinism;
- unused-port shutdown, explicit admin state and default-policy provenance;
- cross-Assignment same-named interfaces and per-device fingerprint isolation;
- unknown/UNSUPPORTED synthetic capabilities via the CIS-01A resolver;
- missing PID, missing License, ROMMON image and Stack identity failure;
- invalid revisions, cross-event isolation, unknown Assignment, immutable
  revision history and deterministic fingerprints;
- JSON Schema publication: catalog media type, direct aggregate/device schemas,
  Draft 2020-12 validation of real saved revision/Stack/Port-Channel/routed
  documents, `$ref`/`$defs` resolution, and rejection of unsafe or malformed
  documents by an independent `jsonschema` validator;
- no CLI output, no command field, no device-operation route and `GET`-only
  preview routes.

## Out of scope

CIS-02B1 does not start CIS-02B2 or CIS-03, renders no Cisco CLI, produces no
deployment-grade configuration, opens no Console/SSH session, performs no
device write or clear, and does not touch Hillstone/Kea deployment or real
hardware. Physical hardware certification remains **NOT VERIFIED** in Issue #4.
