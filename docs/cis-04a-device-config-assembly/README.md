# CIS-04A Device Configuration Assembly foundation

CIS-04A turns the existing L2/L3 review contracts into one chaptered, read-only
**Device Configuration Assembly** for exactly one Cisco Assignment of one
immutable Saved Revision. It is a review foundation, not a deployment artifact.

## Safety invariants

```text
executable = false
full_config_generated = false
deployment_allowed = false
hardware_verified = false
device_connection = none
running_config_read = false
device_runtime_state = unknown-not-read
```

The assembly API accepts only the Event, Revision and Assignment UUID path
identifiers. It rebuilds the L2/L3 intents, previews, candidate documents,
production Evidence Registries and independent validation reports from the
trusted database and frozen server objects. Client-supplied Registry IDs,
fingerprints, candidate text, verdicts or device identity are rejected.

## Capability gap inventory (CIS-01/02/03)

| Area | Existing verified path | CIS-04A treatment | Remaining gap |
| --- | --- | --- | --- |
| L2 intent/preview | CIS-02A/B1, immutable revision binding, target IDs, VLAN/reference changes | Reused as the L2 source of the assembly | None for the current reviewed L2 contract |
| L2 candidates/validation | CIS-02B2 renderer and independent validator | Sectioned into VLAN/STP/interface/access/trunk/Port-Channel/PortFast/PoE chapters | A complete per-model offline renderer still needs section-specific synthesis |
| 9300 L3 | Frozen 9300 Registry, 9 PASS / 1 BLOCKED | IP routing/SVI/static route chapters | DHCP Helper blocked; SSH/AAA not implemented |
| 9200 L3 | Reviewed C9200 Registry, 6 PASS / 2 BLOCKED | IP routing/SVI/static route chapters | SVI role blockers; Default Route/DHCP Helper blocked |
| 2960X / 3850 / C1000 L3 | No reviewed production L3 Registry | Blocked sections only; no inherited 9300/9200 CLI | Vendor evidence, exact capability review and independent review |
| Management, authentication, SSH/AAA | Planning intent only | Required `management-auth-ssh` chapter is `NOT_IMPLEMENTED` | Template/rules, secrets handling, Console recovery and independent validation |
| SNMP / Syslog / NTP | Planning intent only | Optional `snmp-syslog-ntp` chapter is `NOT_IMPLEMENTED` | Planning model, applicability rules and evidence |
| Boot/storage/Stack operations | Inventory planning only | Not rendered | CIS-01 capability and deployment contracts |
| DHCP Relay License | Issue #30 remains unresolved | `dhcp-relay-issue-30` cross-check is `BLOCKED` when relays exist | License resolution and independent review |

## Assembly contract

```text
contract_id: cis-04-device-config-assembly-v1
assembly_schema_version: 1
```

The header binds:

- Event UUID, Revision UUID/number/canonical hash, Assignment UUID;
- physical device identity, exact PID, software image/License, Stack snapshot;
- L2 intent/preview/render/validation and individual candidate fingerprints;
- L3 intent/render/validation and individual candidate fingerprints;
- L2 and L3 Evidence Registry IDs/fingerprints.

### Chapters

| Section ID | Source | Required |
| --- | --- | --- |
| `vlan-definitions` | L2 | Yes |
| `stp-vtp` | L2 | Yes |
| `physical-interfaces` | L2 | Yes |
| `access-trunk-vlans` | L2 | Yes |
| `port-channels-lacp` | L2 | When channels exist |
| `portfast-bpdu-poe` | L2 | When planned |
| `ip-routing` | L3 | Core |
| `svi` | L3 | Core |
| `routes` | L3 | Core |
| `dhcp` | L3 | When relays exist |
| `management-auth-ssh` | none | Yes, currently not implemented |
| `snmp-syslog-ntp` | none | Optional, currently not implemented |

Every chapter reports `required`, `applicability`, `candidate_count`,
`passed_count`, `failed_count`, `blocked_count`, `missing_count`,
`reason_codes`, `evidence_references`, `source_fingerprints` and individual
candidate records.

Section statuses are `VALIDATED_SECTION`, `PARTIAL`, `BLOCKED`,
`NOT_APPLICABLE` and `NOT_IMPLEMENTED`.

The device is `COMPLETE` only when every required chapter is validated or
explicitly not applicable and no cross-layer check fails. The current 9300 and
9200 plans are therefore **not complete**: management/auth/SSH is not
implemented and additional L2/L3 blockers remain.

### Cross-layer checks

The assembly emits eleven independent checks:

1. `vlan-definition-exists`
2. `svi-vlan-definition-consistency`
3. `routed-switchport-conflict`
4. `port-channel-membership`
5. `native-allowed-vlan-reference`
6. `shutdown-uplink-consistency`
7. `static-route-next-hop-dependency`
8. `default-route-evidence-gate`
9. `dhcp-relay-issue-30`
10. `physical-interface-assignment`
11. `management-vlan-management-ip`

Checks use stable UUIDs and physical-device/Stack ownership, never same-named
strings, to avoid merging another Assignment or Revision.

## API

```text
GET /api/v1/events/{event_id}/plan-revisions/{revision_id}/assignments/{assignment_id}/config-assembly-preview
```

Read-only. Returns `X-Config-Assembly-Scope: full` only after both L2 and L3
source/integrity gates pass. No body, query parameter, Registry/fingerprint,
candidate or device-identity override is accepted.

## UI

The existing Unified Cisco Config Preview displays a **Device configuration
assembly** chapter. The Saved Revision and Cisco Assignment selectors remain the
only selection inputs. Changing either immediately invalidates the old
assembly. Chapter commands are shown only for individually `PASS` candidates;
there is no combined script, Copy All, Execute or Deploy action.

English and Chinese labels are supported, with 390/1366/1920 responsive checks.

## Out of scope

No device connection, running-config read, command execution, deployment file,
full offline configuration, hardware certification or deployment authorization
is generated. A future complete offline configuration requires the missing
management/auth/SSH, SNMP/Syslog/NTP, evidence and independent-review paths
listed in the gap inventory above.
