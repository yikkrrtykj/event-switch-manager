# CIS-02B2 Cisco Layer 2 offline candidate renderer contract

Status: **contract design only — no renderer, no candidate CLI text, no deployment**.

- Contract ID: `cis-02b2-cisco-l2-cli-candidate-v1`
- Planned `render_schema_version`: `1`
- Inputs: immutable CIS-02A intent `1` and CIS-02B1 preview `1`
- Implementation status: **NOT STARTED**
- Hardware certification: **NOT VERIFIED**
- Device writes: **BLOCKED**

This document is the normative design for the future offline renderer. It may be
implemented only after independent review and explicit authorization. No endpoint,
module or command output is added by CIS-02B2-01.

## 1. Scope and non-goals

CIS-02B2 will render **review-only candidate text** for Layer 2 settings from one
immutable saved revision. A candidate is a suggestion for human review; it is not
a configuration file, not an execution plan and not evidence that a device will
accept it.

In scope: VLAN definition, access VLAN, trunk/native/allowed VLAN, Port-Channel,
LACP mode, Rapid PVST+, VTP transparent, root priority, PortFast, BPDU Guard, PoE,
speed/duplex, description, admin shutdown and unused-port shutdown.

Out of scope: routing, SVIs, static/default routes, DHCP, AAA, SSH, boot/image
management, Stack renumbering, Console/SSH, device connection, deployment,
Hillstone/Kea, CIS-03 and any real hardware operation.

The existing CIS-02A/B1 `cli` field remains `null`. Candidate text is a new,
separate field and must never overwrite `cli`.

## 2. Safety invariants

Every render response, including blocked responses, carries:

| Field | Required value |
| --- | --- |
| `candidate_only` | `true` |
| `executable` | `false` |
| `deployable` | `false` |
| `deployment_allowed` | `false` |
| `device_connection` | `"none"` |
| `running_config_read` | `false` |
| `device_writes_enabled` | `false` |
| `cli` | `null` |
| `deployment_artifact` | `null` |
| `device_runtime_state` | `"unknown-not-read"` |
| `hardware_verified` | `false` |

`executable=false` means the system provides no execution authorization and no
execution path. It does **not** mean the candidate text is harmless. Candidate
text may be copied by a human, so the safety model, validation and risk
classification below still apply.

There is no endpoint, flag, request field or environment setting that can turn a
candidate into a deployment artifact in CIS-02B2. No full configuration file,
paste-ready script or multi-device bundle may be produced.

## 3. Input contract

### 3.1 Server-side reconstruction

The renderer never trusts a client-supplied preview, intent or command text. For
every request the server must:

1. load the saved revision by `event_id` and `revision_id`;
2. rebuild the CIS-02A intent from that revision under its frozen contract;
3. rebuild the CIS-02B1 preview from the rebuilt intent;
4. verify the caller's expected fingerprints and identity;
5. render only from that rebuilt preview and the rebuilt intent.

A client may supply only a selector (assignment and optional category filter). It
must not supply planned values, candidate text, device state or evidence claims.

### 3.2 Required bindings

| Binding | Requirement |
| --- | --- |
| Saved revision UUID | exact match |
| Revision number | exact match |
| Canonical revision hash | exact match |
| CIS-02A `intent_schema_version` | `1` |
| CIS-02A `intent_fingerprint` | exact match with recomputation |
| CIS-02B1 `preview_schema_version` | `1` |
| CIS-02B1 contract ID | `cis-02b1-layer2-config-preview-v1` |
| CIS-02B1 `preview_fingerprint` | exact match with recomputation |
| Assignment UUID | exact assignment in the rebuilt revision |
| Exact Cisco PID | `pid_evidence="exact-verified-pid"` |
| Software release | exact catalog release for that PID |
| License | exact reviewed license scope; suffix is not evidence |
| Capability evidence | rebuilt CIS-01A checks; no client claims |
| Stack identity | `standalone` or fully `resolved`, all members ready |
| Device identity | complete PID/serial/image/license/Stack evidence |

Rejection reasons are deterministic, e.g. `revision-hash-mismatch`,
`intent-fingerprint-mismatch`, `preview-fingerprint-mismatch`,
`assignment-not-in-revision`, `pid-not-verified`, `release-unmatched`,
`license-unmatched`, `capability-unknown`, `capability-unsupported`,
`stack-identity-unresolved`, `device-identity-incomplete`.

### 3.3 Planned request shape

The future read-only compute route is expected to be:

`GET /api/v1/events/{event_id}/plan-revisions/{revision_id}/assignments/{assignment_id}/l2-cli-candidates`

Optional category filter only. The route performs no persistence, audit write or
device access. Refuse any request that tries to submit candidate text, override
planning values or supply a preview document.

## 4. Output contract

The response distinguishes five things that must never be collapsed:

1. planned configuration intent (from CIS-02B1);
2. candidate lines for human review;
3. unresolved prerequisites and risks;
4. syntax-validation evidence;
5. device runtime state and deployability.

### 4.1 Document fields

| Field | Type | Meaning |
| --- | --- | --- |
| `render_schema_version` | `1` | B2 contract version |
| `contract_id` | string | `cis-02b2-cisco-l2-cli-candidate-v1` |
| `source` | object | revision/intent/preview identity and fingerprints |
| `assignment_id` | UUID | one Assignment only |
| `device` | object | hostname, family, exact PID, release, license, Stack identity/members |
| `render_state` | enum | `blocked`, `no-supported-candidates`, `review-candidates` |
| `candidates` | array | candidate or blocked objects |
| `unresolved_prerequisites` | array | deduplicated prerequisites |
| `evidence` | array | capability and syntax evidence references |
| `device_runtime_state` | `"unknown-not-read"` | never observed |
| `safety` | object | mandatory invariants from section 2 |
| `render_fingerprint` | SHA-256 | canonical document without this field |

`render_state` is not a deployment status. Even `review-candidates` remains
`executable=false`, `deployable=false`, `deployment_allowed=false`.

### 4.2 Candidate object

| Field | Type | Meaning |
| --- | --- | --- |
| `candidate_id` | string | deterministic `cand-` hash |
| `assignment_id` | UUID | owning Assignment |
| `target` | object | device / VLAN / interface / Port-Channel stable ID and name |
| `category` | enum | one of the B2 command categories |
| `risk_class` | enum | R0–R6 from section 7 |
| `status` | enum | `candidate`, `blocked`, `unsupported` |
| `candidate_text` | string or null | only present for `status="candidate"`; never a full config |
| `parameters` | object | typed, validated parameter values used |
| `provenance` | object | CIS-02B1 `item_id`, `change_id`, transition, planned/baseline sources |
| `capability_evidence` | array | capability ID, verdict, check ID, reason |
| `syntax_evidence` | array | per-release command-evidence IDs and evidence level |
| `syntax_validation` | enum | `not-run`, `dictionary-only`, `parser-verified` |
| `potential_connectivity_impact` | boolean | link/VLAN/aggregate/management risk |
| `requires_field_verification` | boolean | derived from B1 risk and B2 prerequisites |
| `prerequisites` | array | unresolved prerequisites for this candidate |
| `blocking_reasons` | array | deterministic codes when status is blocked/unsupported |
| `candidate_fingerprint` | SHA-256 | canonical candidate without this field |

In CIS-02B2-01 every candidate object is `blocked` with `candidate_text=null`.
The field exists so B2-02 can add text without changing the contract identity.

### 4.3 Empty result

If no category can be rendered, return a valid response with
`render_state="no-supported-candidates"` and deterministic blockers, not an HTTP
error. Only malformed identity/binding requests return `4xx`.

## 5. Platform evidence matrix

### 5.1 Evidence identifiers

All rows come from the existing CIS-01A catalog and Cisco vendor pages already
used by that catalog. No new vendor claim is introduced by this table.

| ID | Evidence scope | Source |
| --- | --- | --- |
| HW-2960 | 2960X chassis, PoE, Stack hardware | [2960-X datasheet](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-2960-x-series-switches/datasheet_c78-728232.html), "Switch models and FlexStack-Plus" |
| HW-3850 | 3850 chassis, PoE, StackWise-480 | [3850 datasheet](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-3850-series-switches/datasheet_c78-720918.html), "Configurations and StackWise-480" |
| HW-9200 | 9200/9200L chassis and StackWise kits | [9200 datasheet](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9200-series-switches/nb-06-cat9200-ser-data-sheet-cte-en.html), "Switch configurations and stacking" |
| HW-9300 | 9300/9300L/9300X chassis and StackWise kits | [9300 datasheet](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html), "Switch configurations and stacking" |
| HW-1000 | C1000 24/48-port models and PoE | [C1000 product overview](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst1000/hardware/installation/24_48_port_hig/b_c1000_24_48_hig/product_overview.html), "24-port and 48-port switch models" |
| REL-2960 | 2960X release identity | [2960-X release notes](https://www.cisco.com/c/dam/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/release_notes/Release_notes_2960x_2960xr_1527E.pdf), "Supported Hardware; Software Images; New Software Features" |
| REL-3850 | 3850 release identity | [3850 release notes](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3850/software/release/16-12/release_notes/ol-16-12-3850.html), "Supported Hardware; What's New" |
| REL-9200 | 9200 release identity | [9200 software images](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/release_notes/ol-17-12-9200/upgrading_the_switch_software.html), "Software Images" |
| REL-9300 | 9300 release identity | [9300 software images](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/release_notes/ol-17-12-9300/upgrading_the_switch_software.html), "Software Images" |
| REL-1000 | C1000 release identity | [C1000 release notes](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst1000/software/releases/15_2_7_e/release_notes/ol_15_2_7_e_c1000.html), "Supported Hardware; Software Image" |
| IF-2960 | 2960X interface characteristics | [2960X interface chapter](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/configuration_guide/b_1527e_consolidated_2960x_cg/m_int_inter_cg.html) |
| IF-3850 | 3850 interface characteristics | [3850 interface chapter](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3850/software/release/16-12/configuration_guide/int_hw/b_1612_int_and_hw_3850_cg/configuring_interface_characteristics.html) |
| IF-9200 | 9200 interface characteristics | [9200 interface chapter](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/int_hw/b_1712_int_and_hw_9200_cg/configuring_interface_characteristics.html) |
| IF-9300 | 9300 interface characteristics | [9300 interface chapter](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/int_hw/b_1712_int_and_hw_9300_cg/configuring_interface_characteristics.html) |
| IF-1000 | C1000 interface characteristics | [C1000 interface chapter](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst1000/software/releases/15_2_7_e/configuration_guides/int_hw/b_1527e_int_and_hw_c1000_cg/configuring_interface_characteristics.html) |
| L2-2960 | 2960X Layer 2 command reference | [2960X Layer 2 commands](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr/layer_2_commands.html), "channel-group and LAN Lite limits" |
| L2-3850 | 3850 EtherChannels | [3850 Layer 2 guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3850/software/release/16-12/configuration_guide/lyr2/b_1612_lyr2_3850_cg.pdf), "Configuring EtherChannels" |
| L2-9200 | 9200 Layer 2 guide | [9200 Layer 2 guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/lyr2/b_1712_lyr2_9200_cg.pdf) |
| L2-9300 | 9300 Layer 2 guide | [9300 Layer 2 guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/lyr2/b_1712_lyr2_9300_cg.pdf) |
| L2-1000 | C1000 EtherChannels | [C1000 EtherChannels](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst1000/software/releases/15_2_7_e/configuration_guides/lyr2/b_1527e_layer2_c1000_cg/configuring_etherchannels.html), "Layer 2 EtherChannels and LACP modes" |
| ST-2960 | 2960X Stack membership | [2960X stacking guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/configuration_guide/b_1527e_consolidated_2960x_cg/m_stck_cg.html), "Switch Stack Membership" |
| ST-3850 | 3850 Stack management | [3850 Stack guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3850/software/release/16-12/configuration_guide/stck_mgr_ha/b_1612_stck_mgr_ha_3850_cg.pdf), "Managing Switch Stacks" |
| ST-9200 | 9200 Stack management | [9200 Stack guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/ha/b_1712_stck_mgr_ha_9200_cg/managing_switch_stacks.html), "Stack Member Software Compatibility" |
| ST-9300 | 9300 Stack management | [9300 Stack guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/stck_mgr_ha/b_1712_stck_mgr_ha_9300_cg/managing_switch_stacks.html), "Stack Member Software Compatibility" |
| ACC-9200 | 9200 switch-port behavior | [9200 interface chapter](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/int_hw/b_1712_int_and_hw_9200_cg/configuring_interface_characteristics.html), "Switch Ports" |
| ACC-9300 | 9300 switch-port behavior | [9300 interface chapter](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/int_hw/b_1712_int_and_hw_9300_cg/configuring_interface_characteristics.html), "Switch Ports" |

### 5.2 Exact PID / release / license / Stack envelope

| Family | Exact reviewed PIDs | Operating release identity | Reviewed feature releases | Reviewed license scope | Stack limit and identity rule |
| --- | --- | --- | --- | --- | --- |
| Catalyst 2960X | `WS-C2960X-24TS-L`, `WS-C2960X-24PS-L`, `WS-C2960X-24TS-LL` | IOS `15.2(7)E`, `15.2(7)E7`, `15.2(7)E1a` | `15.2(7)E`, `15.2(7)E7`; `15.2(7)E1a` identity only | LAN Base for 24TS-L/24PS-L; LAN Lite for 24TS-LL | 8 for LAN Base with FlexStack-Plus; 0 for LAN Lite; every member exact PID and ready |
| Catalyst 3850 | `WS-C3850-24T`, `WS-C3850-24P`, `WS-C3850-24T-L`, `WS-C3850-24P-S` | IOS XE `16.12.12`, `16.12.10a` | `16.12.12`; `16.12.10a` aggregation rows only | LAN Base, IP Base, IP Services | 9 with StackWise-480; matching feature sets; uplink module evidence unknown |
| Catalyst 9200 / 9200L | `C9200-24T`, `C9200-24P`, `C9200L-24T-4G`, `C9200L-24T-4G-E`, `C9200L-24P-4X`, `C9200L-24P-4X-A` | IOS XE `17.12.4`, `17.12.5` | `17.12.4`; `17.12.5` identity only | Network Essentials, Network Advantage | 8 with model-appropriate StackWise kit and matching license; modular C9200 module evidence required |
| Catalyst 9300 / 9300L / 9300X | `C9300-24T`, `C9300-24P`, `C9300L-24T-4G`, `C9300L-24T-4G-E`, `C9300L-24P-4X`, `C9300L-24P-4X-E`, `C9300X-24Y`, `C9300X-24Y-A` | IOS XE `17.12.4`, `17.12.5` | `17.12.4`; `17.12.5` identity only | Network Essentials, Network Advantage | 8 with model-appropriate StackWise hardware and matching license; modular uplink module evidence required |
| Catalyst 1000 | `C1000-24T-4G-L`, `C1000-24P-4G-L` | IOS `15.2(7)E1` | `15.2(7)E1` | Stock image; explicit License claims remain UNKNOWN | No reviewed Stack; Single IP Management needs separate layout evidence |

Rules that follow from this table:

- The license suffix in a PID is never evidence. The active software license must
  match the reviewed profile.
- `17.12.5`, `15.2(7)E1a` and bare `15.2(7)E` on C1000 are **identity-only** and
  must not render.
- `16.12.10a` on 3850 may use aggregation rows only; other categories stay
  blocked.
- Uplink modules, optics, PoE budget, Stack kits and mixed-member images remain
  field unknowns even when the chassis row is documented.

### 5.3 Layer 2 feature-evidence matrix

Legend:

- `FEAT-S` — CIS-01A feature evidence supported for the listed release/license.
- `FEAT-U` — no CIS-01A feature row for that family; UNKNOWN, fail closed.
- `HW-S` — hardware/interface evidence only; not a software command claim.
- `SYN-P` — command-level evidence is not established in CIS-02B2-01 for any
  cell. B2-02 must add per-release command evidence before text is rendered.

| Category | 2960X | 3850 | 9200/9200L | 9300/9300L | C1000 |
| --- | --- | --- | --- | --- | --- |
| VLAN definition | FEAT-U / SYN-P | FEAT-U / SYN-P | FEAT-S (L2-9200) / SYN-P | FEAT-S (L2-9300) / SYN-P | FEAT-U / SYN-P |
| Access VLAN | FEAT-U / SYN-P | FEAT-U / SYN-P | FEAT-S (ACC-9200) / SYN-P | FEAT-S (ACC-9300) / SYN-P | FEAT-U / SYN-P |
| Trunk mode | FEAT-U / SYN-P | FEAT-U / SYN-P | FEAT-S (L2-9200) / SYN-P | FEAT-S (L2-9300) / SYN-P | FEAT-U / SYN-P |
| Native VLAN | FEAT-U / SYN-P | FEAT-U / SYN-P | FEAT-S (L2-9200) / SYN-P | FEAT-S (L2-9300) / SYN-P | FEAT-U / SYN-P |
| Allowed VLAN | FEAT-U / SYN-P | FEAT-U / SYN-P | FEAT-S (L2-9200) / SYN-P | FEAT-S (L2-9300) / SYN-P | FEAT-U / SYN-P |
| Port-Channel | FEAT-S (L2-2960) / SYN-P | FEAT-S (L2-3850) / SYN-P | FEAT-S (L2-9200) / SYN-P | FEAT-S (L2-9300) / SYN-P | FEAT-S (L2-1000) / SYN-P |
| LACP mode | FEAT-S (L2-2960) / SYN-P | FEAT-S (L2-3850) / SYN-P | FEAT-S (L2-9200) / SYN-P | FEAT-S (L2-9300) / SYN-P | FEAT-S (L2-1000) / SYN-P |
| Rapid PVST+ | FEAT-U / SYN-P | FEAT-U / SYN-P | FEAT-S (L2-9200) / SYN-P | FEAT-S (L2-9300) / SYN-P | FEAT-U / SYN-P |
| VTP transparent | FEAT-U / SYN-P | FEAT-U / SYN-P | FEAT-S (L2-9200) / SYN-P | FEAT-S (L2-9300) / SYN-P | FEAT-U / SYN-P |
| Root priority | FEAT-U / SYN-P | FEAT-U / SYN-P | FEAT-S via Rapid PVST+ / SYN-P | FEAT-S via Rapid PVST+ / SYN-P | FEAT-U / SYN-P |
| PortFast | FEAT-U / SYN-P | FEAT-U / SYN-P | FEAT-S (L2-9200) / SYN-P | FEAT-S (L2-9300) / SYN-P | FEAT-U / SYN-P |
| BPDU Guard | FEAT-U / SYN-P | FEAT-U / SYN-P | FEAT-S (L2-9200) / SYN-P | FEAT-S (L2-9300) / SYN-P | FEAT-U / SYN-P |
| PoE mode | HW-S on 24PS-L / SYN-P | HW-S on 24P / SYN-P | HW-S on P/PoE+ PIDs / SYN-P | HW-S on P/PoE+ PIDs / SYN-P | HW-S on 24P / SYN-P |
| Speed | FEAT-S (IF-2960) / SYN-P | FEAT-S (IF-3850) / SYN-P | FEAT-S (IF-9200) / SYN-P | FEAT-S (IF-9300) / SYN-P | FEAT-S (IF-1000) / SYN-P |
| Duplex | FEAT-S (IF-2960) / SYN-P | FEAT-S (IF-3850) / SYN-P | FEAT-S (IF-9200) / SYN-P | FEAT-S (IF-9300) / SYN-P | FEAT-S (IF-1000) / SYN-P |
| Description | HW-S / SYN-P | HW-S / SYN-P | HW-S / SYN-P | HW-S / SYN-P | HW-S / SYN-P |
| Admin shutdown | HW-S / SYN-P | HW-S / SYN-P | HW-S / SYN-P | HW-S / SYN-P | HW-S / SYN-P |
| Unused-port shutdown | HW-S + policy / SYN-P | HW-S + policy / SYN-P | HW-S + policy / SYN-P | HW-S + policy / SYN-P | HW-S + policy / SYN-P |

Current consequence: **no category can legitimately render a candidate in
CIS-02B2-01**, because command-level evidence is `SYN-P` everywhere and several
families lack feature evidence. This is intentional fail-closed behavior, not a
missing feature of this document.

### 5.4 Evidence gaps that B2-02 must close before rendering

| Gap | Current state | Required before render |
| --- | --- | --- |
| 2960X / 3850 / C1000 VLAN, access, trunk, STP, VTP feature evidence | Not in `FEATURES`; CIS-01A returns UNKNOWN | Add reviewed CIS-01A feature rows for the exact PID/release/license, or keep those categories BLOCKED |
| Command-level grammar for every category and release | Not established (`SYN-P`) | Add per-release command-evidence rows with vendor section, extracted grammar, license/release scope and reviewer |
| PoE command behavior vs hardware rating | Hardware PoE rating only | Separate command evidence plus power-budget prerequisites; otherwise BLOCKED |
| Description/shutdown command behavior | No feature evidence row | Add reviewed command evidence per family/release, or keep BLOCKED |
| Root-priority command evidence | Derived from Rapid PVST+ feature row only | Add exact per-release command evidence; otherwise BLOCKED |
| 17.12.5 / 15.2(7)E1a / 3850 16.12.10a non-interface categories | Identity-only or limited scope | Do not render; keep UNKNOWN |
| Stack mixed members, modules, optics, PoE budget | Field unknown | Block affected categories; require field prerequisites |

CIS-02B2 may not silently broaden these. Extending CIS-01A evidence is a separate
reviewed change and must not modify the frozen CIS-02A/B1 contracts.

## 6. Command categories and CIS-02A/B1 traceability

| B2 category | CIS-02A item/category | Governing capability | B1 source |
| --- | --- | --- | --- |
| `vlan-definition` | VLAN definition | VLAN | `item.category="vlan"`, field `definition` |
| `access-vlan` | Access VLAN | ACCESS | `access_vlan` |
| `trunk-mode` | Trunk mode | TRUNK | `mode` for trunk |
| `native-vlan` | Native VLAN | TRUNK | `native_vlan` |
| `allowed-vlans` | Allowed VLAN list | TRUNK | `allowed_vlans` |
| `port-channel` | Port-Channel | PORT_CHANNEL | `number`, `member_ids` |
| `lacp-mode` | LACP mode | LACP | `lacp` |
| `rapid-pvst` | STP mode | RAPID_PVST | `spanning-tree-mode` |
| `vtp-transparent` | VTP mode | VTP_TRANSPARENT | `vtp-mode` |
| `root-priority` | Root priority | RAPID_PVST | `root-priority` |
| `portfast` | PortFast | PORTFAST | `portfast` |
| `bpdu-guard` | BPDU Guard | BPDU_GUARD | `bpdu_guard` |
| `poe-mode` | PoE mode | POE | `poe_mode` |
| `speed` / `duplex` | Speed/Duplex | SPEED / DUPLEX | `speed`, `duplex` |
| `description` | Description | PORT_MEDIA (hardware only) | `description` |
| `admin-shutdown` | Admin state | PORT_MEDIA (hardware only) | `admin_state`, `shutdown_intent` |
| `unused-shutdown` | Unused-port policy | PORT_MEDIA + policy | `shutdown_intent` with policy source |

Each candidate retains B1 `item_id`, `change_id`, transition and source. B2 adds
renderer traceability; it does not reinterpret the B1 item.

## 7. Risk and transition model

### 7.1 Risk classes

| Class | Meaning | Examples |
| --- | --- | --- |
| R0 | Planned value only | VLAN name, description, global STP mode/VTP mode, root priority value |
| R1 | Interface state/power | admin shutdown, unused-port shutdown, PoE mode, speed/duplex |
| R2 | VLAN/trunk connectivity | access VLAN, trunk mode, native VLAN, allowed VLAN, STP edge/BPDU Guard |
| R3 | Aggregate topology | Port-Channel add/remove, LACP mode, member add/remove/migrate |
| R4 | Cleanup/removal | old access/native/allowed fields, member detach, VLAN definition delete, Port-Channel removal |
| R5 | Management/uplink risk | native VLAN change, trunk-to-access, VLAN delete, shutdown of a management/uplink port with unverified topology |
| R6 | Prohibited | reload, erase/format/factory reset, boot/image/license changes, AAA/SSH credentials, Stack renumbering, bulk VLAN wipe, any L3 or device-management command |

A candidate inherits the highest applicable class. R5 requires an explicit
human-review prerequisite even when the syntax is documented. R6 operations are
never rendered and return `unsupported`/`blocked` with `dangerous-operation-denied`.

### 7.2 Transition handling

| Transition | Risk | Required handling |
| --- | --- | --- |
| Access → Trunk | R2 + R4 | include explicit old-access cleanup intent; block if management/uplink role unverified |
| Trunk → Access | R2 + R4 + R5 | include native/allowed cleanup intent; block if management/uplink role unverified |
| Independent → Port-Channel | R3 | channel identity + member target; no implicit execution order |
| Port-Channel → Independent | R3 + R4 | member detach cleanup; source channel evidence |
| Channel-to-Channel migration | R3 + R4 | resolve source/destination by stable IDs; never by interface name |
| Native VLAN change | R2 + R5 | explicit management/uplink risk; no default assumption |
| Allowed VLAN change | R2 | native VLAN unaffected unless separately planned |
| VLAN definition delete | R4 + R5 | requires no current references, field confirmation and explicit human review; no baseline-driven destructive command |
| Unused-port shutdown | R1 | policy-derived shutdown requires field verification; not proof the port is unused |
| Stack member missing/unresolved | Block | no chassis-specific candidate at all |
| Management/uplink affected | R5 / Block | require topology evidence; otherwise block |

CIS-02A dependencies are association metadata only. The renderer may use them to
group or label candidates, but must not expose them as a verified execution
order. No `order`, `sequence` or `execution_plan` field may be produced.

### 7.3 Baseline and cleanup boundary

CIS-02B1 baseline is a planning baseline, not a running-config. Therefore:

- cleanup candidates are marked `cleanup-requires-field-verification`;
- no candidate may assume an old value exists on a real device;
- no VLAN wipe, interface default, channel clear or destructive cleanup is
  rendered from baseline-only evidence;
- `vlan-unreferenced`/`vlan-removed` items produce no automatic delete candidate.

## 8. Input validation and injection defense

All user-editable text is untrusted even though it passed EventPlan validation.
The renderer revalidates before rendering.

| Input | Rule |
| --- | --- |
| VLAN ID | integer 1–4094, not a string rendered as text |
| VLAN name | 1–80 chars; after plan trim, ASCII letters/digits plus internal space, `.`, `_`, `-`; must start/end alphanumeric; no double space, quotes, backslash, control, newline or tab |
| Description | 0–240 printable ASCII; reject control, CR/LF/TAB, `"` and `\`; one line; no leading/trailing whitespace |
| Port/Port-Channel names | typed B1 values only; no client-supplied names |
| Speed/Duplex | enum from the plan; no free text |
| Category/assignment IDs | typed UUID/enum; no free-form command |
| Any command text | client-supplied command text is never accepted |

Rendering is atomic: a text failure blocks that candidate/category; it never
emits a partially escaped line. A user text value is never concatenated into
multiple lines, never used as a command name, never used as a template override
and never interpreted as a second command.

Injection test corpus must include CR/LF, NUL, ESC, tabs, quotes, backslashes,
Unicode, overlong strings, semicolons, comment markers, leading/trailing spaces
and mixed-case control sequences. Expected result: zero candidate lines and a
deterministic `unsafe-text:<field>:<target>` blocker.

## 9. Independent validation model

Renderer output must not be validated by reusing the renderer's own rules.

| Level | What it is | What it can prove | What it cannot prove |
| --- | --- | --- | --- |
| L0 | Vendor documentation and CIS-01A feature rows | Documented feature/license/release scope | Exact grammar, device acceptance, current state |
| L1 | Version-scoped command dictionary/grammar | Candidate conforms to documented token grammar | Device will accept or behave correctly |
| L2 | Independent parser (B2-03) | Candidate parses under an independently authored grammar | Device state or runtime behavior |
| L3 | Emulator | Model/config behavior in a simulator | Real hardware or optics/PoE/Stack state |
| L4 | Real device | Actual device acceptance and behavior | — (out of scope; NOT VERIFIED) |

Rules:

- B2-03 grammar and parser must be separately authored; they may consume reviewed
  evidence data, but must not import renderer templates or validation helpers as
  their oracle.
- Parser success sets `syntax_validation="parser-verified"`, not
  `hardware_verified`; hardware stays `false`.
- Emulator success cannot mark hardware or deployment readiness.
- No self-generated golden output may be the only expected result.
- B2-03 must include differential/adversarial tests and a candidate corpus that
  is at least partly hand-authored.

### 9.1 Per-family validation method

Each family is validated independently; evidence is never inherited from a
same-family PID or another Catalyst family.

| Family | Evidence anchors | B2 validation path | Hard block |
| --- | --- | --- | --- |
| Catalyst 2960X | HW-2960, REL-2960, IF-2960, L2-2960, ST-2960 | IOS `15.2(7)E`/`15.2(7)E7`; LAN Base/LAN Lite; aggregation and speed/duplex dictionary rows; L1 dictionary + L2 parser; Stack only with FlexStack-Plus layout | `15.2(7)E1a` (identity only), LAN Lite Stack, VLAN/access/trunk/STP/VTP until feature+command evidence |
| Catalyst 3850 | HW-3850, REL-3850, IF-3850, L2-3850, ST-3850 | IOS XE `16.12.12`; `16.12.10a` aggregation-only; EtherChannel/Stack/interface dictionary rows; L1 + L2 | `16.12.10a` non-aggregation categories, modular uplink without module evidence, non-aggregation categories until evidence |
| Catalyst 9200 / 9200L | HW-9200, REL-9200, IF-9200, L2-9200, ST-9200, ACC-9200 | IOS XE `17.12.4`; VLAN/access/trunk/STP/VTP/PortFast/BPDU Guard/EtherChannel dictionary rows; L1 + L2 | `17.12.5` (identity only), C9200 modular module unknown, PoE mode/description/shutdown until command evidence |
| Catalyst 9300 / 9300L / 9300X | HW-9300, REL-9300, IF-9300, L2-9300, ST-9300, ACC-9300 | IOS XE `17.12.4`; same dictionary scope as 9200 plus modular/SFP28 per-PID layout; L1 + L2 | `17.12.5` (identity only), uplink module/optics unknown, PoE mode/description/shutdown until command evidence |
| Catalyst 1000 | HW-1000, REL-1000, IF-1000, L2-1000 | IOS `15.2(7)E1`; EtherChannel and interface dictionary rows; L1 + L2; no Stack | Bare `15.2(7)E`, Stack claims, VLAN/access/trunk/STP/VTP until feature+command evidence |

Configuration order, cleanup operations and dangerous-command treatment require a
separate independent review in B2-03, in addition to syntax parsing. B2-02 may
group candidates by target for display, but must not assert a verified execution
order.

## 10. Determinism, fingerprint and compatibility

- `render_fingerprint` = SHA-256 of the canonical document without itself.
- `candidate_fingerprint` = SHA-256 of the canonical candidate without itself.
- Candidate IDs hash Assignment UUID, category, stable target ID and field.
- Repeated rendering of the same revision and contract version is byte-identical.
- Inputs bind revision UUID/number/hash, intent schema/fingerprint, preview
  schema/contract/fingerprint and Assignment UUID.
- Renderer is additive: it does not modify the saved revision, CIS-02A intent or
  CIS-02B1 preview. `cli` stays `null`; B1 `preview_fingerprint` is not replaced.
- A semantic correction may change recomputed render fingerprints; the contract
  must state this rather than promise cross-version fingerprint equality.
- Version changes (`intent_schema_version`, `preview_schema_version`,
  `render_schema_version`, `contract_id`) require a new compatibility review.

## 11. Test plan

### 11.1 B2-01 contract tests (this stage)

- Evidence matrix rows map only to existing catalog entries and vendor sections.
- Every `FEAT-S` row names its PID/release/license/Stack scope.
- Every `FEAT-U`/`SYN-P` row is explicitly blocked, never guessed.
- No renderer, endpoint, command text, device connection or deployment field is
  added.
- The document contains no paste-ready command sequence.
- Independent review confirms the safety model and phase gates.

### 11.2 B2-02 renderer tests (future)

- Five-family matrix: only documented combinations render; all others blocked.
- Exact PID, release, license and Stack negatives.
- UNKNOWN/UNSUPPORTED capability fail closed; no candidate text.
- Stack missing/unresolved member fails closed.
- Access↔trunk, independent↔Port-Channel, channel migration, native/allowed
  changes, VLAN delete, shutdown and PoE risk classification.
- Baseline cleanup never becomes destructive.
- Injection corpus yields zero candidate lines.
- Input fingerprint/identity mismatches rejected; client preview never trusted.
- Determinism, cross-device isolation, stable IDs and fingerprints.
- No network/device imports, no full config, no deployment artifact.
- Existing CIS-02A/B1 regression suites remain unchanged and passing.

### 11.3 B2-03 independent validation tests (future)

- Independent parser accepts every rendered candidate for documented combos.
- Parser rejects malformed/adversarial corpus.
- Renderer/parser differential cases and hand-authored goldens.
- Denylist proves R6 operations never appear.
- No renderer-rule reuse; no hardware/emulator PASS promotion.
- Security review of text handling, escaping, logging, redaction and route surface.

## 12. Phased PR plan

### B2-01 — contract and safety design (this PR)

- **Input**: merged CIS-02A/B1 contracts and evidence catalog.
- **Output**: this contract, evidence matrix, risk model, schema design, test plan,
  phase gates.
- **Allowed files**: `docs/cis-02b2-cisco-l2-cli-candidate-contract.md`; Issue #4
  handoff comment. No code, no tests, no API.
- **Forbidden**: renderer, candidate text, endpoint, device path, B1/A changes,
  CLI renderer, deployment feature.
- **Gate**: independent review; PASS only if evidence gaps and fail-closed matrix
  are explicit.
- **Stop**: any need to claim unsupported syntax, modify B1/A, or add renderer
  code to finish the contract.

### B2-02 — offline renderer implementation

- **Input**: approved B2-01 contract; immutable revision/preview; new reviewed
  command-evidence rows.
- **Output**: typed candidate documents with blocked/candidate states; no full
  config, no execution.
- **Allowed files**: new renderer module, command-evidence data/catalog additions,
  tests, docs. Additive only.
- **Forbidden**: changing CIS-02A intent or CIS-02B1 preview output semantics,
  existing `cli=null`, device writes/Console/SSH, deployment state, network
  clients, full configuration/script export.
- **Gate**: full Windows/Linux pytest/ruff/mypy/Vitest/Playwright/Gitleaks;
  fail-closed matrix; injection corpus; deterministic fingerprint; independent
  review. Hardware remains SKIP.
- **Stop**: missing/ambiguous command evidence, any UNKNOWN renders text, any
  injection passes, any schema break, any device path, or any new P0/P1/P2.

### B2-03 — independent syntax and security validation

- **Input**: B2-02 candidates and separately authored grammar/dictionary.
- **Output**: independent validation report and tests; still no deployment.
- **Allowed files**: independent parser/grammar module and adversarial tests;
  docs/evidence updates.
- **Forbidden**: importing renderer templates as validation oracle, hardware
  claims, deployment/renderer execution path.
- **Gate**: parser and adversarial suites pass; security review; hardware remains
  NOT VERIFIED; independent review.
- **Stop**: shared renderer/parser oracle, any hardware PASS claim, any candidate
  promoted to executable/deployable, any unresolved P0/P1.

Each phase requires independent review and explicit merge authorization. No stage
auto-starts the next.

## 13. Acceptance status of this design stage

| Item | Status |
| --- | --- |
| Contract, input/output schema design, risk model | PASS (design draft) |
| Exact PID/release/license/Stack matrix | PASS for current CIS-01A evidence |
| Command-syntax evidence matrix | BLOCKED — all `SYN-P`; no candidate text authorized |
| Five-family validation method | PASS (L0–L4 model defined) |
| B2-01/B2-02/B2-03 phase plan | PASS (design) |
| Renderer implementation | BLOCKED / NOT STARTED |
| Independent review | PENDING (separate gate) |
| Hardware verification | SKIP / NOT VERIFIED |
| Device writes / Console / SSH / Hillstone / Kea / CIS-03 | BLOCKED |

## 14. Open risks for reviewers

1. Current CIS-01A evidence covers Layer 2 feature rows only for 9200/9300;
   2960X/3850/C1000 require reviewed evidence expansion before those categories
   can render.
2. Command-level grammar is not established for any category; B2-02 must add it
   per exact release and obtain independent review before generating text.
3. Description/shutdown/PoE mode have no command evidence row and must remain
   blocked until added.
4. Native VLAN, trunk-to-access, VLAN deletion, Port-Channel migration and
   management/uplink changes require an explicit R5 review path; topology role
   evidence may be incomplete.
5. Stack/module/optic/PoE-budget states remain field unknowns and may block
   otherwise documented commands.
6. Fingerprint values can change after semantic corrections; consumers must bind
   to the contract version, not assume cross-version equality.
