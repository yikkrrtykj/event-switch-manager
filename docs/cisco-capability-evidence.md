# CIS-01A Cisco capability evidence

The read-only resolver scopes a capability to an immutable EventPlan revision, Device
Assignment, exact PhysicalDevice PID, software release and active license or feature set.
Physical port and Stack member IDs select the chassis that owns an interface. The resolver
disregards imported capability claims as evidence. Its results never certify a device.

| Response | Meaning |
| --- | --- |
| `supported` | Cisco documentation applies to the requested capability and profile. |
| `unsupported` | The requested ability is excluded by applicable documentation or a documented hardware limit. |
| `unknown` | Required context, applicable evidence, or an operational prerequisite is missing. |
| `verification: not-verified` | The physical device and site configuration have yet to be verified. |
| `deployment_status: blocked` | Deployment-grade generation is unavailable for every result in CIS-01A. |

Network planning, editing and revision saves continue under the existing schema and validation.
The endpoint can read documentary findings from historical revisions. The blockers capture
missing and negative evidence, invalid revisions, missing hardware verification, and the
disabled rollout. A warning or documented capability cannot authorize deployment.

## Hardware and software envelopes

The exact PID keys and version/edition scopes live in the
[machine-readable catalog](../apps/api/src/event_switch_manager/cisco_catalog.py).
Only specific orderable variants and chassis PIDs are accepted. The license suffix on a
PID never determines the active license. Hardware-only facts such as fixed port counts
can be queried before the release is known. An out-of-scope version or tier makes
release-dependent support UNKNOWN.

| Exact chassis PIDs | Software/feature set scope | Physical port and Stack evidence |
| --- | --- | --- |
| WS-C2960X-24TS-L, WS-C2960X-24PS-L, WS-C2960X-24TS-LL | IOS 15.2(7)Ex; LAN Base for the first two, LAN Lite for 24TS-LL | 24 copper ports rated at 10/100/1000, with PoE+ on 24PS-L. 4/4/2 SFP cages respectively. Slot 0 numbering continues after the copper ports. LAN Base homogeneous Stack max 8 with FlexStack-Plus hardware. LAN Lite has no FlexStack-Plus. [Cisco switch configuration and stacking](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-2960-x-series-switches/datasheet_c78-728232.html) |
| WS-C3850-24T, WS-C3850-24P | IOS XE 16.12.x; LAN Base, IP Base, IP Services | 24 copper ports rated at 10/100/1000, with PoE+ on 24P. Installed uplink module and complete layout are UNKNOWN. StackWise-480 max 9, matching active feature sets. [Cisco model and feature-set tables](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-3850-series-switches/datasheet_c78-720918.html) |
| C9200-24T, C9200-24P, C9200L-24T-4G, C9200L-24P-4X | IOS XE 17.12.x; Network Essentials, Network Advantage | 24 copper ports rated at 10/100/1000, with PoE+ on P. Fixed 4G has four SFP cages and fixed 4X four SFP+ cages. Installed module on modular C9200 remains UNKNOWN. Max 8. C9200 and C9200L require their respective 160 or 80 StackWise kits and matching license levels. [Cisco model, stacking and license tables](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9200-series-switches/nb-06-cat9200-ser-data-sheet-cte-en.html) |
| C9300-24T, C9300-24P, C9300L-24T-4G, C9300L-24P-4X, C9300X-24Y | IOS XE 17.12.x; Network Essentials, Network Advantage | T/P chassis have 24 copper ports rated at 10/100/1000 with PoE+ on P. Fixed 4G and 4X have four SFP or four SFP+ cages respectively. C9300X-24Y has 24 fixed SFP28 downlinks rated for 1/10/25G. Modular uplinks require installed module evidence. Max 8 with model-appropriate StackWise hardware and matching active license. [Cisco models and stacking](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html) · [17.12 model/license table](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/release_notes/ol-17-12-9300/introduction.html) |
| C1000-24T-4G-L, C1000-24P-4G-L | IOS 15.2(7)Ex; stock image, explicit license claims stay UNKNOWN | 24 copper ports rated at 10/100/1000 plus four 1G SFP cages. P adds PoE+. Slot 0 numbering continues after copper. Single IP Management requires separate layout evidence. [Cisco 24/48-port product overview](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst1000/hardware/installation/24_48_port_hig/b_c1000_24_48_hig/product_overview.html) |

Interface characteristics chapters give slot, index, prefix and copper speed/duplex
constraints. Copper at 1 Gbps excludes half duplex. Optical rates describe the cage;
configured speed and duplex stay UNKNOWN without the actual optic. Rates above the
physical limit are UNSUPPORTED. Port PoE+ does not establish delivered power, compatible
power supplies, available budget or mode-specific CLI behavior. Scope excludes mixed
Stack certification and actual member image/feature tiers, wiring, kits and failover.

## Feature matrix

These are scoped documentary findings. Everything outside the listed combinations is
UNKNOWN. All device-level verification is NOT VERIFIED.

| Capability | Reviewed scope and evidence | Remaining gaps |
| --- | --- | --- |
| VLAN, Access, Trunk | C9200 and C9300 profiles, interface characteristics and Layer 2 VLAN/trunk chapters. | Older platform feature-set and interface restrictions. |
| Port-Channel and LACP | The catalog records the EtherChannels chapter or Layer 2 command reference for each of the five families in the reviewed trains. | Group limits, actual member line rates, neighbors and cross-Stack behavior. |
| Rapid PVST+, PortFast, BPDU Guard, VTP Transparent | Selected C9200/C9300 rows in the STP, optional STP features and VTP chapters. [C9200 Layer 2](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/lyr2/b_1712_lyr2_9200_cg.html) · [C9300 Layer 2](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/lyr2/b_1712_lyr2_9300_cg.pdf) | Endpoint role, edge/trunk variants, other PIDs and releases. |
| SVI, IPv4 routing, Routed Port, Static and Default Route | Selected C9300 rows. C9200 rows cover SVI, Routed Port, IPv4 routing and Static Route. [C9300 IPv4 unicast routing](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/rtng/b_1712_rtng_9300_cg/configuring_ip_unicast_routing.html) | Per-platform capacity and SDM mode. Other profile rows remain UNKNOWN. |
| DHCP Server, Relay and Client | C9300 IOS XE 17.12.x within the reviewed Network Advantage envelope. [Cisco IP Addressing Services](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/ip/b_1712_ip_9300_cg.pdf) | Essentials and other profiles, relay placement and actual DORA require separate evidence. The envelope does not assert exclusion on other tiers. |
| SSHv2 and AAA | The C9300 Security Guide provides SSHv2 prerequisites and AAA evidence. [Cisco Security Guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/sec/b_1712_sec_9300_cg.pdf) | SSHv2 remains UNKNOWN until image and keys are observed. AAA policy and recovery are unverified. |
| Boot and storage | C9300 System Management and release notes document boot mode and image/flash requirements. [Cisco System Management](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/sys_mgmt/b_1712_sys_mgmt_9300_cg.pdf) | Actual mode, boot variables, provisioned files, available storage and recovery remain UNKNOWN. |

## WEB-02 read contract

`GET /api/v1/events/{event_id}/plan-revisions/{revision_id}/assignments/{assignment_id}/cisco-capability`

Set `capability` to an enum value. Select `interface_id` for physical port options or
`stack_member` for a member lookup. Optional `speed` (Mbps or `auto`) and `duplex`
(`auto`, `full`, `half`) let the editor query alternate settings. Without them the resolver
reads the saved interface settings. The result contains the revision UUID and SHA-256,
target IDs, documented port groups, reason code, verdict, and applicable source URL,
locator, version scope, licenses and conditions. Unrelated revision, assignment or
interface queries return 404. If a member is ambiguous, the verdict is UNKNOWN.

WEB-02 may show documented support, limits and independent device-verification status.
UNKNOWN remains editable as planning intent. The read path leaves the revision UUID,
canonical JSON, SHA-256 and ETag intact. The UI integration is tracked at #5.

The Foundation CI runs the synthetic capability cases and existing regressions on Windows
and Linux. Hardware and Console discovery stay SKIP / NOT VERIFIED. Device writes and
deployment generation remain BLOCKED.
