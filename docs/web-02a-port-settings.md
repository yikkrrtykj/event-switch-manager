# WEB-02A port settings

A v1 plan stores intent on physical ports and logical Port-Channels under
`settings`. The mode, VLANs, address and Port-Channel `lacp` retain their
existing locations. The new fields are optional.

| Field | Explicit intent | Scope |
| --- | --- | --- |
| `description` | Single-line text of up to 240 characters. An empty string clears the description. | Physical or aggregate |
| `admin_state` | `up` or `down` for planned administrative state | Physical or aggregate |
| `speed` | `auto` or a fixed integer in Mbps. The schema enumerates common Ethernet rates from 10 to 800000 Mbps. | Physical |
| `duplex` | `auto`, `full` or `half` | Physical |
| `poe_mode` | `auto`, `static` or `never` | Physical |
| `portfast` | `edge` for access, `edge-trunk` for trunk or `disabled` | Layer 2 physical or aggregate |
| `bpdu_guard` | `enabled` or `disabled`. Interface-level intent is independent of PortFast. | Layer 2 physical or aggregate |

Missing or null fields mean platform-default intent. Automatic negotiation or power
management is an explicit setting. The plan's existing capability state describes
observations independently of these choices. Port capability marked verified on a general
inventory record still needs evidence for specific speed, media, PoE and spanning-tree
settings. The validator reports such requests as unverified. The future hardware phase can
evaluate exact SKU, port medium, software and license evidence.

## Validation and compatibility

All legacy interface, VLAN, Stack and Port-Channel checks still apply. Physical media
settings and PoE belong to member interfaces. Explicit conflicting fixed speeds or
duplexes within an aggregate produce errors. Fixed members mixed with automatic or default
members produce warnings. Where spanning-tree intent is specified in more than one place
in a group, explicit settings must agree. Descriptions, member administrative state and
PoE intent remain local to their respective interfaces.

Explicit spanning-tree settings require Layer 2 mode. Half duplex with a fixed speed
above 1000 Mbps is rejected. For a 1000 Mbps half-duplex plan, verify the exact port and medium. The references document
specific platform behavior and model differences.
[Catalyst interface guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-17/configuration_guide/int_hw/b_1717_int_and_hw_9300_cg.pdf) ·
[Power over Ethernet](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-13/configuration_guide/int_hw/b_1713_int_and_hw_9300_cg/configuring_poe.html) ·
[Spanning-tree features](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-17/configuration_guide/lyr2/b_1717_lyr2_9300_cg/configuring_optional_spanning_tree_features.html) ·
[EtherChannels](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-14/configuration_guide/lyr2/b_1714_lyr2_9300_cg/configuring_etherchannels.html)

Canonical v1 JSON omits only null values for the seven additions. Explicit settings and
empty descriptions participate in SHA-256. Old exports and immutable revision rows are
returned directly with their original bytes, UUIDs and ETags. The database continues to
store revisions as canonical JSON at Alembic 0002. An older parser can read legacy exports.
An export containing new intent requires an application version that understands these
fields.

## WEB-02B development input

Use the existing revision API and Hallmark v2.0.0 App Screens. In single-port and bulk
editing, represent an untouched field independently of explicit null, an explicit
disabled choice and an explicit empty description. Preview the before/after changes per
confirmed visible target. Keep compatible fields the operator leaves untouched. Surface any
mode transition that requires clearing incompatible settings and confirm that change.
Use the issue field paths to distinguish incompatible settings from unverified hardware.
Keep the current immutable save/export path and active filter protections.
