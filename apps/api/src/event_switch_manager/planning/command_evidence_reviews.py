"""Independent review attestations for the CIS-02B2 L1 command evidence.

Generated from the independent reviewers' digest-bound re-attestation output.
Each record names the reviewer, the review date, the exact ``content_digest``
the reviewer attested, and the concrete page evidence they observed.

A row that does not appear in either table keeps ``PENDING_REVIEW`` and cannot
render command text. A row whose content changed after its attestation no longer
matches its reviewed content digest and also cannot render.
"""

from __future__ import annotations

REVIEWED_RECORDS: dict[str, dict[str, object]] = {
    'l1-catalyst-2960x-lanbase-admin-shutdown-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": 'fbd43b82a1fdc5859a32b6cf204c7040b5a741ae1b1839e08c3e5be3ad6e4f0d',
        "findings": (
        (
            "The cited guide's 'Shutting Down and Restarting the Interface' procedure prints"
            "'shutdown' ('Shuts down an interface.') and 'no shutdown' ('Restarts an"
            "interface.') in interface configuration mode, matching the row's command forms and"
            'command mode.'
        ),
        (
            "Requirement 'admin-state-topology' is correctly a blocking safety gate about"
            'missing field evidence (management/uplink/WAN/aggregate role must be confirmed'
            'from the device) and does not claim any current device state; the page prints'
            'nothing that contradicts the row.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanbase-channel-group-lacp-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": 'a6febf2e649fd2b974b3d6168b038d66680f41fa1a9d17d1b207324b32156910',
        "findings": (
        (
            "The cited page's 'channel-group' section prints the channel-group form with"
            "'active' and 'passive' LACP modes in 'Interface configuration' mode and 'Channel"
            "group number. The range is 1 to 24.', matching the row's LACP grammar, mode and"
            '1-24 range.'
        ),
        (
            "The same cited page prints 'An LACP channel group can have up to 16 Ethernet ports"
            'of the same type. Up to eight ports can be active, and up to eight ports can be in'
            "standby mode.' in its lacp port-priority and lacp system-priority usage"
            "guidelines, matching the row's 16-port eight-active/eight-standby limit."
        ),
        (
            "Requirement 'channel-member-count-limit' is described as a renderer restriction"
            '(never more than eight planned members per channel), not as a vendor claim, and'
            "'channel-membership-consistent' is a plan-consistency gate that claims no current"
            'device state; both are correctly classified blocking gates.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanbase-channel-group-static-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": 'e5b34cdbd268b730be5590a5a77fbfaeb1e70f5752a9ea8275b02b6f0fbd8462',
        "findings": (
        (
            "The cited page's 'channel-group' section prints 'channel-group { auto |"
            'channel-group-number mode {active | auto [non-silent] | desirable [non-silent] |'
            "on | passive}}' in 'Interface configuration' mode with 'Channel group number. The"
            "range is 1 to 24.', matching the row's 'mode on' form, mode and 1-24 range."
        ),
        (
            "The same page prints 'In on mode, a usable EtherChannel exists only when both"
            "connected port groups are in the on mode.' and 'The LAN Base feature set supports"
            "up to 24 EtherChannels', matching the row's static on-mode and LAN Base"
            '24-EtherChannel limits.'
        ),
        (
            "Requirement 'channel-member-count-limit' is classified safety and is described as"
            "a renderer restriction ('the renderer refuses more than eight planned members per"
            "channel'), not as a vendor claim; 'channel-membership-consistent' is a blocking"
            'platform gate about planned membership that claims no current device state.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanbase-description-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": 'e49cc360131167f5c5527015f756c894eb747e6d16df95a96ba43a57c186f336',
        "findings": (
        (
            "The cited guide's 'Adding a Description for an Interface' procedure prints"
            "'description string' in interface configuration mode and says it 'Adds a"
            "description (up to 240 characters) for an interface', matching the row's grammar,"
            'mode and 240-character maximum.'
        ),
        (
            "The row's requirements list is correctly empty: the cited page prints no platform"
            'or safety precondition for the description command, so no gate is asserted.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanbase-duplex-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": 'e7a463bd7da0554927e101e0cb273c3d20941e83e9a2a7b726245a0125b6414e',
        "findings": (
        (
            "The cited page's 'duplex' section prints 'duplex {auto | full | half}' in"
            "'Interface configuration' mode, states half duplex is 'only for interfaces"
            "operating at 10 or 100 Mb/s', and that 'Duplex options are not supported on the"
            "1000BASE-x or 10GBASE-x ... SFP modules', matching all three row limits."
        ),
        (
            "Requirement 'copper-port-required' is a blocking platform gate and"
            "'optic-field-note' is a non-blocking field-note; both are correctly classified and"
            'neither claims a vendor limit or current device state.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanbase-poe-mode-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": '74595f697046afa997b5904826648df99e2805eddc8e36db172dcb69b4b2db63',
        "findings": (
        (
            "The cited page's 'power inline' section prints 'power inline {auto [max"
            "max-wattage] | never | port priority {high | low} | static [max max-wattage]}' in"
            "interface configuration mode, documents 'static' as pre-allocating power, and"
            "states 'max max-wattage ... The range is 4000 to 30000 mW', matching the row's"
            'modes and wattage limit.'
        ),
        (
            "The page states 'This command is supported only on PoE-capable ports', and the"
            "'LAN Base image' wording appears on the same page for the adjacent power inline"
            "consumption/police commands, consistent with the row's LAN Base scope note;"
            'nothing on the page contradicts it.'
        ),
        (
            "Requirements are correctly classified: 'poe-capable-port' (platform) matches the"
            "printed PoE-capable-port restriction, 'poe-static-budget' (safety) restates the"
            "printed pre-allocation plus required budget evidence, and 'poe-budget-field-note'"
            'is a non-blocking field-note.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanbase-port-channel-interface-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": 'dbeebf6ecb9e3f276bb39e3ae6306db5c6707f7bcd35e805d1e26e165c73b012',
        "findings": (
        (
            "The cited page's 'interface port-channel' section prints 'interface port-channel"
            "port-channel-number' in 'Global configuration' mode and 'port-channel-number ..."
            "The range is 1 to 24', matching the row's grammar, command_mode=global and 1-24"
            'parameter rule.'
        ),
        (
            "The page's channel-group usage guidelines print 'The LAN Base feature set supports"
            'up to 24 EtherChannels; however, in mixed stack configurations, only six'
            "EtherChannels are supported', matching the row's LAN Base 24-EtherChannel and 1-24"
            'number-range limits; the mixed-stack caveat qualifies but does not contradict the'
            'row.'
        ),
        (
            "Requirement 'channel-number-platform-range' (platform) is a blocking renderer"
            "range gate with no vendor claim, and 'channel-membership-consistent' (platform) is"
            'a plan-consistency gate on planned members that makes no claim about current'
            'device state; both are correctly classified as gates.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanbase-speed-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": 'cdbca518805662a1934a72f25035dd8851aa45a47fb37ba99a6f58b53ad63908',
        "findings": (
        (
            "The cited guide's 'Setting the Interface Speed and Duplex Parameters' procedure"
            "prints 'speed {10 | 100 | 1000 | 2500 | 5000 | 10000 | auto [10 | 100 | 1000 |"
            "2500 | 5000 | 10000] | nonegotiate}' in interface configuration mode; the row's"
            'reviewed copper values 10/100/1000/auto are printed and no documented restriction'
            'contradicts the row.'
        ),
        (
            "The same page states 'Ethernet interfaces on the switch operate at 10, 100, or"
            "1000 Mb/s', that nonegotiate 'is available only for SFP module ports', and the"
            "guideline 'Do not disable Auto-Negotiation on PoE switches.', matching the row's"
            'two restrictions.'
        ),
        (
            "Requirement 'copper-port-required' is correctly a blocking platform gate (SFP"
            "ports need installed-optic evidence) and 'optic-field-note' is correctly a"
            'non-blocking field-note; neither adds an unprinted vendor claim.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-admin-shutdown-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": '3cae49224906d60f0637b72cf3932836624a6cd5a681c571de91944f01aeff73',
        "findings": (
        (
            "The cited guide's 'Shutting Down and Restarting the Interface' procedure prints"
            "'shutdown' ('Shuts down an interface.') and 'no shutdown' ('Restarts an"
            "interface.') in interface configuration mode, matching the row's command forms and"
            'command mode.'
        ),
        (
            "Requirement 'admin-state-topology' is correctly a blocking safety gate about"
            'missing field evidence and does not claim any current device state; the page'
            'prints nothing that contradicts the row.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-channel-group-lacp-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": 'dcd4a091c4370855c008f706978e7f1f54a63262edb030b893a302aebcf91821',
        "findings": (
        (
            "The cited page's 'channel-group' section prints the 'active'/'passive' LACP modes"
            "in 'Interface configuration' mode with 'Channel group number. The range is 1 to"
            "24.', and prints 'The LAN Lite feature set supports up to six EtherChannels.',"
            "matching the row's grammar, mode, printed range and LAN Lite limit."
        ),
        (
            "The same page prints 'An LACP channel group can have up to 16 Ethernet ports of"
            'the same type. Up to eight ports can be active, and up to eight ports can be in'
            "standby mode.', which does not contradict the row or the renderer's tighter"
            'eight-planned-member restriction.'
        ),
        (
            "Requirements are correctly classified: 'channel-member-count-limit' describes a"
            'renderer restriction (never more than eight planned members), not a vendor claim,'
            "and 'channel-membership-consistent' is a blocking platform plan-consistency gate"
            'with no current-device-state claim.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-channel-group-static-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": '03e97ae31daf21982fcfb4d97c7d8815cea4ae173406b5e0bc00a92e7902f50e',
        "findings": (
        (
            "The cited page's 'channel-group' section prints the channel-group form including"
            "'mode on' in 'Interface configuration' mode with 'Channel group number. The range"
            "is 1 to 24.', and prints 'The LAN Lite feature set supports up to six"
            "EtherChannels.', matching the row's static form, mode, printed range and LAN Lite"
            'limit.'
        ),
        (
            'The parameter maximum 6 is the reviewed six-EtherChannel renderer restriction'
            "while the row's limits keep the printed channel-group number range at 1 to 24;"
            'nothing on the page says the CLI accepts only 1-6.'
        ),
        (
            "Requirement 'channel-member-count-limit' is correctly safety-kind and is described"
            "as a renderer restriction ('the renderer refuses more than eight planned members"
            "per channel'), not a vendor claim; 'channel-membership-consistent' is a"
            'plan-consistency gate that claims no current device state.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-description-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": 'be3b85df58d97c59f093074a8332139f9c18e302a31f50ea3cfab474ee1af919',
        "findings": (
        (
            "The cited guide's 'Adding a Description for an Interface' procedure prints"
            "'description string' in interface configuration mode and says it 'Adds a"
            "description (up to 240 characters) for an interface', matching the row's grammar,"
            'mode and 240-character maximum.'
        ),
        (
            "The row's requirements list is correctly empty: the cited page prints no platform"
            'or safety precondition for the description command, so no gate is asserted.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-duplex-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": '9c1f019eea58f0da7121fed335ce466572142ae8c83d2512afebfdc9404db2d1',
        "findings": (
        (
            "The cited page's 'duplex' section prints 'duplex {auto | full | half}' in"
            "'Interface configuration' mode and states half duplex is 'only for interfaces"
            "operating at 10 or 100 Mb/s', exactly matching the row's two limits; nothing on"
            'the page contradicts the LAN Lite scope.'
        ),
        (
            "Requirement 'copper-port-required' is a blocking platform gate and"
            "'optic-field-note' is a non-blocking field-note; both are correctly classified and"
            'neither claims a vendor limit or current device state.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-poe-mode-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": 'b9ad432e36c6aa9fcd532e37bef4eadb61fd7cd2dd7d3391108b49e6f35ca042',
        "findings": (
        (
            "The cited page's 'power inline' section prints the command in interface"
            "configuration mode with 'static' documented as pre-allocating power and 'max"
            "max-wattage ... The range is 4000 to 30000 mW', and states 'This command is"
            "supported only on PoE-capable ports', matching the row's command evidence."
        ),
        (
            "The row's limit that LAN Lite PoE is expected to be blocked by hardware capability"
            "is consistent with the page's '% Invalid input detected' behaviour on a non-PoE"
            'port; the page neither claims LAN Lite PoE support nor contradicts the row.'
        ),
        (
            "Requirements are correctly classified: 'poe-capable-port' (platform) matches the"
            "printed PoE-capable-port restriction, 'poe-static-budget' (safety) restates the"
            "printed pre-allocation with required budget evidence, and 'poe-budget-field-note'"
            'is a non-blocking field-note.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-port-channel-interface-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": '79b316b7c9d890bfed7f8020c5a8de39eea697a6c4b94132ba756da685d17e0f',
        "findings": (
        (
            "The cited page's 'interface port-channel' section prints the global-mode form"
            "'interface port-channel port-channel-number' with 'port-channel-number ... The"
            "range is 1 to 24', and the channel-group guidelines print 'The LAN Lite feature"
            "set supports up to six EtherChannels.', matching the row's command, mode, printed"
            '1-24 range and six-EtherChannel LAN Lite limit.'
        ),
        (
            'The parameter maximum 6 encodes the printed LAN Lite six-EtherChannel cap as a'
            "reviewed renderer range; the row's own limits keep the printed channel-group"
            'number range at 1 to 24 and the page never claims a 1-6 CLI range.'
        ),
        (
            "Requirements 'channel-number-platform-range' and 'channel-membership-consistent'"
            'are both correctly classified blocking platform gates (range and'
            'planned-membership consistency); neither adds a vendor claim or claims current'
            'device state.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-speed-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-20',
        "content_digest": 'eab4e40a08de2d965efd26c77ff13df34873cf48d77f0f086d9678a3831cf300',
        "findings": (
        (
            "The cited guide's 'Setting the Interface Speed and Duplex Parameters' procedure"
            'prints the speed command (10/100/1000/auto plus other port-type values) in'
            "interface configuration mode, and the page states 'Ethernet interfaces on the"
            "switch operate at 10, 100, or 1000 Mb/s', matching the row's copper speed values."
        ),
        (
            "The page says nothing about LAN Lite or PoE; the row's 'LAN Lite image does not"
            "support PoE' licence-scope note is neither printed nor contradicted here, and no"
            'documented restriction contradicts the row.'
        ),
        (
            "Requirement 'copper-port-required' is correctly a blocking platform gate and"
            "'optic-field-note' is correctly a non-blocking field-note; neither claims a vendor"
            'limit or current device state.'
        ),
        ),
    },
    'l1-catalyst-3850-admin-shutdown-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": '75eb044a0aae1a58857563c09073ed89c5a6132673d00b95293d2d18eedb8faa',
        "findings": (
        (
            'The cited guide prints shutdown and no shutdown steps under Shutting Down and'
            'Restarting the Interface with the command entered in interface configuration mode,'
            "matching the row's grammar and mode."
        ),
        (
            'The page describes the effect as marking the interface administratively'
            "unavailable, which is consistent with the row's administrative-state limit;"
            "admin-state-topology is correctly a safety gate that requires the target's role to"
            'be confirmed from the device and asserts nothing about current device state.'
        ),
        ),
    },
    'l1-catalyst-3850-channel-group-lacp-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": '4716d9367f60c2abe9ab39a0184f592f228fc3ca202483cba9be0e2f22f71f1b',
        "findings": (
        (
            'The same command reference prints the modes active and passive with'
            'channel-group-number range 1 to 128 in interface configuration, matching the LACP'
            "grammar, mode and range; the page's auto/desirable PAgP modes are excluded by the"
            'row as scope, not contradicted.'
        ),
        (
            'channel-member-count-limit is a renderer refusal of more than eight planned'
            'members (a renderer restriction, not a vendor claim), which is consistent with the'
            'page allowing an LACP channel group of up to 16 Ethernet ports with eight active'
            'and eight in standby.'
        ),
        (
            'channel-membership-consistent is a platform plan-consistency gate and asserts'
            'nothing about current device state.'
        ),
        ),
    },
    'l1-catalyst-3850-channel-group-static-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": '76d2f09008254ec551c363caf0b8fecaebadd414a4249ab12e62a684b842f345',
        "findings": (
        (
            'The cited Layer 2/3 Command Reference prints the channel-group command in'
            'interface configuration mode with channel-group-number range 1 to 128 and includes'
            'the mode on keyword, matching the static on-mode grammar, interface mode and'
            'range.'
        ),
        (
            "The release's EtherChannel guide prints that on mode is a manual configuration"
            'needing both ends configured on and that each EtherChannel can consist of up to'
            'eight compatibly configured Ethernet ports; no documented restriction contradicts'
            'the row.'
        ),
        (
            'channel-member-count-limit is worded as a renderer restriction (the renderer'
            'refuses more than eight planned members per channel), not as a Cisco vendor limit,'
            'and is correctly classified safety; channel-membership-consistent is a platform'
            'plan-consistency gate with no device-state claim.'
        ),
        ),
    },
    'l1-catalyst-3850-description-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": 'a1e18a55ac0e1a57a06e8715d49c64f1b903d4cd73fad6d08da30ffa55831fbb',
        "findings": (
        (
            'The cited interface-characteristics guide prints description string as an'
            'interface configuration command and states that it adds a description of up to 240'
            "characters, matching the row's grammar, interface mode and 240-character maximum."
        ),
        (
            'No documented restriction contradicts the row, and its empty requirements list is'
            'appropriate because a description string needs no platform or safety gate and no'
            'field note.'
        ),
        ),
    },
    'l1-catalyst-3850-duplex-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": 'c6175f1066ce517aa1f8adb0f5dd3a2a796e14976994eeacee45b8ff220efe15',
        "findings": (
        (
            'The same cited page prints duplex {auto | full | half} in interface configuration'
            'mode, states that half is only for interfaces operating at 10 or 100 Mbps, and'
            'states that duplex is not configurable on 10-Gigabit Ethernet ports, matching'
            'every row limit.'
        ),
        (
            'The page also states that duplex options are not supported on 1000BASE-x and'
            '10GBASE-x SFP modules, which is consistent with the copper-port-required gate and'
            "with the row's optic exclusion; no documented restriction contradicts the row."
        ),
        (
            'copper-port-required and optic-field-note are correctly classified (renderer'
            'platform gate versus human field note) and neither claims that an optic is'
            'installed.'
        ),
        ),
    },
    'l1-catalyst-3850-poe-mode-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": '33bd646c607b21a47d6f6efd46c3bc19149dbb5699cb1848cf5e4f10b259abdf',
        "findings": (
        (
            'The cited page prints power inline {auto [max max-wattage] | never | port priority'
            '{high | low} | static [max max-wattage]} in interface configuration mode, states'
            'that static pre-allocates (reserves) power before the switch discovers the powered'
            'device, gives the max-wattage range as 4000 to 30000 mW, and states the command is'
            'supported only on PoE-capable ports.'
        ),
        (
            "The same release's PoE configuration guide prints that the max-wattage range for"
            "Cisco UPOE ports is 4000 to 60000 mW, matching the row's up-to-60000-mW UPOE"
            'limit; no documented restriction contradicts the row.'
        ),
        (
            'poe-capable-port (platform) and poe-static-budget (safety) rest on claims printed'
            'on the cited page, and poe-budget-field-note is correctly a human field note about'
            'unknowns.'
        ),
        ),
    },
    'l1-catalyst-3850-port-channel-interface-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": '4f63b98b91d170440fbfe380a4e07a221daaafa4ae7d9b1ed12bb1be533223e2',
        "findings": (
        (
            'The cited EtherChannel guide prints that each EtherChannel has a port-channel'
            'logical interface numbered from 1 to 128 and that the interface port-channel'
            "port-channel-number form is a global configuration command, matching the row's"
            'grammar, global command mode and 1-128 range.'
        ),
        (
            "The guide's documented restrictions (all members in the same VLAN or trunk; LACP"
            '1:1 redundancy only on port-channel interfaces) do not contradict the row.'
        ),
        (
            'channel-number-platform-range is a renderer platform gate on the reviewed release'
            'range and channel-membership-consistent is a plan-consistency gate on planned'
            'members; neither contains a vendor claim or a claim about current device state.'
        ),
        ),
    },
    'l1-catalyst-3850-speed-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": 'bb270297f343965ba7530772363981ae877cbecb4b52f009f1ae50a0a2b6e369',
        "findings": (
        (
            'The cited Interface and Hardware Command Reference prints speed {10 | 100 | 1000 |'
            '2500 | 5000 | auto [10 | 100 | 1000 | 2500 | 5000] | nonegotiate} in interface'
            'configuration mode and states that you cannot configure speed on 10-Gigabit'
            "Ethernet ports, so the row's 10/100/1000/auto form and 10G restriction are"
            'supported.'
        ),
        (
            "The release's interface-characteristics guide prints that Gigabit Ethernet ports"
            'support all speed options and that the 1000BASE-x SFP module ports support the'
            "nonegotiate keyword, matching the row's remaining limits; no documented"
            'restriction contradicts the row.'
        ),
        (
            'copper-port-required is a platform gate that requires installed-optic evidence for'
            'SFP ports without asserting that an optic is installed, and optic-field-note is'
            'correctly a human field note listing unknowns; neither carries an unprinted vendor'
            'claim.'
        ),
        ),
    },
    'l1-catalyst-9200-access-mode-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": '3dcf725791ce337a8e5797f7dc8c1f0bda900dd2ff4ffbaf5d29f92356d71504',
        "findings": (
        (
            "The cited VLAN guide's 'Assigning Static-Access Ports to a VLAN' procedure (under"
            "'How to Configure Normal-Range VLANs') still prints 'switchport mode access' in"
            "interface configuration mode, described as 'Defines the VLAN membership mode for"
            "the port (Layer 2 access port)', matching the grammar and the Layer 2 switchport"
            'limit; the row carries no structured requirements, so no gate was left unche'
        ),
        ),
    },
    'l1-catalyst-9200-access-vlan-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": '06c29e9a2bf359db66fe9c2c155a3e37fcd0869ef8e9f21ebbd7e061092644dd',
        "findings": (
        (
            "The 'Assigning Static-Access Ports to a VLAN' procedure's Step 5 still prints"
            "'switchport access vlan vlan-id' in interface configuration mode with 'Valid VLAN"
            "IDs are 1 to 4094', matching the row's grammar, mode and vlan-id range."
        ),
        (
            "The same guide prints 'VLAN numbers 1002 through 1005 are reserved for Token Ring"
            "and FDDI VLANs', supporting the row's reserved-id list."
        ),
        (
            'Requirement mode-transition-consistency is correctly classified as a safety gate'
            'and truthful: it states the renderer inheritance rule for access/trunk/routed'
            'transitions (the renderer blocks access-to-trunk, trunk-to-access,'
            'routed-to-switchport and switchport-to-routed), and contains no vendor claim'
            'requiring page support.'
        ),
        ),
    },
    'l1-catalyst-9200-admin-shutdown-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": '55c027fdf15fca92c7dd3d54ab1678c4cc1aa398e4da24c040eeeca766781608',
        "findings": (
        (
            "The guide's 'Shutting Down and Restarting an Interface' section still prints"
            "'shutdown' and 'no shutdown' in interface configuration mode and describes"
            "shutdown as disabling 'all functions on the specified interface' and marking it"
            "'unavailable on all monitoring command displays', matching the row's"
            'administrative-state-only limit.'
        ),
        (
            'Requirement admin-state-topology is correctly classified as a safety gate and is'
            'truthful: it is a renderer/planning rule that management, uplink, WAN and'
            'aggregate roles come from the device (the renderer blocks port-channel,'
            'channel-member, ISP/transit WAN and link-role administrative changes absent device'
            'topology evidence), and it contains no vendor CLI claim the page would need to'
            'print.'
        ),
        ),
    },
    'l1-catalyst-9200-allowed-vlans-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": '67c0473b3026688fd5c3869a9c933f1a64fad3baecaa643c4e554441c542141f',
        "findings": (
        (
            "The 'switchport trunk' section still prints the syntax 'switchport trunk {allowed"
            "vlan vlan-list | native vlan vlan-id | pruning vlan vlan-list}' in interface"
            "configuration mode and gives the vlan-list format 'all | none | [add | remove |"
            "except]vlan-atom [,vlan-atom...]', with 'vlan-atom is either a single VLAN number"
            "from 1 to 4094 or a continuous range', matching the row's vlan-list parameter a"
        ),
        (
            'Requirement mode-transition-consistency is correctly a safety gate (the renderer'
            'blocks inherited access/trunk/routed mode transitions), and'
            'allowed-vlans-replacement-semantics is correctly a non-blocking field-note'
            "consistent with the page: it says 'add adds the defined list of VLANs to those"
            "currently set instead of replacing the list' and 'remove removes ... instead of"
            "replacing the list', i.e."
        ),
        ),
    },
    'l1-catalyst-9200-bpdu-guard-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": '613deb981b74cb0f44cc08ffd2d387b46d2841e3ea7bf899830e3a0a36e101b1',
        "findings": (
        (
            'Re-fetched the cited 17.12 Catalyst 9200 optional spanning-tree guide (HTTP 200):'
            "the '(Optional) Enabling Bridge Protocol Data Unit Guard' section still prints"
            "'spanning-tree bpduguard enable' as an interface configuration command ('You also"
            'can use the spanning-tree bpduguard enable interface configuration command to'
            'enable BPDU guard on any port without also enabling the PortFast feature. When'
        ),
        (
            'bpdu-guard-edge-role is correctly classified as a SAFETY gate about missing'
            'planning/field evidence rather than a new vendor claim: the err-disable'
            'service-loss risk is the already-supported vendor behaviour applied to a planned'
            'link/ISP/transit target, an aggregate member or Port-Channel target, a core-role'
            'device or an unresolved-role target (bpdu-guard-non-edge-topology:*,'
            'bpdu-guard-aggregate-'
        ),
        ),
    },
    'l1-catalyst-9200-channel-group-lacp-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": '288b530d308abe67044267fd620d3e41d78f4a122aa86f7d654e8581dc637f72',
        "findings": (
        (
            "The 'channel-group' section prints the interface-configuration syntax with the"
            "active and passive keywords and 'The range is 1 to 48', so 'channel-group"
            "channel-group-number mode {active | passive}' is supported."
        ),
        (
            "The page defines active as 'places a port into a negotiating state in which the"
            "port initiates negotiations with other ports by sending LACP packets' and passive"
            "as 'responds to received LACP packets but does not initiate LACP packet"
            "negotiation', matching the row's LACP limit text."
        ),
        (
            'Requirements: channel-membership-consistent (platform) and'
            'channel-member-count-limit (safety) are correctly classified and truthful; the'
            "count requirement is worded as the renderer restriction 'the renderer refuses more"
            "than eight planned members per channel', which matches the renderer's eight-member"
            'check rather than asserting a vendor CLI limit.'
        ),
        ),
    },
    'l1-catalyst-9200-channel-group-static-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": 'c753fb02fd62dc7bccde89b6f0de12e643d7ea22388186d647e4ec35e0acdbfe',
        "findings": (
        (
            "The 'channel-group' section still prints 'channel-group channel-group-number mode"
            "{active | auto [non-silent] | desirable [non-silent] | on | passive}' in interface"
            "configuration mode with 'The range is 1 to 48', and documents 'on Enables the on"
            "mode', so the static 'mode on' form is supported."
        ),
        (
            "The usage guidelines state 'In on mode, a usable EtherChannel exists only when"
            "both connected port groups are in the on mode', matching the row's"
            'static-aggregation limit, and the eight-port limit is the same-release'
            "EtherChannel guide sentence 'up to eight compatibly configured Ethernet ports'."
        ),
        (
            'Requirements: channel-membership-consistent is correctly a platform gate and'
            'truthful (the renderer passes added/unchanged members and blocks'
            'migrating/detached members), while channel-member-count-limit is explicitly'
            "described as a renderer restriction - 'the renderer refuses more than eight"
            "planned members per channel' - not as a vendor claim, and the renderer constant"
            'MAX_CHANNEL_MEMBERS = 8 en'
        ),
        ),
    },
    'l1-catalyst-9200-duplex-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": '5e4808d1b4544393554941ddf3b62d7ebf1bdcfdf8ce274a89069c7d2823807e',
        "findings": (
        (
            "The 'duplex' section still prints 'duplex {auto | full | half}' in interface"
            "configuration mode and states 'You cannot configure half-duplex mode for"
            "interfaces operating at 1000 Mb/s, 10,000 Mb/s, 2.5Gb/s, or 5Gb/s', matching the"
            "row's half-duplex limit."
        ),
        (
            "The same section states 'Duplex options are not supported on the 1000BASE-x or"
            "10GBASE-x ... SFP modules', matching the row's SFP restriction exactly."
        ),
        (
            'Requirements are correctly classified and truthful: copper-port-required'
            '(platform) reflects that duplex legality on an SFP/SFP+/SFP28 port depends on the'
            'installed optic (the same-release guide allows duplex only with a 1000BASE-T SFP),'
            'and optic-field-note is correctly a non-blocking field-note.'
        ),
        ),
    },
    'l1-catalyst-9200-poe-mode-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": '18105336e09686b6ca7a9fb1da46173b841d3b4e29830a25b203884331f8e4b9',
        "findings": (
        (
            "The guide's 'Configuring a Power Management Mode on a PoE Port' section still"
            "prints 'power inline {auto [max max-wattage] | never | static [max max-wattage] }'"
            "in interface configuration mode and states 'auto: ... This is the default"
            "setting', matching the row's enum and default limit."
        ),
        (
            'Requirement poe-capable-port is correctly a platform gate and truthful: the page'
            "configures the mode on a PoE port and prints 'A PoE-capable switch port"
            "automatically supplies power ...', so power inline applies to PoE-capable ports of"
            "the inventoried PID; the 'exact PID and image' part is the renderer's port-group"
            'capability check rather than a page claim.'
        ),
        (
            'Requirement poe-static-budget is correctly a safety gate and truthful: the page'
            "says static mode will 'Preallocate (reserve) power for a port before the device"
            "discovers the powered device', matching 'static mode reserves power before"
            "detection', and the renderer blocks static candidates pending budget/class/cabling"
            'evidence; poe-budget-field-note is correctly a non-blocking field-note.'
        ),
        ),
    },
    'l1-catalyst-9200-port-channel-interface-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": 'b67a160f9cfe3d2d4fd49e51ba49329feefe054f2f3fe7bb7a3591525ffd20b7',
        "findings": (
        (
            "The Layer 2/3 Commands page's 'interface port-channel' section still prints"
            "'interface port-channel port-channel-number', says 'To access or create a port"
            "channel, use the interface port-channel command in global configuration mode', and"
            "gives port-channel-number 'The range is 1 to 48' - matching the row's grammar,"
            'global command mode and 1-48 range.'
        ),
        (
            "The same page's 'lacp max-bundle' usage guidelines print 'An LACP channel group"
            'can have up to 16 Ethernet ports of the same type. Up to eight ports can be'
            "active', and the same-release EtherChannel configuration guide prints 'each"
            "EtherChannel can consist of up to eight compatibly configured Ethernet ports',"
            "matching the row's eight-port limit."
        ),
        (
            'Requirements are correctly classified and truthful: channel-number-platform-range'
            'is a platform gate whose 1-48 range is printed on the cited page, and'
            'channel-membership-consistent is a renderer consistency gate (the renderer rejects'
            'a Port-Channel whose planned members are currently mapped to another channel) that'
            'contains no vendor claim needing page support.'
        ),
        ),
    },
    'l1-catalyst-9200-portfast-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": '2abf0bb32512e211da73624aece1a21bcfed54ca89fb6be75d3125125ab428ce',
        "findings": (
        (
            'Re-fetched the cited 17.12 Catalyst 9200 optional spanning-tree guide (HTTP 200,'
            "updated July 28, 2023): the '(Optional) Enabling PortFast' procedure still prints"
            "'spanning-tree portfast [trunk]' in interface configuration mode with example"
            "'spanning-tree portfast trunk', and its note still states 'To enable PortFast on"
            'trunk ports, you must use the spanning-tree portfast trunk interface configura'
        ),
        (
            'portfast-edge-role is correctly classified as a SAFETY gate about missing'
            'planning/field evidence rather than a vendor claim: it is a blocking renderer'
            'precondition that rejects a planned link/ISP/transit target, an aggregate member'
            'or Port-Channel target, a core-role device and an unresolved-role target'
            '(portfast-non-edge-topology:*, portfast-aggregate-member-role-unverified,'
            'portfast-aggregate-r'
        ),
        ),
    },
    'l1-catalyst-9200-rapid-pvst-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": 'f353fa8a5ab533fbc300d4f2dfe5807f8445b031fff7991921b2e1b963f09e69',
        "findings": (
        (
            "The 'Changing the Spanning-Tree Mode' procedure still prints 'spanning-tree mode"
            "{pvst | mst | rapid-pvst}' in global configuration mode with 'Select rapid-pvst to"
            "enable rapid PVST+', and the guide states 'By default, the device runs the Rapid"
            "PVST+ protocol' and 'All stack members run the same version of spanning tree',"
            "matching the row's global mode and topology-wide limit."
        ),
        (
            'Requirement topology-wide-evidence is correctly classified as a safety gate and'
            'truthful: it is a renderer/planning precondition (the renderer always reports the'
            'unresolved topology precondition for topology-wide commands) and contains no'
            'vendor claim that the page would need to print.'
        ),
        ),
    },
    'l1-catalyst-9200-root-priority-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": '68cc2da37feb34b54737835aecca35c0fc90e509293d5cf3d81cdc15692e8a56',
        "findings": (
        (
            "The '(Optional) Configuring the Device Priority of a VLAN' procedure still prints"
            "'spanning-tree vlan vlan-id priority priority' in global configuration mode with"
            "example 'spanning-tree vlan 20 priority 8192', matching the row's grammar and"
            'mode.'
        ),
        (
            "The step states 'For vlan-id ... The range is 1 to 4094' and 'For priority, the"
            "range is 0 to 61440 in increments of 4096; the default is 32768', and lists the"
            "valid multiples of 4096, matching the row's parameter min/max/step exactly."
        ),
        (
            'Requirement topology-wide-evidence is correctly classified as a safety gate and'
            'truthful (renderer/planning precondition, no vendor claim).'
        ),
        ),
    },
    'l1-catalyst-9200-speed-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": '57938e3dc915ee26aec8d973c505fa83625cf374fe9bb0fa3c0f17d7c2baa06c',
        "findings": (
        (
            "The cited configuration guide's 'Setting the Interface Speed and Duplex"
            "Parameters' procedure still prints only a duplex step, and the only speed"
            "configuration examples on the page are 'speed 10' and 'speed 100', so the row's"
            "disclosure that only those examples are printed is accurate; the 'Speed and Duplex"
            "Configuration Guidelines' section also prints that SFP/SFP+/SFP28 ports support"
            'only the no'
        ),
        (
            'The disputed usage line is visible on a more specific same-release page: the'
            "Interface and Hardware Commands command reference's 'speed' section prints 'speed"
            '{10 | 100 | 1000 | 2500 | 5000 | auto [10 | 100 | 1000 | 2500 | 5000] |'
            "nonegotiate}' in interface configuration mode and states 'You cannot configure"
            "speed on 10-Gigabit Ethernet ports', which supports the reviewed 10/100/1000/auto"
            'interfac'
        ),
        (
            'Requirements are correctly classified and truthful: copper-port-required'
            '(platform) matches the printed optics restrictions (speed on SFP/SFP+ limited to'
            'nonegotiate forms unless a 1000BASE-T SFP is installed; the duplex command'
            "reference prints 'Duplex options are not supported on the 1000BASE-x or 10GBASE-x"
            "... SFP modules'), so an SFP/SFP+/SFP28 target needs installed-optic evidence, and"
            'optic-'
        ),
        ),
    },
    'l1-catalyst-9200-trunk-mode-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": 'd7478a103be47ef922d8663b54245168eda6b31885bd8021f7d2cebbcae5b7bf',
        "findings": (
        (
            "The 'Layer 2 Interface Modes' table on the cited VLAN-Trunk guide still prints"
            "'switchport mode trunk - Puts the interface into permanent trunking mode ...', and"
            "the guide states 'The default switchport mode for all Ethernet interfaces is"
            "dynamic auto', matching the row's grammar, interface mode and explicit-trunk"
            'limit; the row carries no structured requirements.'
        ),
        ),
    },
    'l1-catalyst-9200-vlan-name-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": '5f17469480f6f46b9ba877a748a26416f5cb7093569a8d175dc3a364defb6e64',
        "findings": (
        (
            "The 'vlan' section's VLAN-configuration-mode usage guidelines still print 'name"
            'vlan-name - Names the VLAN with an ASCII string from 1 to 32 characters that must'
            "be unique within the administrative domain', matching the 1-32 ASCII parameter and"
            "the row's source-section pointer to those usage guidelines."
        ),
        (
            'Requirement vlan-name-platform-policy is correctly a platform gate and truthful:'
            'the 1-32 ASCII bound is printed on the cited page, and the renderer applies a'
            'narrower safe subset and refuses rather than truncating or escaping (renderer'
            'VLAN_NAME_PATTERN and the vlan_name_reason rejection path match the described'
            'policy).'
        ),
        ),
    },
    'l1-catalyst-9200-vlan-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": '082f576965162fd2733612aa2b5c4a0cae0ac2b796ff2944831328c04ea8d63e',
        "findings": (
        (
            "The VLAN Commands page's 'vlan' section still prints 'vlan vlan-id' in global"
            "configuration mode and 'The range is 1 to 4094', with usage guidelines giving"
            "normal-range VLANs 1-1005 and extended-range VLANs 1006-4094, matching the row's"
            'grammar, mode and range.'
        ),
        (
            "The show vlan sample output on the same page lists '1002 fddi-default', '1003"
            "token-ring-default', '1004 fddinet-default' and '1005 trnet-default', and the"
            "same-release VLAN configuration guide prints 'VLAN numbers 1002 through 1005 are"
            "reserved for Token Ring and FDDI VLANs', supporting the 1002-1005 reservation"
            'asserted in the row and in the requirement.'
        ),
        (
            'Requirement vlan-id-platform-range is correctly classified as a platform gate and'
            'truthful: VLAN ids 1-4094 and the 1002-1005 default/reserved range are both'
            'printed in the 17.12 Catalyst 9200 VLAN documentation.'
        ),
        ),
    },
    'l1-catalyst-9200-vtp-transparent-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": 'e9cf37255cf22a804e53dba73fe012fdf37579fe7e828e15ef83f1d5f2737063',
        "findings": (
        (
            "The 'vtp (global configuration)' section still prints 'vtp {domain domain-name |"
            'file filename | interface interface-name [only] | mode {client | off | server |'
            'transparent} [mst | unknown | vlan] | password password [hidden | secret] |'
            "pruning | version number}' in global configuration mode, so 'vtp mode transparent'"
            'is supported.'
        ),
        (
            "The transparent description states the device 'is disabled for VTP, does not send"
            'advertisements or learn from advertisements sent by other devices, and cannot'
            "affect VLAN configurations on other devices' and still forwards advertisements on"
            "trunk ports, matching the row's local VLAN-database/propagation limit and its"
            'exclusion that this is not a claim that all VTP traffic stops.'
        ),
        (
            'Requirement topology-wide-evidence is correctly classified as a safety gate and'
            'truthful (renderer/planning precondition, no vendor claim).'
        ),
        ),
    },
    'l1-catalyst-9300-access-mode-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": '3bc702162e2873ad9c8c731b7ad561680d3494d1b9ba7f4d55e1e0a3cf25300e',
        "findings": (
        (
            "The VLAN guide's 'Assigning Static-Access Ports to a VLAN' procedure Step 4 prints"
            "'switchport mode access' in interface configuration mode with the purpose 'Defines"
            "the VLAN membership mode for the port (Layer 2 access port)'."
        ),
        (
            "The row has no parameters and no structured requirements; its 'Layer 2 switchport"
            "command only' limit matches the printed Layer 2 access-port scope of the"
            'procedure.'
        ),
        ),
    },
    'l1-catalyst-9300-access-vlan-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": '37c016db794f488b12cf4cdbee0d20b7637fb8553ff550d0ab1c692d6b0bbf85',
        "findings": (
        (
            "The same 'Assigning Static-Access Ports to a VLAN' procedure Step 5 prints"
            "'switchport access vlan vlan-id' in interface configuration mode with 'Valid VLAN"
            "IDs are 1 to 4094', and the guide prints 'VLAN numbers 1002 through 1005 are"
            "reserved for Token Ring and FDDI VLANs'."
        ),
        (
            'Requirement mode-transition-consistency is correctly a safety gate with no vendor'
            'CLI claim: it states the renderer inheritance rule for blocked access/trunk/routed'
            'transitions on the same interface or Port-Channel, which the renderer enforces via'
            'mode-transition-inherited blocking.'
        ),
        ),
    },
    'l1-catalyst-9300-admin-shutdown-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": '4f7f4ec49121ff882d971b3feb334fd1074fe39c3089cd3e6c3c154069cf9501',
        "findings": (
        (
            "The cited guide's 'Shutting Down and Restarting an Interface' section prints"
            "'shutdown' and 'no shutdown' in interface configuration mode, and says shutdown"
            'disables all functions on the interface and marks it unavailable on monitoring'
            "displays, matching the row's administrative-state limit."
        ),
        (
            'Requirement admin-state-topology is correctly a safety gate containing no vendor'
            'CLI claim: it requires device-confirmed management/uplink/WAN/aggregate roles, and'
            'the renderer blocks port-channel, channel-member, ISP/transit and link-role'
            'administrative changes absent that evidence.'
        ),
        ),
    },
    'l1-catalyst-9300-allowed-vlans-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": 'b621615e3f1c5e67abdd529d45dd14e331b42c45ceffc313079fa68c359afdb9',
        "findings": (
        (
            "The 'switchport trunk' section prints 'allowed vlan vlan-list' in interface"
            "configuration mode and the vlan-list format 'all | none | [add | remove | except]"
            "vlan-atom [,vlan-atom...]' with vlan atoms 1 to 4094, matching the row's"
            'documented explicit-list form.'
        ),
        (
            'Requirement allowed-vlans-replacement-semantics is correctly a non-blocking'
            "field-note consistent with the page: 'add adds the defined list of VLANs to those"
            "currently set instead of replacing the list' implies the plain form replaces the"
            'allowed list; mode-transition-consistency is a truthful safety gate.'
        ),
        ),
    },
    'l1-catalyst-9300-bpdu-guard-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": 'adbe13633a6066dfd2111037e43eaacaf9c9a1384d9ae2b73c909a69bfd47136',
        "findings": (
        (
            "The cited BPDU Guard section prints the interface-level 'spanning-tree bpduguard"
            "enable' form and states that a port receiving a BPDU is put in the error-disabled"
            "state, while the same-release Layer 2/3 Command Reference documents 'spanning-tree"
            "bpduguard { enable | disable }' in interface configuration mode, so the"
            'enable/disable eligibility and err-disable behaviour are unchanged and still suppo'
        ),
        (
            'The added bpdu-guard-edge-role requirement is correctly a blocking SAFETY gate'
            'about missing field evidence: its BPDU/err-disable premise is printed on the cited'
            'page, the renderer blocks planned link/ISP/transit, aggregate/channel-member,'
            'core-role and role-unverified targets because they could lose service to an'
            'unexpected err-disable, and the existing bpdu-guard-topology-note remains a'
            'non-bloc'
        ),
        ),
    },
    'l1-catalyst-9300-channel-group-lacp-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": '683ec8626fd5faeb386f6da6be9e543eb66db957e9c3b6be283c625ecf3e1b1b',
        "findings": (
        (
            "The 'channel-group' section prints the interface-configuration syntax"
            "'channel-group channel-group-number mode {active | auto [non-silent] | desirable"
            "[non-silent] | on | passive}' and defines 'active' as initiating LACP negotiation"
            "and 'passive' as only responding, so the row's active/passive modes are supported."
        ),
        (
            'Parameter maximum 48 is the conservative intersection (command reference 1-128'
            "versus 1-48 on other 17.12 9300 pages); the limits' 1-128 sentence is attributed"
            'to the command reference and is therefore qualified, not an unqualified'
            'accepted-range claim.'
        ),
        (
            'Requirements are truthful and correctly classified: channel-membership-consistent'
            "is a platform gate; channel-member-count-limit is worded as the renderer's"
            'eight-member restriction (MAX_CHANNEL_MEMBERS = 8), a safety gate and not a vendor'
            'CLI claim.'
        ),
        ),
    },
    'l1-catalyst-9300-channel-group-static-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": 'e9c037d53e62a3e80895b9fc8535bbe7dc73336dbbecd3ad83eb6b04d16a6d7a',
        "findings": (
        (
            "The Layer 2/3 Commands page prints 'channel-group channel-group-number mode"
            "{active | auto [non-silent] | desirable [non-silent] | on | passive}' in interface"
            "configuration mode with 'channel-group-number ... The range is 1 to 128', and the"
            "usage guidelines describe 'In on mode, a usable EtherChannel exists only when both"
            "connected port groups are in the on mode.'"
        ),
        (
            "Parameter maximum 48 is the conservative intersection of the command reference's"
            "1-128 with the 1-48 printed on other 17.12 9300 pages (STP guide 'The port-channel"
            "range is 1 to 48'; Interface and Hardware Commands CR 'The port-channel-number"
            "range is 1 to 48'); the limits' 128 sentence is attributed to the command"
            'reference, not a bare accepted range.'
        ),
        (
            'Requirements are correctly classified and truthful: channel-membership-consistent'
            'is a platform gate the renderer enforces for added/unchanged members, and'
            "channel-member-count-limit is explicitly described as a renderer restriction ('the"
            "renderer refuses more than eight planned members per channel'), matching the"
            'renderer constant MAX_CHANNEL_MEMBERS = 8, not a vendor claim.'
        ),
        ),
    },
    'l1-catalyst-9300-duplex-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": '26ea90a2853fb12cfa4a6323e363a8b1e5051e74469d2ee7f87087dc1f06b0a7',
        "findings": (
        (
            "The Interface and Hardware Commands CR prints 'duplex {auto | full | half}' / 'no"
            "duplex {auto | full | half}' and states the command is used in interface"
            'configuration mode, describing auto, full and half.'
        ),
        (
            "The page prints 'You cannot configure half-duplex mode for interfaces operating at"
            "1000 Mb/s, 10,000 Mb/s, 2.5Gb/s, or 5Gb/s', matching the row's half-duplex limit,"
            "and 'Duplex options are not supported on the 1000BASE-x or 10GBASE-x ... SFP"
            "modules'; copper-port-required is a truthful platform gate and optic-field-note is"
            'correctly a non-blocking field-note.'
        ),
        ),
    },
    'l1-catalyst-9300-native-vlan-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": 'bd55fa32f17091ef428b1fffb9abca55922bfa6b36197f570d5f11e1cc274fb1',
        "findings": (
        (
            "The VLAN Commands page's 'switchport trunk' section prints 'switchport trunk"
            "{allowed vlan vlan-list | native vlan vlan-id | pruning vlan vlan-list}' in"
            "interface configuration mode, gives native vlan-id 'The range is 1 to 4094', and"
            "states 'VLAN 1 is the default native VLAN ID on the port.'"
        ),
        (
            "The same-release VLAN Trunks guide documents 'switchport trunk native vlan"
            "vlan-id' in its native-VLAN procedure and its Restrictions for VLAN Trunks section"
            'does not prohibit it, so no contradiction exists; mode-transition-consistency and'
            'topology-wide-evidence are correctly classified safety gates with no vendor CLI'
            'claim.'
        ),
        ),
    },
    'l1-catalyst-9300-poe-mode-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": '8fb78bb70bb615e05eb696bcce59422c89a029765275d9bed164ac4d71e0f278',
        "findings": (
        (
            "The PoE guide's 'Configuring a Power Management Mode on a PoE Port' section prints"
            "'power inline {auto [max max-wattage] | never | static [max max-wattage]}' in"
            'interface configuration mode, states auto is the default, and describes static as'
            "'Preallocate (reserve) power for a port before the device discovers the powered"
            "device'."
        ),
        (
            'poe-capable-port is a truthful platform gate: the page configures the mode on a'
            'PoE port and lists C9300-24T and C9300L-24T as switches that do not support PoE;'
            'poe-static-budget matches the printed reserve-before-detection text and the'
            'renderer blocks static pending budget evidence, and poe-budget-field-note is'
            'correctly a non-blocking field-note.'
        ),
        ),
    },
    'l1-catalyst-9300-port-channel-interface-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": '943622962127a7349982b860d74856d1ebc97c637577b73e3dfff0e6a4e5e2c9',
        "findings": (
        (
            "The Layer 2/3 Commands page prints 'interface port-channel port-channel-number' /"
            "'no interface port-channel' in global configuration mode with 'port-channel-number"
            "... The range is 1 to 128.'"
        ),
        (
            'Parameter maximum 48 is the conservative intersection: the 17.12.4 STP guide'
            "prints 'The port-channel range is 1 to 48' and the Interface and Hardware Commands"
            "command reference prints 'The port-channel-number range is 1 to 48'; the limits'"
            '1-128 sentence is attributed to the command reference, so it is not an unqualified'
            'accepted-range claim.'
        ),
        (
            "The eight-port limit is printed in the 17.12 EtherChannel guide ('each"
            "EtherChannel can consist of up to eight compatibly configured Ethernet ports');"
            'the requirements are correctly classified platform gates:'
            'channel-number-platform-range over the reviewed 1-48 range and'
            'channel-membership-consistent over planned member mappings, neither asserting a'
            'vendor CLI claim.'
        ),
        ),
    },
    'l1-catalyst-9300-portfast-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": 'af334e3b61a5e1af319c08adc8a40ab63f932e35c4be2883792f4d1678122580',
        "findings": (
        (
            "The cited '(Optional) Enabling PortFast' procedure prints 'spanning-tree portfast"
            "[trunk]' in interface configuration mode and its step note states 'The"
            "spanning-tree portfast command will not work on trunk ports', so the grammar and"
            'the trunk-only rule are unchanged and still supported.'
        ),
        (
            'The added portfast-edge-role requirement is correctly a blocking SAFETY gate about'
            'missing field evidence: the renderer blocks planned link/ISP/transit,'
            'aggregate/channel-member, core-role and role-unverified targets instead of'
            'presenting them as ordinary edge candidates, and the unreferenced-port case still'
            'carries requires_field_verification plus the non-blocking portfast-topology-note,'
            'so no re'
        ),
        ),
    },
    'l1-catalyst-9300-rapid-pvst-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": '2b4e74723a0e131d440e6dd7a1cea373d81bbbd688a7a4e2987458a07e7024a2',
        "findings": (
        (
            "The STP guide's 'Changing the Spanning-Tree Mode' Step 3 prints 'spanning-tree"
            "mode {pvst | mst | rapid-pvst}' in global configuration mode with 'Select"
            "rapid-pvst to enable rapid PVST+', matching the row's global rapid-pvst command."
        ),
        (
            'The page states all stack members run the same version of spanning tree,'
            "consistent with the row's topology-wide scope; requirement topology-wide-evidence"
            'is correctly a safety gate with no vendor CLI claim.'
        ),
        ),
    },
    'l1-catalyst-9300-root-priority-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": '1f0ec159f4776a0c6e19655a9e9c61f090217f0202a5a1cee636b86d62ec2339',
        "findings": (
        (
            "The STP guide's '(Optional) Configuring the Device Priority of a VLAN' Step 3"
            "prints 'spanning-tree vlan vlan-id priority priority' in global configuration mode"
            "with 'For priority, the range is 0 to 61440 in increments of 4096; the default is"
            "32768' and vlan-id range 1 to 4094."
        ),
        (
            "The row's priority min 0 / max 61440 / step 4096 and vlan-id 1-4094 are printed"
            'verbatim; topology-wide-evidence is correctly a safety gate with no vendor CLI'
            'claim.'
        ),
        ),
    },
    'l1-catalyst-9300-speed-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": '1082e1fe6dda8c3eb5f09a11494d64de0dee6a299916f73bedb3b740fbff54d1',
        "findings": (
        (
            "The cited Interface Characteristics guide's 'Setting the Interface Speed and"
            "Duplex Parameters' section prints the step usage line 'speed {10 | 100 | 1000 |"
            "2500 | 5000 | 10000 | auto [10 | 100 | 1000 | 2500 | 5000 | 10000] | nonegotiate}'"
            "in interface configuration, so the row's 10/100/1000/auto values are a documented"
            'subset.'
        ),
        (
            'Requirement copper-port-required is a truthful platform gate: the same guide'
            'prints that SFP/SFP+/SFP28 ports support speed only with a 1000BASE-T SFP or the'
            'nonegotiate forms, so an SFP target needs installed-optic evidence;'
            'optic-field-note is correctly a non-blocking field-note.'
        ),
        (
            "The page's speed examples ('speed 10', 'speed 100') are supplemented by the full"
            "step usage line above, so the row's limits caveat that only examples were printed"
            'understates the page but no claimed speed value or interface mode is contradicted.'
        ),
        ),
    },
    'l1-catalyst-9300-trunk-mode-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": 'ad128a23f11bc7f1189cd8a16c2faa35c698788cfb21aa9ea22388dee54aa0f3',
        "findings": (
        (
            "The VLAN Trunks guide's 'Layer 2 Interface Modes' section prints 'switchport mode"
            "trunk' and the trunk procedure prints 'switchport mode trunk' in interface"
            "configuration mode (example 'Device(config-if)# switchport mode trunk')."
        ),
        (
            "The page states 'The default mode for Layer 2 interfaces is switchport mode"
            "dynamic auto', matching the row's limit that trunk mode must be explicit; the row"
            'carries no structured requirements.'
        ),
        ),
    },
    'l1-catalyst-9300-vlan-name-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": 'ea00c22be45e828d55946dd706136b77a2a6f0223b7a800a86294371eabe9f49',
        "findings": (
        (
            "The VLAN Commands page's vlan usage guidelines print 'name vlan-name-Names the"
            'VLAN with an ASCII string from 1 to 32 characters that must be unique within the'
            "administrative domain', matching the row's 1-32 ASCII bound, and list the command"
            'among the VLAN configuration mode commands.'
        ),
        (
            'Requirement vlan-name-platform-policy is a truthful platform gate: the 1-32 ASCII'
            'bound is printed, and the narrower safe-character subset / no-truncation rule is'
            'explicitly described as renderer policy rather than a vendor claim.'
        ),
        ),
    },
    'l1-catalyst-9300-vlan-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": '03bf732c46399e7b1d008f5dfe81b1c64e0c149355f24ba06244bb5bd579b186',
        "findings": (
        (
            "The VLAN Commands page's 'vlan' section prints 'vlan vlan-id' / 'no vlan vlan-id'"
            "in global configuration mode with 'The range is 1 to 4094', and the usage"
            'guidelines give normal-range VLANs 1-1005 and extended-range VLANs 1006-4094.'
        ),
        (
            "The show vlan sample lists '1002 fddi-default', '1003 token-ring-default', '1004"
            "fddinet-default' and '1005 trnet-default', and the same-release VLAN guide prints"
            "'VLAN IDs 1002 through 1005 are reserved for Token Ring and FDDI VLANs',"
            "supporting the requirement's reserved-default claim; vlan-id-platform-range is a"
            'truthful platform gate.'
        ),
        ),
    },
    'l1-catalyst-9300-vtp-transparent-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-20',
        "content_digest": '4e006b068d0512001d84dbd9b68979f480300ec3ff887a5bbc8975738009bdb2',
        "findings": (
        (
            "The VLAN Commands page's vtp section prints 'vtp {domain ... | mode {client | off"
            "| server | transparent} ...}' in global configuration mode with the example"
            "'Device(config)# vtp mode transparent', and states a transparent-mode device does"
            'not participate in VTP or propagate changes.'
        ),
        (
            "The page prints 'The vtp mode transparent command disables VTP from the domain but"
            "does not remove the domain from the device', consistent with the row's local"
            'VLAN-database/propagation limit; topology-wide-evidence is correctly a safety gate'
            'with no vendor CLI claim.'
        ),
        ),
    },
    'l1-catalyst-c1000-admin-shutdown-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": '4a47479e5b19adac08dd86dcfa1842fdf14ef6ce35baf58e3d60a0e0830cf2f5',
        "findings": (
        (
            'The cited guide prints shutdown and no shutdown under Shutting Down and Restarting'
            'the Interface with the command entered in interface configuration mode, matching'
            "the row's grammar and mode."
        ),
        (
            "admin-state-topology is correctly a safety gate requiring the target's management,"
            'uplink, WAN and aggregate role to be confirmed from the device; it makes no claim'
            'about current device state and contains no unprinted vendor claim.'
        ),
        ),
    },
    'l1-catalyst-c1000-channel-group-lacp-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": '0000f4555cab05d86aee6d21cacd51479bbe8ed118a977a8ee60d63e9258df26',
        "findings": (
        (
            'The same cited page prints the modes active and passive with channel-group-number'
            'range 1 to 6 in interface configuration mode, matching the LACP grammar, mode and'
            'range; auto/desirable PAgP modes are documented but excluded by the row as scope.'
        ),
        (
            'channel-member-count-limit is explicitly a renderer restriction (the renderer'
            'refuses more than eight planned members per channel), not a Cisco claim, which is'
            "consistent with the release's EtherChannel guide allowing LACP groups of up to 16"
            'configured ports (eight active plus eight standby).'
        ),
        (
            'channel-membership-consistent is a platform plan-consistency gate and makes no'
            'current-device-state claim.'
        ),
        ),
    },
    'l1-catalyst-c1000-channel-group-static-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": '8780a670ac31e124d622f2c484ebcb4a3fc5626b8529a2239bb716b0a31e1540',
        "findings": (
        (
            'The cited page prints channel-group in interface configuration mode with'
            'channel-group-number range 1 to 6 and includes the mode on keyword, matching the'
            'static on-mode grammar, interface mode and range.'
        ),
        (
            "The release's EtherChannel configuration guide prints that the number of"
            "EtherChannels is limited to 6, matching the row's limits; no documented"
            'restriction contradicts the row.'
        ),
        (
            'channel-member-count-limit is stated as a renderer refusal of more than eight'
            'planned members, i.e. a renderer restriction and not a vendor claim, and is'
            'correctly classified safety.'
        ),
        ),
    },
    'l1-catalyst-c1000-description-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": '84d846725a9c78491dc3eab550ac682fdb93b9b8952c16687f52886ba5a43210',
        "findings": (
        (
            'The cited interface-characteristics guide prints description string as an'
            'interface configuration command and states that it adds a description of up to 240'
            "characters, matching the row's grammar, interface mode and 240-character maximum."
        ),
        (
            'No documented restriction contradicts the row, and an empty requirements list is'
            'appropriate for this benign command.'
        ),
        ),
    },
    'l1-catalyst-c1000-duplex-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": '041f0d0b660cf05bc4a6567f910729aae99c2a64c9229dc4351c35d3be6d2718',
        "findings": (
        (
            'The cited page prints duplex {auto | full | half} in interface configuration mode,'
            'states that half is only for interfaces operating at 10 or 100 Mb/s, and states'
            'that duplex options are not supported on the 1000BASE-x and 10GBASE-x SFP modules,'
            "matching the row's grammar and limits."
        ),
        (
            'No documented restriction contradicts the row; copper-port-required and'
            'optic-field-note are correctly classified, with the SFP condition expressed as a'
            'renderer gate rather than a claim about an installed optic.'
        ),
        ),
    },
    'l1-catalyst-c1000-poe-mode-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": '60da6fcc1e28e2cf6ff064617cca199131f5dcb989b1004268bb12405e0abe9d',
        "findings": (
        (
            'The cited page prints power inline {auto [max max-wattage] | ... | never | ... |'
            'static [max max-wattage]} in interface configuration mode, states that static'
            'pre-allocates (reserves) power for a port before the switch discovers the powered'
            'device, gives the max-wattage range as 4000 to 30000 mW, and states the command is'
            'supported only on PoE-capable ports.'
        ),
        (
            'No documented restriction contradicts the row; poe-capable-port (platform) and'
            'poe-static-budget (safety) rest on claims printed on the cited page, and'
            'poe-budget-field-note is correctly a human field note about unknowns.'
        ),
        ),
    },
    'l1-catalyst-c1000-port-channel-interface-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": '62d4cc4c3e35fea8212355af3bb4eaa87abdd2b688f4b8bd137c04fef3e21faa',
        "findings": (
        (
            'The cited Layer 2 Command Reference prints interface port-channel'
            'port-channel-number with global configuration mode and a port-channel-number range'
            "of 1 to 6, matching the row's grammar, mode and 1-6 range."
        ),
        (
            "The release's EtherChannel configuration guide prints that the number of"
            "EtherChannels is limited to 6, supporting the row's six-EtherChannel limit; no"
            'documented restriction contradicts the row.'
        ),
        (
            'channel-number-platform-range is a renderer platform gate on the 1-6 reviewed'
            'range and channel-membership-consistent is a plan-consistency gate; neither claims'
            'current device state or contains an unprinted vendor claim.'
        ),
        ),
    },
    'l1-catalyst-c1000-speed-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-20',
        "content_digest": '7b8a42b353ff3973a7602f8101ab836a253f428eb6c8183f788455dc41713104',
        "findings": (
        (
            'The cited Interface and Hardware Command Reference prints speed { 10 | 100 | 1000'
            '| auto [ 10 | 100 | 1000 ] } in interface configuration mode and states that you'
            "cannot configure speed on 10-Gigabit Ethernet ports, matching the row's documented"
            'form, mode and 10G limit.'
        ),
        (
            "The release's interface-characteristics guide prints that Gigabit Ethernet ports"
            'support all speed options, which is consistent with the row; no documented'
            'restriction contradicts the row.'
        ),
        (
            'copper-port-required and optic-field-note are correctly classified and condition'
            'SFP ports on installed-optic evidence without asserting an unseen optic.'
        ),
        ),
    },
}

REJECTED_RECORDS: dict[str, dict[str, object]] = {
    'l1-catalyst-9200-native-vlan-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-20',
        "content_digest": '7f33407710997ba74ea5346a5ae075de47ea38ce0e950e33f68516b6491640ed',
        "findings": (
        (
            "The cited VLAN Commands page still prints 'switchport trunk {allowed vlan"
            "vlan-list | native vlan vlan-id | pruning vlan vlan-list}' in interface"
            "configuration mode with native vlan-id 'The range is 1 to 4094', so the command is"
            "documented there, and the page's native-VLAN section also prints 'The no form of"
            'the native vlan command resets the native mode VLAN to the appropriate default'
            'VLAN for th'
        ),
        (
            'The contradiction is still live on the 17.12 Catalyst 9200 VLAN-Trunk'
            "configuration guide: under 'Restrictions for VLAN Trunks' it states 'The"
            "switchport trunk native vlan command is not supported.' - a direct contradiction"
            'of the row, so the row remains fail.'
        ),
        (
            'Its requirements (mode-transition-consistency and topology-wide-evidence, both'
            'safety) are correctly classified and contain no vendor claim needing page support;'
            'the failure is the published unsupported-command restriction, not the requirement'
            'classification.'
        ),
        ),
    },
}

#: Rows an independent reviewer could not confirm from the cited page. Recorded
#: for the Issue #4 evidence record; the registry keeps them pending.
UNVERIFIED_EVIDENCE: dict[str, str] = {
    'l1-catalyst-9200-description-v1': (
        "The cited guide's 'Adding a Description for an Interface' section prints the"
        "command form 'description string' with the example 'Device(config-if)# description"
        "Connects to Marketing' in interface configuration mode, and the example section"
        'repeats that CLI, so the command form and mode are visible.'
    ),
    'l1-catalyst-9300-description-v1': (
        "The cited Interface Characteristics guide's 'Adding a Description for an"
        "Interface' section and its example print 'description string' in interface"
        'configuration mode, so the command form and mode are visible.'
    ),
}

__all__ = ["REJECTED_RECORDS", "REVIEWED_RECORDS", "UNVERIFIED_EVIDENCE"]
