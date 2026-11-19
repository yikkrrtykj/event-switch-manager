"""Independent review attestations for the CIS-02B2 L1 command evidence.

Generated from the independent reviewers' structured output
(``review-9200.json``, ``review-9300.json``, ``review-2960x.json`` and
``review-3850-c1000.json``). Each record names the reviewer, the review date and
the concrete page evidence the reviewer observed.

A row that does not appear in either table keeps ``PENDING_REVIEW`` and cannot
render command text. That is the intended fail-closed state for a row whose
citation did not survive independent review.
"""

from __future__ import annotations

REVIEWED_RECORDS: dict[str, dict[str, object]] = {
    'l1-catalyst-2960x-lanbase-admin-shutdown-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The page\'s "Shutting Down and Restarting the Interface" procedure prints'
            '"shutdown" ("Shuts down an interface.") and "no shutdown" ("Restarts an'
            'interface.") after entering interface configuration mode, matching the row\'s'
            'command forms and command mode.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanbase-channel-group-lacp-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The "channel-group" section prints "channel-group { auto | channel-group-number'
            'mode {active | auto [non-silent] | desirable [non-silent] | on | passive}}" in'
            'Interface configuration mode, "channel-group-number ... The range is 1 to 24", and'
            '"The LAN Base feature set supports up to 24 EtherChannels", matching the'
            'active/passive modes and the number/licence limits.'
        ),
        (
            'The same page prints "An LACP channel group can have up to 16 Ethernet ports of'
            'the same type. Up to eight ports can be active, and up to eight ports can be in'
            'standby mode.", matching the row\'s 16-port (eight active/eight standby) limit.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanbase-channel-group-static-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The "channel-group" section prints "channel-group { auto | channel-group-number'
            'mode {active | auto [non-silent] | desirable [non-silent] | on | passive}}" in'
            'Interface configuration mode, "Channel group number. The range is 1 to 24.", and'
            '"In on mode, a usable EtherChannel exists only when both connected port groups are'
            'in the on mode."'
        ),
        (
            'The page\'s usage guidelines print "The LAN Base feature set supports up to 24'
            'EtherChannels; however, in mixed stack configurations, only six EtherChannels are'
            'supported.", matching the row\'s LAN Base limit and number range.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanbase-description-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The page\'s "Adding a Description for an Interface" procedure prints "description'
            'string" in interface configuration mode and says it "Adds a description (up to 240'
            'characters) for an interface", matching the row\'s 240-character maximum.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanbase-duplex-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The page\'s "duplex" section prints "duplex {auto | full | half}" in Interface'
            'configuration mode and states half-duplex is "only for interfaces operating at 10'
            'or 100 Mb/s".'
        ),
        (
            'The same section states "Duplex options are not supported on the 1000BASE-x or'
            '10GBASE-x ... SFP modules", matching all three row limits.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanbase-poe-mode-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The page\'s "power inline" section prints "power inline {auto [max max-wattage] |'
            'never | port priority {high | low} | static [max max-wattage]}" in interface'
            'configuration mode, documents "static" as pre-allocating power, and states "max'
            'max-wattage ... The range is 4000 to 30000 mW", matching the row\'s modes and'
            'wattage range.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanbase-port-channel-interface-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The cited page loads as "Consolidated Platform Command Reference, Cisco IOS'
            'Release 15.2(7)E (Catalyst 2960-X Switches)" and its "interface port-channel"'
            'section prints "interface port-channel port-channel-number" with usage "To access'
            'or create a port channel, use the interface port-channel command in global'
            'configuration mode", Command Modes "Global configuration", and'
            '"port-channel-number ... T'
        ),
        (
            'The page\'s channel-group usage guidelines print "The LAN Base feature set supports'
            'up to 24 EtherChannels; however, in mixed stack configurations, only six'
            'EtherChannels are supported.", matching the row\'s LAN Base limit and 1-to-24'
            'number range.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanbase-speed-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The page\'s "Setting the Interface Speed and Duplex Parameters" section prints the'
            'speed command with 10, 100, 1000 and auto values, and the guidelines state'
            '"Ethernet interfaces on the switch operate at 10, 100, or 1000 Mb/s", so the row\'s'
            'speed values are supported.'
        ),
        (
            'The same page states nonegotiate "is available only for SFP module ports" and "Do'
            'not disable Auto-Negotiation on PoE switches", matching the row\'s two'
            'restrictions.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-admin-shutdown-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The page\'s "Shutting Down and Restarting the Interface" procedure prints'
            '"shutdown" ("Shuts down an interface.") and "no shutdown" ("Restarts an'
            'interface.") after entering interface configuration mode, matching the row\'s'
            'command forms and command mode.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-channel-group-lacp-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The page prints "channel-group { auto | channel-group-number mode {active | auto'
            '[non-silent] | desirable [non-silent] | on | passive}}" in Interface configuration'
            'mode, "channel-group-number ... The range is 1 to 24", and "The LAN Lite feature'
            'set supports up to six EtherChannels", matching the active/passive modes and LAN'
            'Lite six-channel limit.'
        ),
        (
            'The same page prints "An LACP channel group can have up to 16 Ethernet ports of'
            'the same type. Up to eight ports can be active, and up to eight ports can be in'
            'standby mode.", corroborating the row\'s eight-ports-per-EtherChannel expectation'
            'for LACP.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-channel-group-static-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The "channel-group" section prints "channel-group { auto | channel-group-number'
            'mode {active | auto [non-silent] | desirable [non-silent] | on | passive}}" in'
            'Interface configuration mode, "Channel group number. The range is 1 to 24.", and'
            '"In on mode, a usable EtherChannel exists only when both connected port groups are'
            'in the on mode."'
        ),
        (
            'The usage guidelines print "The LAN Lite feature set supports up to six'
            'EtherChannels.", matching the row\'s LAN Lite six-EtherChannel limit and 1-to-24'
            'number range.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-description-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The page\'s "Adding a Description for an Interface" procedure prints "description'
            'string" in interface configuration mode and says it "Adds a description (up to 240'
            'characters) for an interface", matching the row\'s 240-character maximum.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-duplex-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The page\'s "duplex" section prints "duplex {auto | full | half}" in Interface'
            'configuration mode and states half-duplex is "only for interfaces operating at 10'
            'or 100 Mb/s", exactly matching the row\'s two limits.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-poe-mode-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The page\'s "power inline" section prints "power inline {auto [max max-wattage] |'
            'never | port priority {high | low} | static [max max-wattage]}" with "static"'
            'documented and "max max-wattage ... The range is 4000 to 30000 mW", so the command'
            'evidence the row cites is present.'
        ),
        (
            'The same section\'s usage guidelines restrict the command to PoE-capable ports ("%'
            'Invalid input detected" otherwise), consistent with the row\'s note that LAN Lite'
            'PoE use would be blocked by hardware capability rather than by the command syntax.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-port-channel-interface-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The "interface port-channel" section prints "interface port-channel'
            'port-channel-number" in Global configuration mode with "port-channel-number ...'
            'The range is 1 to 24", and the channel-group usage guidelines print "The LAN Lite'
            'feature set supports up to six EtherChannels."'
        ),
        (
            "Together those match the row's command form, global mode, 1-to-24 number range and"
            'LAN Lite six-EtherChannel limit.'
        ),
        ),
    },
    'l1-catalyst-2960x-lanlite-speed-v1': {
        "reviewer": 'independent-review-agent-rev-2960x',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'The page\'s "Setting the Interface Speed and Duplex Parameters" section prints'
            'speed values including 10, 100, 1000 and auto, and the guidelines state "Ethernet'
            'interfaces on the switch operate at 10, 100, or 1000 Mb/s" and that nonegotiate'
            '"is available only for SFP module ports", matching the row\'s copper speed values.'
        ),
        (
            "The page prints nothing about LAN Lite or PoE licensing in this section; the row's"
            'LAN Lite/PoE remark is a licence-scope note that the page neither states nor'
            'contradicts.'
        ),
        ),
    },
    'l1-catalyst-3850-admin-shutdown-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 16.12 Catalyst 3850 'Shutting Down and Restarting the Interface' section"
            "prints Step 4 'shutdown' ('Shuts down an interface') and Step 5 'no shutdown'"
            "('Restarts an interface') in interface configuration mode."
        ),
        (
            "The section's text that shutdown disables all functions and marks the interface"
            "unavailable supports the row's administrative-state-only limit."
        ),
        ),
    },
    'l1-catalyst-3850-channel-group-lacp-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 16.12 Catalyst 3850 command reference's 'channel-group' section prints"
            "the mode alternation including 'active' and 'passive' in interface configuration"
            "mode with channel-group-number 'The range is 1 to 128'; the syntax description"
            "defines 'active - Unconditionally enables Link Aggregation Control Protocol"
            "(LACP)' and 'passive - Enables LACP only if a LACP device is detected'."
        ),
        (
            "The same page's 'interface port-channel' section prints port-channel-number 'The"
            "range is 1 to 128', matching the row's remaining 'port-channel logical interface"
            "numbers: 1 to 128' limit."
        ),
        ),
    },
    'l1-catalyst-3850-channel-group-static-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 16.12 Catalyst 3850 command reference's 'channel-group' section prints"
            "'channel-group { auto | channel-group-number mode {active | auto [non-silent] |"
            "desirable [non-silent] | on | passive}}', states 'Command Modes: Interface"
            "configuration', gives channel-group-number 'The range is 1 to 128', and defines"
            "'on - Enables the on mode'."
        ),
        (
            "The row's only remaining limit is also on the cited page: the 'interface"
            "port-channel' section prints 'interface port-channel port-channel-number' with"
            "port-channel-number 'The range is 1 to 128', matching 'port-channel logical"
            "interface numbers: 1 to 128.'"
        ),
        ),
    },
    'l1-catalyst-3850-description-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 16.12 Catalyst 3850 'Adding a Description for an Interface' section"
            "prints Step 4 'description string' with the purpose 'Adds a description (up to 240"
            "characters) for an interface', in interface configuration mode."
        ),
        (
            "That matches the row's grammar, interface command mode and 240-character"
            'parameter.'
        ),
        ),
    },
    'l1-catalyst-3850-duplex-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 16.12 Catalyst 3850 'duplex' section prints 'duplex {auto | full |"
            "half}' in interface configuration mode, says half is 'only for interfaces"
            "operating at 10 or 100 Mbps' and 'You cannot configure half-duplex mode for"
            "interfaces operating at 1000 or 10,000 Mbps'."
        ),
        (
            "It also states 'You cannot configure the duplex mode on 10-Gigabit Ethernet ports;"
            "it is always full' and 'Duplex options are not supported on the 1000BASE-x or"
            "10GBASE-x ... SFP modules', matching the row's limits."
        ),
        ),
    },
    'l1-catalyst-3850-poe-mode-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 16.12 Catalyst 3850 'power inline' section prints 'power inline {auto"
            '[max max-wattage] | never | port priority {high | low} | static [max'
            "max-wattage]}' in interface configuration mode, documents the 'static' keyword"
            "('Pre-allocates (reserves) power for a port before the switch discovers the"
            "powered device') and gives max max-wattage 'The range is 4000 to 30000 mW'."
        ),
        (
            "The row's auto/static/never modes, 'static' keyword and command-reference"
            '4000-30000 mW range are printed there; the 60000 mW UPOE figure is a hardware'
            'rating (the same 16.12 documentation family states UPOE doubles power per port to'
            '60 watts), not a value printed in this command-reference section.'
        ),
        ),
    },
    'l1-catalyst-3850-port-channel-interface-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 16.12.x Catalyst 3850 'Configuring EtherChannels' page contains the"
            "section 'Channel Groups and Port-Channel Interfaces' and states 'Each EtherChannel"
            "has a port-channel logical interface numbered from 1 to 128', naming the global"
            "command 'interface port-channel port-channel-number' to create the logical"
            'interface.'
        ),
        (
            "The same page's EtherChannel Overview states 'Each EtherChannel can consist of up"
            "to eight compatibly configured Ethernet ports', so the 1-128 range, the eight-port"
            'limit and the logical Port-Channel creation claim are all confirmed on the cited'
            'page.'
        ),
        ),
    },
    'l1-catalyst-3850-speed-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 16.12 Catalyst 3850 'speed' section prints 'speed {10 | 100 | 1000 |"
            "2500 | 5000 | auto [10 | 100 | 1000 | 2500 | 5000] | nonegotiate}' in interface"
            "configuration mode, so the row's 10/100/1000/auto values are a documented subset"
            '(2500/5000 are visible only on multi-Gigabit models).'
        ),
        (
            "The same section states 'You cannot configure speed on 10-Gigabit Ethernet ports'"
            'and that, except for 1000BASE-T SFP modules, speed can be set to not negotiate'
            "(nonegotiate) on SFP module ports, matching the row's restrictions."
        ),
        ),
    },
    'l1-catalyst-9200-access-mode-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The named section 'Assigning Static-Access Ports to a VLAN' exists and Step 4"
            "prints 'switchport mode access' in interface configuration mode, with the purpose"
            "'Defines the VLAN membership mode for the port (Layer 2 access port)'."
        ),
        (
            "The row has no numeric parameters, and the page's Layer 2 access-port description"
            "matches the row's 'Layer 2 switchport command only' limit."
        ),
        ),
    },
    'l1-catalyst-9200-access-vlan-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The named section 'Assigning Static-Access Ports to a VLAN' exists and Step 5"
            "prints 'switchport access vlan vlan-id' in interface configuration mode, with the"
            "purpose text 'Valid VLAN IDs are 1 to 4094'."
        ),
        (
            "The same page's Normal-Range VLAN Configuration Guidelines state 'VLAN numbers"
            "1002 through 1005 are reserved for Token Ring and FDDI VLANs', supporting the"
            "row's reserved ids."
        ),
        ),
    },
    'l1-catalyst-9200-admin-shutdown-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The named section 'Shutting Down and Restarting an Interface' exists and its"
            "procedure prints 'shutdown' (Step 4) and 'no shutdown' (Step 5) in interface"
            'configuration mode.'
        ),
        (
            'The page describes the feature as disabling all functions on the interface and'
            "marking it unavailable on monitoring displays, matching the row's"
            'administrative-state-only semantics (the up/down values are a planner mapping, not'
            'CLI keywords).'
        ),
        ),
    },
    'l1-catalyst-9200-allowed-vlans-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'switchport trunk' section prints 'switchport trunk {allowed vlan vlan-list |"
            "native vlan vlan-id | pruning vlan vlan-list}' in interface configuration mode,"
            "and its Usage Guidelines give the vlan-list format 'all | none | [add | remove |"
            "except]vlan-atom [,vlan-atom...]'."
        ),
        (
            "The page states vlan-atom is 'a single VLAN number from 1 to 4094 or a continuous"
            "range', matching the row's vlan-list type and 1-4094 bounds."
        ),
        ),
    },
    'l1-catalyst-9200-bpdu-guard-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The named section '(Optional) Enabling Bridge Protocol Data Unit Guard' exists;"
            "after its procedure the page prints 'You also can use the spanning-tree bpduguard"
            'enable interface configuration command to enable BPDU guard on any port without'
            "also enabling the PortFast feature'."
        ),
        (
            "The page's BPDU guard description states ports receiving a BPDU are put in the"
            "error-disabled state, matching the row's 'err-disables a port that receives BPDUs'"
            'limit.'
        ),
        ),
    },
    'l1-catalyst-9200-channel-group-lacp-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'channel-group' section prints the 'mode {active | auto | desirable | on |"
            "passive}' alternation in interface configuration mode with channel-group-number"
            "range 1 to 48, so 'channel-group channel-group-number mode {active | passive}' is"
            'supported.'
        ),
        (
            "The page defines 'active' as initiating LACP negotiation ('places a port into a"
            "negotiating state in which the port initiates negotiations') and 'passive' as"
            "responding only ('responds to received LACP packets but does not initiate LACP"
            "packet negotiation'), matching the row's limits."
        ),
        ),
    },
    'l1-catalyst-9200-channel-group-static-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'channel-group' section prints 'channel-group channel-group-number mode"
            "{active | auto [non-silent] | desirable [non-silent] | on | passive}', says to use"
            'it in interface configuration mode, and gives the channel-group-number range as 1'
            'to 48.'
        ),
        (
            "The 'on' keyword is documented ('on - Enables the on mode' and 'In on mode, a"
            'usable EtherChannel exists only when both connected port groups are in the on'
            "mode'), matching the static form the row renders."
        ),
        ),
    },
    'l1-catalyst-9200-duplex-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'duplex' section prints 'duplex {auto | full | half}' in interface"
            "configuration mode, and its 'half' description says half-duplex is only for 10 or"
            "100 Mb/s: 'You cannot configure half-duplex mode for interfaces operating at 1000"
            "Mb/s, 10,000 Mb/s, 2.5Gb/s, or 5Gb/s.'"
        ),
        (
            "The page also states 'Duplex options are not supported on the 1000BASE-x or"
            "10GBASE-x ... SFP modules', matching the row's restriction limits exactly."
        ),
        ),
    },
    'l1-catalyst-9200-poe-mode-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The named section 'Configuring a Power Management Mode on a PoE Port' exists and"
            "Step 4 prints 'power inline {auto [max max-wattage] | never | static [max"
            "max-wattage] }' in interface configuration mode."
        ),
        (
            "The step's keyword list documents auto, static and never and says 'auto: ... This"
            "is the default setting', matching the row's enum values and its 'auto is the"
            "default' limit."
        ),
        ),
    },
    'l1-catalyst-9200-port-channel-interface-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The page's 'interface port-channel' section prints 'interface port-channel"
            "port-channel-number', says the command is used in global configuration mode, and"
            "states 'The range is 1 to 48' for port-channel-number."
        ),
        (
            "The same section says the command is used 'To access or create a port channel'"
            "(matching 'creates the logical Port-Channel interface'), and the LACP usage text"
            "elsewhere on the page ('up to 16 Ethernet ports ... up to eight ports can be"
            "active') is consistent with the eight-port bundling limit."
        ),
        ),
    },
    'l1-catalyst-9200-portfast-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The named section '(Optional) Enabling PortFast' exists and Step 4 prints"
            "'spanning-tree portfast [trunk]' in interface configuration mode with example"
            "'spanning-tree portfast trunk'."
        ),
        (
            "The note states 'To enable PortFast on trunk ports, you must use the spanning-tree"
            'portfast trunk interface configuration command. The spanning-tree portfast command'
            "will not work on trunk ports', matching the row's trunk-form requirement."
        ),
        ),
    },
    'l1-catalyst-9200-rapid-pvst-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The named section 'Changing the Spanning-Tree Mode' exists and Step 3 prints"
            "'spanning-tree mode {pvst | mst | rapid-pvst}' in global configuration mode, with"
            'rapid-pvst described as enabling rapid PVST+.'
        ),
        (
            "The page also notes Rapid PVST+ is the default mode and 'All stack members run the"
            "same version of spanning tree', consistent with the row's topology-wide limit."
        ),
        ),
    },
    'l1-catalyst-9200-root-priority-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The named section '(Optional) Configuring the Device Priority of a VLAN' exists"
            "and Step 3 prints 'spanning-tree vlan vlan-id priority priority' in global"
            "configuration mode with example 'spanning-tree vlan 20 priority 8192'."
        ),
        (
            "The step states the vlan-id range is 1 to 4094 and 'For priority, the range is 0"
            "to 61440 in increments of 4096; the default is 32768', matching the row's priority"
            'limits and choosing step exactly.'
        ),
        ),
    },
    'l1-catalyst-9200-trunk-mode-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The named section 'Layer 2 Interface Modes' exists and its table lists 'switchport"
            "mode trunk' (Puts the interface into permanent trunking mode ...), and the page"
            "states 'The default switchport mode for all Ethernet interfaces is dynamic auto.'"
        ),
        (
            "The 'Configuring a Trunk Port' procedure prints 'switchport mode {dynamic {auto |"
            "desirable} | trunk}' in interface configuration mode, confirming both the trunk"
            'keyword and the explicit-trunk requirement.'
        ),
        ),
    },
    'l1-catalyst-9200-vlan-name-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'vlan' command's Usage Guidelines list 'name vlan-name - Names the VLAN with"
            'an ASCII string from 1 to 32 characters that must be unique within the'
            "administrative domain', in VLAN configuration mode."
        ),
        (
            "That matches the row's 1-32 character, unique-in-domain parameter exactly; the"
            "cited section is the 'vlan' section's usage-guideline text, an equivalent location"
            "to the row's section description."
        ),
        ),
    },
    'l1-catalyst-9200-vlan-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            'Re-fetched the page including its vlan section: the section prints the syntax vlan'
            "vlan-id in global configuration mode, and the Syntax Description states 'The range"
            "is 1 to 4094'."
        ),
        (
            'The Usage Guidelines print normal-range VLANs (VLAN IDs 1 to 1005) and'
            'extended-range VLANs (VLAN IDs 1006 to 4094), and the show vlan example output'
            'prints 1002 fddi-default, 1003 token-ring-default, 1004 fddinet-default and 1005'
            'trnet-default (types fddi/tr/fdnet/trnet), supporting the 1-4094 range and the'
            '1002-1005 FDDI/Token Ring default-VLAN limits the trimmed row now claims.'
        ),
        ),
    },
    'l1-catalyst-9200-vtp-transparent-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'vtp (global configuration)' section prints the syntax 'vtp {domain"
            "domain-name | ... | mode {client | off | server | transparent} ...}' in global"
            "configuration mode and the example 'Device(config)# vtp mode transparent'."
        ),
        (
            "The transparent description states the device 'is disabled for VTP, does not send"
            'advertisements or learn from advertisements sent by other devices, and cannot'
            "affect VLAN configurations on other devices', matching the row's"
            'VLAN-database/propagation limit.'
        ),
        ),
    },
    'l1-catalyst-9300-access-mode-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'Assigning Static-Access Ports to a VLAN' section exists and its procedure"
            "Step 4 prints 'switchport mode access' with the purpose 'Defines the VLAN"
            "membership mode for the port (Layer 2 access port)'."
        ),
        (
            'The surrounding steps show interface configuration mode; the row has no'
            'numeric/enumerated parameter claims to check.'
        ),
        ),
    },
    'l1-catalyst-9300-access-vlan-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The same section's Step 5 prints 'switchport access vlan vlan-id' with the purpose"
            "'Assigns the port to a VLAN. Valid VLAN IDs are 1 to 4094.'"
        ),
        (
            "The same page's 'Supported VLANs' text states 'VLAN IDs 1002 through 1005 are"
            "reserved for Token Ring and FDDI VLANs', confirming the reserved range."
        ),
        ),
    },
    'l1-catalyst-9300-admin-shutdown-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'Shutting Down and Restarting an Interface' section exists and its procedure"
            "prints 'shutdown' ('Shuts down an interface') followed by 'no shutdown' ('Restarts"
            "an interface') in interface configuration mode."
        ),
        (
            "The section's Step 3 shows entries for vlan, gigabitethernet and port-channel"
            "interfaces, consistent with the row's administrative-state scope."
        ),
        ),
    },
    'l1-catalyst-9300-allowed-vlans-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'switchport trunk' section prints 'allowed vlan vlan-list' and the vlan-list"
            "format 'all | none | [add | remove | except]vlan-atom [,vlan-atom...]' with vlan"
            "atoms 1 to 4094, matching the row's documented forms."
        ),
        (
            "Examples print 'switchport trunk allowed vlan add 1,2,5,6'; the page does not"
            "state the row's 'native VLAN is unaffected' sentence, but nothing on the page"
            'contradicts it.'
        ),
        ),
    },
    'l1-catalyst-9300-bpdu-guard-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The '(Optional) Enabling Bridge Protocol Data Unit Guard' section exists; its"
            "procedure prints global 'spanning-tree portfast bpduguard default', and the page's"
            "'What to do next' prints 'you also can use the spanning-tree bpduguard enable"
            "interface configuration command to enable BPDU guard on any port'."
        ),
        (
            "The page states a port that receives a BPDU 'is put it in the error-disabled"
            "state', matching the row's err-disable limit; only the enable form is printed by"
            'the page, as the row itself notes.'
        ),
        ),
    },
    'l1-catalyst-9300-channel-group-lacp-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'channel-group' section prints the mode options 'active' and 'passive'"
            '(alongside auto, desirable and on), states the command is used in interface'
            'configuration mode, and gives channel-group-number range 1 to 128.'
        ),
        (
            "Usage guidelines print 'Active mode ... initiates negotiations ... by sending LACP"
            "packets' and 'Passive mode ... responds to received LACP packets but does not"
            "initiate LACP packet negotiation', matching the row's LACP wording."
        ),
        ),
    },
    'l1-catalyst-9300-channel-group-static-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'channel-group' section prints 'channel-group channel-group-number mode"
            "{active | auto [non-silent] | desirable [non-silent] | on | passive}' and states"
            "'Command Modes: Interface configuration', with 'channel-group-number ... The range"
            "is 1 to 128.'"
        ),
        (
            "The literal 'on' keyword is printed in the syntax and in the usage guidelines ('In"
            'on mode, a usable EtherChannel exists only when both connected port groups are in'
            "the on mode'); the page names the argument channel-group-number rather than"
            'port-channel-number.'
        ),
        ),
    },
    'l1-catalyst-9300-duplex-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'duplex' section prints 'duplex {auto | full | half}' with 'Command Modes:"
            "Interface configuration', and describes auto/full/half."
        ),
        (
            "The page states 'You cannot configure half-duplex mode for interfaces operating at"
            "1000 Mb/s, 10,000 Mb/s, 2.5Gb/s, or 5Gb/s', matching the row's half-duplex"
            'restriction; it also notes duplex options are not supported on'
            '1000BASE-x/10GBASE-x SFP modules, which the row covers with its installed-optic'
            'exclusion.'
        ),
        ),
    },
    'l1-catalyst-9300-native-vlan-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'switchport trunk' section prints 'switchport trunk {allowed vlan vlan-list |"
            "native vlan vlan-id | pruning vlan vlan-list}', 'native vlan vlan-id ... The range"
            "is 1 to 4094', 'Command Modes: Interface configuration' and 'VLAN 1 is the default"
            "native VLAN ID on the port'."
        ),
        (
            "An example prints 'switchport trunk native vlan 3'; the 1002-1005 VLANs appear on"
            'the same page as non-prunable default VLANs.'
        ),
        ),
    },
    'l1-catalyst-9300-poe-mode-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'Configuring a Power Management Mode on a PoE Port' section exists and Step 4"
            "prints 'power inline {auto [max max-wattage] | never | static [max max-wattage]}'"
            'in interface configuration, with auto stated as the default and auto/static/never'
            'described.'
        ),
        (
            'The page also explicitly lists C9300-24T and C9300L-24T among switches that do not'
            "support PoE while the row's PID list includes C9300-24T and C9300L-24T-4G; this"
            "does not contradict the row's own limit that command evidence is separate from the"
            'hardware PoE rating, but PoE applicability is limited to PoE-capable SKUs.'
        ),
        ),
    },
    'l1-catalyst-9300-port-channel-interface-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'interface port-channel' section prints 'interface port-channel"
            "port-channel-number' / 'no interface port-channel', states 'Command Modes: Global"
            "configuration', and gives 'port-channel-number ... The range is 1 to 128.'"
        ),
        (
            "The section does not print the row's 'up to eight compatibly configured ports'"
            "sentence; the page's related wording elsewhere is 'Up to eight ports can be"
            "active' (of up to 16 ports in an LACP channel group), which is consistent but not"
            'verbatim.'
        ),
        ),
    },
    'l1-catalyst-9300-portfast-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The '(Optional) Enabling PortFast' section exists and Step 4 prints 'spanning-tree"
            "portfast [trunk]' in interface configuration, with 'To enable PortFast on trunk"
            'ports, you must use the spanning-tree portfast trunk interface configuration'
            "command. The spanning-tree portfast command will not work on trunk ports.'"
        ),
        (
            "The page's literal keyword is 'trunk'; the row's enum tokens edge/edge-trunk are"
            'consistent labels for the portfast and portfast-trunk forms and no page text'
            'contradicts them.'
        ),
        ),
    },
    'l1-catalyst-9300-rapid-pvst-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'Changing the Spanning-Tree Mode' section exists and Step 3 prints"
            "'spanning-tree mode {pvst | mst | rapid-pvst}' in global configuration (example"
            "'spanning-tree mode pvst'), with 'Select rapid-pvst to enable rapid PVST+'."
        ),
        (
            'The page also states all stack members run the same version of spanning tree,'
            "consistent with the row's topology-wide scope."
        ),
        ),
    },
    'l1-catalyst-9300-root-priority-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The '(Optional) Configuring the Device Priority of a VLAN' section exists and Step"
            "3 prints 'spanning-tree vlan vlan-id priority priority' in global configuration,"
            "with 'For priority, the range is 0 to 61440 in increments of 4096; the default is"
            "32768' and vlan-id range 1 to 4094."
        ),
        (
            'The page does not print the 1002-1005 reserved list for vlan-id (only the 1-4094'
            'range), so that parameter metadata is not visible here, but the priority'
            'range/step/default claimed by the row is verbatim.'
        ),
        ),
    },
    'l1-catalyst-9300-speed-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'Setting the Interface Speed and Duplex Parameters' section exists and Step 4"
            "prints 'speed {10 | 100 | 1000 | 2500 | 5000 | 10000 | auto [10 | 100 | 1000 |"
            "2500 | 5000 | 10000] | nonegotiate}' in interface configuration, so the row's"
            '10/100/1000/auto values are a documented subset.'
        ),
        (
            "The row's caveat that 'the full usage line was not visible' is inaccurate: the"
            'page does print the full step-level usage line (including 2500, 5000, 10000 and'
            'nonegotiate). No claimed value is contradicted; the row simply enumerates a'
            'subset.'
        ),
        ),
    },
    'l1-catalyst-9300-trunk-mode-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'Layer 2 Interface Modes' section exists and its table prints 'switchport mode"
            "trunk'; the trunk procedure Step 4 prints 'switchport mode {dynamic {auto |"
            "desirable} | trunk}'."
        ),
        (
            "The page states 'The default mode for Layer 2 interfaces is switchport mode"
            "dynamic auto', matching the row's limit that trunk mode is explicit."
        ),
        ),
    },
    'l1-catalyst-9300-vlan-name-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The vlan command's Usage Guidelines print 'name vlan-name—Names the VLAN with an"
            'ASCII string from 1 to 32 characters that must be unique within the administrative'
            "domain', matching the row's 1-32 limit."
        ),
        (
            "There is no standalone 'name' command section, but 'name vlan-name' is printed in"
            "the vlan command's VLAN-configuration command list, so the cited section exists as"
            'an explicitly referenced usage-guideline entry.'
        ),
        ),
    },
    'l1-catalyst-9300-vlan-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'vlan' section prints 'vlan vlan-id' / 'no vlan vlan-id', states 'Command"
            "Modes: Global configuration', and gives 'The range is 1 to 4094'; its usage"
            'guidelines split normal-range VLANs 1 to 1005 from extended-range VLANs 1006 to'
            '4094.'
        ),
        (
            "The 1002-1005 reservation is supported by the page's 'show vlan' example, which"
            'lists 1002 fddi-default, 1003 token-ring-default, 1004 fddinet-default and 1005'
            "trnet-default (act/unsup), and by the 'switchport trunk' note that VLANs 1002 to"
            "1005 cannot be pruned; the word 'reserved' itself is not printed on this page."
        ),
        ),
    },
    'l1-catalyst-9300-vtp-transparent-v1': {
        "reviewer": 'independent-review-agent-rev-9300',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The 'vtp (global configuration)' section prints 'vtp {domain ... | mode {client |"
            "off | server | transparent} ...}' in global configuration and an example"
            "'Device(config)# vtp mode transparent'."
        ),
        (
            'Usage guidelines state a transparent-mode device is disabled for VTP and does not'
            "send advertisements (it receives and forwards them), and that 'The vtp mode"
            'transparent command disables VTP from the domain but does not remove the domain'
            "from the device', matching the row's limits."
        ),
        ),
    },
    'l1-catalyst-c1000-admin-shutdown-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 15.2(7)Ex Catalyst 1000 'Shutting Down and Restarting the Interface'"
            "section prints Step 4 'shutdown' ('Shuts down an interface') and Step 5 'no"
            "shutdown' ('Restarts an interface') in interface configuration mode."
        ),
        (
            'The section text that shutdown disables all functions and marks the interface'
            "unavailable supports the row's administrative-state limit."
        ),
        ),
    },
    'l1-catalyst-c1000-channel-group-lacp-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 15.2(7)Ex Catalyst 1000 'channel-group' section prints the mode"
            "alternation including 'active' and 'passive' in interface configuration mode with"
            "channel-group-number 'The range is from 1 to 6', defining 'active -"
            "Unconditionally enables LACP' and 'passive - Enables LACP only if a LACP device is"
            "detected'."
        ),
        (
            "The row's remaining limit (channel-group-number range 1 to 6; six EtherChannels"
            'maximum) matches that printed range; the removed LACP 16-port/eight-active note is'
            'no longer claimed.'
        ),
        ),
    },
    'l1-catalyst-c1000-channel-group-static-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 15.2(7)Ex Catalyst 1000 'channel-group' section prints 'channel-group |"
            'channel-group-number mode {active | auto [non-silent] | desirable [non-silent] |'
            "on | passive}' (the stray '|' is the page's rendering) in interface configuration"
            "mode with channel-group-number 'The range is from 1 to 6', and defines 'on -"
            "Enables the on mode'."
        ),
        (
            'The printed 1-to-6 channel-group-number range is the six-EtherChannel limit the'
            'revised row claims, and the removed configuration-guide-only limits are no longer'
            'claimed.'
        ),
        ),
    },
    'l1-catalyst-c1000-description-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 15.2(7)Ex Catalyst 1000 'Adding a Description for an Interface' section"
            "prints Step 4 'description string' with 'Adds a description (up to 240 characters)"
            "for an interface' in interface configuration mode."
        ),
        (
            "That matches the row's grammar and 240-character parameter."
        ),
        ),
    },
    'l1-catalyst-c1000-duplex-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 15.2(7)Ex Catalyst 1000 'duplex' section prints 'duplex {auto | full |"
            "half}' in interface configuration mode, says half is only for 10/100 Mb/s ('You"
            'cannot configure half-duplex mode for interfaces operating at 1000 or 10,000'
            "Mb/s'), and states 'Duplex options are not supported on the 1000BASE-x or"
            "10GBASE-x ... SFP modules'."
        ),
        (
            "These match the row's keyword values and both duplex restrictions; command history"
            'confirms the 15.2(7)E1 release.'
        ),
        ),
    },
    'l1-catalyst-c1000-poe-mode-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 15.2(7)Ex Catalyst 1000 'power inline' section prints 'power inline"
            '{auto [max max-wattage] | consumption wattage | never | police ... | port ... |'
            "static [max max-wattage]}' in interface configuration mode, documents the static"
            "keyword (pre-allocates power), gives max max-wattage 'The range is 4000 to 30000"
            "mW', and states 'This command is supported only on PoE-capable ports'."
        ),
        (
            "All of the row's claims (auto/static/never modes, static keyword, 4000-30000 mW"
            'range, PoE-capable-only restriction) are printed there.'
        ),
        ),
    },
    'l1-catalyst-c1000-port-channel-interface-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 15.2(7)Ex Catalyst 1000 'interface port-channel' section prints"
            "'interface port-channel port-channel-number' / 'no interface port-channel', states"
            "the command is used in global configuration mode 'To access or create a port"
            "channel', and gives port-channel-number 'The range is from 1 to 6'."
        ),
        (
            "The same page's 'channel-group' section prints channel-group-number 'The range is"
            "from 1 to 6', so the row's 'channel-group-number range is 1 to 6; six"
            "EtherChannels maximum' and logical-Port-Channel creation limits are supported by"
            'the cited page.'
        ),
        ),
    },
    'l1-catalyst-c1000-speed-v1': {
        "reviewer": 'independent-review-agent-rev-3850-c1000',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited 15.2(7)Ex Catalyst 1000 'speed' section prints 'speed { 10 | 100 | 1000"
            "| auto [ 10 | 100 | 1000 ] }' in interface configuration mode and states 'You"
            "cannot configure speed on 10-Gigabit Ethernet ports', matching the row's grammar"
            'and restrictions.'
        ),
        (
            "The command history line 'Cisco IOS Release 15.2(7)E1 - This command was"
            "introduced' confirms the reviewed release."
        ),
        ),
    },
}

REJECTED_RECORDS: dict[str, dict[str, object]] = {
    'l1-catalyst-9200-native-vlan-v1': {
        "reviewer": 'independent-review-agent-rev-9200',
        "reviewed_at": '2026-11-19',
        "findings": (
        (
            "The cited command reference does print 'switchport trunk {allowed vlan vlan-list |"
            "native vlan vlan-id | pruning vlan vlan-list}' in interface configuration mode"
            "with native VLAN 'The range is 1 to 4094', so the cited page itself documents the"
            'command.'
        ),
        (
            'However the same-release 17.12 Catalyst 9200 VLAN Trunk configuration guide'
            "(configuring_vlan_trunks.html) states in 'Restrictions for VLAN Trunks': 'The"
            "switchport trunk native vlan command is not supported.' That documented"
            'restriction contradicts the row, so it cannot be accepted as supported evidence.'
        ),
        ),
    },
}

#: Rows an independent reviewer could not confirm from the cited page. Recorded
#: for the Issue #4 evidence record; the registry keeps them pending.
UNVERIFIED_EVIDENCE: dict[str, str] = {
    'l1-catalyst-9200-description-v1': (
        "The named section 'Example: Adding a Description to an Interface' exists and"
        "prints 'Device(config-if)# description Connects to Marketing' in interface"
        "configuration mode; the procedure section also prints the 'description string'"
        'command.'
    ),
    'l1-catalyst-9200-speed-v1': (
        "The named section 'Setting the Interface Speed and Duplex Parameters' exists, but"
        'its procedure table prints only a duplex step; the only speed evidence on the page'
        "is the examples 'speed 10' and 'speed 100' plus the SFP note 'speed (auto, 10,"
        "100, 1000)'."
    ),
    'l1-catalyst-9300-description-v1': (
        "The 'Example: Adding a Description to an Interface' section exists (an 'Adding a"
        "Description for an Interface' procedure is also present) and the page prints the"
        "interface-configuration step 'description string' with the example 'description"
        "Connects to Marketing'."
    ),
}

__all__ = ["REJECTED_RECORDS", "REVIEWED_RECORDS", "UNVERIFIED_EVIDENCE"]
