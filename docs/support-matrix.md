# V1 support and certification matrix

Target families are inventory categories in PR #1. A family row makes no claim about the capabilities of an exact PID, image, license, SDM profile or Stack composition. For each shipping profile, record the exact identification and its reproducible lab evidence.

| Target | Device classification | V1 qualification required | Hardware status | Auto Clean Deploy |
| --- | --- | --- | --- | --- |
| Catalyst 2960X | IOS | PID, image and feature set, interface/Stack mapping, PoE, limited L3 and DHCP feature checks | NOT VERIFIED | Disabled |
| Catalyst 3850 | IOS XE | PID, image, license, standalone/Stack, L2/L3, DHCP, boot and storage layout | NOT VERIFIED | Disabled |
| Catalyst 9200 | IOS XE | PID and uplink SKU, image, license, standalone/Stack, L2/L3, DHCP and boot/storage layout | NOT VERIFIED | Disabled |
| Catalyst 9300 | IOS XE | PID and uplink module, image, license, standalone/Stack, L2/L3, DHCP and boot/storage layout | NOT VERIFIED | Disabled |
| Catalyst C1000 | IOS | PID, image, port layout, PoE and L3/DHCP evidence per SKU | NOT VERIFIED | Disabled |
| Hillstone SG6000-A3800 | StoneOS 5.5R11P2-v6 | SSH identity, allowed read-only queries, route and rule precedence, Track/NAT/QoS behavior | NOT VERIFIED | Prohibited |
| Proxmox VE | Version and API permission profile TBD | Certificate identity, VM import/create, permissions, offline guest and rollback | NOT VERIFIED | N/A |
| VMware ESXi | Version, edition/license and API permission profile TBD | Certificate identity, VM import/create, permissions, offline guest and rollback | NOT VERIFIED | N/A |
| Ubuntu VM with Kea/Stork/PostgreSQL | Package and hook compatibility profile TBD | Offline artifact integrity, configuration reload and backup/restore, DORA and relay from client VLANs | NOT VERIFIED | N/A |

## Evidence required per Cisco profile

1. Record exact PID, OS build, software mode/license, interface names, uplink type and standalone or healthy existing Stack state. Cover port layout and any supported member combinations.
2. Run config and validation fixtures for VLAN, STP, LACP, access/trunk/routed transitions, SSH/AAA/Console recovery, PoE, SVI, routes and DHCP Server/Relay/Client as applicable. Unsupported and unknown features must fail validation before deployment.
3. Capture sanitized discovery and backup manifests. Verify encrypted backup and recovery separately. Exercise the reset strategy on authorized lab hardware, including independent VLAN storage, clean reboot, startup/boot integrity, license preservation and configuration persistence. Cover interruption and manual recovery.
4. Record test date, revision, exact profile, expected and observed results, and a pointer to sanitized evidence. Promote read-only, generation and destructive certifications independently. Keep any unproven cell marked NOT VERIFIED.
