"""Production attestations for CIS-03-03A L3 command evidence.

The five base-forwarding rows were independently reviewed by:

    ChatGPT (GPT-6) — independent read-only AI evidence reviewer

on 2026-11-22.  This is an independent AI review process, not Cisco TAC, a
human engineer or a cryptographic signature.  The review was bound to R33
HEAD ``8f5fa14f7678e2eb600b64cf506e6b3bf52f284e`` and tree
``8119cf4c536ea2664e15f35a7d0d5d1c000942af``.

DHCP Relay remains PENDING and is intentionally absent here.  Its license
question is tracked by Issue #30 and must not be inferred from this file.
"""

from __future__ import annotations

REVIEWED_RECORDS: dict[str, dict[str, object]] = {
    "l3-9300-ip-routing-v1": {
        "reviewer": "ChatGPT (GPT-6) — independent read-only AI evidence reviewer",
        "reviewed_at": "2026-11-22",
        "findings": (
            "9300 17.12 Enabling IP Unicast Routing documents global ip routing.",
            "Information About IP Routing supports base static/default IPv4 "
            "routing under Network Essentials and Network Advantage.",
            "Historical model support, target Supported Hardware and 17.12.4 "
            "release notes support platform applicability.",
            "Cisco Core-only, at least one planned SVI and no no-form are Renderer restrictions.",
            "Field device state is not verified.",
        ),
        "content_digest": "4bc17e044c45b5d823b596cd7bd74bbe20505eec50e9abebb5f265ad0c724f47",
    },
    "l3-9300-svi-interface-v1": {
        "reviewer": "ChatGPT (GPT-6) — independent read-only AI evidence reviewer",
        "reviewed_at": "2026-11-22",
        "findings": (
            "9300 17.12 Configuration Guidelines for IP Routing documents "
            "SVI creation via interface vlan.",
            "System Management Guide Manually Assigning IP Information to "
            "Multiple SVIs supports VLAN 1-4094.",
            "VLAN 1/1002-1005 exclusion, canonical Vlan name, planned carrier "
            "and Gateway/Transit binding are Renderer safety restrictions.",
            "PID, release and license scope are supported by the complete "
            "R33 evidence chain.",
            "Actual SVI line protocol is not verified.",
        ),
        "content_digest": "8c19d4f33d944b3230c8888ea0b7077758ee56af8afbbb41da93132d8a03ec51",
    },
    "l3-9300-svi-address-v1": {
        "reviewer": "ChatGPT (GPT-6) — independent read-only AI evidence reviewer",
        "reviewed_at": "2026-11-22",
        "findings": (
            "9300 17.12 IP Addressing Services Commands ip address is "
            "interface configuration mode.",
            "Without secondary, ip address configures the primary address.",
            "One primary IPv4 address is supported per interface.",
            "First batch supports IPv4 primary, /1-/30, usable host and Gateway/Subnet binding.",
            "/31, /32, secondary, DHCP and unnumbered forms are outside current generation scope.",
            "PID, release and license scope are supported by the R33 evidence chain.",
        ),
        "content_digest": "2540d35d2c4200cc67e9b3adfe070cb0724aeddf40901552979ca18090f3a071",
    },
    "l3-9300-static-route-v1": {
        "reviewer": "ChatGPT (GPT-6) — independent read-only AI evidence reviewer",
        "reviewed_at": "2026-11-22",
        "findings": (
            "9300 17.12 Configuring Static Unicast Routes documents the "
            "ip route command in global configuration mode.",
            "IOS XE Protocol-Independent Command Reference documents "
            "distance 1-255 with default 1.",
            "Administrative distance 255 is not installed and is blocked by "
            "the Renderer.",
            "First batch only allows IPv4 next-hop, non-default destination "
            "and an eligible on-link SVI dependency.",
            "VRF, interface-only, track, permanent, cleanup and other "
            "excluded forms are not generated.",
            "PID, release and license scope are supported by the complete R33 evidence chain.",
        ),
        "content_digest": "647c4577cc5348f32cbdb3f974aeea9f491c2e6080f21c06cc1b7f8cc7aa7ecc",
    },
    "l3-9300-default-route-v1": {
        "reviewer": "ChatGPT (GPT-6) — independent read-only AI evidence reviewer",
        "reviewed_at": "2026-11-22",
        "findings": (
            "9300 17.12 static route syntax and Information About Default "
            "Routes and Networks support a static 0/0 default route.",
            "TrustSec Configuring Default Route SGT confirms use of "
            "ip route 0.0.0.0 to create a default route.",
            "Generic IOS XE command reference and gateway-of-last-resort "
            "documentation provide syntax and AD evidence.",
            "Only planned Transit, preferred default route ID, Hillstone "
            "next-hop and eligible SVI dependency are allowed.",
            "AD 255, ip default-network and interface-only forms remain excluded.",
            "Actual default route installation and forwarding success are not proven.",
        ),
        "content_digest": "ab9ba793037ef8c66b13b6363a2411134ec4e1dd82f1b290699628abb4ac307c",
    },
}

REJECTED_RECORDS: dict[str, dict[str, object]] = {}
