# WEB-02B draft-aware capability preview

The Port Editor evaluates the current unsaved EventPlan draft through a read-only
preview. It does not allocate a Plan Revision, write to the planning database or
change any historical revision. The persisted revision capability endpoint from
CIS-01A remains unchanged.

## HTTP contract

`POST /api/v1/events/{event_id}/plan/capability-preview`

```json
{
  "plan": { "schema_version": 1, "event_id": "…" },
  "assignment_id": "…",
  "capabilities": ["port-media", "poe", "speed", "dhcp-relay"],
  "interface_id": "…",
  "stack_member": 2,
  "speed": 1000,
  "duplex": "full"
}
```

`plan` is the complete draft. `interface_id` is optional for assignment or member
lookups. `speed` and `duplex` are optional editor overrides; the Port Editor sends
the proposed settings in the draft plan itself. `capabilities` contains 1–32
distinct capability IDs.

```json
{
  "source": "unsaved-draft",
  "draft_fingerprint": "SHA-256 of the canonical draft plan",
  "input_fingerprint": "SHA-256 of the draft plus target and query",
  "decisions": [
    {
      "capability_id": "poe",
      "verdict": "supported",
      "reason_code": "poe-documented",
      "reason": "The port is rated for PoE and PoE+.",
      "evidence": [{ "url": "https://www.cisco.com/…", "section": "…", "version_scope": null,
        "licenses": [], "conditions": "…", "status": "vendor-documentation" }],
      "affected": {
        "event_id": "…", "assignment_id": "…", "physical_device_id": "…",
        "interface_id": "…", "interface_name": "Gi1/0/1", "stack_member": null,
        "sku": "C9300L-24P-4X", "software": "17.12.4", "license": "Network Advantage"
      },
      "port_groups": [],
      "verification": "not-verified",
      "deployment_status": "blocked",
      "blocks_deployment": true,
      "deployment_blockers": ["deployment-generation-disabled", "hardware-not-verified",
        "draft-not-persisted"]
    }
  ]
}
```

The draft target deliberately has no `revision_id` or `revision_hash`. There is no
way to name a persisted revision through this endpoint. `source` distinguishes the
draft query from the unchanged saved-revision endpoint.

`draft_fingerprint` is exactly the canonical draft plan hash, so it equals the
saved revision `content_hash` when the draft content matches. `input_fingerprint`
also covers the assignment, interface, Stack member and speed/duplex options.
Repeated identical requests are deterministic.

The resolver reuses the CIS-01A catalog and verdict rules. Unknown release labels,
ROMMON/boot loader values, missing software, unmatched licenses, unknown PID or
serial, ambiguous Stack ownership, unsupported media and missing evidence remain
UNKNOWN with a reason code. Hardware evidence can stay SUPPORTED when the running
software is unknown, but every result keeps `verification: not-verified` and
`deployment_status: blocked`. Draft results additionally include
`draft-not-persisted` in `deployment_blockers`.

## Read-only and isolation guarantees

- The endpoint uses the database only to read the event and to run current plan
  identity checks. It never calls `add`, `flush`, `commit`, revision allocation or
  revision lookup.
- An event mismatch returns 422. Assignment or interface IDs from another event
  return 422 through the existing assignment identity check. An interface outside
  the submitted assignment or plan returns 404.
- A structurally invalid draft still produces resolver output, but the decision
  carries `plan-invalid`. A malformed or ambiguous target returns UNKNOWN.
- Historical revision UUIDs, canonical JSON, SHA-256 and ETag are untouched. A
  preview can be repeated without creating an extra revision.
- Imported `capability_status: verified` or `software.capabilities` claims are not
  evidence and cannot promote a verdict.

## Port Editor behavior

The single-port editor, batch editor and Port-Channel editor call the preview with
the proposed records, not the stale saved revision. Each target is queried
separately, including mixed devices and Stack members. The UI:

- shows SUPPORTED, UNSUPPORTED and UNKNOWN per capability, with reason code,
  evidence URL, release scope, License scope and the NOT VERIFIED badge;
- marks every previous result Stale as soon as the draft or query changes and
  aborts the older request; late responses cannot replace a newer result;
- replaces a failed request with UNKNOWN instead of reusing the previous success;
- adds Device, Interface, Stack member, Intended setting, Verdict, Reason,
  Evidence and Verification columns to the Before / After confirmation;
- never summarizes a batch as fully SUPPORTED when any target differs;
- keeps UNKNOWN editable as planning intent;
- never presents documented support as hardware verification or deployment
  approval. Device writes and deployment-grade generation remain disabled.

The language selector changes presentation only. The capability request body and
fingerprints do not contain the active locale, and switching language does not
reissue a capability query.

## Regression coverage

- API: saved/draft parity, PID/software/license/ROMMON changes, Stack and interface
  ownership, speed/duplex, media, multiple capabilities, event isolation, read-only
  revision identity, imported claims and request validation.
- Browser: documented SUPPORTED, ROMMON UNKNOWN, stale request replacement, mixed
  batch targets, API failure without reuse, locale-independent query, and
  screenshot/overflow checks at 320, 800, 1280, 1440 and 1920 CSS pixels.
- Hardware and field verification remain SKIP / NOT VERIFIED. No Cisco CLI
  renderer, Console execution, Hillstone write or deployment path is added.

The WEB-02C controls layer maps these decisions to Port Editor candidates; see [WEB-02C capability-driven controls](web-02c-capability-controls.md).

