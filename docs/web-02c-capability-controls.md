# WEB-02C capability-driven Port Editor controls

WEB-02C maps the documented Cisco capability results from WEB-02B/CIS-01A to
the concrete candidates a Port Editor control offers. It does not add a second
vendor rule set to the browser: every hard limit is derived either from a
current UNSUPPORTED verdict or from the documented `port_groups` range returned
by the draft-aware capability preview for the exact target. Deployment-grade
generation, device writes and CIS-02A remain out of scope and blocked.

## Evidence contract

The Port Editor reuses `POST /api/v1/events/{event_id}/plan/capability-preview`
for the complete current draft, the exact assignment, physical interface, Stack
member, PID, software release and License. Each capability decision already
carries:

- `verdict` (`supported`, `unsupported`, `unknown`);
- `reason_code`, the localized reason and the documentation evidence scope;
- `port_groups` with the documented medium, slot, port range and rates;
- `verification: not-verified` and `deployment_status: blocked`.

The browser maps an **applicable and current** verdict to a control candidate.
Only an applicable UNSUPPORTED verdict, or a documented port range that excludes
a candidate, can hard-block a new selection. UNKNOWN, NOT VERIFIED, loading,
stale and error results are warning-only. A missing or unavailable result never
reuses the previous verdict, so an old SUPPORTED or UNSUPPORTED conclusion
cannot outlive its input fingerprint.

## Outcomes

| Outcome | Meaning | Control behaviour |
| --- | --- | --- |
| ALLOWED | Applicable documented evidence supports this candidate. Still NOT VERIFIED. | Candidate is selectable; no pass or verification claim is made. |
| HARD_BLOCKED | Current applicable evidence explicitly does not support this candidate. | Candidate option is disabled, the target and reason are shown, Apply is blocked until the proposal changes. |
| WARNING_ONLY | UNKNOWN or unverified planning intent, e.g. ROMMON release, unmatched License, missing optic, unobserved Stack member. | Candidate stays selectable; the note says planning intent only and no hardware support is reported. |
| NOT CURRENT | Loading, stale or failed preview. | No old verdict is reused; no hard limit is applied and no support is reported. |

`SUPPORTED` means the vendor documentation applies to the exact target. It is
never presented as hardware verification. The deployment block and the NOT
VERIFIED badge remain visible on every result.

## Candidate judgements

| Control | Candidate rule | Evidence |
| --- | --- | --- |
| Speed | Copper: documented rate is ALLOWED. Integer above `max(port_groups.rates)` or outside the documented copper rates is HARD_BLOCKED (`speed-outside-port-range`, `speed-unsupported`). `auto` is ALLOWED on documented copper. SFP/SFP+/SFP28: a rate within the documented maximum stays WARNING_ONLY (`optic-unknown`); a rate above the documented maximum is HARD_BLOCKED. | Current `speed` decision and its documented `port_groups`. |
| Duplex | Judged with the proposed effective speed and the documented medium. Copper: `auto`/`full` ALLOWED; `half` with 1000 Mbps HARD_BLOCKED; `half` with 10/100 Mbps ALLOWED; `half` with auto/unknown speed WARNING_ONLY. Optical media stays WARNING_ONLY unless the proposed speed already exceeds the documented range, which is HARD_BLOCKED. | Current `duplex` decision and `port_groups`. |
| PoE | `static` requires a documented PoE-capable port: ALLOWED when supported, HARD_BLOCKED when the current evidence says UNSUPPORTED. `auto` on non-PoE hardware is WARNING_ONLY because it still needs PoE hardware when a powered device asks. `never` is ALLOWED: explicitly turning PoE off is a safe intent that needs no power budget. | Current `poe` decision (hardware evidence, independent of software identity). |
| Access / Trunk / Routed | Each mode candidate is judged by its own feature evidence: `access`, `trunk` and `routed-port`. UNSUPPORTED blocks only that candidate; UNKNOWN warns. | Current feature decisions. |
| PortFast / BPDU Guard | Explicit enabling candidates are judged by their feature evidence. The `disabled`/off candidate is always ALLOWED as a safe planning intent. | Current `portfast` and `bpdu-guard` decisions. |
| LACP | `active`/`passive` require the `lacp` capability. `static` requires only the `port-channel` capability, so a static aggregation is never blocked because LACP negotiation is UNKNOWN. UNSUPPORTED blocks only the affected candidates; UNKNOWN warns. | Current `lacp` and `port-channel` decisions, one per selected member target. |
| Port-Channel members | Adding/resizing an aggregate is judged against the `port-channel` capability for the proposed member targets; no target is silently skipped. | Current `port-channel` decision per member target. |
| IPv4 address on a routed port | Judged by `routed-port` and `ipv4-routing`. | Current feature decisions. |
| Stack member / Stack layout | No hard control: a Stack member number is inventory identity, not a device write. The Stack capability and evidence stay visible as an advisory hint. A candidate Stack member number is never silently rewritten. | Current `stack` decision. |
| Physical port and media | The documented `port_groups` medium and rates drive Speed/Duplex. UNKNOWN media or a missing transceiver remains WARNING_ONLY. | Current `port-media`, `speed` and `duplex` decisions. |
| SVI / L3 / DHCP Relay | Advisory only; they have no direct control in this editor. The capability panel and related hints show their verdict and evidence before related records or deployment work. | Current `svi`, `ipv4-routing` and `dhcp-relay` decisions. |
| Description / admin state / VLAN references | No hardware candidate rule. Plan validation still applies independently. | Plan validation, not capability evidence. |

Speed, Duplex and PoE candidates use the documented port range for the exact
physical interface. The maximum rate of the device family is never applied to
every port, and a current `speed: SUPPORTED` verdict is never used to infer a
different speed candidate.

## Reset and Keep

| Field | Reset judgement |
| --- | --- |
| Speed / Duplex | The documented default is auto negotiation; judged as the `auto` candidate. |
| PoE | Reset removes the explicit setting. Documented PoE ports ALLOW it; non-PoE or UNKNOWN evidence keeps it WARNING_ONLY with a verify-the-default note. Reset is never hard-blocked. |
| PortFast / BPDU Guard | Reset means the platform disabled state and is ALLOWED. |
| LACP | Reset is not offered; the existing Keep/Set semantics are unchanged. |
| Keep | Never restricted or rewritten by the capability policy. A stored historical value that current evidence does not support stays visible, is preserved, and can be replaced. |
| Other settings | Reset removes the override; no capability restriction applies. |

Reset is judged by the documented default behaviour instead of assuming the
default is always safe. A reset is reported as warning-only rather than blocked
so that an operator can always repair a historical value.

## Batch editing

Every target is judged separately, including mixed devices and Stack members.
The field notice lists the per-target result, for example "blocked for
Synthetic-Access-B · Gi1/0/2; documented support for Synthetic-Access-A ·
Gi1/0/1". A candidate is not offered when any selected target is HARD_BLOCKED,
so one target cannot silently receive an unsupported setting. The operator can
adjust the selection or choose another candidate. Apply rechecks the policy and
refuses to change the draft while any selected target is hard-blocked. Mixed
values, Keep/Reset/Set, hidden-target confirmation and the Before/After review
are unchanged.

## Stale, loading, error and unknown

- A changed draft marks every previous result stale and aborts the older
  request. A late response cannot replace a newer result or a newer control
  policy.
- A failed request becomes warning-only for the affected targets; the previous
  success is not reused.
- UNKNOWN keeps the candidate editable and saveable as planning intent, with
  the UNKNOWN reason, evidence gap and deployment blockers shown.
- No path reports "hardware support passed" for an UNKNOWN, stale, loading or
  failed result. `device_writes_enabled` stays false.

## Apply and save safety

The control policy is evaluated while editing and again in the confirmation
step before the draft is changed. A HARD_BLOCKED proposed setting cannot pass
the Apply path: the Apply button is disabled and the confirmation view lists the
blocked targets and reasons. Save Revision keeps the existing behaviour: it
persists the validated plan and does not turn vendor capability rules into
global EventPlan rejection rules. Existing Plan Validation ERROR rules continue
to run independently. UNKNOWN planning intent remains saveable. Deployment-grade
generation remains disabled.

## Historical compatibility

A saved revision that contains a value current evidence does not support stays
readable and exportable byte-for-byte: original values, UUIDs, canonical JSON,
SHA-256 and ETag are unchanged. Opening it never clears the value. The editor
shows the stored value, the capability reason, and lets the operator replace it
with a supported candidate. Fields left on Keep are not rewritten.

## Tests

- Vitest: candidate matrix for PoE, Speed, Duplex, mode, PortFast, BPDU Guard,
  LACP vs static aggregation, reset defaults, batch per-target judgement,
  preserved historical values, stale/loading/error isolation and advisory
  capabilities.
- API: the existing draft preview contract stays the only capability source;
  port groups, PID/software/License/ROMMON/interface/Stack and read-only
  revision identity keep their existing regressions.
- Playwright (packaged build and Vite proxy): non-PoE static block, PoE-capable
  allowance, copper rate limits, optical UNKNOWN, Speed/Duplex linkage,
  ROMMON/unknown patch warning-only, License and PID/interface re-judgement,
  LACP/static separation, mixed batch, no silent partial update, Keep/Reset/Set,
  historical unsupported preservation, UNKNOWN save, stale/error without reuse,
  old asynchronous response isolation, Before/After consistency, bilingual
  states, revision identity and the existing LACP/Transit/VPN safety tests.
- Hallmark v2.0.0 static lint and browser review at 320, 800, 1280, 1440 and
  1920 CSS pixels, keyboard/focus, screen-reader text, error states and reduced
  motion.

Physical hardware, Console, SSH, Hillstone and Kea execution remain
SKIP / NOT VERIFIED. No Cisco CLI renderer or deployment-generation path is
added.
