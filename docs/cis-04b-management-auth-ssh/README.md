# CIS-04B — Management / SSHv2 / Authentication foundation

Status: **software candidate only, PENDING evidence, NOT deployable**

This milestone adds the device-level management intent contract, PENDING Cisco
IOS XE 17.12.4 management command evidence, a fail-closed management candidate
renderer/validator, and read-only integration into the Unified Cisco Config
Preview and the existing Device Configuration Assembly.

## Delivered contracts

| Contract | Purpose |
| --- | --- |
| `cis-04b-management-intent-v1` | Revision/Assignment-bound management VLAN/IP, SSHv2 policy, local authentication, AAA/console recovery policy, opaque credential reference and blockers |
| `cis-04b-management-command-evidence-draft-v1` | PENDING official Cisco evidence rows for Catalyst 9300/9200 |
| `cis-04b-cisco-management-cli-candidate-v1` | Management command candidates; production candidates are BLOCKED and contain no text |
| `cis-04b-management-cli-validation-v1` | Independent candidate/evidence/binding validation report |

Management intent is derived from the immutable Saved Revision, existing
exact device identity, management VLAN and management IP. It does not create a
second device identity, management VLAN or saved configuration state.

## Safety invariants

- SSHv2 only; SSHv1 fallback, Telnet and plaintext management authentication
  are not part of the policy.
- RSA key state is `unknown-not-read`; no key is assumed to exist.
- Local username/secret commands never render text and cannot use a placeholder.
- No password, private key or secret value is accepted by the plan schema,
  persisted, logged, returned by the API or rendered by the UI.
- Credential References are opaque, event-scoped identifiers (`credref:<event UUID>:<opaque id>`).
  They explicitly do **not** prove that a usable secret exists.
- External AAA, a protected credential provider and console operations are
  NOT IMPLEMENTED.
- Console recovery remains unverified. Passing an SSH candidate cannot imply
  console recovery.
- No device connection, running-config read, command execution, deployment
  artifact or full configuration generation.

## Evidence state

The registry contains 18 PENDING rows (9 topics × Catalyst 9300/9200) with
Cisco IOS XE Dublin 17.12.4, exact supported PIDs, licenses, official Cisco URLs,
configuration mode, preconditions, exclusions, risks and content digests.
`renderable_count` is zero. No row has an independent REVIEWED status.

Topics:

1. management domain name
2. `ip ssh version 2`
3. RSA key generation precondition
4. local username/secret (secret-bearing; never renderable here)
5. VTY `transport input ssh`
6. line `login local`
7. `aaa new-model`
8. `aaa authentication login default local`
9. console `login authentication`

The management section remains **BLOCKED** until every required topic has a
fixed reviewed evidence digest and the authentication, credential-provider,
AAA/fallback and console-recovery gates are independently verified.

## API

```text
GET /api/v1/events/{event_id}/plan-revisions/{revision_id}/assignments/{assignment_id}/management-intent
GET .../management-cli-candidates
GET .../management-cli-validation
```

Read-only. Responses carry `X-Management-Scope: full` only after the saved
revision hash, Assignment, intent, PENDING evidence registry and validator
integrity checks pass. No body/query/header override, secret input or candidate
registry override is accepted.

## Assembly and UI

The existing `management-auth-ssh` chapter is now dynamically populated from
the management intent: required, `APPLICABLE`, `BLOCKED`, with management
reason codes and PENDING evidence references. The 12 sections and 11
cross-layer checks remain unchanged. The chapter is not COMPLETE.

The Unified Cisco Config Preview adds a Management / SSHv2 / Authentication
review panel showing management VLAN/IP, SSHv2 plan, local authentication,
AAA, console recovery, opaque credential metadata, evidence state, candidate
status and blockers. It never shows a credential reference value, secret,
private key, combined management script, Copy All, Execute or Deploy action.

## Tests

- Backend management tests cover evidence pending state, intent binding,
  credential isolation/cross-event rejection, missing/invalid management
  VLAN/IP, duplicates, unknown release evidence, PENDING and digest-tampered
  evidence, test-only reviewed renderer/validator mechanics, API scope,
  Assembly integration, old plan hash compatibility and secret leakage.
- Web tests cover management contract validation, secret-field rejection,
  SSHv1/Telnet policy rejection, console operation rejection, unverified
  candidate acceptance and responsive/English/Chinese rendering.
- C9300/C9200 L3 counts, Registry/Evidence digests and Default Route/DHCP
  Helper gates are unchanged.

## R61A independent validation closure

The production UI now fails closed unless all of the following are true:

- The management VLAN is an integer in `1..4094` and equals the selected
  trusted Saved Revision's `management_vlan`; a missing Revision Plan is
  rejected.
- The exact device identity (Assignment, hostname, role, family, PID, image,
  license and Stack identity) matches the selected Assignment.
- The Management Intent and Validation Report canonical SHA-256 fingerprints
  are recomputed in the browser with the same Python-compatible canonical JSON
  rules used by the backend.
- The Intent/Report reference exactly the frozen PENDING registry:
  `cis-04b-management-command-evidence-draft-v1` with fingerprint
  `7ad9d17396f8cd8ed2c18c70b3ca021a3932800d54b94eef9c5d22405694d640`.
- Exactly nine expected management topics are present once each.
- All production candidates remain `blocked` / `blocked`, use the PENDING
  review state, carry no CLI text, and the Summary is exactly 0 PASS / 9
  BLOCKED / 0 FAIL.
- Any client-supplied alternative Registry ID/fingerprint, REVIEWED claim, PASS
  candidate or missing/duplicate/unknown topic is rejected even if the
  response fingerprints were recomputed.

The backend Independent Validator independently derives the expected topic and
evidence set, recomputes Candidate/Document fingerprints, verifies Candidate
IDs, Evidence IDs, content digests, review states and source URLs for both
PASS and BLOCKED candidates, and derives status, Summary and Overall Status
from those checks. Resealed deletions, duplicate/unknown topics, forged
reviewed states and BLOCKED evidence tampering are rejected.

## Management chapter COMPLETE conditions

The chapter can only become COMPLETE after all of the following:

1. Every required management evidence topic has an independent REVIEWED row
   with a fixed digest for Catalyst 9300 and 9200 on 17.12.4.
2. The credential-provider integration is reviewed and can prove an event-scoped
   credential without returning or logging the secret.
3. Local authentication account creation, local fallback and VTY policy pass
   independent command validation; secret-bearing commands remain redacted.
4. Console recovery has an explicitly verified local recovery path, and no
   lockout-capable operation is generated without that path.
5. AAA external/fallback policy has reviewed servers, protocol, security scope
   and recovery evidence, or remains explicitly NOT IMPLEMENTED and required.
6. SSHv2 preconditions (domain, key state, management reachability) are
   independently verified without assuming hardware state.
7. Assembly consumes reviewed management candidates through the same exact
   source-candidate binding and canonical fingerprint rules as L2/L3, with
   independent management validation.
8. Hardware and deployment remain NOT VERIFIED / NOT ALLOWED; software
   validation must never be reported as device configuration success.
