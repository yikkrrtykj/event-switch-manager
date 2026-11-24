# CIS-04B-3 — Domain-only Read-only Authorization Foundation

Status: **software foundation and isolated validation only; production authorization PENDING**

R68 introduces a separate, versioned, server-fixed Domain-only read-only
authorization contract for:

```text
ip domain name <validated-domain>
```

This is **not** a production activation.  The formal approval collections and
server-fixed provenance remain empty.

```text
DOMAIN_APPROVED_RECORDS=()
DOMAIN_ONLY_APPROVAL_PROVENANCE={}
PRODUCTION_APPROVED_RECORDS=()
MANAGEMENT_APPROVED_REVIEWS=()
```

No active production Registry is selected.  Production Management remains
**0 PASS / 9 BLOCKED**.

## Domain-only approval contract

The only allowed Evidence set is exactly:

```text
mgmt-9300-domain-name-v1
b476f57fa27800820d04ae75bd8aee091af2bb4bc7d491e4ba4a84479982473d

mgmt-9200-domain-name-v1
e221b98733c8a9df0d45d2d68878c62efcf3051e89ecdd7bcffeca30fc642b44
```

Requirements implemented:

- Exactly two records; each Evidence ID exactly once.
- SSH Version Evidence is rejected by exact-set validation.
- Fixed Family, Release `17.12.4`, official Evidence URL and digest.
- Approval scope is exactly `PRODUCTION_READONLY_CANDIDATE_DISPLAY`.
- Approval record binds reviewer, review date, review scope, findings,
  approval source URL, supplemental DNS evidence digest and a canonical
  approval payload digest.
- The reviewer/date/source/findings must exactly match the separately fixed
  `DOMAIN_ONLY_APPROVAL_PROVENANCE`; a record cannot authorize itself.
- Any approval field change changes the payload digest and invalidates the
  manifest.
- An incomplete/duplicate/unknown/tampered manifest fails closed to the
  original Draft Registry.
- No test-only Registry ID/fingerprint can become the production Registry.

## Registry

```text
Production Domain-only Registry ID:
cis-04b3-management-command-evidence-domain-only-v1

Isolated test Registry ID:
cis-04b3-management-command-evidence-domain-only-isolated-v1

Isolated test fingerprint:
8afbd0ae4fa4505575f26e7fa9d525b677dd70e0c1ddb95493c57704270f735a
```

The production Registry fingerprint is recomputed from the actual approved
reviewer/date/findings and therefore cannot be frozen before the formal
approval exists.  The isolated fixture contract fingerprint
`a8f50940020695487498cb33b73f7242565722f8caff0e990ab3f3eec509457a` belongs to
a test-only approval and must not be added to the active production allowlist.

Registry composition:

```text
Total Evidence:       18
Domain REVIEWED:      2   (only in isolated authorized test)
Other Evidence:       16 PENDING

Domain:                1 PASS
SSH Version:           1 BLOCKED
Other seven topics:    7 BLOCKED
Overall:               PARTIAL
Management Assembly:   BLOCKED
```

Production without an approval remains:

```text
Production Registry:   original Draft Registry
Production Management: 0 PASS / 9 BLOCKED
```

## PID / Ordering SKU / License semantics

R68 separates:

- Hardware/Product Model, e.g. `C9300L-24P-4X`
- Ordering SKU, e.g. `C9300L-24P-4X-E`
- Exact device PID (hardware model only)
- Declared software Release `17.12.4`
- Declared License from the Saved Revision
- Verified Active License

`-A` / `-E` are Ordering SKU suffixes that record default Network Advantage /
Network Essentials.  They are **not** the device's active license.

Explicit mapping sources:

- C9300 Release Notes 17.12.x Supported Hardware table.
- C9200 Release Notes 17.12.x Supported Hardware table.
- C9300 Hardware Installation Guide / C9200 Data Sheet for bare hardware
  models.

An exact device PID must be a hardware model.  If a Saved Revision declares an
Ordering SKU as its exact PID, the Domain candidate is blocked with:

```text
management-ordering-sku-not-exact-device-pid
```

The renderer never strips `-A/-E` and silently grants authorization.

## License evidence levels

```text
DOCUMENTED_COMPATIBILITY
DECLARED_NOT_DEVICE_VERIFIED
DEVICE_VERIFIED
UNKNOWN
UNSUPPORTED
```

Current Saved Revision licenses are marked:

```text
feature compatibility:        DOCUMENTED_COMPATIBILITY
active license evidence:      DECLARED_NOT_DEVICE_VERIFIED
active_license_verified:      false
```

No planning path has device-verified active license evidence.  A missing
license is `UNKNOWN`; a license outside Network Essentials/Advantage is
`UNSUPPORTED`.  A completely separate hardware/runtime gate is required before
any future device configuration or deployment.

## Supplemental DNS evidence

Added as read-only supplemental evidence without changing the original R63
Evidence rows or digests:

- C9300: `System Management Configuration Guide, Cisco IOS XE Dublin 17.12.x
  (Catalyst 9300 Switches) — Administering the Device > Setting Up DNS`.
- C9200: equivalent Catalyst 9200 page.

The supplemental evidence records:

- `ip domain name name`
- Global Configuration Mode
- default DNS domain: none configured
- official warning not to include the initial period separating an
  unqualified name from the domain name
- limitation that Cisco does not document the complete maximum DNS name
  length/all character-set boundaries on that page

The application's DNS regex remains a deliberately conservative application
restriction, not a claim of complete vendor CLI grammar.

## Frontend contract

The existing Unified Cisco Config Preview is reused.  An isolated explicit
contract has:

```text
reviewedTopics: ["management-domain-name"]
passed: 1
blocked: 8
overall: partial
domainTextAllowed: true
```

It is **not** added to the production Active Allowlist.  Under the explicit
isolated contract:

- Domain CLI is displayed only from the validated Candidate Document.
- Domain must match the trusted Saved Revision Assignment.
- Evidence ID, digest and source URL are exact.
- Candidate/Document/Report fingerprints are recomputed.
- SSH Version remains PENDING/BLOCKED with no CLI.
- Other seven topics remain BLOCKED.
- Missing or tampered Document hides the command.
- No Secret, Credential Value or Private Key is exposed.
- Management Assembly remains BLOCKED.

Real Python Backend serialized fixtures are checked in for C9300/C9200 and
validated by Vitest.  The production default allowlist rejects them.

## Future activation boundary

Future production read-only display still requires:

1. A formal read-only approval with fixed reviewer/date/source/findings.
2. Active License evidence for the exact device or an explicit acceptance of
   `DECLARED_NOT_DEVICE_VERIFIED`.
3. Exact hardware PID scope; no Ordering SKU substitution.
4. The Domain-only Manifest populated server-side and the production Registry
   fingerprint frozen.
5. The reviewed contract added to the frontend Active Allowlist only after
   approval.
6. Separate hardware/runtime verification before any actual configuration
   deployment.

R68 does not connect to devices, generate a full configuration, or enable
Execute/Deploy.

## Verification

- Backend tests: Domain-only 1/8, two-domain persisted versioning, API
  positive/negative paths, PID/SKU/license semantics, frozen R63 digests.
- Frontend Vitest: real C9300/C9200 Domain-only fixtures, explicit isolated
  contract, default allowlist rejection, tamper/missing-document behavior.
- Production API without approval: 0 PASS / 9 BLOCKED.
- Management Assembly: required=true / BLOCKED.
- Production authorization constants remain empty.
