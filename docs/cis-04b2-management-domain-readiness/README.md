# CIS-04B-2 — Management Domain CLI Production Readiness

Status: **software readiness only; production authorization PENDING; management CLI BLOCKED**

This milestone proves the complete read-only call chain for the first future
production Management command:

```text
Saved Revision → Management Intent → Candidate Document → Independent Validator
→ Management API → Unified Cisco Config Preview
```

No Production Reviewed Registry is activated. `PRODUCTION_APPROVED_RECORDS` and
`MANAGEMENT_APPROVED_REVIEWS` remain empty. Production Management remains
0 PASS / 9 BLOCKED.

## Review status gate

`review_status()` now returns production `REVIEWED` only when the complete
server-fixed Production Manifest passes whole-manifest validation. A single
record with `production_authorized=True`, an incomplete/duplicate/unknown
Manifest, or a caller-supplied Attestation cannot return `REVIEWED`.
Document-syntax records remain `DOCUMENT-SYNTAX-REVIEWED` only.

## Registry → Intent binding

`build_management_intent(..., evidence_registry=...)` now uses the selected
Registry ID, fingerprint and evidence status:

- Draft Registry → `PENDING`.
- Four reviewed rows plus fourteen pending rows → `PARTIAL`.
- All rows reviewed → `REVIEWED`.

Candidate Document and Independent Validator require the Intent identity to
match the selected Registry ID/fingerprint exactly. A Registry/fingerprint
mismatch is rejected with `management-intent-registry-mismatch`.

The production selector remains server-fixed: the empty production Manifest
returns the original Draft Registry. The API never enables
`test_only_registry=True`.

## Isolated readiness result

With a temporary server-side production test-double manifest (never committed
to production constants), the real Management API read-only path returns:

```text
Management Intent registry: cis-04b1-management-command-evidence-reviewed-v1
Management evidence status: PARTIAL
Candidate/Validation: 1 PASS / 8 BLOCKED / 0 FAIL
Overall: PARTIAL
Domain candidate: ip domain name example.com
SSH version: BLOCKED
Management Assembly chapter: BLOCKED
```

This proves software readiness. It is explicitly not production authorization.
The temporary manifest is monkeypatched only within tests and restored to empty.

## Frontend trust contract

The browser has a versioned `ManagementRegistryTrustContract` allowlist. The
active production contract is only the frozen PENDING Draft Registry with
0 PASS / 9 BLOCKED.

A reviewed contract can be supplied only explicitly, for isolated tests. Under
that contract the browser validates:

- Registry ID/fingerprint match.
- Intent/Document/Report canonical fingerprints.
- Exactly one verified Domain Name candidate and eight blocked rows.
- Document text is exactly `ip domain name <validated-domain>`.
- Other eight topics remain blocked and textless.
- Server fields alone cannot add a reviewed contract to the active production
  allowlist.

The future real reviewed contract may be added only after independent production
authorization and version/fingerprint freeze. `management-auth-ssh` Assembly
remains required and BLOCKED.

## R65A reviewed-contract closure

The reviewed readiness path now distinguishes Evidence Review State from
Candidate Verdict:

| Topic | Evidence Review | Candidate | CLI |
| --- | --- | --- | --- |
| management-domain-name | independently-reviewed | PASS | `ip domain name <validated>` |
| management-ssh-version | independently-reviewed | BLOCKED | none |
| other seven topics | pending-independent-review | BLOCKED | none |

The frontend derives the expected review state from the trusted Registry
contract and topic, not from arbitrary server fields. SSH Version cannot become
PASS merely because its Evidence is reviewed.

Domain Name is also bound to the trusted Saved Revision Assignment:

```text
intent.management_domain == revision.plan.assignments[current].management_domain
```

A missing Assignment, missing domain, non-string/invalid domain, or a response
domain that differs from the Saved Revision is rejected even after recomputing
Intent/Document/Report fingerprints.

The reviewed Evidence ID/Digest/Source are frozen for the four R63 entries.
Report and Document must carry the same actual Evidence Content Digest and
Source URL; 64-hex format and a Cisco hostname prefix alone are insufficient.

Real backend fixtures were generated from the Python Management API using an
isolated temporary production test-double Manifest and committed under
`apps/web/src/planner/fixtures/` for C9300 and C9200. Vitest validates the
actual Intent, Candidate Document and Validation Report, including both
REVIEWED-but-BLOCKED SSH evidence and the single Domain PASS, under an explicit
test-only Reviewed trust contract. Production active allowlist still contains
only the Draft Registry; the reviewed test contract is rejected by default.

A backend test verifies the serialized fixtures' reviewed Registry ID,
fingerprint, both reviewed topics, digest/source, 1/8 summary and trusted
Saved Revision domain. Production constants remain empty.
## Activation prerequisites

1. Independent production approval covering exact Evidence digests, Reviewer,
   Date, Findings, source record, PID, IOS XE Release, License and command risk.
2. A fixed server-side `PRODUCTION_APPROVED_RECORDS` manifest with exactly the
   four unique fixed Evidence/Record identities.
3. A versioned Production Registry ID/fingerprint selected only by the server
   manifest.
4. Frontend reviewed contract added to the explicit allowlist after approval.
5. Separate Production Registry authorization; machine-readable readiness and
   CI success do not substitute for it.
6. Management assembly remains BLOCKED; SSH/AAA/VTY/Console/Secret commands
   remain blocked.

## Non-goals

No `ip ssh version 2` activation, RSA key generation, local username/secret,
VTY/login, AAA/console, full configuration script, Execute/Deploy, hardware
connection or deployment is added.
