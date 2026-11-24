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
