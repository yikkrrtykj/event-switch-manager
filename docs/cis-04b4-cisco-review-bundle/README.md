# CIS-04B-4 — Cisco Read-only Review Bundle Export

Status: **read-only review artifact only; not a complete configuration or deployment artifact**

R71 adds a backend-built, single-request JSON review bundle for the existing
Cisco Config Preview.  The client supplies only the Event, saved Revision and
Cisco Assignment UUIDs; the server rebuilds every source from the persisted
revision and production selectors.

## Endpoint

```text
GET /api/v1/events/{event_id}/plan-revisions/{revision_id}/
    assignments/{assignment_id}/cisco-review-bundle
```

First batch scope: a Core Catalyst 9300 or 9200 assignment with the existing
L2, L3, Management and Assembly contracts.  Unsupported families and non-Core
assignments are rejected rather than silently reported as complete.

Response headers:

```text
Content-Disposition: attachment; filename="cisco-config-review-<event>-<device>-r<n>.json"
X-Cisco-Review-Bundle-Scope: read-only
X-Cisco-Review-Bundle-Content-Digest: <sha256>
ETag: "<sha256>"
Cache-Control: no-store
```

## JSON structure

```text
bundle_schema_version
contract_id = cis-04b-cisco-config-review-bundle-v1
generated_at                     (non-deterministic metadata)
suggested_filename               (sanitized)
content_digest                   (canonical digest of content only)
content
  report_schema_version
  report_type
  banner [
    CISCO CONFIGURATION REVIEW REPORT
    READ ONLY
    NON-EXECUTABLE
    PARTIAL CONFIGURATION CANDIDATES
    NOT HARDWARE VERIFIED
    NOT APPROVED FOR DEPLOYMENT
  ]
  identity (Event, Revision canonical hash, Assignment, hostname, role,
            family, exact PID, image, license, stack identity)
  l2 / l3 / management
    contract, Registry ID/fingerprint, Intent/Document/Validation fingerprints,
    overall status, summary, candidates
  assembly
    contract/fingerprint, completeness, 12 sections, 11 cross-layer checks,
    safety
  source_fingerprints
  safety
    read_only=true, non_executable=true,
    partial_configuration_candidates=true,
    software_validation=completed,
    hardware_verified=false, deployment_allowed=false,
    full_config_generated=false, executable=false,
    device_connection=none, device_writes_enabled=false,
    production_authorization=PENDING
  limitations
```

`generated_at` is outside `content`; the same frozen inputs therefore produce
the same canonical `content_digest`.  No timestamp enters the digest.

## Candidate command policy

- A candidate `command_text` is emitted only when the candidate document has a
  real command, its independent Verdict is `pass`, and its status is
  `candidate`.
- BLOCKED / FAILED / NOT-RUN / UNKNOWN candidates have `command_text=null`.
- Management secret-bearing candidates can never include command text.
- There is no merged configuration, CLI script, `.cfg`, deployment artifact,
  Execute or Deploy field.  The only candidate texts are individual reviewed
  commands under `PARTIAL CONFIGURATION CANDIDATES`.

## Integrity gates

The backend refuses the bundle rather than downgrading integrity errors to
ordinary BLOCKED status when:

- Revision canonical hash, Event or Assignment binding disagrees.
- L2/L3/Management source or document/evidence Registry IDs/fingerprints
  disagree.
- Candidate Document and Validation Report candidate sets or fingerprints
  disagree.
- Independent validation integrity is false.
- A blocked candidate contains command text, or a pass candidate lacks its
  document text.
- Assembly fingerprint or source fingerprints disagree.
- A required management/validation report fingerprint does not recompute.

All checks use trusted server-side objects.  The browser does not assemble the
report from separate responses.

## GUI

The existing `#cisco-preview` page has one `Download review report` button.

- Disabled while revisions/Assignment/previews are loading or no valid
  Core assignment is selected.
- Disabled for non-Core/non-supported bundle assignments.
- Switching Revision or Assignment aborts an in-flight request and clears the
  downloaded-ready state.
- The file is downloaded from the backend response; JSON remains the standard
  machine-verifiable format.
- English and Simplified Chinese messages are provided.
- No Secret, Credential Value or Private Key is sent to the browser.

## Verification

- Backend: C9300/C9200 bundle, partial/blocked candidates, unsupported family,
  non-Core rejection, revision/assignment binding, registry/assembly/report
  tamper rejection, blocked-text injection rejection, no secret material,
  deterministic content digest, frozen L3 counts and Assembly 12/11.
- Frontend: filename sanitization/Content-Disposition, exact URL binding,
  server digest, non-success rejection, real Playwright download, switch
  invalidation.
- Production Management remains **0 PASS / 9 BLOCKED**; Domain-only production
  activation is not performed.
