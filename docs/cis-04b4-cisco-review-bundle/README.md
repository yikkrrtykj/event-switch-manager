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

## R71A content revalidation and GUI eligibility closure

The bundle builder now recomputes current object fingerprints immediately before
any command text is emitted:

- L2: `recompute_candidate_fingerprint()` and
  `recompute_render_fingerprint()` for every current Candidate and Document;
  every report Candidate fingerprint and report render binding is checked.
- L3: `independent_candidate_fingerprint()`,
  `independent_render_fingerprint()` and
  `independent_report_fingerprint()` for the current objects.
- Management: the existing canonical candidate/document/report fingerprint
  helpers are recomputed for the current objects.

It does not rely only on pre-existing `integrity=True` fields.  A PASS command
text changed while its stored fingerprint is left stale is rejected; so are
stale document/report fingerprints, duplicate/missing Candidate IDs and
Report/Document/Assembly binding mismatches.

The GUI download button now requires:

- selected Saved Revision and valid Assignment;
- `role = core`;
- `family in {catalyst-9300, catalyst-9200}`;
- all relevant previews loaded, none in integrity/error state;
- Abort handling and state clearing on Revision/Assignment switch.

A trustworthy partial report with business BLOCKED candidates remains
exportable.  C3850/C2960X/C1000 Core, C9300 Access, loading and integrity-error
states are disabled.  Backend Family/Role rejection remains authoritative.
## R71B L2 Validation Report fingerprint closure

R71A recomputed current L2 Candidate and Document fingerprints, but the current
L2 Validation Report fingerprint was not yet recomputed.  R71B adds:

```text
recomputed current L2 report fingerprint
    == stored L2 report report_fingerprint
```

using the existing `layer2_cli_validation._report_fingerprint()` canonical
hash implementation.  It is checked alongside the existing:

```text
stored L2 report fingerprint
    == Assembly source L2 validation fingerprint
```

A fail-first test mutates a current L2 Report Candidate's risk findings while
leaving the Candidate Document, Candidate fingerprints, Report fingerprint,
Report integrity flags, Assembly fingerprint and Revision unchanged.  Before
the fix the bundle was produced; after the fix the backend raises
`ReviewBundleError("review-bundle-l2-report-fingerprint-mismatch")` and the API
returns a structured conflict without a download.

Normal BLOCKED candidates, unchanged PASS command text, untampered C9300/C9200
bundles and deterministic content digest behavior remain unchanged.
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
## Review and merge gate (R72 postmortem / R73)

PR #43 was merged after a clean preflight, but `gh pr ready` triggered an
asynchronous Codex review after the preflight. A new P2 thread was created
before Merge but the thread list was not re-read before Merge. The P2 finding
was real: complete filenames were passed through the component-level
64-character sanitizer, which could truncate the Revision suffix and `.json`
extension.

Required gate for future PRs:

1. Preflight: exact repository, clean worktree, Base/HEAD/Tree, merge base, PR
   state, CI bound to HEAD and current Review Threads.
2. Ready: perform only when authorized.
3. Wait while automatic review is queued or in progress; do not treat an early
   zero-thread sample as completion.
4. After review settles, read all Review Threads, Review Decision and Required
   Checks. A green `gh pr checks` does not mean zero unresolved threads.
5. Handle every new finding; stale CI PASS is not resolution.
6. Immediately before Merge, re-read HEAD, Review Decision, Review Threads and
   Required Checks. If ambiguous, do not merge.
7. Merge with the authorized method and exact head match.
8. Post-merge, re-read Review Threads, Merge Parents/Tree and main CI. A late
   finding must be recorded and stops final acceptance.

R73 filename rule: `safeFilenamePart()` keeps its 64-character per-component
limit. Complete Content-Disposition basenames are handled by
`safeCompleteFilename()`: remove directories/illegal characters, preserve the
full basename including `-r<revision>.json`, never slice the whole basename to
64 characters, and reject over-length/malformed names in favour of a safe
Revision-aware fallback.

Gate closure does not imply production authorization, hardware verification,
device connection, full configuration generation or deployment approval.