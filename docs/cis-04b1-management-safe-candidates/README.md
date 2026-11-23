# CIS-04B-1 — First staged Management CLI candidates

Status: **AI document-syntax review recorded; production authorization PENDING; management CLI BLOCKED**

This milestone prepares four management Evidence rows for a future reviewed
production registry. An AI independent read-only **document-syntax review** is
recorded in a real GitHub comment, but no production activation approval has
been granted. Production remains **0 PASS / 9 BLOCKED**.
The isolated test-only path proves the intended target of 1 PASS / 8 BLOCKED
without making it available to the API or UI.

## Four staged rows

| Family | Topic | Evidence ID | Corrected Cisco section |
| --- | --- | --- | --- |
| Catalyst 9300 | management-domain-name | `mgmt-9300-domain-name-v1` | Configuring Secure Shell → Setting Up the Device to Run SSH → `ip domain name` |
| Catalyst 9300 | management-ssh-version | `mgmt-9300-ssh-version-v1` | Secure Shell Version 2 Support → `ip ssh version 2` |
| Catalyst 9200 | management-domain-name | `mgmt-9200-domain-name-v1` | Configuring Secure Shell → Setting Up the Device to Run SSH → `ip domain name` |
| Catalyst 9200 | management-ssh-version | `mgmt-9200-ssh-version-v1` | Secure Shell Version 2 Support → `ip ssh version 2` |

Official 17.12.x pages:

- 9300 SSH: `https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/sec/b_1712_sec_9300_cg/configuring_secure_shell__ssh_.html`
- 9300 SSHv2: `https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/sec/b_1712_sec_9300_cg/secure_shell_version_2_support.html`
- 9200 SSH: `https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/sec/b_1712_sec_9200_cg/configuring_secure_shell__ssh_.html`
- 9200 SSHv2: `https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/configuration_guide/sec/b_1712_sec_9200_cg/secure_shell_version_2_support.html`

Both commands are global configuration commands. The SSH version command only
selects protocol version; it does not enable the SSH server, install an RSA key,
configure authentication, VTY access or console recovery. Those gates remain
closed.

## Old and corrected content digests

| Evidence ID | Original digest | Staged digest |
| --- | --- | --- |
| `mgmt-9300-domain-name-v1` | `1350a8446a67a4aa744aabf3981508a8b4a3779da6603ae0731f2d18893189f3` | `b476f57fa27800820d04ae75bd8aee091af2bb4bc7d491e4ba4a84479982473d` |
| `mgmt-9300-ssh-version-v1` | `045576701a4effa0bcc4284b5d42d95e643e7829a60221b5d72a8b0c393a2dd7` | `27b5c1975cf2bbc98337875827b9b931d535d9aba10055f0d467cdc00b5f88f5` |
| `mgmt-9200-domain-name-v1` | `b585e1d6612794bc273e2457e1c3bad9c8f358d4cf1974f5468afaace05ab945` | `e221b98733c8a9df0d45d2d68878c62efcf3051e89ecdd7bcffeca30fc642b44` |
| `mgmt-9200-ssh-version-v1` | `be5db50d62874e19c28370b1f92a3e25a77a4bd0317da90d4b505bb95406f370` | `62786d76920888edd472a14118393db3cf608f8b2499fffc8c8a8a45b1fd6882` |

The original draft registry is unchanged:

```text
cis-04b-management-command-evidence-draft-v1
7ad9d17396f8cd8ed2c18c70b3ca021a3932800d54b94eef9c5d22405694d640
18 PENDING / 0 REVIEWED
```

The staged registry has 18 rows (4 corrected, 14 unchanged), all PENDING:

```text
cis-04b1-management-command-evidence-staged-v1
565d4ded43aa867f0e46bc16797d9ea6d6d9817286b8323a295adb94014489c2
```

## Review provenance

### R63A independent document-syntax review

A real GitHub comment records the externally supplied AI document review:

`https://github.com/yikkrrtykj/event-switch-manager/pull/40#issuecomment-7110303139`

```text
Review type: AI-independent-read-only-document-review
Reviewer: ChatGPT (GPT-6) — independent read-only AI documentation reviewer
Review date: 2026-11-23
Scope: DOCUMENT_SYNTAX_ONLY
Production authorization: NOT GRANTED
```

It confirms documentation syntax/scope only: both commands are global
configuration commands in IOS XE 17.12.x; Domain Name does not enable SSH; and
SSH Version does not replace RSA key, Authentication, VTY or Console Recovery
verification. It explicitly does not verify hardware, running License or all
device/PID combinations.

`DOCUMENT_REVIEW_RECORDS` contains four server-fixed records bound to the four
staged digests and the real comment URL. `review_status()` reports these as
`DOCUMENT-SYNTAX-REVIEWED`, never `REVIEWED`. They do not authorize production.

### Production authorization boundary

`ManagementReviewAttestation` remains a caller-supplied structural object. Its
`complete` property proves field presence only, not review identity or
authority. `build_reviewed_registry()` is test-only: without the explicit
test-only flag it raises, and even test-only registries must use a
`cis-04b1-management-test-only-*` ID. A complete-looking forged AI/Cisco
TAC/human attestation cannot activate production.

`PRODUCTION_APPROVED_RECORDS` and `MANAGEMENT_APPROVED_REVIEWS` are empty.
`production_management_registry()` returns the original PENDING draft registry.
Production Reviewed Registry activation requires a separate server-fixed,
versioned manifest with `PRODUCTION_ACTIVATION` scope and real provenance; that
is not present.

## Isolated candidate result

With the test-only reviewed registry (never reachable from the production API):

```text
Management: 1 PASS / 8 BLOCKED / 0 FAIL
Overall: PARTIAL
PASS: ip domain name example.com
SSH version: BLOCKED (authentication, RSA key state, console recovery)
Management Chapter: BLOCKED
Full Configuration: NOT ALLOWED
```

Domain parameters are validated against a strict DNS-domain grammar and the
Saved Revision. Newline, semicolon, whitespace, quotes, empty labels, trailing
dots, underscores and CLI punctuation are rejected. Only the domain row can
become a candidate in this milestone; SSH version remains blocked even with
reviewed evidence.

## Frontend and Assembly

The browser now fetches the Management Candidate Document in addition to Intent
and Validation Report. Candidate text is accepted only from the validated
Document, checked against report status/evidence binding and a strict expected
command grammar; a report-only PASS cannot display CLI. Secret-bearing rows and
all blocked rows render no command text. Candidate/document fingerprints are
recomputed and the existing frozen draft Registry gate remains active because
no reviewed production registry is approved.

The `management-auth-ssh` Assembly chapter remains required and BLOCKED; no
management CLI is added to Assembly until an independently reviewed production
registry is activated.

## Activation prerequisites

1. Independent review explicitly approves all four corrected rows and provides
   fixed reviewer/date/findings/source/digest attestations.
2. The approved manifest is committed as a versioned production contract.
3. The production registry ID and fingerprint are frozen and added to the
   frontend trusted registry contract.
4. Production API selects that registry; unknown PIDs/releases/licenses and all
   other 14 PENDING rows remain fail-closed.
5. Management auth/key/recovery gates remain in force: SSH version cannot render
   until those are verified.

Until then: `MANAGEMENT-EVIDENCE=PENDING`, `MANAGEMENT-CLI=BLOCKED`,
`FULL-CONFIG-GENERATION=NOT-ALLOWED`, `HARDWARE=NOT-VERIFIED`,
`DEPLOYMENT=NOT-ALLOWED`.
