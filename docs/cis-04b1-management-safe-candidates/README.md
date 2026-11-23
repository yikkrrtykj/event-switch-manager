# CIS-04B-1 — First staged Management CLI candidates

Status: **staged/PENDING independent review; production management CLI remains BLOCKED**

This milestone prepares four management Evidence rows for a future reviewed
production registry. No independent reviewer has approved the staged rows, so no
production review is activated and production remains **0 PASS / 9 BLOCKED**.
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

## Review binding

`ManagementReviewAttestation` binds each staged row to:

- Evidence ID and exact corrected Content Digest.
- Reviewer, review date, findings and official source URL.
- Explicit AI-review disclosure where applicable.

The fixed approved manifest is deliberately empty. A manifest must contain
exactly four distinct, complete attestations with matching digest/source; any
missing, duplicate, unknown, forged or stale entry raises
`ManagementReviewError`. Evidence content changes automatically invalidate old
attestations because the digest no longer matches.

`production_management_registry()` returns the original draft registry while
the approved manifest is empty. It never activates a registry based only on a
client-provided ID/fingerprint or `test_only_registry=True`.

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
