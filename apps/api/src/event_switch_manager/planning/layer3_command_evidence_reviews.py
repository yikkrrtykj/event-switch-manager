"""Production attestations for CIS-03-03A L3 command evidence.

No production command-evidence row has been independently reviewed yet.
Consequently both tables are empty and every row in
:mod:`layer3_command_evidence` remains ``pending-independent-review``.

A record, when one exists, must contain:

* ``reviewer``: a non-empty independent reviewer identity;
* ``reviewed_at``: an ISO date;
* ``findings``: a sequence of review findings;
* ``content_digest``: the exact ``CommandEvidenceRow.content_digest()``.

The implementation author must not populate these records without a real
independent review.  Tests use an explicitly test-only registry instead.
"""

from __future__ import annotations

REVIEWED_RECORDS: dict[str, dict[str, object]] = {}
REJECTED_RECORDS: dict[str, dict[str, object]] = {}
