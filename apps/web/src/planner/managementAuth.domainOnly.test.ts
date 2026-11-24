import { describe, expect, it } from 'vitest'
import { canonicalSha256 } from './canonical'
import c9300Raw from './fixtures/management-domain-only-c9300.json'
import c9200Raw from './fixtures/management-domain-only-c9200.json'
import type { PreviewBinding } from './ciscoPreview'
import { validateManagementReview } from './managementAuth'
import type {
  ManagementCandidateDocument, ManagementIntent,
  ManagementRegistryTrustContract, ManagementReview,
  ManagementValidationReport,
} from './managementAuth'

interface SerializedFixture {
  contract: ManagementRegistryTrustContract
  binding: PreviewBinding
  intent: ManagementIntent
  document: ManagementCandidateDocument
  report: ManagementValidationReport
}

function withoutKey(value: object, key: string): Record<string, unknown> {
  const copy = { ...value } as Record<string, unknown>
  delete copy[key]
  return copy
}

function resealDocument(review: ManagementReview): void {
  for (const candidate of review.document.candidates) {
    candidate.candidate_fingerprint = canonicalSha256(
      withoutKey(candidate, 'candidate_fingerprint'),
    )
  }
  review.document.render_fingerprint = canonicalSha256(
    withoutKey(review.document, 'render_fingerprint'),
  )
}

function resealReview(review: ManagementReview): ManagementReview {
  review.intent.intent_fingerprint = canonicalSha256(
    withoutKey(review.intent, 'intent_fingerprint'),
  )
  review.report.source.management_intent_fingerprint =
    review.intent.intent_fingerprint
  review.report.expected_source.management_intent_fingerprint =
    review.intent.intent_fingerprint
  review.report.source.evidence_registry_id = review.intent.evidence_registry_id
  review.report.expected_source.evidence_registry_id =
    review.intent.evidence_registry_id
  review.report.source.evidence_registry_fingerprint =
    review.intent.evidence_registry_fingerprint
  review.report.expected_source.evidence_registry_fingerprint =
    review.intent.evidence_registry_fingerprint
  review.report.report_fingerprint = canonicalSha256(
    withoutKey(review.report, 'report_fingerprint'),
  )
  review.document.source = { ...review.report.source }
  review.document.render_fingerprint = canonicalSha256(
    withoutKey(review.document, 'render_fingerprint'),
  )
  return review
}

function parse(raw: unknown): {
  review: ManagementReview
  binding: PreviewBinding
  contract: ManagementRegistryTrustContract
} {
  const fixture = raw as SerializedFixture
  return {
    review: {
      intent: fixture.intent,
      document: fixture.document,
      report: fixture.report,
    },
    binding: fixture.binding,
    contract: fixture.contract,
  }
}

const fixtures = [
  ['C9300', c9300Raw],
  ['C9200', c9200Raw],
] as const

for (const [family, raw] of fixtures) {
  describe(`${family} real Domain-only backend fixture`, () => {
    it('accepts only the explicit isolated Domain-only contract', () => {
      const { review, binding, contract } = parse(structuredClone(raw))
      expect(contract.reviewedTopics).toEqual(['management-domain-name'])
      expect(contract.passed).toBe(1)
      expect(contract.blocked).toBe(8)
      expect(validateManagementReview(review, binding, [contract])).toEqual([])
      const domain = review.document.candidates.find(
        (candidate) => candidate.topic === 'management-domain-name',
      )
      const ssh = review.document.candidates.find(
        (candidate) => candidate.topic === 'management-ssh-version',
      )
      const sshReport = review.report.candidates.find(
        (candidate) => candidate.topic === 'management-ssh-version',
      )
      expect(domain?.candidate_text).toBe('ip domain name example.com')
      expect(ssh?.candidate_text).toBeNull()
      expect(sshReport?.evidence_review_state).toBe(
        'pending-independent-review',
      )
      expect(sshReport?.status).toBe('blocked')
      expect(review.report.summary).toEqual({
        total: 9, passed: 1, blocked: 8, failed: 0,
      })
    })

    it('is rejected by the production default allowlist', () => {
      const { review, binding } = parse(structuredClone(raw))
      expect(validateManagementReview(review, binding))
        .toContain('management-pending-registry')
    })

    it('rejects a wrong registry fingerprint', () => {
      const { review, binding, contract } = parse(structuredClone(raw))
      expect(validateManagementReview(review, binding, [{
        ...contract,
        fingerprint: '0'.repeat(64),
      }])).toContain('management-pending-registry')
    })

    it('rejects giving SSH Version a reviewed state', () => {
      const { review, binding, contract } = parse(structuredClone(raw))
      const report = review.report.candidates.find(
        (candidate) => candidate.topic === 'management-ssh-version',
      )!
      const document = review.document.candidates.find(
        (candidate) => candidate.topic === 'management-ssh-version',
      )!
      report.evidence_review_state = 'independently-reviewed'
      document.evidence_review_state = 'independently-reviewed'
      resealDocument(review)
      resealReview(review)
      expect(validateManagementReview(review, binding, [contract]))
        .toContain('management-reviewed-claim')
      // A reviewed SSH topic is not part of this Domain-only contract.  The
      // production active allowlist has no such contract either.
      expect(contract.reviewedTopics).not.toContain('management-ssh-version')
    })

    it('rejects an unsaved or mismatched Saved Revision domain', () => {
      const { review, binding, contract } = parse(structuredClone(raw))
      const plan = binding.revision.plan as unknown as {
        assignments: Record<string, unknown>[]
      }
      const assignment = plan.assignments.find(
        (item) => item.id === binding.assignment.assignmentId,
      )!
      assignment.management_domain = 'other.example.com'
      expect(validateManagementReview(review, binding, [contract]))
        .toContain('management-domain-binding')

      const second = parse(structuredClone(raw))
      second.review.intent.management_domain = 'other.example.com'
      const domainDocument = second.review.document.candidates.find(
        (candidate) => candidate.topic === 'management-domain-name',
      )!
      domainDocument.candidate_text = 'ip domain name other.example.com'
      resealDocument(second.review)
      resealReview(second.review)
      expect(validateManagementReview(second.review, second.binding,
        [second.contract])).toContain('management-domain-binding')
    })

    it('hides the command when the document is missing or forged', () => {
      const missing = parse(structuredClone(raw))
      delete (missing.review as unknown as Record<string, unknown>).document
      expect(validateManagementReview(
        missing.review, missing.binding, [missing.contract],
      )).toContain('management-document-contract')

      const forged = parse(structuredClone(raw))
      forged.review.document.candidates[0]!.evidence_content_digest =
        '0'.repeat(64)
      forged.review.document.candidates[0]!.evidence_source_url =
        'https://www.cisco.com/forged.html'
      resealDocument(forged.review)
      resealReview(forged.review)
      expect(validateManagementReview(
        forged.review, forged.binding, [forged.contract],
      )).toContain('management-document-binding')

      const digest = parse(structuredClone(raw))
      const domainReport = digest.review.report.candidates.find(
        (candidate) => candidate.topic === 'management-domain-name',
      )!
      const domainDocument = digest.review.document.candidates.find(
        (candidate) => candidate.topic === 'management-domain-name',
      )!
      domainReport.evidence_content_digest = '0'.repeat(64)
      domainDocument.evidence_content_digest = '0'.repeat(64)
      resealDocument(digest.review)
      resealReview(digest.review)
      expect(validateManagementReview(
        digest.review, digest.binding, [digest.contract],
      )).toContain('management-evidence-binding')
    })
  })
}
