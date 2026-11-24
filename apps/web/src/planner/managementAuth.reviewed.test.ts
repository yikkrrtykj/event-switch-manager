import { describe, expect, it } from 'vitest'
import { canonicalSha256 } from './canonical'
import c9300Raw from './fixtures/management-reviewed-c9300.json'
import c9200Raw from './fixtures/management-reviewed-c9200.json'
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
  describe(`${family} real backend reviewed fixture`, () => {
    it('accepts the real API response only under the explicit reviewed contract', () => {
      const { review, binding, contract } = parse(raw)
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
      expect(sshReport?.evidence_review_state).toBe('independently-reviewed')
      expect(sshReport?.status).toBe('blocked')
      expect(review.report.summary).toEqual({
        total: 9, passed: 1, blocked: 8, failed: 0,
      })
    })

    it('rejects reviewed evidence when SSH review state is downgraded to pending', () => {
      const { review, binding, contract } = parse(structuredClone(raw))
      const sshReport = review.report.candidates.find(
        (candidate) => candidate.topic === 'management-ssh-version',
      )!
      const sshDocument = review.document.candidates.find(
        (candidate) => candidate.topic === 'management-ssh-version',
      )!
      sshReport.evidence_review_state = 'pending-independent-review'
      sshDocument.evidence_review_state = 'pending-independent-review'
      resealDocument(review)
      resealReview(review)
      expect(validateManagementReview(review, binding, [contract]))
        .toContain('management-reviewed-claim')
    })

    it('rejects a pending topic claiming reviewed evidence', () => {
      const { review, binding, contract } = parse(structuredClone(raw))
      const report = review.report.candidates.find(
        (candidate) => candidate.topic === 'management-rsa-key',
      )!
      const document = review.document.candidates.find(
        (candidate) => candidate.topic === 'management-rsa-key',
      )!
      report.evidence_review_state = 'independently-reviewed'
      document.evidence_review_state = 'independently-reviewed'
      resealDocument(review)
      resealReview(review)
      expect(validateManagementReview(review, binding, [contract]))
        .toContain('management-reviewed-claim')
    })

    it('keeps SSH version blocked even when evidence is reviewed', () => {
      const { review, binding, contract } = parse(structuredClone(raw))
      const report = review.report.candidates.find(
        (candidate) => candidate.topic === 'management-ssh-version',
      )!
      const document = review.document.candidates.find(
        (candidate) => candidate.topic === 'management-ssh-version',
      )!
      report.status = 'candidate'
      report.independent_verdict = 'pass'
      report.candidate_text_present = true
      document.status = 'candidate'
      document.candidate_text = 'ip ssh version 2'
      resealDocument(review)
      resealReview(review)
      expect(validateManagementReview(review, binding, [contract]).length)
        .toBeGreaterThan(0)
    })

    it('rejects domain changes against the trusted Saved Revision', () => {
      const { review, binding, contract } = parse(structuredClone(raw))
      const assignment = (binding.revision.plan as unknown as {
        assignments: Record<string, unknown>[]
      }).assignments.find(
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

    it('rejects evidence digest/source tampering after resealing', () => {
      const { review, binding, contract } = parse(structuredClone(raw))
      const report = review.report.candidates.find(
        (candidate) => candidate.topic === 'management-domain-name',
      )!
      const document = review.document.candidates.find(
        (candidate) => candidate.topic === 'management-domain-name',
      )!
      report.evidence_content_digest = '0'.repeat(64)
      document.evidence_content_digest = '0'.repeat(64)
      resealDocument(review)
      resealReview(review)
      expect(validateManagementReview(review, binding, [contract]))
        .toContain('management-evidence-binding')

      const source = parse(structuredClone(raw))
      const sourceReport = source.review.report.candidates.find(
        (candidate) => candidate.topic === 'management-domain-name',
      )!
      const sourceDocument = source.review.document.candidates.find(
        (candidate) => candidate.topic === 'management-domain-name',
      )!
      sourceReport.evidence_source_url = 'https://www.cisco.com/forged.html'
      sourceDocument.evidence_source_url = 'https://www.cisco.com/forged.html'
      resealDocument(source.review)
      resealReview(source.review)
      expect(validateManagementReview(source.review, source.binding,
        [source.contract])).toContain('management-evidence-binding')
    })

    it('hides CLI when the document is missing or inconsistent', () => {
      const missing = parse(structuredClone(raw))
      delete (missing.review as unknown as Record<string, unknown>).document
      expect(validateManagementReview(
        missing.review, missing.binding, [missing.contract],
      )).toContain('management-document-contract')

      const mismatch = parse(structuredClone(raw))
      mismatch.review.report.candidates[0]!.evidence_id = 'mgmt-forged'
      resealReview(mismatch.review)
      expect(validateManagementReview(
        mismatch.review, mismatch.binding, [mismatch.contract],
      )).toContain('management-document-binding')
    })

    it('is rejected by the production default allowlist', () => {
      const { review, binding } = parse(structuredClone(raw))
      expect(validateManagementReview(review, binding))
        .toContain('management-pending-registry')
    })
  })
}
