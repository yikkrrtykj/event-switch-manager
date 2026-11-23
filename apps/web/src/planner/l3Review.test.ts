import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api'
import type { Revision } from './model'
import {
  canLoadCandidates, coreAssignments, expectedRegistryBinding, fetchValidation, filterReviewRows,
  isUnreviewedRegistry, overallKeys, parseReviewError, reviewErrorKey, reviewRows, validateDocument,
  validateReport, verdictKeys, L3_C9200_REGISTRY_FINGERPRINT, L3_C9200_REGISTRY_ID,
  L3_UNREVIEWED_REGISTRY_FINGERPRINT, L3_UNREVIEWED_REGISTRY_ID,
} from './l3Review'
import type {
  L3CandidateDocument, L3CandidateValidation, L3Integrity, L3Source, L3SourceField,
  L3ValidationReport, ReviewBinding,
} from './l3Review'

const eventId = '11111111-1111-4111-8111-111111111111'
const revisionId = '22222222-2222-4222-8222-222222222222'
const assignmentId = '33333333-3333-4333-8333-333333333333'
const otherAssignmentId = '44444444-4444-4444-8444-444444444444'
const hash = 'a'.repeat(64)
const registryHash = '27d9c46f610b974de5570fb13e115260e2d109475a8d967704de9bb9ca6ef00b'
const unreviewedRegistryHash = L3_UNREVIEWED_REGISTRY_FINGERPRINT

const revision: Revision = {
  id: revisionId, number: 1, content_hash: hash, created_at: '2026-11-22T00:00:00Z',
  schema_version: 1, validation_status: 'VALID', warnings: [], validation_errors: [],
  plan: {
    schema_version: 1, event_id: eventId, management_vlan: 10,
    physical_devices: [
      { id: 'device-core', vendor: 'cisco', model: 'C9300L-24P-4X', verified_serial: 'R52-CORE-0001' },
      { id: 'device-access', vendor: 'cisco', model: 'C9300L-24T-4G' },
      { id: 'device-other', vendor: 'hillstone', model: 'SG6000' },
    ],
    assignments: [
      { id: assignmentId, hostname: 'Core', role: 'core', family: 'catalyst-9300',
        physical_device_id: 'device-core', software: { image: '17.12.4', license: 'Network Advantage' } },
      { id: otherAssignmentId, hostname: 'Core-ByName-Only', role: 'access', family: 'catalyst-9300',
        physical_device_id: 'device-access' },
      { id: 'assignment-other', hostname: 'Other', role: 'core', family: 'catalyst-9300',
        physical_device_id: 'device-other' },
    ],
  },
}

const sourceFields = {
  event_id: eventId, saved_revision_uuid: revisionId, revision_number: 1,
  revision_canonical_hash: hash, l3_intent_schema_version: 1,
  l3_intent_fingerprint: 'b'.repeat(64), l3_render_contract_id: 'cis-03-cisco-l3-cli-candidate-v1',
  l3_render_contract_version: 1, l3_render_fingerprint: 'c'.repeat(64),
  command_evidence_registry_id: 'cis-03-l1-command-evidence-v1',
  command_evidence_registry_fingerprint: registryHash,
  assignment_id: assignmentId, baseline_revision_uuid: null, baseline_revision_hash: null,
}

const evidence = {
  evidence_id: 'l3-9300-ip-routing-v1', topic: 'ip-routing', review_state: 'independently-reviewed',
  content_digest: 'd'.repeat(64), source_url: 'https://example.invalid/doc',
  source_section: 'IP routing', scope_ok: true, reason_codes: [],
}
const context = {
  expected_mode: 'global', actual_mode: 'global', header_bound: true, target_kind: 'device',
  target_stable_id: assignmentId, target_name: 'Core', bound: true, reason_codes: [],
}
const candidate = (id: string, category: string, verdict: L3CandidateValidation['independent_verdict']): L3CandidateValidation => ({
  candidate_id: id, category, target_kind: 'device', target_stable_id: assignmentId,
  target_name: 'Core',
  parse: { status: verdict === 'pass' ? 'pass' : 'not-run', form: category, mode: 'global',
    target_class: 'device', parameters: [], failures: verdict === 'pass' ? [] : ['blocked'] },
  evidence: verdict === 'blocked'
    ? { ...evidence, review_state: 'pending-independent-review', scope_ok: false, reason_codes: ['license-unresolved'] }
    : evidence,
  context_binding: context,
  target_capability: { capability: 'ipv4-routing', verdict: 'documented', documented: true, reason_codes: [] },
  security: { text_safe: true, reason_codes: [] }, semantics: { status: verdict, reason_codes: [] },
  risk: { renderer_risk: 'R2', independent_floor: 'R2', non_degraded: true, reason_codes: [] },
  independent_verdict: verdict, fail_closed_action: 'offline-review-only',
})

function report(): L3ValidationReport {
  return {
    validation_contract_id: 'cis-03-03-independent-cli-validation-v1',
    validation_schema_version: 1, validation_scope: 'production',
    expected_source: { ...sourceFields }, source: { ...sourceFields },
    assignment_id: assignmentId,
    device: { assignment_id: assignmentId, hostname: 'Core', role: 'core', family: 'catalyst-9300',
      exact_pid: 'C9300L-24P-4X', software_image: '17.12.4', software_license: 'Network Advantage',
      stack_identity: 'standalone', hardware_verified: false },
    integrity: {
      revision_canonical_hash: true, baseline_canonical_hash: true, intent_rebuilt: true,
      intent_fingerprint: true, expected_source: true, document_source: true,
      document_fingerprint: true, candidate_fingerprints: true, candidate_ids_unique: true,
      candidate_set: true, summary: true, safety: true,
    },
    candidates: [candidate('c1', 'ip-routing', 'pass'), candidate('c2', 'dhcp-helper-address', 'blocked')],
    summary: { total: 2, passed: 1, failed: 0, blocked: 1, not_run: 0,
      base_categories_passed: 1, base_categories_failed: 0, base_candidates_passed: 1,
      base_candidates_failed: 0, dhcp_helper_blocked: true },
    overall_status: 'partial',
    safety: { candidate_only: true, executable: false, deployable: false, deployment_allowed: false,
      hardware_verified: false, device_connection: 'none', running_config_read: false,
      device_writes_enabled: false, cli: null, deployment_artifact: null,
      independent_parser: 'cis-03-03b', parser_verified: true, deployment_authorized: false },
    report_fingerprint: 'e'.repeat(64),
  }
}

function document(): L3CandidateDocument {
  return {
    l3_render_schema_version: 1, contract_id: 'cis-03-cisco-l3-cli-candidate-v1',
    source: {
      revision_uuid: revisionId, revision_number: 1, revision_hash: hash,
      l3_intent_schema_version: 1, l3_intent_fingerprint: 'b'.repeat(64),
      command_evidence_registry_id: 'cis-03-l1-command-evidence-v1',
      command_evidence_registry_fingerprint: registryHash,
    },
    assignment_id: assignmentId,
    device: { assignment_id: assignmentId, hostname: 'Core', role: 'core', family: 'catalyst-9300',
      exact_pid: 'C9300L-24P-4X', software_image: '17.12.4',
      software_license: 'Network Advantage', stack_identity: 'standalone' },
    render_state: 'review-candidates',
    candidates: [
      { candidate_id: 'c1', assignment_id: assignmentId,
        target: { kind: 'device', stable_id: assignmentId, name: 'Core' }, category: 'ip-routing',
        command_context: { mode: 'global', mode_header: 'configure terminal', target_name: 'Core' },
        status: 'candidate', candidate_text: 'ip routing', parameters: {}, provenance: {},
        capability_evidence: [], syntax_evidence: [],
        syntax_validation: { level: 'dictionary-only', dictionary_id: 'cis-03-l1-command-dictionary-v1', parser_verified: false },
        risk_class: 'R2', potential_connectivity_impact: true, requires_field_verification: true,
        prerequisites: [], blocking_reasons: [], candidate_fingerprint: 'f'.repeat(64) },
      { candidate_id: 'c2', assignment_id: assignmentId,
        target: { kind: 'svi', stable_id: 'svi-1', name: 'Vlan20' }, category: 'dhcp-helper-address',
        command_context: { mode: 'interface', mode_header: 'interface Vlan20', target_name: 'Vlan20' },
        status: 'blocked', candidate_text: null, parameters: {}, provenance: {},
        capability_evidence: [], syntax_evidence: [],
        syntax_validation: { level: 'dictionary-only', dictionary_id: 'cis-03-l1-command-dictionary-v1', parser_verified: false },
        risk_class: 'R2', potential_connectivity_impact: true, requires_field_verification: true,
        prerequisites: [], blocking_reasons: ['syntax-evidence-pending'], candidate_fingerprint: '0'.repeat(64) },
    ],
    blocked_operations: [], unresolved_prerequisites: [], deployment_blockers: [],
    safety: { candidate_only: true, executable: false, deployable: false, deployment_allowed: false,
      hardware_verified: false, device_connection: 'none', running_config_read: false,
      device_writes_enabled: false, cli: null, deployment_artifact: null, parser_verified: false },
    summary: { total: 2, candidates: 1, blocked: 1, unsupported: 0, categories: ['ip-routing', 'dhcp-helper-address'] },
    l3_render_fingerprint: 'c'.repeat(64), verification: 'not-verified', deployment_status: 'blocked',
    executable: false, cli: null, device_writes_enabled: false,
  }
}

const binding: ReviewBinding = { eventId, revision, assignmentId }

function c9200Revision(image = '17.12.4'): Revision {
  const copied = structuredClone(revision)
  const devices = copied.plan.physical_devices as Record<string, unknown>[]
  devices[0]!.model = 'C9200L-24P-4X'
  const assignments = copied.plan.assignments as Record<string, unknown>[]
  assignments[0]!.family = 'catalyst-9200'
  assignments[0]!.software = { image, license: 'Network Advantage' }
  return copied
}

const reviewedC9200Binding: ReviewBinding = {
  eventId, revision: c9200Revision(), assignmentId,
}
const unreviewedBinding: ReviewBinding = {
  eventId, revision: c9200Revision('17.12.5'), assignmentId,
}

function unreviewedCandidate(id: string, category: string): L3CandidateValidation {
  const base = candidate(id, category, 'blocked')
  return {
    ...base,
    evidence: { ...base.evidence, evidence_id: null, topic: null, review_state: null, scope_ok: false },
  }
}

function unreviewedReport(): L3ValidationReport {
  const value = report()
  const source = {
    ...sourceFields,
    command_evidence_registry_id: L3_UNREVIEWED_REGISTRY_ID,
    command_evidence_registry_fingerprint: unreviewedRegistryHash,
  }
  return {
    ...value,
    source: { ...source },
    expected_source: { ...source },
    device: {
      ...value.device, family: 'catalyst-9200', exact_pid: 'C9200L-24P-4X',
      software_image: '17.12.5',
    },
    candidates: [
      unreviewedCandidate('c1', 'ip-routing'),
      {
        ...unreviewedCandidate('c2', 'dhcp-helper-address'),
        target_kind: 'svi', target_stable_id: 'svi-1', target_name: 'Vlan20',
      },
    ],
    summary: {
      total: 2, passed: 0, failed: 0, blocked: 2, not_run: 0,
      base_categories_passed: 0, base_categories_failed: 0,
      base_candidates_passed: 0, base_candidates_failed: 0,
      dhcp_helper_blocked: false,
    },
    overall_status: 'partial',
  }
}

function unreviewedDocument(): L3CandidateDocument {
  const value = document()
  const source = {
    ...value.source,
    command_evidence_registry_id: L3_UNREVIEWED_REGISTRY_ID,
    command_evidence_registry_fingerprint: unreviewedRegistryHash,
  }
  const candidates = value.candidates.map((item) => ({
    ...item, status: 'blocked' as const, candidate_text: null,
  }))
  return {
    ...value,
    source,
    device: {
      ...value.device, family: 'catalyst-9200', exact_pid: 'C9200L-24P-4X',
      software_image: '17.12.5',
    },
    candidates,
    render_state: 'blocked',
    summary: { ...value.summary, candidates: 0, blocked: 2, unsupported: 0 },
  }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('L3 review data contracts', () => {
  it('binds all fourteen source fields and keeps PARTIAL distinct from PASS', () => {
    expect(validateReport(report(), binding)).toEqual([])
    expect(overallKeys.partial).toBe('overallPartial')
    expect(overallKeys.partial).not.toBe(overallKeys.pass)
    expect(verdictKeys.pass).toBe('verdictPass')
  })

  it('binds 9300, reviewed C9200 and unreviewed identities to three fixed registries', () => {
    expect(expectedRegistryBinding(binding)).toMatchObject({
      registryId: 'cis-03-l1-command-evidence-v1',
      registryFingerprint: registryHash,
      evidenceApproved: true,
    })
    expect(expectedRegistryBinding(reviewedC9200Binding)).toMatchObject({
      registryId: L3_C9200_REGISTRY_ID,
      registryFingerprint: L3_C9200_REGISTRY_FINGERPRINT,
      evidenceApproved: true,
    })
    expect(expectedRegistryBinding(unreviewedBinding)).toMatchObject({
      registryId: L3_UNREVIEWED_REGISTRY_ID,
      registryFingerprint: unreviewedRegistryHash,
      evidenceApproved: false,
    })
    expect(validateReport(report(), binding)).toEqual([])
    const sentinel = unreviewedReport()
    expect(validateReport(sentinel, unreviewedBinding)).toEqual([])
    expect(isUnreviewedRegistry(sentinel)).toBe(true)
    expect(validateDocument(sentinel, unreviewedDocument(), unreviewedBinding)).toEqual([])
  })

  it('rejects a sentinel on 9300, a 9300 registry on C9200, and forged registry contracts', () => {
    const sentinelOn9300 = report()
    sentinelOn9300.source = {
      ...sentinelOn9300.source,
      command_evidence_registry_id: L3_UNREVIEWED_REGISTRY_ID,
      command_evidence_registry_fingerprint: unreviewedRegistryHash,
    }
    expect(validateReport(sentinelOn9300, binding)).toContain('source-binding')

    const reviewedRegistryOnC9200 = unreviewedReport()
    reviewedRegistryOnC9200.source = {
      ...reviewedRegistryOnC9200.source,
      command_evidence_registry_id: 'cis-03-l1-command-evidence-v1',
    }
    expect(validateReport(reviewedRegistryOnC9200, unreviewedBinding)).toContain('source-binding')

    for (const source of [
      { command_evidence_registry_id: 'forged-registry', command_evidence_registry_fingerprint: unreviewedRegistryHash },
      { command_evidence_registry_id: L3_UNREVIEWED_REGISTRY_ID, command_evidence_registry_fingerprint: '0'.repeat(64) },
      { command_evidence_registry_id: 'cis-03-l1-command-evidence-v1', command_evidence_registry_fingerprint: unreviewedRegistryHash },
    ]) {
      const forged = unreviewedReport()
      forged.source = { ...forged.source, ...source }
      expect(validateReport(forged, unreviewedBinding)).toContain('source-binding')
      expect(validateDocument(forged, unreviewedDocument(), unreviewedBinding)).toContain('document-source')
    }
  })

  it('rejects a report device that differs from the trusted C9200 identity', () => {
    for (const change of [
      { family: 'catalyst-9300' },
      { exact_pid: 'C9300L-24P-4X' },
      { software_image: '17.12.6' },
      { software_license: 'Network Essentials' },
    ]) {
      const forged = unreviewedReport()
      forged.device = { ...forged.device, ...change }
      expect(validateReport(forged, unreviewedBinding)).toContain('report-device')
    }
  })

  it('rejects PASS candidates, reviewed evidence and PASS overall in a sentinel report', () => {
    const pass = unreviewedReport()
    pass.candidates[0] = candidate('c1', 'ip-routing', 'pass')
    pass.summary = { ...pass.summary, passed: 1, blocked: 1 }
    expect(validateReport(pass, unreviewedBinding)).toContain('report-candidates')

    const reviewed = unreviewedReport()
    reviewed.candidates[0] = {
      ...reviewed.candidates[0]!,
      evidence: { ...reviewed.candidates[0]!.evidence, review_state: 'independently-reviewed' },
    }
    expect(validateReport(reviewed, unreviewedBinding)).toContain('report-candidates')

    const overall = unreviewedReport()
    overall.overall_status = 'pass'
    overall.summary = {
      ...overall.summary, blocked: 0, passed: 2,
      base_categories_passed: 2, base_candidates_passed: 2,
    }
    expect(validateReport(overall, unreviewedBinding)).toContain('report-candidates')
  })

  it('rejects CLI text or a candidate status in a sentinel candidate document', () => {
    const text = unreviewedDocument()
    text.candidates[0] = {
      ...text.candidates[0]!, status: 'candidate', candidate_text: 'ip routing',
    }
    text.summary = { ...text.summary, candidates: 1, blocked: 1 }
    const problems = validateDocument(unreviewedReport(), text, unreviewedBinding)
    expect(problems).toContain('document-candidates')
    expect(problems).toContain('candidate-text')
  })

  it('fails closed when the trusted C9200 identity is incomplete', () => {
    const incomplete = structuredClone(unreviewedBinding.revision)
    const devices = incomplete.plan.physical_devices as Record<string, unknown>[]
    delete devices[0]!.verified_serial
    expect(expectedRegistryBinding({ ...unreviewedBinding, revision: incomplete })).toBeNull()
    expect(validateReport(unreviewedReport(), { ...unreviewedBinding, revision: incomplete }))
      .toContain('report-device')
  })

  it('rejects a forged revision number in ActualSource even when ExpectedSource is unchanged', () => {
    const forged = report()
    forged.source = { ...forged.source, revision_number: 2 }
    expect(validateReport(forged, binding)).toContain('expected-source')
  })

  it('rejects source binding to another revision or assignment', () => {
    const forged = report()
    forged.source = { ...forged.source, saved_revision_uuid: otherAssignmentId }
    expect(validateReport(forged, binding)).toContain('source-binding')
    const wrong = report()
    wrong.assignment_id = otherAssignmentId
    expect(validateReport(wrong, binding)).toContain('report-assignment')
    const registry = report()
    registry.source = { ...registry.source, command_evidence_registry_fingerprint: '0'.repeat(64) }
    expect(validateReport(registry, binding)).toContain('source-binding')
  })

  it('does not request candidates for a report containing FAIL', () => {
    const failed = report()
    failed.overall_status = 'fail'
    failed.candidates = [candidate('c1', 'ip-routing', 'fail')]
    failed.summary = { ...failed.summary, total: 1, passed: 0, failed: 1, blocked: 0, not_run: 0 }
    expect(canLoadCandidates(failed)).toBe(false)
  })

  it('requires every fixed integrity field to be present and strictly true', () => {
    const complete = report()
    expect(validateReport(complete, binding)).toEqual([])
    expect(canLoadCandidates(complete)).toBe(true)

    const missingCandidateSet = report().integrity
    delete (missingCandidateSet as Partial<L3Integrity>).candidate_set
    const missingRevisionHash = report().integrity
    delete (missingRevisionHash as Partial<L3Integrity>).revision_canonical_hash
    const missingSafety = report().integrity
    delete (missingSafety as Partial<L3Integrity>).safety
    const falseField = { ...report().integrity, summary: false }
    const nullField = { ...report().integrity, candidate_set: null }
    const stringTrue = { ...report().integrity, safety: 'true' }
    const empty = {}
    const arrayInsteadOfObject: unknown = []
    const extraInsteadOfMissing = { ...report().integrity, extra: true }
    delete (extraInsteadOfMissing as Partial<L3Integrity>).candidate_set
    for (const integrity of [
      missingCandidateSet, missingRevisionHash, missingSafety,
      falseField, nullField, stringTrue, empty, arrayInsteadOfObject, extraInsteadOfMissing,
    ]) {
      const forged = report()
      forged.integrity = integrity as L3Integrity
      expect(validateReport(forged, binding), JSON.stringify(integrity)).toContain('report-integrity')
      expect(canLoadCandidates(forged)).toBe(false)
    }
  })

  it('requires all fourteen source fields instead of normalizing missing values to null', () => {
    const missing = (source: L3Source, field: L3SourceField): L3Source => {
      const copy = { ...source } as Record<string, unknown>
      delete copy[field]
      return copy as L3Source
    }
    const legalEmpty = report()
    expect(validateReport(legalEmpty, binding)).toEqual([])

    const actualMissingHash = report()
    actualMissingHash.source = missing(actualMissingHash.source, 'baseline_revision_hash')
    expect(validateReport(actualMissingHash, binding)).toContain('actual-source')
    expect(canLoadCandidates(actualMissingHash)).toBe(false)

    const expectedMissingHash = report()
    expectedMissingHash.expected_source = missing(
      expectedMissingHash.expected_source, 'baseline_revision_hash',
    )
    expect(validateReport(expectedMissingHash, binding)).toContain('expected-source')
    expect(canLoadCandidates(expectedMissingHash)).toBe(false)

    const bothMissingHash = report()
    bothMissingHash.source = missing(bothMissingHash.source, 'baseline_revision_hash')
    bothMissingHash.expected_source = missing(
      bothMissingHash.expected_source, 'baseline_revision_hash',
    )
    const bothHashProblems = validateReport(bothMissingHash, binding)
    expect(bothHashProblems).toContain('actual-source')
    expect(bothHashProblems).toContain('expected-source')
    expect(canLoadCandidates(bothMissingHash)).toBe(false)

    const bothMissingIntent = report()
    bothMissingIntent.source = missing(bothMissingIntent.source, 'l3_intent_fingerprint')
    bothMissingIntent.expected_source = missing(
      bothMissingIntent.expected_source, 'l3_intent_fingerprint',
    )
    expect(validateReport(bothMissingIntent, binding)).toContain('actual-source')
    expect(validateReport(bothMissingIntent, binding)).toContain('expected-source')
    expect(canLoadCandidates(bothMissingIntent)).toBe(false)

    const undefinedBaselineHash = report()
    undefinedBaselineHash.source = {
      ...undefinedBaselineHash.source, baseline_revision_uuid: null, baseline_revision_hash: undefined,
    } as unknown as L3Source
    expect(validateReport(undefinedBaselineHash, binding)).toContain('actual-source')
    expect(canLoadCandidates(undefinedBaselineHash)).toBe(false)

    const legalRevision2 = report()
    const baselineUuid = '99999999-9999-4999-8999-999999999999'
    const baselineHash = 'd'.repeat(64)
    for (const frame of [legalRevision2.source, legalRevision2.expected_source]) {
      frame.baseline_revision_uuid = baselineUuid
      frame.baseline_revision_hash = baselineHash
    }
    expect(validateReport(legalRevision2, binding)).toEqual([])
  })

  it('keeps BLOCKED command text null and requires matching candidate IDs', () => {
    const rows = reviewRows(report(), document())
    expect(rows.find((row) => row.candidateId === 'c1')?.text).toBe('ip routing')
    expect(rows.find((row) => row.candidateId === 'c2')?.text).toBeNull()
    expect(rows.find((row) => row.candidateId === 'c2')?.status).toBe('blocked')
    const forged = document()
    forged.source = { ...forged.source, revision_hash: '0'.repeat(64) }
    expect(validateDocument(report(), forged, binding)).toContain('document-source')
    const missing = document()
    missing.candidates.pop()
    expect(validateDocument(report(), missing, binding)).toContain('document-candidates')
  })

  it('does not expose command text when no candidate document is bound', () => {
    expect(reviewRows(report()).every((row) => row.text === null)).toBe(true)
  })

  it('filters only the local table view and leaves the report summary unchanged', () => {
    const rows = reviewRows(report(), document())
    const filtered = filterReviewRows(rows, 'ip-routing', '')
    expect(filtered).toHaveLength(1)
    expect(report().summary).toMatchObject({ total: 2, passed: 1, blocked: 1 })
    expect(filterReviewRows(rows, '', 'blocked')).toHaveLength(1)
  })

  it('detects Cisco Core by role and Cisco vendor, never by hostname', () => {
    const cores = coreAssignments(revision.plan)
    expect(cores).toHaveLength(1)
    expect(cores[0]?.assignmentId).toBe(assignmentId)
    const fake = { ...revision.plan, assignments: [
      { id: assignmentId, hostname: 'Core-Any-Name', role: 'access', physical_device_id: 'device-core' },
    ] }
    expect(coreAssignments(fake)).toEqual([])
  })

  it('parses stable structured API errors without trusting raw text', () => {
    const error = parseReviewError(new ApiError(409, {
      reason_code: 'assignment-not-eligible-for-l3-cli', stage: 'assignment', failures: ['not-core'],
    }))
    expect(error).toEqual({
      status: 409, reasonCode: 'assignment-not-eligible-for-l3-cli',
      stage: 'assignment', failures: ['not-core'],
    })
    expect(reviewErrorKey(error)).toBe('l3AssignmentNotEligible')
    expect(reviewErrorKey(parseReviewError(new ApiError(409, {
      reason_code: 'candidate-document-not-reviewable',
    })))).toBe('l3CandidateDocumentNotReviewable')
    expect(reviewErrorKey(parseReviewError(new ApiError(400, {})))).toBe('l3RequestRejected')
    expect(reviewErrorKey(parseReviewError(new ApiError(404, {})))).toBe('l3ReviewNotFound')
    expect(reviewErrorKey(parseReviewError(new ApiError(422, {})))).toBe('l3ReviewUnprocessable')
    expect(reviewErrorKey(parseReviewError(new Error('offline')))).toBe('l3ReviewNetworkError')
  })

  it('requires the full validation scope header and preserves the report on success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(report()), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    })))
    await expect(fetchValidation(eventId, revisionId, assignmentId)).rejects.toMatchObject({ status: 409 })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(report()), {
      status: 200, headers: { 'Content-Type': 'application/json', 'X-Validation-Scope': 'full' },
    })))
    await expect(fetchValidation(eventId, revisionId, assignmentId)).resolves.toMatchObject({
      validation_scope: 'production', overall_status: 'partial',
    })
  })
})
