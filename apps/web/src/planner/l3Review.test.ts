import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api'
import type { Revision } from './model'
import {
  canLoadCandidates, coreAssignments, fetchValidation, filterReviewRows, overallKeys, parseReviewError,
  reviewErrorKey, reviewRows, validateDocument, validateReport, verdictKeys,
} from './l3Review'
import type {
  L3CandidateDocument, L3CandidateValidation, L3ValidationReport, ReviewBinding,
} from './l3Review'

const eventId = '11111111-1111-4111-8111-111111111111'
const revisionId = '22222222-2222-4222-8222-222222222222'
const assignmentId = '33333333-3333-4333-8333-333333333333'
const otherAssignmentId = '44444444-4444-4444-8444-444444444444'
const hash = 'a'.repeat(64)
const registryHash = '27d9c46f610b974de5570fb13e115260e2d109475a8d967704de9bb9ca6ef00b'

const revision: Revision = {
  id: revisionId, number: 1, content_hash: hash, created_at: '2026-11-22T00:00:00Z',
  schema_version: 1, validation_status: 'VALID', warnings: [], validation_errors: [],
  plan: {
    schema_version: 1, event_id: eventId, management_vlan: 10,
    physical_devices: [
      { id: 'device-core', vendor: 'cisco', model: 'C9300L-24P-4X' },
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
