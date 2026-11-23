import { describe, expect, it } from 'vitest'

import { ApiError } from '../api'
import type { RecordValue, Revision } from './model'
import {
  L2_PREVIEW_CONTRACT,
  L2_REGISTRY_FINGERPRINT,
  L2_REGISTRY_ID,
  L2_RENDER_CONTRACT,
  L2_VALIDATION_CONTRACT,
  ciscoAssignments,
  isL2NotApplicable,
  l2ReviewRows,
  l2Status,
  overallStatus,
  parsePreviewError,
  validateL2Document,
  validateL2Report,
} from './ciscoPreview'
import type {
  CiscoAssignment,
  L2CandidateDocument,
  L2CandidateValidation,
  L2Integrity,
  L2Source,
  L2ValidationReport,
  PreviewBinding,
} from './ciscoPreview'

const eventId = '11111111-1111-4111-8111-111111111111'
const revisionId = '22222222-2222-4222-8222-222222222222'
const assignmentId = '33333333-3333-4333-8333-333333333333'
const hash = 'a'.repeat(64)

const revision: Revision = {
  id: revisionId, number: 1, content_hash: hash, created_at: '2026-11-22T00:00:00Z',
  schema_version: 1, validation_status: 'VALID', warnings: [], validation_errors: [],
  plan: {
    schema_version: 1, event_id: eventId, management_vlan: 10,
    physical_devices: [{ id: 'device-access', vendor: 'cisco', model: 'C9300L-24P-4X' }],
    assignments: [{
      id: assignmentId, hostname: 'L2-Access', role: 'access', family: 'catalyst-9300',
      physical_device_id: 'device-access', software: { image: '17.12.4', license: 'Network Advantage' },
    }],
  },
}

const assignment: CiscoAssignment = {
  assignmentId, hostname: 'L2-Access', role: 'access', family: 'catalyst-9300',
  physicalDeviceId: 'device-access', pid: 'C9300L-24P-4X', image: '17.12.4',
  license: 'Network Advantage', stackIdentity: 'standalone', isCore: false,
}

const binding: PreviewBinding = { eventId, revision, assignment }

const source: L2Source = {
  render_schema_version: 1, render_contract_id: L2_RENDER_CONTRACT,
  saved_revision_uuid: revisionId, revision_number: 1, revision_canonical_hash: hash,
  intent_schema_version: 1, intent_fingerprint: 'b'.repeat(64),
  preview_schema_version: 1, preview_contract_id: L2_PREVIEW_CONTRACT,
  preview_fingerprint: 'c'.repeat(64), command_evidence_registry_id: L2_REGISTRY_ID,
  command_evidence_fingerprint: L2_REGISTRY_FINGERPRINT,
  render_fingerprint: 'f'.repeat(64), assignment_id: assignmentId,
}

const integrity: L2Integrity = {
  status: 'pass', render_fingerprint_recomputed: 'f'.repeat(64),
  render_fingerprint_match: true, candidate_fingerprints_match: true,
  candidate_ids_unique: true, source_binding_format_ok: true,
  evidence_content_digests_ok: true, assignment_binding_ok: true,
  expected_source_match: true, failures: [],
}

function candidate(overrides: Partial<L2CandidateValidation> = {}): L2CandidateValidation {
  return {
    candidate_id: 'c1', category: 'access-vlan', renderer_status: 'candidate',
    candidate_text_present: true, syntax_validation_level: 'dictionary-only',
    parser_verified: false, candidate_fingerprint: 'd'.repeat(64),
    candidate_fingerprint_recomputed: 'd'.repeat(64), candidate_fingerprint_match: true,
    parse: {
      status: 'pass', topic: 'access-vlan', form: 'access-vlan', mode: 'interface',
      modes: ['interface'], target_class: 'interface', parameters: {}, failures: [],
    },
    scope: {
      status: 'allowed', reason_code: 'scope-allowed', evidence_id: 'l1-access-vlan-v1',
      evidence_review_state: 'independently-reviewed',
    },
    context_binding: { status: 'pass', reasons: [] },
    target_capability: { status: 'pass', applicable: true, reasons: [] },
    security: { status: 'pass', reason_codes: [] },
    semantics: { status: 'pass', mismatches: [] },
    risk: { status: 'pass', renderer_risk_class: 'R1', independent_floor: 'R1', findings: [] },
    independent_verdict: 'pass', fail_closed_action: null,
    ...overrides,
  }
}

function report(overrides: Partial<L2ValidationReport> = {}): L2ValidationReport {
  const items = [candidate()]
  return {
    validation_schema_version: 1, validation_contract_id: L2_VALIDATION_CONTRACT,
    source: { ...source }, assignment_id: assignmentId,
    device: {
      hostname: 'L2-Access', family: 'catalyst-9300', exact_pid: 'C9300L-24P-4X',
      release: '17.12.4', license: 'Network Advantage', role: 'access',
      stack_identity: 'standalone', stack_members: [], identity_verdict: 'pass',
      identity_reasons: [],
    },
    integrity: { ...integrity }, candidates: items,
    registry_coverage: [], topology_review: { status: 'pass', checks: [], findings: [] },
    summary: {
      total_candidates: 1, parsed_candidates: 1, parse_pass: 1, parse_fail: 0,
      not_run: 0, scope_blocked: 0, context_fail: 0, capability_fail: 0,
      capability_not_run: 0, security_fail: 0, semantic_mismatch: 0, risk_fail: 0,
      failed_candidates: 0, topics_parsed: ['access-vlan'], registry_rows: 72,
      registry_reviewed: 69, registry_rejected: 1, registry_unreviewed: 2,
      overall_status: 'pass',
    },
    safety: {
      candidate_only: true, executable: false, deployable: false, deployment_allowed: false,
      hardware_verified: false, device_connection: 'none', running_config_read: false,
      device_writes_enabled: false, device_runtime_state: 'unknown-not-read', cli: null,
      deployment_artifact: null, independent_validation_is_not_execution_authorization: true,
      public_candidate_schema_unchanged: true, parser_verified_public_field_unchanged: true,
    },
    report_fingerprint: 'e'.repeat(64),
    ...overrides,
  }
}

function document(overrides: Partial<L2CandidateDocument> = {}): L2CandidateDocument {
  return {
    render_schema_version: 1, contract_id: L2_RENDER_CONTRACT,
    source: {
      saved_revision_uuid: revisionId, revision_number: 1, revision_canonical_hash: hash,
      intent_schema_version: 1, intent_fingerprint: 'b'.repeat(64),
      preview_schema_version: 1, preview_contract_id: L2_PREVIEW_CONTRACT,
      preview_fingerprint: 'c'.repeat(64), command_evidence_registry_id: L2_REGISTRY_ID,
      command_evidence_fingerprint: L2_REGISTRY_FINGERPRINT,
    },
    assignment_id: assignmentId,
    device: {
      hostname: 'L2-Access', family: 'catalyst-9300', exact_pid: 'C9300L-24P-4X',
      release: '17.12.4', license: 'Network Advantage', role: 'access',
      stack_identity: 'standalone', stack_members: [],
    },
    render_state: 'review-candidates',
    candidates: [{
      candidate_id: 'c1', assignment_id: assignmentId,
      target: { kind: 'interface', stable_id: 'port-1', name: 'Gi1/0/1' },
      category: 'access-vlan', command_context: {
        mode: 'interface', mode_header: 'interface configuration', target_name: 'Gi1/0/1',
      },
      status: 'candidate', candidate_text: 'switchport access vlan 20', parameters: {},
      provenance: {}, capability_evidence: [], syntax_evidence: [],
      syntax_validation: { level: 'dictionary-only', dictionary_id: 'l1', parser_verified: false },
      risk_class: 'R1', requires_field_verification: false, prerequisites: [],
      blocking_reasons: [], candidate_fingerprint: 'd'.repeat(64),
    }],
    unresolved_prerequisites: [], evidence: [], device_runtime_state: 'unknown-not-read',
    safety: {
      candidate_only: true, executable: false, deployable: false, deployment_allowed: false,
      hardware_verified: false, device_connection: 'none', running_config_read: false,
      device_writes_enabled: false, device_runtime_state: 'unknown-not-read', cli: null,
      deployment_artifact: null,
    },
    summary: { total: 1, candidates: 1, blocked: 0, unsupported: 0, categories_rendered: ['access-vlan'] },
    deployment_blockers: [], render_fingerprint: 'f'.repeat(64),
    ...overrides,
  }
}

describe('L2 unified preview contracts', () => {
  it('binds the exact fourteen-field L2 Source and finds no problem', () => {
    expect(validateL2Report(report(), binding)).toEqual([])
    expect(validateL2Document(report(), document(), binding)).toEqual([])
  })

  it('rejects missing L2 source and integrity fields without normalizing them', () => {
    const missingSource = report()
    delete (missingSource.source as Partial<L2Source>).saved_revision_uuid
    expect(validateL2Report(missingSource, binding)).toContain('l2-source-contract')

    const missingIntegrity = report()
    delete (missingIntegrity.integrity as Partial<L2Integrity>).expected_source_match
    expect(validateL2Report(missingIntegrity, binding)).toContain('l2-report-integrity')
  })

  it('rejects a different L2 registry, revision or assignment', () => {
    const wrongRegistry = report()
    wrongRegistry.source = { ...wrongRegistry.source, command_evidence_fingerprint: '0'.repeat(64) }
    expect(validateL2Report(wrongRegistry, binding)).toContain('l2-source-contract')

    const wrongRevision = report()
    wrongRevision.source = { ...wrongRevision.source, saved_revision_uuid: '99999999-9999-4999-8999-999999999999' }
    expect(validateL2Report(wrongRevision, binding)).toContain('l2-source-binding')

    const wrongAssignment = report()
    wrongAssignment.assignment_id = '99999999-9999-4999-8999-999999999999'
    expect(validateL2Report(wrongAssignment, binding)).toContain('l2-report-assignment')
  })

  it('withholds command text unless the independent verdict and document status both pass', () => {
    const blocked = report({ candidates: [candidate({
      renderer_status: 'blocked', candidate_text_present: false,
      independent_verdict: 'not-run', parse: { ...candidate().parse, status: 'not-run' },
    })] })
    const blockedDocument = document({
      candidates: [{ ...document().candidates[0]!, status: 'blocked', candidate_text: null, candidate_fingerprint: 'd'.repeat(64) }],
      summary: { total: 1, candidates: 0, blocked: 1, unsupported: 0, categories_rendered: [] },
    })
    expect(validateL2Document(blocked, blockedDocument, binding)).toEqual([])
    const rows = l2ReviewRows(blocked, blockedDocument)
    expect(rows).toHaveLength(1)
    expect(rows[0]?.text).toBeNull()
    expect(l2Status(blocked, rows, blockedDocument, null)).toBe('partial')

    const exposed = document({
      candidates: [{ ...blockedDocument.candidates[0]!, candidate_text: 'switchport access vlan 20' }],
    })
    expect(validateL2Document(blocked, exposed, binding)).toContain('l2-candidate-text')
  })

  it('treats an unavailable candidate document as partial, never PASS', () => {
    const valid = report()
    const rows = l2ReviewRows(valid, null)
    expect(l2Status(valid, rows, null, null)).toBe('partial')
    expect(overallStatus('pass', 'partial')).toBe('partial')
    expect(overallStatus('na', 'pass')).toBe('pass')
    expect(overallStatus('fail', 'pass')).toBe('fail')
    expect(overallStatus('na', 'na')).toBe('na')
  })

  it('reports L2 PASS only when every verified candidate is a rendered candidate', () => {
    const valid = report()
    const rendered = document()
    expect(l2Status(valid, l2ReviewRows(valid, rendered), rendered, null)).toBe('pass')
    expect(overallStatus('pass', 'partial')).toBe('partial')
  })

  it('detects Cisco assignments by device vendor, including non-Core devices', () => {
    const plan = revision.plan
    const devices = plan.physical_devices as unknown as RecordValue[]
    devices.push({ id: 'device-other', vendor: 'hillstone', model: 'SG6000' } as unknown as RecordValue)
    const assignments = plan.assignments as unknown as RecordValue[]
    assignments.push({
      id: 'assignment-other', hostname: 'FW', role: 'external-distribution',
      family: 'hillstone', physical_device_id: 'device-other',
    } as unknown as RecordValue)
    const found = ciscoAssignments(plan)
    expect(found).toHaveLength(1)
    expect(found[0]?.assignmentId).toBe(assignmentId)
    expect(found[0]?.isCore).toBe(false)
  })

  it('recognizes structured not-applicable errors without turning them into data failures', () => {
    const notApplicable = parsePreviewError(new ApiError(404, {
      reason_code: 'assignment-not-found', stage: 'preview',
    }))
    expect(isL2NotApplicable(notApplicable)).toBe(true)
    const otherNotFound = parsePreviewError(new ApiError(404, {
      reason_code: 'saved-revision-not-found', stage: 'revision',
    }))
    expect(isL2NotApplicable(otherNotFound)).toBe(false)
    expect(parsePreviewError(new ApiError(409, {
      reason_code: 'validation-integrity-failure', stage: 'validation',
      failures: ['source-mismatch'],
    }))).toMatchObject({ status: 409, reasonCode: 'validation-integrity-failure', failures: ['source-mismatch'] })
  })
})
