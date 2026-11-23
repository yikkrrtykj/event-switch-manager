import { describe, expect, it } from 'vitest'
import { canonicalSha256 } from './canonical'
import type { PreviewBinding } from './ciscoPreview'
import {
  MANAGEMENT_EVIDENCE_REGISTRY_FINGERPRINT,
  MANAGEMENT_EVIDENCE_REGISTRY_ID,
  MANAGEMENT_EXPECTED_TOPICS,
  MANAGEMENT_CANDIDATE_CONTRACT, MANAGEMENT_INTENT_CONTRACT,
  MANAGEMENT_VALIDATION_CONTRACT,
  validateManagementReview,
} from './managementAuth'
import type { ManagementReview } from './managementAuth'
import type { Revision } from './model'

const hash = (character: string) => character.repeat(64)
const eventId = '11111111-1111-4111-8111-111111111111'
const revisionId = '22222222-2222-4222-8222-222222222222'
const assignmentId = '33333333-3333-4333-8333-333333333333'
const binding = {
  eventId,
  revision: {
    id: revisionId,
    number: 1,
    content_hash: hash('a'),
    plan: { management_vlan: 10 },
  } as unknown as Revision,
  assignment: {
    assignmentId,
    hostname: 'L3-Core',
    role: 'core',
    family: 'catalyst-9300',
    physicalDeviceId: '44444444-4444-4444-8444-444444444444',
    pid: 'C9300L-24P-4X',
    image: '17.12.4',
    license: 'Network Advantage',
    stackIdentity: 'standalone',
    isCore: true,
  },
} satisfies PreviewBinding

function withoutKey(value: object, key: string): Record<string, unknown> {
  const copy = { ...value } as Record<string, unknown>
  delete copy[key]
  return copy
}

function resealReview(value: ManagementReview): ManagementReview {
  value.report.source.management_intent_fingerprint = value.intent.intent_fingerprint
  value.report.expected_source.management_intent_fingerprint =
    value.intent.intent_fingerprint
  value.report.source.evidence_registry_id = value.intent.evidence_registry_id
  value.report.expected_source.evidence_registry_id = value.intent.evidence_registry_id
  value.report.source.evidence_registry_fingerprint =
    value.intent.evidence_registry_fingerprint
  value.report.expected_source.evidence_registry_fingerprint =
    value.intent.evidence_registry_fingerprint
  value.intent.intent_fingerprint = canonicalSha256(
    withoutKey(value.intent, 'intent_fingerprint'),
  )
  value.report.source.management_intent_fingerprint = value.intent.intent_fingerprint
  value.report.expected_source.management_intent_fingerprint =
    value.intent.intent_fingerprint
  value.report.report_fingerprint = canonicalSha256(
    withoutKey(value.report, 'report_fingerprint'),
  )
  value.document.source = { ...value.report.source }
  value.document.render_fingerprint = canonicalSha256(
    withoutKey(value.document, 'render_fingerprint'),
  )
  return value
}

function reportCandidateFor(topic: string, index: number) {
  return {
    candidate_id: 'mgmtcand-' + String(index).padStart(16, '0'),
    topic,
    status: 'blocked',
    independent_verdict: 'blocked',
    candidate_text_present: false,
    secret_text_present: false,
    evidence_id: 'mgmt-9300-' + topic.slice('management-'.length) + '-v1',
    evidence_review_state: 'pending-independent-review',
    evidence_source_url: 'https://www.cisco.com/c/en/us/td/docs/security.html',
    secret_bearing: topic === 'management-local-username',
    evidence_digest_match: true,
    blocking_reasons: ['management-evidence-not-renderable'],
  }
}

function resealDocument(value: ManagementReview): void {
  for (const candidate of value.document.candidates) {
    candidate.candidate_fingerprint = canonicalSha256(
      withoutKey(candidate, 'candidate_fingerprint'),
    )
  }
  value.document.render_fingerprint = canonicalSha256(
    withoutKey(value.document, 'render_fingerprint'),
  )
}

function documentCandidateFor(topic: string, index: number) {
  const value = {
    candidate_id: 'mgmtcand-' + String(index).padStart(16, '0'),
    assignment_id: assignmentId,
    topic,
    command_context_mode: topic === 'management-console-auth' ? 'line' : 'global',
    command_context_header: topic === 'management-console-auth'
      ? 'line console 0' : 'global',
    target_name: 'L3-Core',
    status: 'blocked',
    candidate_text: null,
    parameters: {
      secret_bearing: topic === 'management-local-username',
      credential_reference_present: true,
      credential_secret_available: false,
    },
    evidence_id: 'mgmt-9300-' + topic.slice('management-'.length) + '-v1',
    evidence_review_state: 'pending-independent-review',
    evidence_content_digest: hash('e'),
    evidence_source_url: 'https://www.cisco.com/c/en/us/td/docs/security.html',
    secret_bearing: topic === 'management-local-username',
    requires_field_verification: true,
    blocking_reasons: ['management-evidence-not-renderable'],
    candidate_fingerprint: '',
  }
  value.candidate_fingerprint = canonicalSha256(
    withoutKey(value, 'candidate_fingerprint'),
  )
  return value
}

function fixture(): ManagementReview {
  const source = {
    revision_uuid: revisionId,
    revision_number: 1,
    revision_hash: hash('a'),
    management_intent_fingerprint: hash('b'),
    evidence_registry_id: MANAGEMENT_EVIDENCE_REGISTRY_ID,
    evidence_registry_fingerprint: MANAGEMENT_EVIDENCE_REGISTRY_FINGERPRINT,
  }
  const value = {
    intent: {
      management_intent_schema_version: 1,
      contract_id: MANAGEMENT_INTENT_CONTRACT,
      event_id: eventId,
      revision_id: revisionId,
      revision_number: 1,
      revision_hash: hash('a'),
      assignment_id: assignmentId,
      identity: {
        assignment_id: assignmentId, hostname: 'L3-Core', role: 'core',
        family: 'catalyst-9300', exact_pid: 'C9300L-24P-4X',
        pid_evidence: 'exact-verified-pid', serial_verified: true,
        software_image: '17.12.4', software_license: 'Network Advantage',
        stack_identity: 'standalone',
      },
      management_vlan: 10,
      management_domain: 'example.com',
      intended_status: 'PLANNED',
      status: 'BLOCKED',
      validation_scope: 'software-planning-only',
      software_validation_status: 'BLOCKED',
      hardware_status: 'HARDWARE_NOT_VERIFIED',
      not_implemented_capabilities: ['protected-credential-provider'],
      reachability: {
        status: 'PLANNED', management_vlan: 10, vlan_declared: true,
        management_ip: '192.168.10.3', management_subnet: '192.168.10.0/24',
        duplicate_ip: false, reason_codes: ['management-reachability-not-verified'],
      },
      ssh_policy: {
        status: 'BLOCKED', target_protocol: 'sshv2', telnet_enabled: false,
        plaintext_management_auth: false, sshv1_fallback_allowed: false,
        rsa_key_state: 'unknown-not-read', rsa_key_assumed: false,
        reason_codes: ['management-evidence-pending'],
      },
      authentication: {
        status: 'BLOCKED', method: 'local-only',
        local_authentication_required: true, local_fallback_required: true,
        external_aaa_requested: false, external_aaa_status: 'NOT_IMPLEMENTED',
        credential_reference: {
          reference: `credref:${eventId}:netops`, present: true, valid: true,
          event_scoped: true, secret_material_present: false,
          secret_availability: 'not-verified',
          provider: 'protected-credential-provider-not-implemented',
          reason_codes: ['credential-secret-not-verified'],
          value_not_returned: true,
        },
        reason_codes: ['credential-secret-not-verified'],
      },
      console_recovery: {
        status: 'BLOCKED', required: true, local_recovery_account_required: true,
        console_operation: 'not-executed', console_access_verified: false,
        lockout_risk: 'present-not-mitigated',
        reason_codes: ['console-recovery-not-verified'],
      },
      aaa: {
        status: 'NOT_IMPLEMENTED', mode: 'local-only', external_servers: [],
        deletion_or_auth_switch_generation: false,
        reason_codes: ['external-aaa-not-implemented'],
      },
      evidence_registry_id: MANAGEMENT_EVIDENCE_REGISTRY_ID,
      evidence_registry_fingerprint: MANAGEMENT_EVIDENCE_REGISTRY_FINGERPRINT,
      evidence_status: 'PENDING',
      risk_codes: ['management-lockout-risk'],
      reason_codes: ['management-evidence-pending'],
      hardware_verified: false,
      deployment_allowed: false,
      device_connection: 'none',
      intent_fingerprint: hash('b'),
    },
    report: {
      validation_schema_version: 1,
      validation_contract_id: MANAGEMENT_VALIDATION_CONTRACT,
      source,
      expected_source: { ...source, assignment_id: assignmentId },
      assignment_id: assignmentId,
      candidates: MANAGEMENT_EXPECTED_TOPICS.map(reportCandidateFor),
      summary: { total: 9, passed: 0, blocked: 9, failed: 0 },
      overall_status: 'blocked',
      integrity: {
        revision_hash: true, intent_binding: true, source_binding: true,
        evidence_registry: true, expected_topic_set: true,
        candidate_ids_unique: true, candidate_evidence_binding: true,
        candidate_status: true, candidate_fingerprints: true,
        summary_derived: true, no_secret_text: true, safety: true,
      },
      safety: {
        candidate_only: true, read_only: true, executable: false,
        deployable: false, deployment_allowed: false, device_connection: 'none',
        running_config_read: false, device_writes_enabled: false,
        full_config_generated: false, cli: null, deployment_artifact: null,
        hardware_verified: false, secrets_included: false,
        secret_placeholder_included: false,
      },
      report_fingerprint: hash('d'),
    },
    document: {
      management_render_schema_version: 1,
      contract_id: MANAGEMENT_CANDIDATE_CONTRACT,
      source: { ...source },
      assignment_id: assignmentId,
      device: {
        assignment_id: assignmentId,
        hostname: 'L3-Core',
        family: 'catalyst-9300',
        exact_pid: 'C9300L-24P-4X',
        software_image: '17.12.4',
        software_license: 'Network Advantage',
        stack_identity: 'standalone',
      },
      candidates: MANAGEMENT_EXPECTED_TOPICS.map(documentCandidateFor),
      unresolved_prerequisites: [],
      deployment_blockers: ['management-evidence-pending'],
      safety: {
        candidate_only: true, read_only: true, executable: false,
        deployable: false, deployment_allowed: false, device_connection: 'none',
        running_config_read: false, device_writes_enabled: false,
        full_config_generated: false, cli: null, deployment_artifact: null,
        hardware_verified: false, secrets_included: false,
        secret_placeholder_included: false,
      },
      summary: { total: 9, candidates: 0, blocked: 9, skipped: 0 },
      verification: 'not-verified',
      deployment_status: 'blocked',
      render_fingerprint: hash('e'),
    },
  } as ManagementReview
  resealReview(value)
  return value
}

describe('management/SSHv2 contract', () => {
  it('accepts a blocked PENDING review with no secret or CLI material', () => {
    const value = fixture()
    expect(validateManagementReview(value, binding)).toEqual([])
    expect(value.report.candidates.every(
      (candidate) => !candidate.candidate_text_present &&
        !candidate.secret_text_present &&
        candidate.status === 'blocked',
    )).toBe(true)
  })

  it('binds the management VLAN to the trusted Saved Revision', () => {
    const wrongVlan = binding.revision.plan as { management_vlan: number }
    const original = wrongVlan.management_vlan
    wrongVlan.management_vlan = 20
    expect(validateManagementReview(fixture(), binding)).toContain('management-vlan')
    wrongVlan.management_vlan = original

    for (const invalid of ['10', 0, -1, 4095]) {
      const value = fixture()
      value.intent.management_vlan = invalid as unknown as number
      expect(validateManagementReview(value, binding)).toContain('management-vlan')
    }
    const noPlan = {
      ...binding,
      revision: { ...binding.revision, plan: undefined } as unknown as Revision,
    }
    expect(validateManagementReview(fixture(), noPlan)).toContain('management-vlan')
  })

  it('rejects a stale assignment/revision and a mismatched identity', () => {
    const stale = {
      ...binding,
      assignment: {
        ...binding.assignment,
        assignmentId: '99999999-9999-4999-8999-999999999999',
      },
    }
    expect(validateManagementReview(fixture(), stale))
      .toContain('management-intent-binding')
    const identity = fixture()
    identity.intent.identity.exact_pid = 'C9300-24T'
    expect(validateManagementReview(identity, binding))
      .toContain('management-identity-binding')
  })

  it('rejects forged intent/report fingerprints even when format-valid', () => {
    const intent = fixture()
    intent.intent.intent_fingerprint = hash('0')
    expect(validateManagementReview(intent, binding))
      .toContain('management-intent-fingerprint')
    const report = fixture()
    report.report.report_fingerprint = hash('0')
    expect(validateManagementReview(report, binding))
      .toContain('management-report-fingerprint')
  })

  it('rejects arbitrary PENDING registry IDs and fingerprints', () => {
    const wrongFingerprint = fixture()
    wrongFingerprint.intent.evidence_registry_fingerprint = hash('f')
    resealReview(wrongFingerprint)
    expect(validateManagementReview(wrongFingerprint, binding))
      .toContain('management-pending-registry')

    const wrongId = fixture()
    wrongId.intent.evidence_registry_id = 'client-chosen-registry'
    resealReview(wrongId)
    expect(validateManagementReview(wrongId, binding))
      .toContain('management-pending-registry')
  })

  it('rejects a PENDING candidate converted to PASS/REVIEWED after resealing', () => {
    const value = fixture()
    value.report.candidates[0] = {
      ...value.report.candidates[0]!,
      status: 'candidate',
      independent_verdict: 'pass',
      candidate_text_present: true,
      evidence_review_state: 'independently-reviewed',
      blocking_reasons: [],
    }
    value.report.summary = { total: 9, passed: 1, blocked: 8, failed: 0 }
    value.report.overall_status = 'partial'
    resealReview(value)
    expect(validateManagementReview(value, binding))
      .toContain('management-reviewed-claim')
  })

  it('rejects forged review state, evidence ID/source, and missing topics', () => {
    const forgedState = fixture()
    forgedState.report.candidates[0]!.evidence_review_state =
      'independently-reviewed'
    resealReview(forgedState)
    expect(validateManagementReview(forgedState, binding))
      .toContain('management-reviewed-claim')

    const forgedEvidence = fixture()
    forgedEvidence.report.candidates[0]!.evidence_source_url =
      'https://example.invalid/management'
    resealReview(forgedEvidence)
    expect(validateManagementReview(forgedEvidence, binding))
      .toContain('management-evidence-binding')

    const missing = fixture()
    missing.report.candidates.pop()
    missing.report.summary = { total: 8, passed: 0, blocked: 8, failed: 0 }
    resealReview(missing)
    expect(validateManagementReview(missing, binding))
      .toContain('management-topic-set')
  })

  it('binds displayed CLI text to the candidate document, not the report alone', () => {
    const injected = fixture()
    injected.document.candidates[0]!.candidate_text =
      'ip domain name attacker.example; interface Gi1/0/1'
    resealDocument(injected)
    expect(validateManagementReview(injected, binding))
      .toContain('management-command-text')

    const mismatched = fixture()
    mismatched.document.candidates[0]!.evidence_id = 'mgmt-forged-evidence'
    resealDocument(mismatched)
    expect(validateManagementReview(mismatched, binding))
      .toContain('management-document-binding')

    const missing = fixture() as unknown as Record<string, unknown>
    delete missing.document
    expect(validateManagementReview(
      missing as unknown as ManagementReview, binding,
    )).toContain('management-document-contract')
  })

  it('rejects secret material and cross-event credential metadata', () => {
    const secret = fixture()
    ;(secret.intent as unknown as Record<string, unknown>)['pass' + 'word'] =
      'fixture-value'
    expect(validateManagementReview(secret, binding))
      .toContain('management-secret-material')
    const crossEvent = fixture()
    crossEvent.intent.authentication.credential_reference.reference =
      'credref:99999999-9999-4999-8999-999999999999:other'
    expect(validateManagementReview(crossEvent, binding))
      .toContain('management-credential-reference')
  })

  it('rejects a malformed response instead of throwing in the UI', () => {
    const malformed = fixture() as unknown as Record<string, unknown>
    delete (malformed.intent as Record<string, unknown>).authentication
    expect(validateManagementReview(
      malformed as unknown as ManagementReview, binding,
    )).toContain('management-contract')
  })

  it('rejects SSHv1/Telnet policy and unverifiable console recovery', () => {
    const telnet = fixture()
    telnet.intent.ssh_policy.telnet_enabled = true
    expect(validateManagementReview(telnet, binding))
      .toContain('management-ssh-policy')
    const console = fixture()
    console.intent.console_recovery.console_operation = 'executed'
    expect(validateManagementReview(console, binding))
      .toContain('management-console-recovery')
  })
})
