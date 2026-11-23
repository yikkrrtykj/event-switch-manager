import { describe, expect, it } from 'vitest'
import type { PreviewBinding } from './ciscoPreview'
import {
  MANAGEMENT_INTENT_CONTRACT, MANAGEMENT_VALIDATION_CONTRACT,
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

function fixture(): ManagementReview {
  const source = {
    revision_uuid: revisionId,
    revision_number: 1,
    revision_hash: hash('a'),
    management_intent_fingerprint: hash('b'),
    evidence_registry_id: 'cis-04b-management-command-evidence-draft-v1',
    evidence_registry_fingerprint: hash('c'),
  }
  return {
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
      evidence_registry_id: 'cis-04b-management-command-evidence-draft-v1',
      evidence_registry_fingerprint: hash('c'),
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
      candidates: [],
      summary: { total: 0, passed: 0, blocked: 0, failed: 0 },
      overall_status: 'blocked',
      integrity: {
        revision_hash: true, intent_binding: true, source_binding: true,
        evidence_registry: true, candidate_ids_unique: true,
        candidate_fingerprints: true, no_secret_text: true, safety: true,
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
  }
}

describe('management/SSHv2 contract', () => {
  it('accepts a blocked management review with no secret material', () => {
    expect(validateManagementReview(fixture(), binding)).toEqual([])
  })

  it('rejects secret material and cross-event credential metadata', () => {
    const secret = fixture()
    ;(secret.intent as unknown as Record<string, unknown>)['pass' + 'word'] = 'fixture-value'
    expect(validateManagementReview(secret, binding)).toContain('management-secret-material')
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
    expect(validateManagementReview(telnet, binding)).toContain('management-ssh-policy')
    const console = fixture()
    console.intent.console_recovery.console_operation = 'executed'
    expect(validateManagementReview(console, binding)).toContain('management-console-recovery')
  })

  it('rejects a PASS candidate without an independently matched evidence digest', () => {
    const value = fixture()
    value.report.candidates = [{
      candidate_id: 'mgmtcand-0000000000000001',
      topic: 'management-domain-name',
      status: 'candidate',
      independent_verdict: 'pass',
      candidate_text_present: true,
      secret_text_present: false,
      evidence_id: 'mgmt-9300-domain-name-v1',
      evidence_review_state: 'independently-reviewed',
      evidence_source_url: 'https://www.cisco.com/',
      secret_bearing: false,
      evidence_digest_match: false,
      blocking_reasons: [],
    }]
    value.report.summary = { total: 1, passed: 1, blocked: 0, failed: 0 }
    expect(validateManagementReview(value, binding)).toContain('management-candidate-binding')
  })
})
