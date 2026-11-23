import { describe, expect, it } from 'vitest'
import type { PreviewBinding } from './ciscoPreview'
import type { ConfigurationAssembly } from './configAssembly'
import {
  assemblyContentFingerprint,
  CONFIG_ASSEMBLY_CHECKS, CONFIG_ASSEMBLY_CONTRACT, CONFIG_ASSEMBLY_SECTIONS,
  validateAssembly,
} from './configAssembly'
import type { Revision } from './model'

const hash = (character: string) => character.repeat(64)
const binding = {
  eventId: '11111111-1111-4111-8111-111111111111',
  revision: {
    id: '22222222-2222-4222-8222-222222222222',
    number: 1,
    content_hash: hash('a'),
  } as Revision,
  assignment: {
    assignmentId: '33333333-3333-4333-8333-333333333333',
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

function fixture(): ConfigurationAssembly {
  const sourceFingerprints = {
    l2_intent: hash('b'), l2_preview: hash('c'), l2_render: hash('d'),
    l2_validation: hash('e'),
    l3_intent: hash('f'), l3_render: hash('0'), l3_validation: hash('1'),
  }
  const sectionStatuses: Record<string, string> = {
    'vlan-definitions': 'BLOCKED',
    'stp-vtp': 'BLOCKED',
    'physical-interfaces': 'BLOCKED',
    'access-trunk-vlans': 'BLOCKED',
    'port-channels-lacp': 'NOT_APPLICABLE',
    'portfast-bpdu-poe': 'NOT_APPLICABLE',
    'ip-routing': 'NOT_APPLICABLE',
    'svi': 'NOT_APPLICABLE',
    'routes': 'NOT_APPLICABLE',
    dhcp: 'NOT_APPLICABLE',
    'management-auth-ssh': 'BLOCKED',
    'snmp-syslog-ntp': 'NOT_IMPLEMENTED',
  }
  const required = new Set([
    'vlan-definitions', 'stp-vtp', 'physical-interfaces', 'access-trunk-vlans',
    'management-auth-ssh',
  ])
  const sections = CONFIG_ASSEMBLY_SECTIONS.map((sectionId) => ({
    section_id: sectionId,
    required: required.has(sectionId),
    applicability: sectionId === 'snmp-syslog-ntp'
      ? 'NOT_IMPLEMENTED' : required.has(sectionId) ? 'APPLICABLE' : 'NOT_APPLICABLE',
    status: sectionStatuses[sectionId],
    candidate_count: 0,
    passed_count: 0,
    failed_count: 0,
    blocked_count: 0,
    missing_count: sectionId === 'management-auth-ssh' ? 1 : 0,
    reason_codes: sectionId === 'management-auth-ssh'
      ? ['management-evidence-pending']
      : sectionStatuses[sectionId] === 'NOT_IMPLEMENTED'
        ? ['section-not-implemented'] : [],
    evidence_references: [],
    source_fingerprints: { ...sourceFingerprints },
    candidates: [],
  })) as ConfigurationAssembly['sections']
  const value = {
    assembly_schema_version: 1,
    contract_id: CONFIG_ASSEMBLY_CONTRACT,
    source: {
      event_id: binding.eventId,
      revision_id: binding.revision.id,
      revision_number: binding.revision.number,
      revision_canonical_hash: binding.revision.content_hash,
      assignment_id: binding.assignment.assignmentId,
      l2_intent_fingerprint: sourceFingerprints.l2_intent,
      l2_preview_fingerprint: sourceFingerprints.l2_preview,
      l2_render_fingerprint: sourceFingerprints.l2_render,
      l2_validation_fingerprint: sourceFingerprints.l2_validation,
      l2_candidate_fingerprints: [],
      l2_command_evidence_registry_id: 'cis-02b2-l1-command-evidence-v1',
      l2_command_evidence_registry_fingerprint: hash('2'),
      l3_intent_fingerprint: sourceFingerprints.l3_intent,
      l3_render_fingerprint: sourceFingerprints.l3_render,
      l3_validation_fingerprint: sourceFingerprints.l3_validation,
      l3_candidate_fingerprints: [],
      l3_command_evidence_registry_id: 'cis-03-l1-command-evidence-v1',
      l3_command_evidence_registry_fingerprint: hash('3'),
      dependency_semantics: 'association-only-not-an-execution-order',
    },
    identity: {
      assignment_id: binding.assignment.assignmentId,
      hostname: binding.assignment.hostname,
      role: binding.assignment.role,
      family: binding.assignment.family,
      physical_device_id: binding.assignment.physicalDeviceId,
      physical_vendor: 'cisco',
      physical_model: binding.assignment.pid,
      verified_serial_present: true,
      exact_pid: binding.assignment.pid,
      pid_evidence: 'exact-verified-pid',
      serial_verified: true,
      software_image: binding.assignment.image,
      software_license: binding.assignment.license,
      stack_identity: 'standalone',
      stack_members: [],
      management_ip: null,
    },
    sections,
    cross_layer_checks: CONFIG_ASSEMBLY_CHECKS.map((checkId) => ({
      check_id: checkId,
      status: 'NOT_APPLICABLE',
      reason_codes: [],
      detail: 'fixture',
    })),
    completeness: {
      status: 'BLOCKED',
      complete: false,
      required_sections: 5,
      validated_sections: 0,
      partial_sections: 0,
      blocked_sections: 5,
      not_applicable_sections: 6,
      not_implemented_sections: 1,
      missing_sections: [
        'vlan-definitions', 'stp-vtp', 'physical-interfaces',
        'access-trunk-vlans', 'management-auth-ssh',
      ],
      missing_features: [
        'vlan-definitions', 'stp-vtp', 'physical-interfaces',
        'access-trunk-vlans', 'management-auth-ssh', 'snmp-syslog-ntp',
      ],
      blockers: [
        'vlan-definitions:BLOCKED', 'stp-vtp:BLOCKED',
        'physical-interfaces:BLOCKED', 'access-trunk-vlans:BLOCKED',
        'management-auth-ssh:BLOCKED',
      ],
    },
    safety: {
      read_only: true,
      candidate_only: true,
      executable: false,
      deployable: false,
      deployment_allowed: false,
      device_connection: 'none',
      running_config_read: false,
      device_writes_enabled: false,
      device_runtime_state: 'unknown-not-read',
      full_config_generated: false,
      deployment_artifact: null,
      cli: null,
      hardware_verified: false,
      assembly_is_not_execution_authorization: true,
    },
    device_runtime_state: 'unknown-not-read',
    verification: 'not-verified',
    deployment_status: 'blocked',
    executable: false,
    cli: null,
    device_writes_enabled: false,
    full_config_generated: false,
    assembly_fingerprint: hash('4'),
  } as ConfigurationAssembly
  value.assembly_fingerprint = assemblyContentFingerprint(value)
  return value
}

describe('configuration assembly contract', () => {
  it('accepts a transaction-bound read-only assembly', () => {
    expect(validateAssembly(fixture(), binding)).toEqual([])
  })

  it('rejects a different binding, contract or section set', () => {
    const value = fixture()
    value.source.assignment_id = '55555555-5555-4555-8555-555555555555'
    expect(validateAssembly(value, binding)).toContain('assembly-source-binding')
    const wrongContract = fixture()
    wrongContract.contract_id = 'other'
    expect(validateAssembly(wrongContract, binding)).toContain('assembly-contract')
    const missing = fixture()
    missing.sections = missing.sections.slice(0, -1)
    expect(validateAssembly(missing, binding)).toContain('assembly-section-set')
  })

  it('rejects a tampered source fingerprint and a forged content hash', () => {
    const value = fixture()
    value.source.l3_validation_fingerprint = 'tampered'
    expect(validateAssembly(value, binding)).toContain('assembly-source-fingerprint')
    const hashForgery = fixture()
    hashForgery.assembly_fingerprint = '1'.repeat(64)
    expect(validateAssembly(hashForgery, binding)).toContain('assembly-content-fingerprint')
  })

  it('fails closed when independent L2/L3 reports are missing', () => {
    const problems = validateAssembly(fixture(), binding, {
      l2: null, l3: null, l3Applicable: true,
    })
    expect(problems).toContain('assembly-l2-trust-gate')
    expect(problems).toContain('assembly-l3-trust-gate')
  })

  it('rejects command text on a blocked candidate', () => {
    const value = fixture()
    const blocked = value.sections.find((section) => section.section_id === 'stp-vtp')!
    blocked.candidates = [{
      candidate_id: 'cand-0000000000000001',
      source_layer: 'l2',
      category: 'rapid-pvst',
      target_kind: 'device',
      target_name: 'L3-Core',
      status: 'blocked',
      verdict: 'blocked',
      candidate_text: 'spanning-tree mode rapid-pvst',
      risk_class: 'R2',
      requires_field_verification: true,
      blocking_reasons: ['blocked'],
      candidate_fingerprint: hash('5'),
    }]
    blocked.candidate_count = 1
    expect(validateAssembly(value, binding)).toContain('assembly-candidate-text')
  })

  it('rejects a COMPLETE claim with missing required sections or unsafe flags', () => {
    const value = fixture()
    value.completeness.complete = true
    value.completeness.status = 'VALIDATED_SECTION'
    expect(validateAssembly(value, binding)).toContain('assembly-complete-claim')
    const unsafe = fixture()
    unsafe.safety.full_config_generated = true
    expect(validateAssembly(unsafe, binding)).toContain('assembly-safety')
  })

  it('rejects unexpected executable or command-sequence shapes', () => {
    const value = fixture()
    ;(value as unknown as Record<string, unknown>).commands = ['configure terminal']
    expect(validateAssembly(value, binding)).toContain('assembly-execution-shape')
  })
})
