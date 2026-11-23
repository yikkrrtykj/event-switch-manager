import { ApiError } from '../api'
import type { L2ValidationReport } from './ciscoPreview'
import type { PreviewBinding } from './ciscoPreview'
import type { L3ValidationReport } from './l3Review'

export const CONFIG_ASSEMBLY_CONTRACT = 'cis-04-device-config-assembly-v1'
export const CONFIG_ASSEMBLY_SCHEMA_VERSION = 1
export const CONFIG_ASSEMBLY_SCOPE_HEADER = 'X-Config-Assembly-Scope'
export const CONFIG_ASSEMBLY_SECTIONS = [
  'vlan-definitions', 'stp-vtp', 'physical-interfaces', 'access-trunk-vlans',
  'port-channels-lacp', 'portfast-bpdu-poe', 'ip-routing', 'svi', 'routes',
  'dhcp', 'management-auth-ssh', 'snmp-syslog-ntp',
] as const
export const CONFIG_ASSEMBLY_CHECKS = [
  'vlan-definition-exists', 'svi-vlan-definition-consistency',
  'routed-switchport-conflict', 'port-channel-membership',
  'native-allowed-vlan-reference', 'shutdown-uplink-consistency',
  'static-route-next-hop-dependency', 'default-route-evidence-gate',
  'dhcp-relay-issue-30', 'physical-interface-assignment',
  'management-vlan-management-ip',
] as const

export type AssemblySectionStatus =
  | 'VALIDATED_SECTION' | 'PARTIAL' | 'BLOCKED' | 'NOT_APPLICABLE'
  | 'NOT_IMPLEMENTED'
export type AssemblyApplicability = 'APPLICABLE' | 'NOT_APPLICABLE' | 'NOT_IMPLEMENTED'
export type CrossLayerStatus = 'PASS' | 'FAIL' | 'BLOCKED' | 'NOT_APPLICABLE'
type CandidateStatus = 'candidate' | 'blocked' | 'unsupported'
type CandidateVerdict = 'pass' | 'fail' | 'blocked' | 'not-run'

export interface AssemblySource {
  event_id: string
  revision_id: string
  revision_number: number
  revision_canonical_hash: string
  assignment_id: string
  l2_intent_fingerprint: string
  l2_preview_fingerprint: string
  l2_render_fingerprint: string
  l2_validation_fingerprint: string
  l2_candidate_fingerprints: string[]
  l2_command_evidence_registry_id: string
  l2_command_evidence_registry_fingerprint: string
  l3_intent_fingerprint: string
  l3_render_fingerprint: string
  l3_validation_fingerprint: string
  l3_candidate_fingerprints: string[]
  l3_command_evidence_registry_id: string
  l3_command_evidence_registry_fingerprint: string
  dependency_semantics: string
}

export interface AssemblyIdentity {
  assignment_id: string
  hostname: string
  role: string
  family: string | null
  physical_device_id: string | null
  physical_vendor: string | null
  physical_model: string | null
  verified_serial_present: boolean
  exact_pid: string | null
  pid_evidence: string
  serial_verified: boolean
  software_image: string | null
  software_license: string | null
  stack_identity: string
  stack_members: {
    number: number
    physical_device_id: string
    exact_pid: string | null
    state: string
  }[]
  management_ip: string | null
}

export interface AssemblyCandidate {
  candidate_id: string
  source_layer: 'l2' | 'l3'
  category: string
  target_kind: string
  target_name: string
  status: CandidateStatus
  verdict: CandidateVerdict
  candidate_text: string | null
  risk_class: string
  requires_field_verification: boolean
  blocking_reasons: string[]
  candidate_fingerprint: string
}

export interface AssemblySection {
  section_id: string
  required: boolean
  applicability: AssemblyApplicability
  status: AssemblySectionStatus
  candidate_count: number
  passed_count: number
  failed_count: number
  blocked_count: number
  missing_count: number
  reason_codes: string[]
  evidence_references: {
    kind: string
    reference_id: string
    detail: string
  }[]
  source_fingerprints: {
    l2_intent: string | null
    l2_preview: string | null
    l2_render: string | null
    l2_validation: string | null
    l3_intent: string | null
    l3_render: string | null
    l3_validation: string | null
  }
  candidates: AssemblyCandidate[]
}

export interface AssemblyCrossCheck {
  check_id: string
  status: CrossLayerStatus
  reason_codes: string[]
  detail: string
}

export interface AssemblyCompleteness {
  status: AssemblySectionStatus
  complete: boolean
  required_sections: number
  validated_sections: number
  partial_sections: number
  blocked_sections: number
  not_applicable_sections: number
  not_implemented_sections: number
  missing_sections: string[]
  missing_features: string[]
  blockers: string[]
}

export interface ConfigurationAssembly {
  assembly_schema_version: number
  contract_id: string
  source: AssemblySource
  identity: AssemblyIdentity
  sections: AssemblySection[]
  cross_layer_checks: AssemblyCrossCheck[]
  completeness: AssemblyCompleteness
  safety: {
    read_only: boolean
    candidate_only: boolean
    executable: boolean
    deployable: boolean
    deployment_allowed: boolean
    device_connection: string
    running_config_read: boolean
    device_writes_enabled: boolean
    device_runtime_state: string
    full_config_generated: boolean
    deployment_artifact: null
    cli: null
    hardware_verified: boolean
    assembly_is_not_execution_authorization: boolean
  }
  device_runtime_state: string
  verification: string
  deployment_status: string
  executable: boolean
  cli: null
  device_writes_enabled: boolean
  full_config_generated: boolean
  assembly_fingerprint: string
}

const sha256 = /^[0-9a-f]{64}$/
const statuses = new Set<AssemblySectionStatus>([
  'VALIDATED_SECTION', 'PARTIAL', 'BLOCKED', 'NOT_APPLICABLE', 'NOT_IMPLEMENTED',
])
const applicability = new Set<AssemblyApplicability>([
  'APPLICABLE', 'NOT_APPLICABLE', 'NOT_IMPLEMENTED',
])
const crossStatuses = new Set<CrossLayerStatus>([
  'PASS', 'FAIL', 'BLOCKED', 'NOT_APPLICABLE',
])
const candidateStatuses = new Set<CandidateStatus>(['candidate', 'blocked', 'unsupported'])
const candidateVerdicts = new Set<CandidateVerdict>(['pass', 'fail', 'blocked', 'not-run'])

function ordinaryRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown> : null
}

function ordinaryArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function text(value: unknown): value is string {
  return typeof value === 'string'
}

function integer(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0
}

export function parseAssemblyError(error: unknown) {
  if (error instanceof ApiError) {
    const detail = ordinaryRecord(error.detail)
    return {
      status: error.status,
      reasonCode: detail && text(detail.reason_code) ? detail.reason_code : '',
      stage: detail && text(detail.stage) ? detail.stage : '',
      failures: detail && Array.isArray(detail.failures)
        ? detail.failures.filter(text) : [],
    }
  }
  return { status: null, reasonCode: '', stage: '', failures: [] }
}

export async function fetchConfigAssembly(
  eventId: string, revisionId: string, assignmentId: string, signal?: AbortSignal,
): Promise<ConfigurationAssembly> {
  const response = await fetch(
    '/api/v1/events/' + encodeURIComponent(eventId) +
    '/plan-revisions/' + encodeURIComponent(revisionId) +
    '/assignments/' + encodeURIComponent(assignmentId) +
    '/config-assembly-preview',
    { signal },
  )
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { detail?: unknown } | null
    throw new ApiError(response.status, body?.detail)
  }
  if (response.headers.get(CONFIG_ASSEMBLY_SCOPE_HEADER) !== 'full') {
    throw new ApiError(409, {
      reason_code: 'config-assembly-scope-not-full',
      stage: 'assembly',
      failures: ['assembly-scope-header'],
    })
  }
  return await response.json() as ConfigurationAssembly
}

export function validateAssembly(
  value: ConfigurationAssembly,
  binding: PreviewBinding,
  l2?: L2ValidationReport | null,
  l3?: L3ValidationReport | null,
): string[] {
  const problems: string[] = []
  const raw = value as unknown as Record<string, unknown>
  if (value.assembly_schema_version !== CONFIG_ASSEMBLY_SCHEMA_VERSION ||
    value.contract_id !== CONFIG_ASSEMBLY_CONTRACT) {
    problems.push('assembly-contract')
  }
  if (!sha256.test(value.assembly_fingerprint)) problems.push('assembly-fingerprint')
  if (raw.execution_order !== undefined || raw.sequence !== undefined ||
    raw.commands !== undefined) problems.push('assembly-execution-shape')

  const source = value.source
  if (source.event_id !== binding.eventId ||
    source.revision_id !== binding.revision.id ||
    source.revision_number !== binding.revision.number ||
    source.revision_canonical_hash !== binding.revision.content_hash ||
    source.assignment_id !== binding.assignment.assignmentId) {
    problems.push('assembly-source-binding')
  }
  const l2CandidateFingerprints = Array.isArray(source.l2_candidate_fingerprints)
    ? source.l2_candidate_fingerprints : []
  const l3CandidateFingerprints = Array.isArray(source.l3_candidate_fingerprints)
    ? source.l3_candidate_fingerprints : []
  for (const fingerprint of [
    source.l2_intent_fingerprint, source.l2_preview_fingerprint,
    source.l2_render_fingerprint, source.l2_validation_fingerprint,
    source.l3_intent_fingerprint, source.l3_render_fingerprint,
    source.l3_validation_fingerprint,
    source.l2_command_evidence_registry_fingerprint,
    source.l3_command_evidence_registry_fingerprint,
    ...l2CandidateFingerprints, ...l3CandidateFingerprints,
  ]) {
    if (!sha256.test(fingerprint)) problems.push('assembly-source-fingerprint')
  }
  if (!Array.isArray(source.l2_candidate_fingerprints) ||
    !Array.isArray(source.l3_candidate_fingerprints)) {
    problems.push('assembly-source-fingerprint')
  }
  if (source.dependency_semantics !== 'association-only-not-an-execution-order') {
    problems.push('assembly-dependency-semantics')
  }
  if (l2) {
    if (source.l2_intent_fingerprint !== l2.source.intent_fingerprint ||
      source.l2_preview_fingerprint !== l2.source.preview_fingerprint ||
      source.l2_render_fingerprint !== l2.source.render_fingerprint ||
      source.l2_validation_fingerprint !== l2.report_fingerprint ||
      source.l2_command_evidence_registry_id !== l2.source.command_evidence_registry_id ||
      source.l2_command_evidence_registry_fingerprint !== l2.source.command_evidence_fingerprint) {
      problems.push('assembly-l2-binding')
    }
  }
  if (l3) {
    if (source.l3_intent_fingerprint !== l3.source.l3_intent_fingerprint ||
      source.l3_render_fingerprint !== l3.source.l3_render_fingerprint ||
      source.l3_validation_fingerprint !== l3.report_fingerprint ||
      source.l3_command_evidence_registry_id !== l3.source.command_evidence_registry_id ||
      source.l3_command_evidence_registry_fingerprint !== l3.source.command_evidence_registry_fingerprint) {
      problems.push('assembly-l3-binding')
    }
  }

  const identity = value.identity
  if (identity.assignment_id !== binding.assignment.assignmentId ||
    identity.hostname !== binding.assignment.hostname ||
    identity.role !== binding.assignment.role ||
    identity.family !== binding.assignment.family ||
    identity.exact_pid !== binding.assignment.pid ||
    identity.software_image !== binding.assignment.image ||
    identity.software_license !== binding.assignment.license) {
    problems.push('assembly-identity')
  }
  if (typeof identity.verified_serial_present !== 'boolean' ||
    typeof identity.serial_verified !== 'boolean' ||
    !text(identity.pid_evidence) || !text(identity.stack_identity) ||
    !Array.isArray(identity.stack_members)) {
    problems.push('assembly-identity-shape')
  }

  const sectionIds = new Set<string>()
  const sectionFingerprints = [
    source.l2_intent_fingerprint, source.l2_preview_fingerprint,
    source.l2_render_fingerprint, source.l2_validation_fingerprint,
    source.l3_intent_fingerprint, source.l3_render_fingerprint,
    source.l3_validation_fingerprint,
  ]
  const expectedSectionFingerprints = {
    l2_intent: source.l2_intent_fingerprint,
    l2_preview: source.l2_preview_fingerprint,
    l2_render: source.l2_render_fingerprint,
    l2_validation: source.l2_validation_fingerprint,
    l3_intent: source.l3_intent_fingerprint,
    l3_render: source.l3_render_fingerprint,
    l3_validation: source.l3_validation_fingerprint,
  }
  let requiredSections = 0
  let validatedSections = 0
  let partialSections = 0
  let blockedSections = 0
  let notApplicableSections = 0
  let notImplementedSections = 0
  for (const section of ordinaryArray(raw.sections) as AssemblySection[]) {
    if (!text(section.section_id) || sectionIds.has(section.section_id) ||
      !CONFIG_ASSEMBLY_SECTIONS.includes(section.section_id as typeof CONFIG_ASSEMBLY_SECTIONS[number])) {
      problems.push('assembly-section-id')
      continue
    }
    sectionIds.add(section.section_id)
    if (!statuses.has(section.status) || !applicability.has(section.applicability)) {
      problems.push('assembly-section-status')
    }
    for (const count of [
      section.candidate_count, section.passed_count, section.failed_count,
      section.blocked_count, section.missing_count,
    ]) {
      if (!integer(count)) problems.push('assembly-section-counts')
    }
    if (section.candidate_count !==
      section.passed_count + section.failed_count + section.blocked_count) {
      problems.push('assembly-section-counts')
    }
    if (section.required) requiredSections += 1
    if (section.status === 'VALIDATED_SECTION') validatedSections += 1
    if (section.status === 'PARTIAL') partialSections += 1
    if (section.status === 'BLOCKED') blockedSections += 1
    if (section.status === 'NOT_APPLICABLE') notApplicableSections += 1
    if (section.status === 'NOT_IMPLEMENTED') notImplementedSections += 1
    if (section.status !== 'VALIDATED_SECTION' && section.status !== 'NOT_APPLICABLE' &&
      section.status !== 'NOT_IMPLEMENTED' && section.status !== 'PARTIAL' &&
      section.status !== 'BLOCKED') {
      problems.push('assembly-section-status')
    }
    const fingerprints = section.source_fingerprints
    if (!fingerprints ||
      fingerprints.l2_intent !== expectedSectionFingerprints.l2_intent ||
      fingerprints.l2_preview !== expectedSectionFingerprints.l2_preview ||
      fingerprints.l2_render !== expectedSectionFingerprints.l2_render ||
      fingerprints.l2_validation !== expectedSectionFingerprints.l2_validation ||
      fingerprints.l3_intent !== expectedSectionFingerprints.l3_intent ||
      fingerprints.l3_render !== expectedSectionFingerprints.l3_render ||
      fingerprints.l3_validation !== expectedSectionFingerprints.l3_validation) {
      problems.push('assembly-section-fingerprint')
    }
    const candidateIds = new Set<string>()
    for (const candidate of ordinaryArray(section.candidates) as AssemblyCandidate[]) {
      if (!text(candidate.candidate_id) || candidateIds.has(candidate.candidate_id) ||
        !sha256.test(candidate.candidate_fingerprint)) {
        problems.push('assembly-candidate')
        continue
      }
      candidateIds.add(candidate.candidate_id)
      if (!candidateStatuses.has(candidate.status) ||
        !candidateVerdicts.has(candidate.verdict)) {
        problems.push('assembly-candidate-status')
      }
      if (candidate.candidate_text !== null) {
        if (!text(candidate.candidate_text) || candidate.status !== 'candidate' ||
          candidate.verdict !== 'pass' || /[\r\n]/.test(candidate.candidate_text)) {
          problems.push('assembly-candidate-text')
        }
      }
    }
  }
  if (CONFIG_ASSEMBLY_SECTIONS.some((section) => !sectionIds.has(section))) {
    problems.push('assembly-section-set')
  }
  const completeness = value.completeness
  if (!statuses.has(completeness.status) ||
    requiredSections !== completeness.required_sections ||
    validatedSections !== completeness.validated_sections ||
    partialSections !== completeness.partial_sections ||
    blockedSections !== completeness.blocked_sections ||
    notApplicableSections !== completeness.not_applicable_sections ||
    notImplementedSections !== completeness.not_implemented_sections) {
    problems.push('assembly-completeness-counts')
  }
  if (completeness.complete) {
    if (completeness.status !== 'VALIDATED_SECTION' || completeness.missing_sections.length) {
      problems.push('assembly-complete-claim')
    }
  }
  for (const section of value.sections) {
    if (section.required &&
      !['VALIDATED_SECTION', 'NOT_APPLICABLE'].includes(section.status) &&
      !completeness.missing_sections.includes(section.section_id)) {
      problems.push('assembly-missing-section')
    }
  }
  const sourceCandidateFingerprints = new Set([
    ...l2CandidateFingerprints, ...l3CandidateFingerprints,
  ])
  const sectionCandidateFingerprints = new Set(
    value.sections.flatMap((section) =>
      section.candidates.map((candidate) => candidate.candidate_fingerprint),
    ),
  )
  if (sourceCandidateFingerprints.size !== sectionCandidateFingerprints.size ||
    [...sourceCandidateFingerprints].some((value) => !sectionCandidateFingerprints.has(value))) {
    problems.push('assembly-candidate-fingerprint')
  }
  const checks = ordinaryArray(raw.cross_layer_checks) as AssemblyCrossCheck[]
  if (checks.length !== CONFIG_ASSEMBLY_CHECKS.length ||
    new Set(checks.map((item) => item.check_id)).size !== checks.length) {
    problems.push('assembly-cross-check-set')
  }
  for (const check of checks) {
    if (!text(check.check_id) || !crossStatuses.has(check.status) ||
      !Array.isArray(check.reason_codes) || !text(check.detail)) {
      problems.push('assembly-cross-check')
    }
  }

  const safety = value.safety
  if (!safety || safety.read_only !== true || safety.candidate_only !== true ||
    safety.executable !== false || safety.deployable !== false ||
    safety.deployment_allowed !== false || safety.device_connection !== 'none' ||
    safety.running_config_read !== false || safety.device_writes_enabled !== false ||
    safety.device_runtime_state !== 'unknown-not-read' ||
    safety.full_config_generated !== false || safety.cli !== null ||
    safety.deployment_artifact !== null || safety.hardware_verified !== false ||
    safety.assembly_is_not_execution_authorization !== true) {
    problems.push('assembly-safety')
  }
  if (value.executable !== false || value.cli !== null ||
    value.device_writes_enabled !== false || value.full_config_generated !== false ||
    value.device_runtime_state !== 'unknown-not-read') {
    problems.push('assembly-safety')
  }
  if (value.verification !== 'not-verified' || value.deployment_status !== 'blocked') {
    problems.push('assembly-safety')
  }
  void sectionFingerprints
  return [...new Set(problems)]
}
