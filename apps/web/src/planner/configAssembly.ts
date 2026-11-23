import { ApiError } from '../api'
import type {
  L2CandidateDocument,
  L2CandidateValidation,
  L2DocumentCandidate,
  L2ValidationReport,
  PreviewBinding,
} from './ciscoPreview'
import type {
  L3Candidate,
  L3CandidateDocument,
  L3CandidateValidation,
  L3ValidationReport,
} from './l3Review'
import { canonicalSha256 } from './canonical'

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

export const CONFIG_ASSEMBLY_SECTION_LAYERS: Record<string, 'l2' | 'l3' | 'none'> = {
  'vlan-definitions': 'l2',
  'stp-vtp': 'l2',
  'physical-interfaces': 'l2',
  'access-trunk-vlans': 'l2',
  'port-channels-lacp': 'l2',
  'portfast-bpdu-poe': 'l2',
  'ip-routing': 'l3',
  'svi': 'l3',
  'routes': 'l3',
  'dhcp': 'l3',
  'management-auth-ssh': 'none',
  'snmp-syslog-ntp': 'none',
}

export const CONFIG_ASSEMBLY_SECTION_CATEGORIES: Record<string, readonly string[]> = {
  'vlan-definitions': ['vlan-definition'],
  'stp-vtp': ['rapid-pvst', 'vtp-transparent', 'root-priority'],
  'physical-interfaces': ['speed', 'duplex', 'description', 'admin-shutdown', 'unused-shutdown'],
  'access-trunk-vlans': ['access-mode', 'access-vlan', 'trunk-mode', 'native-vlan', 'allowed-vlans'],
  'port-channels-lacp': ['port-channel', 'lacp-mode'],
  'portfast-bpdu-poe': ['portfast', 'bpdu-guard', 'poe-mode'],
  'ip-routing': ['ip-routing'],
  'svi': ['svi-interface', 'svi-address'],
  'routes': ['static-route', 'default-route'],
  'dhcp': ['dhcp-helper-address'],
  'management-auth-ssh': [],
  'snmp-syslog-ntp': [],
}

export const CONFIG_ASSEMBLY_PROBLEM_KEYS: Record<string, string> = {
  'assembly-l2-trust-gate': 'ciscoAssemblyTrustL2',
  'assembly-l3-trust-gate': 'ciscoAssemblyTrustL3',
  'assembly-l2-binding': 'ciscoAssemblyTrustL2',
  'assembly-l3-binding': 'ciscoAssemblyTrustL3',
  'assembly-l2-candidate-set': 'ciscoAssemblyTrustL2',
  'assembly-l3-candidate-set': 'ciscoAssemblyTrustL3',
  'assembly-l2-candidate-fingerprint-set': 'ciscoAssemblyCandidateFingerprint',
  'assembly-l3-candidate-fingerprint-set': 'ciscoAssemblyCandidateFingerprint',
  'assembly-candidate-binding': 'ciscoAssemblyCandidateBinding',
  'assembly-candidate-category': 'ciscoAssemblyCandidateBinding',
  'assembly-candidate-layer': 'ciscoAssemblyCandidateBinding',
  'assembly-candidate-set': 'ciscoAssemblyCandidateBinding',
  'assembly-candidate-text': 'ciscoAssemblyCandidateText',
  'assembly-candidate-fingerprint': 'ciscoAssemblyCandidateFingerprint',
  'assembly-source-fingerprint': 'ciscoAssemblyCandidateFingerprint',
  'assembly-content-fingerprint': 'ciscoAssemblyContentFingerprint',
  'assembly-complete-claim': 'ciscoAssemblyCompleteClaim',
  'assembly-section-status': 'ciscoAssemblySectionConsistency',
  'assembly-section-counts': 'ciscoAssemblySectionConsistency',
  'assembly-cross-check': 'ciscoAssemblyCrossCheckConsistency',
  'assembly-cross-check-status': 'ciscoAssemblyCrossCheckConsistency',
  'assembly-cross-check-set': 'ciscoAssemblyCrossCheckSet',
  'assembly-required-section': 'ciscoAssemblyRequiredSection',
  'assembly-candidate-untrusted': 'ciscoAssemblyTrustL2',
}

const NOT_IMPLEMENTED_SECTIONS = new Set(['snmp-syslog-ntp'])
const BASE_L2_SECTIONS = new Set([
  'vlan-definitions', 'stp-vtp', 'physical-interfaces', 'access-trunk-vlans',
])
const CORE_L3_SECTIONS = new Set(['ip-routing', 'svi', 'routes'])
const SECTION_IDS = new Set<string>(CONFIG_ASSEMBLY_SECTIONS)
const CHECK_IDS = new Set<string>(CONFIG_ASSEMBLY_CHECKS)
const CHECK_REQUIRES_VALIDATED_SECTION: Record<string, string[]> = {
  'vlan-definition-exists': ['vlan-definitions'],
  'svi-vlan-definition-consistency': ['vlan-definitions'],
  'routed-switchport-conflict': ['access-trunk-vlans'],
  'native-allowed-vlan-reference': ['access-trunk-vlans'],
  'static-route-next-hop-dependency': ['routes'],
  'default-route-evidence-gate': ['routes'],
  'dhcp-relay-issue-30': ['dhcp'],
}

export interface AssemblyL2Trust {
  report: L2ValidationReport
  document: L2CandidateDocument
}

export interface AssemblyL3Trust {
  report: L3ValidationReport
  document: L3CandidateDocument
}

export interface AssemblyTrustInputs {
  l2: AssemblyL2Trust | null
  l3: AssemblyL3Trust | null
  l3Applicable: boolean
}

export interface AssemblySourceCandidate {
  source_layer: 'l2' | 'l3'
  document_candidate: L2DocumentCandidate | L3Candidate
  report_candidate: L2CandidateValidation | L3CandidateValidation
  expected_verdict: CandidateVerdict
}

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

export function assemblyContentFingerprint(value: ConfigurationAssembly): string {
  const payload = { ...(value as unknown as Record<string, unknown>) }
  delete payload.assembly_fingerprint
  return canonicalSha256(payload)
}

function sameArray(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index])
}

function sameSet(left: ReadonlySet<string>, right: ReadonlySet<string>): boolean {
  return left.size === right.size && [...left].every((item) => right.has(item))
}

function l2ExpectedVerdict(
  candidate: L2DocumentCandidate,
  row: L2CandidateValidation,
): CandidateVerdict {
  if (candidate.status !== 'candidate') return 'blocked'
  if (row.independent_verdict === 'pass') return 'pass'
  if (row.independent_verdict === 'fail') return 'fail'
  return 'not-run'
}

function l3ExpectedVerdict(
  candidate: L3Candidate,
  row: L3CandidateValidation,
): CandidateVerdict {
  if (candidate.status !== 'candidate') return 'blocked'
  if (row.independent_verdict === 'pass') return 'pass'
  if (row.independent_verdict === 'fail') return 'fail'
  if (row.independent_verdict === 'blocked') return 'blocked'
  return 'not-run'
}

interface TrustIndex {
  l2: Map<string, AssemblySourceCandidate>
  l3: Map<string, AssemblySourceCandidate>
  l2Applicable: boolean
  l3Applicable: boolean
  l2Document: L2CandidateDocument | null
  l3Document: L3CandidateDocument | null
  l2Report: L2ValidationReport | null
  l3Report: L3ValidationReport | null
}

function buildTrustIndex(
  binding: PreviewBinding,
  trust: AssemblyTrustInputs,
  problems: string[],
): TrustIndex {
  const l2 = new Map<string, AssemblySourceCandidate>()
  const l3 = new Map<string, AssemblySourceCandidate>()
  let l2Document: L2CandidateDocument | null = null
  let l3Document: L3CandidateDocument | null = null
  let l2Report: L2ValidationReport | null = null
  let l3Report: L3ValidationReport | null = null

  if (!trust.l2) {
    problems.push('assembly-l2-trust-gate')
  } else {
    const document = trust.l2.document
    const report = trust.l2.report
    l2Document = document
    l2Report = report
    if (
      document.assignment_id !== binding.assignment.assignmentId ||
      report.assignment_id !== binding.assignment.assignmentId ||
      document.source.saved_revision_uuid !== binding.revision.id ||
      report.source.saved_revision_uuid !== binding.revision.id ||
      document.source.revision_number !== binding.revision.number ||
      report.source.revision_number !== binding.revision.number ||
      document.source.revision_canonical_hash !== binding.revision.content_hash ||
      report.source.revision_canonical_hash !== binding.revision.content_hash ||
      document.source.intent_fingerprint !== report.source.intent_fingerprint ||
      document.source.preview_fingerprint !== report.source.preview_fingerprint ||
      document.render_fingerprint !== report.source.render_fingerprint ||
      document.source.command_evidence_registry_id !==
        report.source.command_evidence_registry_id ||
      document.source.command_evidence_fingerprint !==
        report.source.command_evidence_fingerprint
    ) {
      problems.push('assembly-l2-binding')
    }
    const reports = new Map(report.candidates.map((row) => [row.candidate_id, row]))
    const documentIds = new Set(document.candidates.map((item) => item.candidate_id))
    if (!sameSet(documentIds, new Set(reports.keys()))) {
      problems.push('assembly-l2-candidate-set')
    }
    for (const candidate of document.candidates) {
      const row = reports.get(candidate.candidate_id)
      if (!row) continue
      if (row.category !== candidate.category ||
        row.candidate_fingerprint !== candidate.candidate_fingerprint) {
        problems.push('assembly-l2-candidate-binding')
      }
      l2.set(candidate.candidate_id, {
        source_layer: 'l2',
        document_candidate: candidate,
        report_candidate: row,
        expected_verdict: l2ExpectedVerdict(candidate, row),
      })
    }
  }

  if (trust.l3Applicable) {
    if (!trust.l3) {
      problems.push('assembly-l3-trust-gate')
    } else {
      const document = trust.l3.document
      const report = trust.l3.report
      l3Document = document
      l3Report = report
      if (
        document.assignment_id !== binding.assignment.assignmentId ||
        report.assignment_id !== binding.assignment.assignmentId ||
        document.source.revision_uuid !== binding.revision.id ||
        report.source.saved_revision_uuid !== binding.revision.id ||
        document.source.revision_number !== binding.revision.number ||
        report.source.revision_number !== binding.revision.number ||
        document.source.revision_hash !== binding.revision.content_hash ||
        report.source.revision_canonical_hash !== binding.revision.content_hash ||
        document.source.l3_intent_fingerprint !== report.source.l3_intent_fingerprint ||
        document.l3_render_fingerprint !== report.source.l3_render_fingerprint ||
        document.source.command_evidence_registry_id !==
          report.source.command_evidence_registry_id ||
        document.source.command_evidence_registry_fingerprint !==
          report.source.command_evidence_registry_fingerprint
      ) {
        problems.push('assembly-l3-binding')
      }
      const reports = new Map(report.candidates.map((row) => [row.candidate_id, row]))
      const documentIds = new Set(document.candidates.map((item) => item.candidate_id))
      if (!sameSet(documentIds, new Set(reports.keys()))) {
        problems.push('assembly-l3-candidate-set')
      }
      for (const candidate of document.candidates) {
        const row = reports.get(candidate.candidate_id)
        if (!row) continue
        if (row.category !== candidate.category ||
          row.target_kind !== candidate.target.kind ||
          row.target_name !== candidate.target.name) {
          problems.push('assembly-l3-candidate-binding')
        }
        l3.set(candidate.candidate_id, {
          source_layer: 'l3',
          document_candidate: candidate,
          report_candidate: row,
          expected_verdict: l3ExpectedVerdict(candidate, row),
        })
      }
    }
  } else if (trust.l3) {
    l3Document = trust.l3.document
    l3Report = trust.l3.report
  }

  return {
    l2,
    l3,
    l2Applicable: true,
    l3Applicable: trust.l3Applicable,
    l2Document,
    l3Document,
    l2Report,
    l3Report,
  }
}

function deriveRequiredSections(
  sections: readonly AssemblySection[],
  trust: TrustIndex | null,
): Set<string> {
  const required = new Set<string>()
  for (const section of sections) {
    if (section.section_id === 'management-auth-ssh') {
      required.add(section.section_id)
    } else if (section.section_id === 'snmp-syslog-ntp') {
      continue
    } else if (BASE_L2_SECTIONS.has(section.section_id)) {
      required.add(section.section_id)
    } else if (CORE_L3_SECTIONS.has(section.section_id)) {
      if (trust?.l3Applicable) required.add(section.section_id)
    } else if (section.section_id === 'dhcp') {
      if ([...(trust?.l3.values() ?? [])].some(
        (source) => source.document_candidate.category === 'dhcp-helper-address',
      )) required.add(section.section_id)
    } else if (section.candidates.length > 0) {
      required.add(section.section_id)
    }
  }
  return required
}

function derivedCompletenessStatus(
  requiredSections: readonly AssemblySection[],
  crossChecks: readonly AssemblyCrossCheck[],
): AssemblySectionStatus {
  const crossBlocked = crossChecks.some(
    (check) => check.status === 'FAIL' || check.status === 'BLOCKED',
  )
  const allRequiredSatisfied = requiredSections.every(
    (section) => section.status === 'VALIDATED_SECTION' ||
      section.status === 'NOT_APPLICABLE',
  )
  if (allRequiredSatisfied && !crossBlocked) return 'VALIDATED_SECTION'
  if (crossBlocked || requiredSections.some((section) => section.status === 'BLOCKED')) {
    return 'BLOCKED'
  }
  if (requiredSections.some((section) => section.status === 'NOT_IMPLEMENTED')) {
    return 'NOT_IMPLEMENTED'
  }
  return 'PARTIAL'
}

function expectedCrossLayerStatus(
  checkId: string,
  trust: TrustIndex | null,
): CrossLayerStatus | null {
  if (!trust || !trust.l3Applicable) return null
  if (checkId === 'default-route-evidence-gate') {
    const rows = [...trust.l3.values()].filter(
      (source) => source.document_candidate.category === 'default-route',
    )
    if (!rows.length) return 'NOT_APPLICABLE'
    return rows.every((source) => source.expected_verdict === 'pass') ? 'PASS' : 'FAIL'
  }
  if (checkId === 'dhcp-relay-issue-30') {
    const rows = [...trust.l3.values()].filter(
      (source) => source.document_candidate.category === 'dhcp-helper-address',
    )
    if (!rows.length) return 'NOT_APPLICABLE'
    return rows.some((source) => source.expected_verdict === 'pass') ? 'FAIL' : 'BLOCKED'
  }
  return null
}

export function validateAssembly(
  value: ConfigurationAssembly,
  binding: PreviewBinding,
  trust?: AssemblyTrustInputs,
): string[] {
  const problems: string[] = []
  const raw = value as unknown as Record<string, unknown>
  if (value.assembly_schema_version !== CONFIG_ASSEMBLY_SCHEMA_VERSION ||
    value.contract_id !== CONFIG_ASSEMBLY_CONTRACT) {
    problems.push('assembly-contract')
  }
  if (!sha256.test(value.assembly_fingerprint)) problems.push('assembly-fingerprint')
  let recomputedFingerprint = ''
  try {
    recomputedFingerprint = assemblyContentFingerprint(value)
  } catch {
    problems.push('assembly-fingerprint')
  }
  if (recomputedFingerprint && recomputedFingerprint !== value.assembly_fingerprint) {
    problems.push('assembly-content-fingerprint')
  }
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

  const trustIndex = trust ? buildTrustIndex(binding, trust, problems) : null
  if (trust) {
    if (!trustIndex?.l2Document) {
      problems.push('assembly-l2-trust-gate')
    }
    if (trust.l3Applicable && !trustIndex?.l3Document) {
      problems.push('assembly-l3-trust-gate')
    }
    if (trustIndex?.l2Document) {
      if (!sameArray(
        l2CandidateFingerprints,
        trustIndex.l2Document.candidates.map((item) => item.candidate_fingerprint),
      )) problems.push('assembly-l2-candidate-fingerprint-set')
    } else if (l2CandidateFingerprints.length) {
      problems.push('assembly-l2-candidate-fingerprint-set')
    }
    if (trust.l3Applicable && trustIndex?.l3Document) {
      if (!sameArray(
        l3CandidateFingerprints,
        trustIndex.l3Document.candidates.map((item) => item.candidate_fingerprint),
      )) problems.push('assembly-l3-candidate-fingerprint-set')
    } else if (l3CandidateFingerprints.length) {
      problems.push('assembly-l3-candidate-fingerprint-set')
    }
  } else if (l2CandidateFingerprints.length || l3CandidateFingerprints.length) {
    problems.push('assembly-source-fingerprint')
  }

  if (trustIndex?.l2Report) {
    if (source.l2_intent_fingerprint !== trustIndex.l2Report.source.intent_fingerprint ||
      source.l2_preview_fingerprint !== trustIndex.l2Report.source.preview_fingerprint ||
      source.l2_render_fingerprint !== trustIndex.l2Report.source.render_fingerprint ||
      source.l2_validation_fingerprint !== trustIndex.l2Report.report_fingerprint ||
      source.l2_command_evidence_registry_id !==
        trustIndex.l2Report.source.command_evidence_registry_id ||
      source.l2_command_evidence_registry_fingerprint !==
        trustIndex.l2Report.source.command_evidence_fingerprint) {
      problems.push('assembly-l2-binding')
    }
  }
  if (trustIndex?.l3Report) {
    if (source.l3_intent_fingerprint !== trustIndex.l3Report.source.l3_intent_fingerprint ||
      source.l3_render_fingerprint !== trustIndex.l3Report.source.l3_render_fingerprint ||
      source.l3_validation_fingerprint !== trustIndex.l3Report.report_fingerprint ||
      source.l3_command_evidence_registry_id !==
        trustIndex.l3Report.source.command_evidence_registry_id ||
      source.l3_command_evidence_registry_fingerprint !==
        trustIndex.l3Report.source.command_evidence_registry_fingerprint) {
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

  const sections = ordinaryArray(raw.sections) as AssemblySection[]
  const sectionIds = new Set<string>()
  const sectionById = new Map<string, AssemblySection>()
  const assemblyCandidateIds = new Set<string>()
  const assemblyCandidateFingerprints = new Set<string>()
  for (const section of sections) {
    if (!text(section.section_id) || sectionIds.has(section.section_id) ||
      !SECTION_IDS.has(section.section_id)) {
      problems.push('assembly-section-id')
      continue
    }
    sectionIds.add(section.section_id)
    sectionById.set(section.section_id, section)
    if (!statuses.has(section.status) || !applicability.has(section.applicability)) {
      problems.push('assembly-section-status')
    }
    for (const count of [
      section.candidate_count, section.passed_count, section.failed_count,
      section.blocked_count, section.missing_count,
    ]) {
      if (!integer(count)) problems.push('assembly-section-counts')
    }
    const fingerprints = section.source_fingerprints
    if (!fingerprints ||
      fingerprints.l2_intent !== source.l2_intent_fingerprint ||
      fingerprints.l2_preview !== source.l2_preview_fingerprint ||
      fingerprints.l2_render !== source.l2_render_fingerprint ||
      fingerprints.l2_validation !== source.l2_validation_fingerprint ||
      fingerprints.l3_intent !== source.l3_intent_fingerprint ||
      fingerprints.l3_render !== source.l3_render_fingerprint ||
      fingerprints.l3_validation !== source.l3_validation_fingerprint) {
      problems.push('assembly-section-fingerprint')
    }
    const layer = CONFIG_ASSEMBLY_SECTION_LAYERS[section.section_id]
    const categories = new Set(CONFIG_ASSEMBLY_SECTION_CATEGORIES[section.section_id] ?? [])
    const candidates = ordinaryArray(section.candidates) as AssemblyCandidate[]
    let passed = 0
    let failed = 0
    let blocked = 0
    for (const candidate of candidates) {
      if (!text(candidate.candidate_id) || assemblyCandidateIds.has(candidate.candidate_id) ||
        !sha256.test(candidate.candidate_fingerprint)) {
        problems.push('assembly-candidate')
        continue
      }
      assemblyCandidateIds.add(candidate.candidate_id)
      assemblyCandidateFingerprints.add(candidate.candidate_fingerprint)
      if (!candidateStatuses.has(candidate.status) ||
        !candidateVerdicts.has(candidate.verdict)) {
        problems.push('assembly-candidate-status')
      }
      if (candidate.verdict === 'pass') passed += 1
      if (candidate.verdict === 'fail') failed += 1
      if (candidate.status !== 'candidate' || candidate.verdict === 'blocked') blocked += 1
      if (candidate.candidate_text !== null && (
        !text(candidate.candidate_text) ||
        candidate.status !== 'candidate' ||
        candidate.verdict !== 'pass' ||
        /[\r\n]/.test(candidate.candidate_text)
      )) {
        problems.push('assembly-candidate-text')
      }
      if (layer === 'none') {
        problems.push('assembly-candidate-section')
      }
      if (!text(candidate.category) || !categories.has(candidate.category)) {
        problems.push('assembly-candidate-category')
      }
      if (candidate.source_layer !== layer) {
        problems.push('assembly-candidate-layer')
      }
      if (!trustIndex) {
        problems.push('assembly-candidate-untrusted')
        continue
      }
      const sourceCandidate = layer === 'l2'
        ? trustIndex.l2.get(candidate.candidate_id)
        : layer === 'l3' ? trustIndex.l3.get(candidate.candidate_id) : undefined
      if (!sourceCandidate) {
        const wrongLayer = layer === 'l2'
          ? trustIndex.l3.has(candidate.candidate_id)
          : trustIndex.l2.has(candidate.candidate_id)
        problems.push(wrongLayer ? 'assembly-candidate-layer' : 'assembly-candidate-binding')
        continue
      }
      const documentCandidate = sourceCandidate.document_candidate
      if (candidate.source_layer !== sourceCandidate.source_layer ||
        candidate.category !== documentCandidate.category ||
        candidate.target_kind !== documentCandidate.target.kind ||
        candidate.target_name !== documentCandidate.target.name ||
        candidate.status !== documentCandidate.status ||
        candidate.verdict !== sourceCandidate.expected_verdict ||
        candidate.candidate_fingerprint !== documentCandidate.candidate_fingerprint ||
        candidate.candidate_text !== documentCandidate.candidate_text) {
        problems.push('assembly-candidate-binding')
      }
      if (candidate.candidate_text !== null && (
        documentCandidate.status !== 'candidate' ||
        sourceCandidate.expected_verdict !== 'pass' ||
        documentCandidate.candidate_text === null
      )) {
        problems.push('assembly-candidate-text')
      }
    }
    if (section.candidate_count !== candidates.length ||
      section.passed_count !== passed ||
      section.failed_count !== failed ||
      section.blocked_count !== blocked) {
      problems.push('assembly-section-counts')
    }
    const required = BASE_L2_SECTIONS.has(section.section_id) ||
      section.section_id === 'management-auth-ssh' ||
      (CORE_L3_SECTIONS.has(section.section_id) && Boolean(trustIndex?.l3Applicable)) ||
      (section.section_id === 'dhcp' && [...(trustIndex?.l3.values() ?? [])].some(
        (candidate) => candidate.document_candidate.category === 'dhcp-helper-address',
      )) ||
      (['port-channels-lacp', 'portfast-bpdu-poe'].includes(section.section_id) &&
        candidates.length > 0)
    if (section.required !== required) problems.push('assembly-required-section')
    if (required && section.status === 'NOT_APPLICABLE') {
      problems.push('assembly-section-status')
    }
    if (!required && section.status === 'VALIDATED_SECTION') {
      problems.push('assembly-section-status')
    }
    if (section.status === 'NOT_IMPLEMENTED' &&
      !NOT_IMPLEMENTED_SECTIONS.has(section.section_id)) {
      problems.push('assembly-section-status')
    }
    if (section.status === 'NOT_IMPLEMENTED' && candidates.length > 0) {
      problems.push('assembly-section-status')
    }
    if (section.status === 'VALIDATED_SECTION' &&
      (candidates.length === 0 || passed !== candidates.length ||
        failed > 0 || blocked > 0 || section.missing_count !== 0)) {
      problems.push('assembly-section-status')
    }
    if (section.status === 'PARTIAL' && (passed === 0 ||
      failed + blocked + section.missing_count === 0)) {
      problems.push('assembly-section-status')
    }
    if (section.status === 'NOT_APPLICABLE' &&
      (candidates.length > 0 || required)) problems.push('assembly-section-status')
    if ((section.status === 'BLOCKED' || section.status === 'NOT_IMPLEMENTED') &&
      failed === 0 && blocked === 0 && candidates.length > 0 && passed > 0) {
      problems.push('assembly-section-status')
    }
    if (section.status === 'BLOCKED' && candidates.length === 0 && !required) {
      problems.push('assembly-section-status')
    }
  }
  if (!sameSet(sectionIds, SECTION_IDS)) problems.push('assembly-section-set')

  const sourceCandidateIds = new Set<string>([
    ...(trustIndex?.l2.keys() ?? []),
    ...(trustIndex?.l3.keys() ?? []),
  ])
  if (trustIndex && !sameSet(assemblyCandidateIds, sourceCandidateIds)) {
    problems.push('assembly-candidate-set')
  }
  if (trustIndex) {
    const sourceCandidateFingerprints = new Set([
      ...[...(trustIndex.l2.values())].map(
        (item) => item.document_candidate.candidate_fingerprint,
      ),
      ...[...(trustIndex.l3.values())].map(
        (item) => item.document_candidate.candidate_fingerprint,
      ),
    ])
    if (!sameSet(assemblyCandidateFingerprints, sourceCandidateFingerprints)) {
      problems.push('assembly-candidate-fingerprint')
    }
  } else if (assemblyCandidateIds.size > 0) {
    problems.push('assembly-candidate-untrusted')
  }

  const checks = ordinaryArray(raw.cross_layer_checks) as AssemblyCrossCheck[]
  const checkIds = new Set<string>()
  for (const check of checks) {
    if (!text(check.check_id) || checkIds.has(check.check_id) ||
      !CHECK_IDS.has(check.check_id) || !crossStatuses.has(check.status) ||
      !Array.isArray(check.reason_codes) || !text(check.detail)) {
      problems.push('assembly-cross-check')
      continue
    }
    checkIds.add(check.check_id)
    const expected = expectedCrossLayerStatus(check.check_id, trustIndex)
    if (expected !== null && check.status !== expected) {
      problems.push('assembly-cross-check-status')
    }
    if (check.status === 'PASS') {
      for (const sectionId of CHECK_REQUIRES_VALIDATED_SECTION[check.check_id] ?? []) {
        const status = sectionById.get(sectionId)?.status
        if (status !== 'VALIDATED_SECTION' && status !== 'NOT_APPLICABLE') {
          problems.push('assembly-cross-check-status')
        }
      }
    }
  }
  if (!sameSet(checkIds, CHECK_IDS)) problems.push('assembly-cross-check-set')

  const derivedRequired = deriveRequiredSections(sections, trustIndex)
  const requiredSections = sections.filter((section) => derivedRequired.has(section.section_id))
  const derivedStatus = derivedCompletenessStatus(requiredSections, checks)
  const derivedMissingSections = requiredSections
    .filter((section) => section.status !== 'VALIDATED_SECTION' &&
      section.status !== 'NOT_APPLICABLE')
    .map((section) => section.section_id)
  const derivedComplete = derivedStatus === 'VALIDATED_SECTION'
  const counts = {
    required: requiredSections.length,
    validated: sections.filter((section) => section.status === 'VALIDATED_SECTION').length,
    partial: sections.filter((section) => section.status === 'PARTIAL').length,
    blocked: sections.filter((section) => section.status === 'BLOCKED').length,
    notApplicable: sections.filter((section) => section.status === 'NOT_APPLICABLE').length,
    notImplemented: sections.filter((section) => section.status === 'NOT_IMPLEMENTED').length,
  }
  const completeness = value.completeness
  if (!statuses.has(completeness.status) ||
    counts.required !== completeness.required_sections ||
    counts.validated !== completeness.validated_sections ||
    counts.partial !== completeness.partial_sections ||
    counts.blocked !== completeness.blocked_sections ||
    counts.notApplicable !== completeness.not_applicable_sections ||
    counts.notImplemented !== completeness.not_implemented_sections) {
    problems.push('assembly-completeness-counts')
  }
  if (completeness.status !== derivedStatus) {
    problems.push('assembly-completeness-status')
  }
  if (completeness.complete !== derivedComplete) {
    problems.push('assembly-complete-claim')
  }
  if (!sameArray(completeness.missing_sections, derivedMissingSections)) {
    problems.push('assembly-missing-section')
  }
  const crossBlocked = checks.some(
    (check) => check.status === 'FAIL' || check.status === 'BLOCKED',
  )
  if (completeness.complete && (crossBlocked || derivedMissingSections.length > 0)) {
    problems.push('assembly-complete-claim')
  }
  if (!derivedComplete && completeness.blockers.length === 0) {
    problems.push('assembly-completeness-blockers')
  }
  if (derivedComplete && (value.executable !== false ||
    value.full_config_generated !== false || value.cli !== null)) {
    problems.push('assembly-safety')
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
  return [...new Set(problems)]
}
