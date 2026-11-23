import { ApiError, request } from '../api'
import { list, read, records } from './model'
import type { MessageKey } from '../messages'
import type { Plan, RecordValue, Revision, Summary } from './model'

export const L3_CONTRACT = 'cis-03-cisco-l3-cli-candidate-v1'
export const L3_VALIDATION_CONTRACT = 'cis-03-03-independent-cli-validation-v1'
export const L3_REGISTRY_ID = 'cis-03-l1-command-evidence-v1'
export const L3_REGISTRY_FINGERPRINT = '27d9c46f610b974de5570fb13e115260e2d109475a8d967704de9bb9ca6ef00b'
export const L3_UNREVIEWED_REGISTRY_ID = 'cis-03-l1-command-evidence-unreviewed-v1'
export const L3_UNREVIEWED_REGISTRY_FINGERPRINT = '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'

// Frozen Catalyst 9300 reviewed scope.  This mirrors the backend selection
// boundary; an unsupported 9300 identity must not inherit the reviewed rows.
const L3_9300_PIDS = new Set([
  'C9300-24T', 'C9300-24P', 'C9300L-24T-4G', 'C9300L-24T-4G-E',
  'C9300L-24P-4X', 'C9300L-24P-4X-E', 'C9300X-24Y', 'C9300X-24Y-A',
])
const L3_9300_RELEASE = '17.12.4'
const L3_9300_LICENSES = new Set(['network essentials', 'network advantage'])
const L3_KNOWN_FAMILIES = new Set(['catalyst-9300', 'catalyst-9200'])

export const sourceFields = [
  'event_id', 'saved_revision_uuid', 'revision_number', 'revision_canonical_hash',
  'l3_intent_schema_version', 'l3_intent_fingerprint', 'l3_render_contract_id',
  'l3_render_contract_version', 'l3_render_fingerprint',
  'command_evidence_registry_id', 'command_evidence_registry_fingerprint',
  'assignment_id', 'baseline_revision_uuid', 'baseline_revision_hash',
] as const

export type L3SourceField = (typeof sourceFields)[number]
export type L3Source = { [K in L3SourceField]: string | number | null }
export type L3Overall = 'pass' | 'partial' | 'fail'
export type L3Verdict = 'pass' | 'fail' | 'blocked' | 'not-run'
export type L3CandidateStatus = 'candidate' | 'blocked' | 'unsupported'
export type L3Risk = 'R2' | 'R3'

export interface L3Integrity {
  revision_canonical_hash: boolean
  baseline_canonical_hash: boolean
  intent_rebuilt: boolean
  intent_fingerprint: boolean
  expected_source: boolean
  document_source: boolean
  document_fingerprint: boolean
  candidate_fingerprints: boolean
  candidate_ids_unique: boolean
  candidate_set: boolean
  summary: boolean
  safety: boolean
}

export const integrityFields = [
  'revision_canonical_hash', 'baseline_canonical_hash', 'intent_rebuilt',
  'intent_fingerprint', 'expected_source', 'document_source', 'document_fingerprint',
  'candidate_fingerprints', 'candidate_ids_unique', 'candidate_set', 'summary', 'safety',
] as const
export type L3IntegrityField = (typeof integrityFields)[number]

export interface L3Safety {
  candidate_only: boolean
  executable: boolean
  deployable: boolean
  deployment_allowed: boolean
  hardware_verified: boolean
  device_connection: string
  running_config_read: boolean
  device_writes_enabled: boolean
  cli: null
  deployment_artifact: null
  independent_parser?: string
  parser_verified?: boolean
  deployment_authorized?: boolean
}

export interface L3Device {
  assignment_id: string
  hostname: string
  role: string
  family: string | null
  exact_pid: string | null
  software_image: string | null
  software_license: string | null
  stack_identity: string
  hardware_verified: boolean
}

export interface L3Summary {
  total: number
  passed: number
  failed: number
  blocked: number
  not_run: number
  base_categories_passed: number
  base_categories_failed: number
  base_candidates_passed: number
  base_candidates_failed: number
  dhcp_helper_blocked: boolean
}

export interface L3Parse {
  status: string
  form: string | null
  mode: string | null
  target_class: string | null
  parameters: { name: string; value: string | number }[]
  failures: string[]
}

export interface L3Evidence {
  evidence_id: string | null
  topic: string | null
  review_state: string | null
  content_digest: string | null
  source_url: string | null
  source_section: string | null
  scope_ok: boolean
  reason_codes: string[]
}

export interface L3Context {
  expected_mode: string
  actual_mode: string | null
  header_bound: boolean
  target_kind: string
  target_stable_id: string
  target_name: string
  bound: boolean
  reason_codes: string[]
}

export interface L3Capability {
  capability: string
  verdict: string | null
  documented: boolean
  reason_codes: string[]
}

export interface L3Security { text_safe: boolean; reason_codes: string[] }
export interface L3Semantics { status: string; reason_codes: string[] }
export interface L3RiskReport {
  renderer_risk: string
  independent_floor: string
  non_degraded: boolean
  reason_codes: string[]
}

export interface L3CandidateValidation {
  candidate_id: string
  category: string
  target_kind: string
  target_stable_id: string
  target_name: string
  parse: L3Parse
  evidence: L3Evidence
  context_binding: L3Context
  target_capability: L3Capability
  security: L3Security
  semantics: L3Semantics
  risk: L3RiskReport
  independent_verdict: L3Verdict
  fail_closed_action: string
}

export interface L3ValidationReport {
  validation_contract_id: string
  validation_schema_version: number
  validation_scope: 'production' | 'test-only'
  expected_source: L3Source
  source: L3Source
  assignment_id: string
  device: L3Device
  integrity: L3Integrity
  candidates: L3CandidateValidation[]
  summary: L3Summary
  overall_status: L3Overall
  safety: L3Safety
  report_fingerprint: string
}

export interface L3CandidateTarget {
  kind: string
  stable_id: string
  name: string
}

export interface L3CommandContext {
  mode: string
  mode_header: string
  target_name: string
}

export interface L3Candidate {
  candidate_id: string
  assignment_id: string
  target: L3CandidateTarget
  category: string
  command_context: L3CommandContext
  status: L3CandidateStatus
  candidate_text: string | null
  parameters: Record<string, unknown>
  provenance: Record<string, unknown>
  capability_evidence: { capability: string; verdict: string; reason_code: string }[]
  syntax_evidence: {
    evidence_id: string; topic: string; release: string; review_state: string;
    content_digest: string; source_url: string; source_section: string
  }[]
  syntax_validation: { level: string; dictionary_id: string; parser_verified: boolean }
  risk_class: string
  potential_connectivity_impact: boolean
  requires_field_verification: boolean
  prerequisites: string[]
  blocking_reasons: string[]
  candidate_fingerprint: string
}

export interface L3CandidateDocument {
  l3_render_schema_version: number
  contract_id: string
  source: {
    revision_uuid: string
    revision_number: number
    revision_hash: string
    l3_intent_schema_version: number
    l3_intent_fingerprint: string
    command_evidence_registry_id: string
    command_evidence_registry_fingerprint: string
  }
  assignment_id: string
  device: Omit<L3Device, 'hardware_verified'>
  render_state: string
  candidates: L3Candidate[]
  blocked_operations: string[]
  unresolved_prerequisites: string[]
  deployment_blockers: string[]
  safety: L3Safety
  summary: { total: number; candidates: number; blocked: number; unsupported: number; categories: string[] }
  l3_render_fingerprint: string
  verification: string
  deployment_status: string
  executable: boolean
  cli: null
  device_writes_enabled: boolean
}

export interface CoreAssignment {
  assignmentId: string
  hostname: string
  family: string | null
  physicalDeviceId: string
  pid: string | null
  verifiedSerial: string | null
  image: string | null
  license: string | null
  stackIdentity: string
  assignment: RecordValue
}

export interface L3RegistryExpectation {
  registryId: string
  registryFingerprint: string
  evidenceApproved: boolean
  identity: {
    hostname: string
    family: string
    exactPid: string
    softwareImage: string
    softwareLicense: string
  }
}

export interface ReviewBinding {
  eventId: string
  revision: Revision
  assignmentId: string
}

export type ReviewProblem =
  | 'validation-scope'
  | 'validation-contract'
  | 'source-binding'
  | 'expected-source'
  | 'actual-source'
  | 'report-integrity'
  | 'report-safety'
  | 'report-fingerprint'
  | 'report-assignment'
  | 'report-device'
  | 'report-summary'
  | 'report-candidates'
  | 'document-contract'
  | 'document-source'
  | 'document-fingerprint'
  | 'document-assignment'
  | 'document-device'
  | 'document-candidates'
  | 'candidate-text'

export const problemKeys: Record<ReviewProblem, MessageKey> = {
  'validation-scope': 'l3DataScopeMismatch',
  'validation-contract': 'l3DataContractMismatch',
  'source-binding': 'l3DataSourceMismatch',
  'expected-source': 'l3DataExpectedSourceMismatch',
  'actual-source': 'l3DataActualSourceMismatch',
  'report-integrity': 'l3DataIntegrityMismatch',
  'report-safety': 'l3DataSafetyMismatch',
  'report-fingerprint': 'l3DataFingerprintMismatch',
  'report-assignment': 'l3DataAssignmentMismatch',
  'report-device': 'l3DataDeviceMismatch',
  'report-summary': 'l3DataSummaryMismatch',
  'report-candidates': 'l3DataCandidateMismatch',
  'document-contract': 'l3DataContractMismatch',
  'document-source': 'l3DataSourceMismatch',
  'document-fingerprint': 'l3DataFingerprintMismatch',
  'document-assignment': 'l3DataAssignmentMismatch',
  'document-device': 'l3DataDeviceMismatch',
  'document-candidates': 'l3DataCandidateMismatch',
  'candidate-text': 'l3DataCandidateTextMismatch',
}

export interface ReviewRow {
  candidateId: string
  category: string
  targetName: string
  status: L3CandidateStatus | null
  verdict: L3Verdict
  risk: string
  capability: string | null
  evidenceReview: string | null
  blockingReasons: string[]
  commandContext: L3CommandContext | null
  text: string | null
  targetKind: string
}

export interface ReviewError {
  status: number | null
  reasonCode: string
  stage: string
  failures: string[]
}

export const overallKeys: Record<L3Overall, MessageKey> = {
  pass: 'overallPass',
  partial: 'overallPartial',
  fail: 'overallFail',
}
export const verdictKeys: Record<L3Verdict, MessageKey> = {
  pass: 'verdictPass',
  fail: 'verdictFail',
  blocked: 'verdictBlocked',
  'not-run': 'verdictNotRun',
}
export const candidateStatusKeys: Record<L3CandidateStatus, MessageKey> = {
  candidate: 'candidateStatusCandidate',
  blocked: 'candidateStatusBlocked',
  unsupported: 'candidateStatusUnsupported',
}

const detailRecord = (detail: unknown): Record<string, unknown> =>
  detail !== null && typeof detail === 'object' && !Array.isArray(detail)
    ? detail as Record<string, unknown> : {}

export function parseReviewError(error: unknown): ReviewError {
  if (error instanceof ApiError) {
    const detail = detailRecord(error.detail)
    const failures = Array.isArray(detail.failures)
      ? detail.failures.filter((item): item is string => typeof item === 'string') : []
    return {
      status: error.status,
      reasonCode: typeof detail.reason_code === 'string' ? detail.reason_code : '',
      stage: typeof detail.stage === 'string' ? detail.stage : '',
      failures,
    }
  }
  return { status: null, reasonCode: '', stage: '', failures: [] }
}

export function isAbort(error: unknown) {
  return error instanceof DOMException && error.name === 'AbortError'
}

export function reviewErrorKey(error: ReviewError): MessageKey {
  if (error.reasonCode === 'validation-scope-not-full') return 'l3DataScopeMismatch'
  if (error.reasonCode === 'assignment-not-eligible-for-l3-cli') return 'l3AssignmentNotEligible'
  if (error.reasonCode === 'candidate-document-not-reviewable') return 'l3CandidateDocumentNotReviewable'
  if (error.status === 400) return 'l3RequestRejected'
  if (error.status === 404) return 'l3ReviewNotFound'
  if (error.status === 409) return 'l3ReviewConflict'
  if (error.status === 422) return 'l3ReviewUnprocessable'
  return 'l3ReviewNetworkError'
}

export function coreAssignments(plan: Plan): CoreAssignment[] {
  const devices = new Map(records(plan, 'physical_devices').map((device) => [String(device.id), device] as const))
  const stacks = new Map(records(plan, 'stacks').map((stack) => [String(stack.assignment_id), stack] as const))
  return records(plan, 'assignments').flatMap((assignment) => {
    if (assignment.role !== 'core') return []
    const physicalDeviceId = String(assignment.physical_device_id ?? '')
    const device = devices.get(physicalDeviceId)
    if (!device || device.vendor !== 'cisco') return []
    const software = deviceOrObject(assignment.software)
    const stack = stacks.get(String(assignment.id))
    const members = stack ? objectArray(stack.members) : []
    const identity = members.length ? `stack:${members.length}` : 'standalone'
    return [{
      assignmentId: String(assignment.id), hostname: String(assignment.hostname ?? ''),
      family: assignment.family === null || assignment.family === undefined ? null : String(assignment.family),
      physicalDeviceId, pid: device.model === null || device.model === undefined ? null : String(device.model),
      verifiedSerial: device.verified_serial === null || device.verified_serial === undefined
        ? null : String(device.verified_serial),
      image: software.image === undefined ? null : String(software.image),
      license: software.license === undefined ? null : String(software.license),
      stackIdentity: identity, assignment,
    } satisfies CoreAssignment]
  })
}

export function expectedRegistryBinding(binding: ReviewBinding): L3RegistryExpectation | null {
  const core = coreAssignments(binding.revision.plan)
    .find((item) => item.assignmentId === binding.assignmentId)
  if (
    !core || !core.family || !core.pid || !core.verifiedSerial ||
    !core.image || !core.license || !L3_KNOWN_FAMILIES.has(core.family)
  ) return null
  const exactPid = core.pid.toUpperCase()
  const reviewed9300 = core.family === 'catalyst-9300' &&
    L3_9300_PIDS.has(exactPid) &&
    core.image === L3_9300_RELEASE &&
    L3_9300_LICENSES.has(core.license.toLowerCase())
  return {
    registryId: reviewed9300 ? L3_REGISTRY_ID : L3_UNREVIEWED_REGISTRY_ID,
    registryFingerprint: reviewed9300 ? L3_REGISTRY_FINGERPRINT : L3_UNREVIEWED_REGISTRY_FINGERPRINT,
    evidenceApproved: reviewed9300,
    identity: {
      hostname: core.hostname,
      family: core.family,
      exactPid,
      softwareImage: core.image,
      softwareLicense: core.license,
    },
  }
}

export function isUnreviewedRegistry(report: L3ValidationReport): boolean {
  return report.source.command_evidence_registry_id === L3_UNREVIEWED_REGISTRY_ID &&
    report.source.command_evidence_registry_fingerprint === L3_UNREVIEWED_REGISTRY_FINGERPRINT
}

function deviceOrObject(value: unknown): RecordValue {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as RecordValue : {}
}
function objectArray(value: unknown): RecordValue[] {
  return Array.isArray(value)
    ? value.filter((item): item is RecordValue => item !== null && typeof item === 'object' && !Array.isArray(item))
    : []
}

function ordinaryRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
    ? value as Record<string, unknown> : null
}

export function integrityComplete(value: unknown): value is L3Integrity {
  const record = ordinaryRecord(value)
  if (!record) return false
  return integrityFields.every((field) =>
    Object.hasOwn(record, field) && record[field] === true)
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const HASH_PATTERN = /^[a-f0-9]{64}$/

export function sourceComplete(value: unknown): value is L3Source {
  const record = ordinaryRecord(value)
  if (!record) return false
  if (!sourceFields.every((field) => Object.hasOwn(record, field))) return false
  const eventId = record.event_id
  const revisionUuid = record.saved_revision_uuid
  const assignmentId = record.assignment_id
  if (
    typeof eventId !== 'string' || !UUID_PATTERN.test(eventId) ||
    typeof revisionUuid !== 'string' || !UUID_PATTERN.test(revisionUuid) ||
    typeof assignmentId !== 'string' || !UUID_PATTERN.test(assignmentId)
  ) return false
  const revisionNumber = record.revision_number
  if (typeof revisionNumber !== 'number' || !Number.isInteger(revisionNumber) || revisionNumber < 1) {
    return false
  }
  for (const field of [
    'revision_canonical_hash', 'l3_intent_fingerprint',
    'l3_render_fingerprint', 'command_evidence_registry_fingerprint',
  ] as const) {
    const value = record[field]
    if (typeof value !== 'string' || !HASH_PATTERN.test(value)) return false
  }
  const contractId = record.l3_render_contract_id
  const registryId = record.command_evidence_registry_id
  const intentSchema = record.l3_intent_schema_version
  const renderVersion = record.l3_render_contract_version
  if (
    typeof contractId !== 'string' || contractId.length === 0 ||
    typeof registryId !== 'string' || registryId.length === 0 ||
    typeof intentSchema !== 'number' || !Number.isInteger(intentSchema) || intentSchema < 1 ||
    typeof renderVersion !== 'number' || !Number.isInteger(renderVersion) || renderVersion < 1
  ) return false
  const baselineUuid = record.baseline_revision_uuid
  const baselineHash = record.baseline_revision_hash
  if (baselineUuid === null) return baselineHash === null
  return typeof baselineUuid === 'string' &&
    UUID_PATTERN.test(baselineUuid) &&
    typeof baselineHash === 'string' &&
    HASH_PATTERN.test(baselineHash)
}

export function validateReport(report: L3ValidationReport, binding: ReviewBinding): ReviewProblem[] {
  const problems: ReviewProblem[] = []
  const expected = expectedRegistryBinding(binding)
  const actualSource = ordinaryRecord(report.source)
  const expectedSource = ordinaryRecord(report.expected_source)
  const actualComplete = sourceComplete(report.source)
  const expectedComplete = sourceComplete(report.expected_source)
  if (!actualComplete) problems.push('actual-source')
  if (!expectedComplete) problems.push('expected-source')
  if (report.validation_scope !== 'production' || report.validation_schema_version !== 1) {
    problems.push('validation-scope')
  }
  if (report.validation_contract_id !== L3_VALIDATION_CONTRACT) problems.push('validation-contract')
  if (actualSource && (
    actualSource.event_id !== binding.eventId ||
    actualSource.saved_revision_uuid !== binding.revision.id ||
    actualSource.revision_number !== binding.revision.number ||
    actualSource.revision_canonical_hash !== binding.revision.content_hash ||
    actualSource.assignment_id !== binding.assignmentId ||
    actualSource.command_evidence_registry_id !== (expected?.registryId ?? '') ||
    actualSource.command_evidence_registry_fingerprint !== (expected?.registryFingerprint ?? '') ||
    actualSource.l3_render_contract_id !== L3_CONTRACT ||
    actualSource.l3_render_contract_version !== 1
  )) problems.push('source-binding')
  if (
    actualComplete && expectedComplete &&
    sourceFields.some((field) => actualSource![field] !== expectedSource![field])
  ) problems.push('expected-source')
  if (report.assignment_id !== binding.assignmentId) problems.push('report-assignment')
  if (
    !expected ||
    report.device.assignment_id !== binding.assignmentId || report.device.role !== 'core' ||
    report.device.hostname !== expected.identity.hostname ||
    report.device.family !== expected.identity.family ||
    (report.device.exact_pid ?? '').toUpperCase() !== expected.identity.exactPid ||
    report.device.software_image !== expected.identity.softwareImage ||
    report.device.software_license !== expected.identity.softwareLicense
  ) problems.push('report-device')
  if (!integrityComplete(report.integrity)) problems.push('report-integrity')
  if (
    report.safety.candidate_only !== true || report.safety.executable !== false ||
    report.safety.deployable !== false || report.safety.deployment_allowed !== false ||
    report.safety.hardware_verified !== false || report.safety.device_connection !== 'none' ||
    report.safety.running_config_read !== false || report.safety.device_writes_enabled !== false ||
    report.safety.cli !== null || report.safety.deployment_artifact !== null
  ) problems.push('report-safety')
  if (!/^[a-f0-9]{64}$/.test(report.report_fingerprint)) problems.push('report-fingerprint')
  const candidateIds = report.candidates.map((candidate) => candidate.candidate_id)
  if (new Set(candidateIds).size !== candidateIds.length) problems.push('report-candidates')
  if (
    report.summary.total !== report.candidates.length ||
    report.summary.total !== report.summary.passed + report.summary.failed +
      report.summary.blocked + report.summary.not_run
  ) problems.push('report-summary')
  if (
    report.overall_status === 'pass' &&
    (report.summary.failed > 0 || report.summary.blocked > 0)
  ) problems.push('report-summary')
  if (expected && !expected.evidenceApproved) {
    // The unreviewed-platform Registry contains no evidence rows.  A legitimate
    // report can therefore contain BLOCKED candidates only; this is checked
    // independently of the ordinary source-equality checks above.
    if (
      report.overall_status === 'pass' ||
      report.summary.passed !== 0 ||
      report.summary.base_candidates_passed !== 0 ||
      report.summary.base_categories_passed !== 0 ||
      report.candidates.some((candidate) => candidate.independent_verdict === 'pass') ||
      report.candidates.some((candidate) => candidate.evidence.review_state !== null)
    ) problems.push('report-candidates')
  }
  return problems
}

export function canLoadCandidates(report: L3ValidationReport) {
  return report.overall_status !== 'fail' &&
    !report.candidates.some((candidate) => candidate.independent_verdict === 'fail') &&
    integrityComplete(report.integrity) &&
    sourceComplete(report.source) &&
    sourceComplete(report.expected_source)
}

export function validateDocument(
  report: L3ValidationReport, document: L3CandidateDocument, binding: ReviewBinding,
): ReviewProblem[] {
  const problems: ReviewProblem[] = []
  const expected = expectedRegistryBinding(binding)
  if (document.contract_id !== L3_CONTRACT || document.l3_render_schema_version !== 1) {
    problems.push('document-contract')
  }
  const source = document.source
  if (
    source.revision_uuid !== report.source.saved_revision_uuid ||
    source.revision_number !== report.source.revision_number ||
    source.revision_hash !== report.source.revision_canonical_hash ||
    source.l3_intent_schema_version !== report.source.l3_intent_schema_version ||
    source.l3_intent_fingerprint !== report.source.l3_intent_fingerprint ||
    source.command_evidence_registry_id !== report.source.command_evidence_registry_id ||
    source.command_evidence_registry_fingerprint !== report.source.command_evidence_registry_fingerprint ||
    source.command_evidence_registry_id !== (expected?.registryId ?? '') ||
    source.command_evidence_registry_fingerprint !== (expected?.registryFingerprint ?? '') ||
    document.l3_render_fingerprint !== report.source.l3_render_fingerprint
  ) problems.push('document-source')
  if (document.assignment_id !== report.assignment_id || binding.assignmentId !== document.assignment_id) {
    problems.push('document-assignment')
  }
  if (
    document.device.assignment_id !== report.device.assignment_id ||
    document.device.hostname !== report.device.hostname ||
    document.device.role !== report.device.role ||
    document.device.family !== report.device.family ||
    document.device.exact_pid !== report.device.exact_pid ||
    document.device.software_image !== report.device.software_image ||
    document.device.software_license !== report.device.software_license ||
    document.device.stack_identity !== report.device.stack_identity ||
    !expected ||
    document.device.hostname !== expected.identity.hostname ||
    document.device.family !== expected.identity.family ||
    (document.device.exact_pid ?? '').toUpperCase() !== expected.identity.exactPid ||
    document.device.software_image !== expected.identity.softwareImage ||
    document.device.software_license !== expected.identity.softwareLicense
  ) problems.push('document-device')
  if (
    document.safety.candidate_only !== true || document.safety.executable !== false ||
    document.safety.deployable !== false || document.safety.deployment_allowed !== false ||
    document.safety.hardware_verified !== false || document.safety.device_connection !== 'none' ||
    document.safety.running_config_read !== false || document.safety.device_writes_enabled !== false ||
    document.safety.cli !== null || document.safety.deployment_artifact !== null ||
    document.executable !== false || document.cli !== null || document.device_writes_enabled !== false
  ) problems.push('report-safety')
  const reportIds = new Set(report.candidates.map((candidate) => candidate.candidate_id))
  const documentIds = new Set(document.candidates.map((candidate) => candidate.candidate_id))
  const renderedCount = document.candidates.filter((candidate) => candidate.status === 'candidate').length
  const blockedCount = document.candidates.filter((candidate) => candidate.status === 'blocked').length
  const unsupportedCount = document.candidates.filter((candidate) => candidate.status === 'unsupported').length
  if (
    reportIds.size !== documentIds.size ||
    [...reportIds].some((id) => !documentIds.has(id)) ||
    document.summary.total !== report.summary.total ||
    document.summary.candidates !== renderedCount ||
    document.summary.blocked !== blockedCount ||
    document.summary.unsupported !== unsupportedCount
  ) problems.push('document-candidates')
  if (expected && !expected.evidenceApproved && (
    document.summary.candidates !== 0 ||
    document.candidates.some((candidate) => candidate.status === 'candidate') ||
    document.candidates.some((candidate) => candidate.candidate_text !== null)
  )) problems.push('document-candidates')
  for (const candidate of document.candidates) {
    const checked = report.candidates.find((item) => item.candidate_id === candidate.candidate_id)
    if (!checked) { problems.push('document-candidates'); continue }
    if (
      candidate.category !== checked.category ||
      candidate.target.stable_id !== checked.target_stable_id ||
      candidate.target.name !== checked.target_name ||
      candidate.assignment_id !== report.assignment_id
    ) {
      problems.push('document-candidates')
    }
    const pass = checked.independent_verdict === 'pass'
    const candidateStatus = candidate.status === 'candidate'
    if (pass !== candidateStatus) problems.push('candidate-text')
    if ((!pass || !candidateStatus) && candidate.candidate_text !== null) {
      problems.push('candidate-text')
    }
    if (
      candidate.candidate_text !== null &&
      (candidate.candidate_text.trim().length === 0 || candidate.candidate_text.includes('\n'))
    ) problems.push('candidate-text')
  }
  return problems
}

export function reviewRows(report: L3ValidationReport, document?: L3CandidateDocument | null): ReviewRow[] {
  const documentById = new Map((document?.candidates ?? []).map((candidate) => [candidate.candidate_id, candidate]))
  return report.candidates.map((candidate) => {
    const rendered = documentById.get(candidate.candidate_id)
    const textAllowed = rendered?.status === 'candidate' && candidate.independent_verdict === 'pass' &&
      rendered.candidate_text !== null
    const reasons = rendered?.blocking_reasons?.length
      ? rendered.blocking_reasons
      : [...candidate.evidence.reason_codes, ...candidate.context_binding.reason_codes,
        ...candidate.target_capability.reason_codes, ...candidate.risk.reason_codes]
    return {
      candidateId: candidate.candidate_id,
      category: candidate.category,
      targetName: candidate.target_name,
      status: rendered?.status ?? null,
      verdict: candidate.independent_verdict,
      risk: candidate.risk.independent_floor,
      capability: candidate.target_capability.verdict ?? null,
      evidenceReview: candidate.evidence.review_state ?? null,
      blockingReasons: [...new Set(reasons)],
      commandContext: textAllowed ? rendered.command_context : null,
      text: textAllowed ? rendered.candidate_text : null,
      targetKind: candidate.target_kind,
    }
  })
}

export function reviewCategories(rows: ReviewRow[]) {
  return [...new Set(rows.map((row) => row.category))].sort()
}

export function filterReviewRows(rows: ReviewRow[], category: string, status: string) {
  return rows.filter((row) =>
    (!category || row.category === category) &&
    (!status || (row.status ?? row.verdict) === status))
}

export async function fetchValidation(
  eventId: string, revisionId: string, assignmentId: string, signal?: AbortSignal,
) {
  const response = await fetch(
    '/api/v1' +
    `/events/${encodeURIComponent(eventId)}/plan-revisions/${encodeURIComponent(revisionId)}` +
    `/assignments/${encodeURIComponent(assignmentId)}/l3-cli-validation`,
    { signal },
  )
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { detail?: unknown } | null
    throw new ApiError(response.status, body?.detail)
  }
  if (response.headers.get('X-Validation-Scope') !== 'full') {
    throw new ApiError(409, {
      reason_code: 'validation-scope-not-full', stage: 'validation',
      failures: ['validation-scope-header'],
    })
  }
  return await response.json() as L3ValidationReport
}

export async function fetchCandidates(
  eventId: string, revisionId: string, assignmentId: string, signal?: AbortSignal,
) {
  return request<L3CandidateDocument>(
    `/events/${encodeURIComponent(eventId)}/plan-revisions/${encodeURIComponent(revisionId)}` +
    `/assignments/${encodeURIComponent(assignmentId)}/l3-cli-candidates`,
    { signal },
  )
}

export { list as listRevisions, read as readRevision }
export type { Revision, Summary }
