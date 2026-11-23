import { ApiError, request } from '../api'
import type { MessageKey } from '../messages'
import { records } from './model'
import type { Plan, RecordValue, Revision } from './model'

export const L2_VALIDATION_CONTRACT = 'cis-02b2-03-independent-cli-validation-v1'
export const L2_RENDER_CONTRACT = 'cis-02b2-cisco-l2-cli-candidate-v1'
export const L2_PREVIEW_CONTRACT = 'cis-02b1-layer2-config-preview-v1'
export const L2_REGISTRY_ID = 'cis-02b2-l1-command-evidence-v1'
// The L2 report and document bind the source-level evidence fingerprint
// (registry id + row versions), not the raw registry object digest. Both are
// deterministic; this one is the value carried in SourceBinding.
export const L2_REGISTRY_FINGERPRINT = '5abd0c57c0a825d77893e6287b76024517b5eb24d42bf061ab34c685b79c1ad8'

export const l2SourceFields = [
  'render_schema_version', 'render_contract_id', 'saved_revision_uuid',
  'revision_number', 'revision_canonical_hash', 'intent_schema_version',
  'intent_fingerprint', 'preview_schema_version', 'preview_contract_id',
  'preview_fingerprint', 'command_evidence_registry_id',
  'command_evidence_fingerprint', 'render_fingerprint', 'assignment_id',
] as const
export type L2SourceField = (typeof l2SourceFields)[number]
export type L2Source = { [K in L2SourceField]: string | number }

export const l2DocumentSourceFields = [
  'saved_revision_uuid', 'revision_number', 'revision_canonical_hash',
  'intent_schema_version', 'intent_fingerprint', 'preview_schema_version',
  'preview_contract_id', 'preview_fingerprint', 'command_evidence_registry_id',
  'command_evidence_fingerprint',
] as const
export type L2DocumentSourceField = (typeof l2DocumentSourceFields)[number]
export type L2DocumentSource = { [K in L2DocumentSourceField]: string | number }

export type L2Verdict = 'pass' | 'fail' | 'not-run'
export type L2RendererStatus = 'candidate' | 'blocked' | 'unsupported'
export type SubsystemStatus = 'pass' | 'partial' | 'fail' | 'na'

export interface L2Integrity {
  status: L2Verdict
  render_fingerprint_recomputed: string
  render_fingerprint_match: boolean
  candidate_fingerprints_match: boolean
  candidate_ids_unique: boolean
  source_binding_format_ok: boolean
  evidence_content_digests_ok: boolean
  assignment_binding_ok: boolean
  expected_source_match: boolean
  failures: string[]
}

export interface L2Failure {
  kind: string
  code: string
  detail?: string
}

export interface L2CandidateValidation {
  candidate_id: string
  category: string
  renderer_status: string
  candidate_text_present: boolean
  syntax_validation_level: string
  parser_verified: boolean
  candidate_fingerprint: string
  candidate_fingerprint_recomputed: string
  candidate_fingerprint_match: boolean
  parse: {
    status: L2Verdict
    topic: string | null
    form: string | null
    mode: string | null
    modes: string[]
    target_class: string | null
    parameters: Record<string, unknown>
    failures: L2Failure[]
  }
  scope: { status: string; reason_code: string; detail?: string; evidence_id?: string | null; evidence_review_state?: string | null }
  context_binding: { status: L2Verdict; reasons: string[] }
  target_capability: { status: L2Verdict; applicable: boolean; reasons: string[]; exact_pid?: string | null }
  security: { status: L2Verdict; reason_codes: string[] }
  semantics: { status: L2Verdict; mismatches: string[] }
  risk: { status: L2Verdict; renderer_risk_class: string; independent_floor: string; findings: string[] }
  independent_verdict: L2Verdict
  fail_closed_action: string | null
}

export interface L2Device {
  hostname: string
  family: string | null
  exact_pid: string | null
  release: string | null
  license: string | null
  role: string
  stack_identity: string
  stack_members: { number: number; exact_pid: string | null; state: string }[]
  identity_verdict: L2Verdict
  identity_reasons: string[]
}

export interface L2Summary {
  total_candidates: number
  parsed_candidates: number
  parse_pass: number
  parse_fail: number
  not_run: number
  scope_blocked: number
  context_fail: number
  capability_fail: number
  capability_not_run: number
  security_fail: number
  semantic_mismatch: number
  risk_fail: number
  failed_candidates: number
  topics_parsed: string[]
  registry_rows: number
  registry_reviewed: number
  registry_rejected: number
  registry_unreviewed: number
  overall_status: L2Verdict
}

export interface L2Safety {
  candidate_only: boolean
  executable: boolean
  deployable: boolean
  deployment_allowed: boolean
  hardware_verified: boolean
  device_connection: string
  running_config_read: boolean
  device_writes_enabled: boolean
  device_runtime_state?: string
  cli: null
  deployment_artifact: null
  independent_validation_is_not_execution_authorization?: boolean
  public_candidate_schema_unchanged?: boolean
  parser_verified_public_field_unchanged?: boolean
}

export interface L2ValidationReport {
  validation_schema_version: number
  validation_contract_id: string
  source: L2Source
  device: L2Device
  assignment_id: string
  integrity: L2Integrity
  candidates: L2CandidateValidation[]
  registry_coverage: unknown[]
  topology_review: { status: string; checks: unknown[]; findings: string[] }
  summary: L2Summary
  safety: L2Safety
  report_fingerprint: string
}

export interface L2DocumentCandidate {
  candidate_id: string
  assignment_id: string
  target: { kind: string; stable_id: string; name: string }
  category: string
  command_context: { mode: string; mode_header: string; target_name: string }
  status: L2RendererStatus
  candidate_text: string | null
  parameters: Record<string, unknown>
  provenance: Record<string, unknown>
  capability_evidence: { capability?: string | null; verdict: string; reason_code: string; check_id?: string | null }[]
  syntax_evidence: {
    evidence_id: string; topic: string; release: string; command: string; grammar: string;
    review_state: string; source_url: string; source_section: string;
    limits: string[]; exclusions: string[]
  }[]
  syntax_validation: { level: string; dictionary_id: string; parser_verified: boolean }
  risk_class: string
  potential_connectivity_impact?: boolean
  requires_field_verification: boolean
  prerequisites: string[]
  blocking_reasons: string[]
  candidate_fingerprint: string
}

export interface L2Intent {
  preview_schema_version: number
  contract_id: string
  source: string
  event_id: string
  revision_id: string
  revision_number: number
  revision_hash: string
  device: {
    contract_id: string
    preview_schema_version: number
    assignment_id: string
    hostname: string
    identity: {
      assignment_id: string
      hostname: string
      role: string
      family: string | null
      pid: string | null
      software_image: string | null
      software_license: string | null
      stack_identity: string
    }
    intent_readiness: { structured_intent_valid: boolean; hardware_verified: boolean; deployment_allowed: boolean }
    deployability: { deployable: boolean; deployment_allowed: boolean }
    summary: {
      config_items: number
      changed_items: number
      deployable_items: number
      evidence_pass_items: number
      evidence_unknown_items: number
      evidence_unsupported_items: number
      planned_changes: number
      dependencies: number
    }
    human_readable: { display_only: boolean; executable: boolean; headline: string; statements: string[] }
    preview_fingerprint: string
  }
  deployment_blockers: string[]
  preview_fingerprint: string
}

export interface L2CandidateDocument {
  render_schema_version: number
  contract_id: string
  source: L2DocumentSource
  assignment_id: string
  device: Omit<L2Device, 'identity_verdict' | 'identity_reasons'>
  render_state: string
  candidates: L2DocumentCandidate[]
  unresolved_prerequisites: string[]
  evidence: unknown[]
  device_runtime_state: string
  safety: L2Safety & { hardware_verified: boolean }
  summary: { total: number; candidates: number; blocked: number; unsupported: number; categories_rendered: string[] }
  deployment_blockers: string[]
  render_fingerprint: string
}

export interface CiscoAssignment {
  assignmentId: string
  hostname: string
  role: string
  family: string
  physicalDeviceId: string
  pid: string | null
  image: string | null
  license: string | null
  stackIdentity: string
  isCore: boolean
}

export interface PreviewBinding {
  eventId: string
  revision: Revision
  assignment: CiscoAssignment
}

export interface PreviewError {
  status: number | null
  reasonCode: string
  stage: string
  failures: string[]
  detail: string
}

export type L2Problem =
  | 'l2-report-contract'
  | 'l2-source-contract'
  | 'l2-source-binding'
  | 'l2-report-integrity'
  | 'l2-report-assignment'
  | 'l2-report-device'
  | 'l2-report-fingerprint'
  | 'l2-report-summary'
  | 'l2-report-candidates'
  | 'l2-document-contract'
  | 'l2-document-source'
  | 'l2-document-assignment'
  | 'l2-document-device'
  | 'l2-document-safety'
  | 'l2-document-candidates'
  | 'l2-candidate-text'
  | 'l2-intent-contract'
  | 'l2-intent-binding'
  | 'l2-intent-safety'

export const l2ProblemKeys: Record<L2Problem, MessageKey> = {
  'l2-report-contract': 'ciscoL2ContractMismatch',
  'l2-source-contract': 'ciscoL2SourceMismatch',
  'l2-source-binding': 'ciscoL2SourceBindingMismatch',
  'l2-report-integrity': 'ciscoL2IntegrityMismatch',
  'l2-report-assignment': 'ciscoL2AssignmentMismatch',
  'l2-report-device': 'ciscoL2DeviceMismatch',
  'l2-report-fingerprint': 'ciscoL2FingerprintMismatch',
  'l2-report-summary': 'ciscoL2SummaryMismatch',
  'l2-report-candidates': 'ciscoL2CandidateMismatch',
  'l2-document-contract': 'ciscoL2ContractMismatch',
  'l2-document-source': 'ciscoL2SourceBindingMismatch',
  'l2-document-assignment': 'ciscoL2AssignmentMismatch',
  'l2-document-device': 'ciscoL2DeviceMismatch',
  'l2-document-safety': 'ciscoL2SafetyMismatch',
  'l2-document-candidates': 'ciscoL2CandidateMismatch',
  'l2-candidate-text': 'ciscoL2CandidateTextMismatch',
  'l2-intent-contract': 'ciscoL2IntentContractMismatch',
  'l2-intent-binding': 'ciscoL2IntentBindingMismatch',
  'l2-intent-safety': 'ciscoL2IntentSafetyMismatch',
}

export interface L2ReviewRow {
  candidateId: string
  category: string
  targetName: string
  targetKind: string
  status: L2RendererStatus | null
  verdict: L2Verdict
  risk: string
  capability: string | null
  evidenceReview: string | null
  blockingReasons: string[]
  commandContext: L2DocumentCandidate['command_context'] | null
  text: string | null
}

const ordinaryRecord = (value: unknown): Record<string, unknown> | null => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
    ? value as Record<string, unknown> : null
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const HASH_PATTERN = /^[a-f0-9]{64}$/
const isUuid = (value: unknown): value is string => typeof value === 'string' && UUID_PATTERN.test(value)
const isHash = (value: unknown): value is string => typeof value === 'string' && HASH_PATTERN.test(value)
const isInteger = (value: unknown): value is number =>
  typeof value === 'number' && Number.isInteger(value) && value > 0

function sourceComplete(value: unknown): value is L2Source {
  const record = ordinaryRecord(value)
  if (!record) return false
  if (!l2SourceFields.every((field) => Object.hasOwn(record, field))) return false
  return (
    isInteger(record.render_schema_version) &&
    record.render_contract_id === L2_RENDER_CONTRACT &&
    isUuid(record.saved_revision_uuid) &&
    isInteger(record.revision_number) &&
    isHash(record.revision_canonical_hash) &&
    isInteger(record.intent_schema_version) &&
    isHash(record.intent_fingerprint) &&
    isInteger(record.preview_schema_version) &&
    record.preview_contract_id === L2_PREVIEW_CONTRACT &&
    isHash(record.preview_fingerprint) &&
    record.command_evidence_registry_id === L2_REGISTRY_ID &&
    record.command_evidence_fingerprint === L2_REGISTRY_FINGERPRINT &&
    isHash(record.render_fingerprint) &&
    isUuid(record.assignment_id)
  )
}

function documentSourceComplete(value: unknown): value is L2DocumentSource {
  const record = ordinaryRecord(value)
  if (!record) return false
  if (!l2DocumentSourceFields.every((field) => Object.hasOwn(record, field))) return false
  return (
    isUuid(record.saved_revision_uuid) &&
    isInteger(record.revision_number) &&
    isHash(record.revision_canonical_hash) &&
    isInteger(record.intent_schema_version) &&
    isHash(record.intent_fingerprint) &&
    isInteger(record.preview_schema_version) &&
    record.preview_contract_id === L2_PREVIEW_CONTRACT &&
    isHash(record.preview_fingerprint) &&
    record.command_evidence_registry_id === L2_REGISTRY_ID &&
    isHash(record.command_evidence_fingerprint)
  )
}

function integrityComplete(value: unknown): value is L2Integrity {
  const record = ordinaryRecord(value)
  if (!record) return false
  const booleans = [
    'render_fingerprint_match', 'candidate_fingerprints_match', 'candidate_ids_unique',
    'source_binding_format_ok', 'evidence_content_digests_ok', 'assignment_binding_ok',
    'expected_source_match',
  ] as const
  if (!booleans.every((field) => record[field] === true)) return false
  return record.status === 'pass' &&
    isHash(record.render_fingerprint_recomputed) &&
    Array.isArray(record.failures) && record.failures.length === 0
}

function safetyComplete(value: unknown, isReport: boolean): boolean {
  const safety = ordinaryRecord(value)
  if (!safety) return false
  const base = (
    safety.candidate_only === true &&
    safety.executable === false &&
    safety.deployable === false &&
    safety.deployment_allowed === false &&
    safety.hardware_verified === false &&
    safety.device_connection === 'none' &&
    safety.running_config_read === false &&
    safety.device_writes_enabled === false &&
    safety.cli === null &&
    safety.deployment_artifact === null
  )
  if (!base) return false
  if (isReport) {
    return safety.independent_validation_is_not_execution_authorization === true &&
      safety.public_candidate_schema_unchanged === true &&
      safety.parser_verified_public_field_unchanged === true
  }
  return true
}

export function validateL2Report(report: L2ValidationReport, binding: PreviewBinding): L2Problem[] {
  const problems: L2Problem[] = []
  const source = ordinaryRecord(report.source)
  const device = ordinaryRecord(report.device)
  const summary = ordinaryRecord(report.summary)
  const candidates = Array.isArray(report.candidates) ? report.candidates : []
  if (!source || !sourceComplete(report.source)) {
    problems.push('l2-source-contract')
  } else {
    if (report.validation_contract_id !== L2_VALIDATION_CONTRACT || report.validation_schema_version !== 1) {
      problems.push('l2-report-contract')
    }
    if (
      source.saved_revision_uuid !== binding.revision.id ||
      source.revision_number !== binding.revision.number ||
      source.revision_canonical_hash !== binding.revision.content_hash ||
      source.assignment_id !== binding.assignment.assignmentId
    ) problems.push('l2-source-binding')
    if (report.assignment_id !== binding.assignment.assignmentId) problems.push('l2-report-assignment')
    if (!device) {
      problems.push('l2-report-device')
    } else {
      if (
        device.hostname !== binding.assignment.hostname ||
        device.family !== binding.assignment.family ||
        device.exact_pid !== binding.assignment.pid ||
        device.release !== binding.assignment.image ||
        device.license !== binding.assignment.license ||
        device.role !== binding.assignment.role ||
        device.stack_identity !== binding.assignment.stackIdentity
      ) problems.push('l2-report-device')
      if (device.identity_verdict !== 'pass') problems.push('l2-report-device')
    }
    if (!integrityComplete(report.integrity)) {
      problems.push('l2-report-integrity')
    } else if (report.integrity.render_fingerprint_recomputed !== source.render_fingerprint) {
      problems.push('l2-report-integrity')
    }
    if (!safetyComplete(report.safety, true)) problems.push('l2-report-integrity')
    if (!isHash(report.report_fingerprint)) problems.push('l2-report-fingerprint')
    if (!summary) {
      problems.push('l2-report-summary')
    } else {
      if (
        summary.total_candidates !== candidates.length ||
        summary.parsed_candidates !== candidates.filter((item) => item.parse?.status === 'pass').length ||
        summary.failed_candidates !== candidates.filter((item) => item.independent_verdict === 'fail').length
      ) problems.push('l2-report-summary')
    }
    const ids = candidates.map((item) => item.candidate_id)
    if (new Set(ids).size !== ids.length) problems.push('l2-report-candidates')
    if (candidates.some((item) =>
      !isHash(item.candidate_fingerprint) ||
      item.candidate_fingerprint !== item.candidate_fingerprint_recomputed ||
      item.candidate_fingerprint_match !== true ||
      item.parser_verified !== false ||
      !['dictionary-only', 'not-run'].includes(item.syntax_validation_level)
    )) problems.push('l2-report-candidates')
  }
  return problems
}

export function validateL2Intent(
  preview: L2Intent, report: L2ValidationReport, binding: PreviewBinding,
): L2Problem[] {
  const problems: L2Problem[] = []
  const device = ordinaryRecord(preview.device)
  const identity = device ? ordinaryRecord(device.identity) : null
  const human = device ? ordinaryRecord(device.human_readable) : null
  const safety = device ? ordinaryRecord(device.deployability) : null
  if (
    preview.contract_id !== 'cis-02b1-layer2-config-preview-v1' ||
    preview.preview_schema_version !== 1 ||
    preview.device?.contract_id !== 'cis-02b1-layer2-config-preview-v1' ||
    preview.device?.preview_schema_version !== 1
  ) problems.push('l2-intent-contract')
  if (
    preview.event_id !== binding.eventId ||
    preview.revision_id !== binding.revision.id ||
    preview.revision_number !== binding.revision.number ||
    preview.revision_hash !== binding.revision.content_hash ||
    preview.device?.assignment_id !== binding.assignment.assignmentId ||
    !identity ||
    identity.assignment_id !== binding.assignment.assignmentId ||
    identity.hostname !== binding.assignment.hostname ||
    identity.family !== binding.assignment.family ||
    identity.pid !== binding.assignment.pid ||
    identity.software_image !== binding.assignment.image ||
    identity.software_license !== binding.assignment.license ||
    identity.role !== binding.assignment.role ||
    identity.stack_identity !== binding.assignment.stackIdentity
  ) problems.push('l2-intent-binding')
  if (
    !human || human.display_only !== true || human.executable !== false ||
    typeof human.headline !== 'string' || !Array.isArray(human.statements) ||
    !safety || safety.deployable !== false || safety.deployment_allowed !== false ||
    preview.preview_fingerprint !== report.source.preview_fingerprint ||
    !isHash(preview.preview_fingerprint) ||
    report.device.hostname !== preview.device.hostname
  ) problems.push('l2-intent-safety')
  return problems
}

export function canLoadL2Candidates(report: L2ValidationReport): boolean {
  return report.summary?.overall_status !== 'fail' &&
    integrityComplete(report.integrity) &&
    !report.candidates.some((item) => item.independent_verdict === 'fail')
}

export function validateL2Document(
  report: L2ValidationReport, document: L2CandidateDocument, binding: PreviewBinding,
): L2Problem[] {
  const problems: L2Problem[] = []
  const source = ordinaryRecord(document.source)
  const device = ordinaryRecord(document.device)
  const candidates = Array.isArray(document.candidates) ? document.candidates : []
  if (document.contract_id !== L2_RENDER_CONTRACT || document.render_schema_version !== 1) {
    problems.push('l2-document-contract')
  }
  if (!source || !documentSourceComplete(document.source)) {
    problems.push('l2-document-source')
  } else {
    const expected = report.source
    if (
      source.saved_revision_uuid !== expected.saved_revision_uuid ||
      source.revision_number !== expected.revision_number ||
      source.revision_canonical_hash !== expected.revision_canonical_hash ||
      source.intent_schema_version !== expected.intent_schema_version ||
      source.intent_fingerprint !== expected.intent_fingerprint ||
      source.preview_schema_version !== expected.preview_schema_version ||
      source.preview_contract_id !== expected.preview_contract_id ||
      source.preview_fingerprint !== expected.preview_fingerprint ||
      source.command_evidence_registry_id !== expected.command_evidence_registry_id ||
      source.command_evidence_fingerprint !== expected.command_evidence_fingerprint ||
      document.render_fingerprint !== expected.render_fingerprint
    ) problems.push('l2-document-source')
  }
  if (
    document.assignment_id !== binding.assignment.assignmentId ||
    document.assignment_id !== report.assignment_id
  ) problems.push('l2-document-assignment')
  if (!device) {
    problems.push('l2-document-device')
  } else {
    const expected = report.device
    if (
      device.hostname !== expected.hostname ||
      device.family !== expected.family ||
      device.exact_pid !== expected.exact_pid ||
      device.release !== expected.release ||
      device.license !== expected.license ||
      device.role !== expected.role ||
      device.stack_identity !== expected.stack_identity
    ) problems.push('l2-document-device')
  }
  if (!safetyComplete(document.safety, false)) problems.push('l2-document-safety')
  if (!isHash(document.render_fingerprint)) problems.push('l2-document-source')

  const reportById = new Map(report.candidates.map((item) => [item.candidate_id, item]))
  const documentIds = new Set(candidates.map((item) => item.candidate_id))
  if (reportById.size !== documentIds.size || [...reportById.keys()].some((id) => !documentIds.has(id))) {
    problems.push('l2-document-candidates')
  }
  const candidateCount = candidates.filter((item) => item.status === 'candidate').length
  const blockedCount = candidates.filter((item) => item.status === 'blocked').length
  const unsupportedCount = candidates.filter((item) => item.status === 'unsupported').length
  if (
    document.summary?.total !== report.summary.total_candidates ||
    document.summary?.candidates !== candidateCount ||
    document.summary?.blocked !== blockedCount ||
    document.summary?.unsupported !== unsupportedCount
  ) problems.push('l2-document-candidates')

  for (const item of candidates) {
    const checked = reportById.get(item.candidate_id)
    if (!checked) {
      problems.push('l2-document-candidates')
      continue
    }
    if (
      item.assignment_id !== binding.assignment.assignmentId ||
      item.category !== checked.category ||
      item.status !== checked.renderer_status ||
      item.candidate_fingerprint !== checked.candidate_fingerprint ||
      item.candidate_fingerprint !== checked.candidate_fingerprint_recomputed
    ) problems.push('l2-document-candidates')
    const pass = checked.independent_verdict === 'pass'
    const candidateStatus = item.status === 'candidate'
    const textPresent = item.candidate_text !== null
    if (checked.candidate_text_present !== textPresent) problems.push('l2-candidate-text')
    if (pass !== candidateStatus) problems.push('l2-candidate-text')
    if ((!pass || !candidateStatus) && textPresent) problems.push('l2-candidate-text')
    if (textPresent && (
      item.candidate_text!.trim().length === 0 || item.candidate_text!.includes('\n') ||
      item.candidate_text!.includes('\r')
    )) problems.push('l2-candidate-text')
  }
  return problems
}

export function l2ReviewRows(
  report: L2ValidationReport, document?: L2CandidateDocument | null,
): L2ReviewRow[] {
  const documentById = new Map((document?.candidates ?? []).map((item) => [item.candidate_id, item]))
  return report.candidates.map((candidate) => {
    const rendered = documentById.get(candidate.candidate_id)
    const textAllowed = rendered?.status === 'candidate' &&
      candidate.independent_verdict === 'pass' && rendered.candidate_text !== null
    const reasons = [
      ...(rendered?.blocking_reasons ?? []),
      candidate.scope?.reason_code,
      ...(candidate.parse?.failures ?? []).map((failure) => failure.code),
      ...(candidate.context_binding?.reasons ?? []),
      ...(candidate.target_capability?.reasons ?? []),
      ...(candidate.security?.reason_codes ?? []),
      ...(candidate.semantics?.mismatches ?? []),
      ...(candidate.risk?.findings ?? []),
    ].filter((reason): reason is string => typeof reason === 'string' && reason.length > 0)
    return {
      candidateId: candidate.candidate_id,
      category: candidate.category,
      targetName: rendered?.target.name ?? candidate.category,
      targetKind: rendered?.target.kind ?? '',
      status: rendered?.status ?? (candidate.renderer_status as L2RendererStatus),
      verdict: candidate.independent_verdict,
      risk: candidate.risk?.independent_floor ?? '',
      capability: candidate.parse?.topic ?? null,
      evidenceReview: candidate.scope?.evidence_review_state ?? null,
      blockingReasons: [...new Set(reasons)],
      commandContext: textAllowed ? rendered.command_context : null,
      text: textAllowed ? rendered.candidate_text : null,
    }
  })
}

export function l2Status(
  report: L2ValidationReport | null, rows: L2ReviewRow[], document: L2CandidateDocument | null,
  candidateError: PreviewError | null,
): SubsystemStatus {
  if (!report) return 'na'
  if (report.summary.overall_status === 'fail' || rows.some((row) => row.verdict === 'fail')) return 'fail'
  if (!document || candidateError || !rows.length) return 'partial'
  if (rows.some((row) => row.verdict !== 'pass' || row.status !== 'candidate')) return 'partial'
  return 'pass'
}

export function overallStatus(left: SubsystemStatus, right: SubsystemStatus): SubsystemStatus {
  const applicable = [left, right].filter((status) => status !== 'na')
  if (!applicable.length) return 'na'
  if (applicable.includes('fail')) return 'fail'
  if (applicable.includes('partial')) return 'partial'
  return 'pass'
}

export function ciscoAssignments(plan: Plan): CiscoAssignment[] {
  const devices = new Map(records(plan, 'physical_devices').map((device) => [String(device.id), device] as const))
  const stacks = new Map(records(plan, 'stacks').map((stack) => [String(stack.assignment_id), stack] as const))
  return records(plan, 'assignments').flatMap((assignment) => {
    const device = devices.get(String(assignment.physical_device_id ?? ''))
    if (!device || device.vendor !== 'cisco') return []
    const software = objectRecord(assignment.software)
    const stack = stacks.get(String(assignment.id))
    const members = stack ? objectArray(stack.members) : []
    return [{
      assignmentId: String(assignment.id),
      hostname: String(assignment.hostname ?? ''),
      role: String(assignment.role ?? ''),
      family: String(assignment.family ?? ''),
      physicalDeviceId: String(assignment.physical_device_id ?? ''),
      pid: device.model === null || device.model === undefined ? null : String(device.model),
      image: software.image === undefined ? null : String(software.image),
      license: software.license === undefined ? null : String(software.license),
      stackIdentity: members.length ? 'stack:' + String(members.length) : 'standalone',
      isCore: assignment.role === 'core',
    } satisfies CiscoAssignment]
  })
}

function objectRecord(value: unknown): RecordValue {
  return ordinaryRecord(value) as RecordValue | null ?? {}
}
function objectArray(value: unknown): RecordValue[] {
  return Array.isArray(value)
    ? value.filter((item): item is RecordValue => ordinaryRecord(item) !== null)
    : []
}

export function parsePreviewError(error: unknown): PreviewError {
  if (error instanceof ApiError) {
    const detail = error.detail
    const record = ordinaryRecord(detail)
    if (record) {
      return {
        status: error.status,
        reasonCode: typeof record.reason_code === 'string' ? record.reason_code : '',
        stage: typeof record.stage === 'string' ? record.stage : '',
        failures: Array.isArray(record.failures)
          ? record.failures.filter((item): item is string => typeof item === 'string') : [],
        detail: '',
      }
    }
    return {
      status: error.status,
      reasonCode: '',
      stage: '',
      failures: [],
      detail: typeof detail === 'string' ? detail : '',
    }
  }
  return { status: null, reasonCode: '', stage: '', failures: [], detail: '' }
}

export function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError'
}

export function isL2NotApplicable(error: PreviewError): boolean {
  return error.status === 404 && error.stage === 'preview' &&
    (error.reasonCode === 'assignment-not-found' || error.reasonCode === 'preview-target-not-found')
}

export function isL3NotApplicable(error: PreviewError): boolean {
  return error.status === 409 && error.reasonCode === 'assignment-not-eligible-for-l3-cli'
}

export function previewErrorKey(error: PreviewError): MessageKey {
  if (error.status === 404) return 'ciscoReviewNotFound'
  if (error.status === 409) return 'ciscoReviewConflict'
  if (error.status === 422) return 'ciscoReviewUnprocessable'
  if (error.status === 400) return 'ciscoRequestRejected'
  return 'ciscoReviewNetworkError'
}

export function l2ErrorFields(error: PreviewError): string[] {
  if (error.reasonCode) return [error.reasonCode, ...error.failures]
  return [error.detail, ...error.failures].filter((item) => item.length > 0)
}

const base = (eventId: string) => '/events/' + encodeURIComponent(eventId)
const assignmentPath = (eventId: string, revisionId: string, assignmentId: string) =>
  base(eventId) + '/plan-revisions/' + encodeURIComponent(revisionId) +
  '/assignments/' + encodeURIComponent(assignmentId)

export async function fetchL2Validation(
  eventId: string, revisionId: string, assignmentId: string, signal?: AbortSignal,
): Promise<L2ValidationReport> {
  const response = await fetch('/api/v1' + assignmentPath(eventId, revisionId, assignmentId) + '/l2-cli-validation', { signal })
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { detail?: unknown } | null
    throw new ApiError(response.status, body?.detail)
  }
  if (response.headers.get('X-Validation-Scope') !== 'full') {
    throw new ApiError(409, {
      reason_code: 'l2-validation-scope-not-full',
      stage: 'validation',
      failures: ['validation-scope-header'],
    })
  }
  return await response.json() as L2ValidationReport
}

export function fetchL2Candidates(
  eventId: string, revisionId: string, assignmentId: string, signal?: AbortSignal,
) {
  return request<L2CandidateDocument>(
    assignmentPath(eventId, revisionId, assignmentId) + '/l2-cli-candidates', { signal },
  )
}

export function fetchL2Intent(
  eventId: string, revisionId: string, assignmentId: string, signal?: AbortSignal,
) {
  return request<L2Intent>(
    base(eventId) + '/plan-revisions/' + encodeURIComponent(revisionId) +
    '/layer2-config-preview/devices/' + encodeURIComponent(assignmentId), { signal },
  )
}
