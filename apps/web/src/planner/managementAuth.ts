import { ApiError } from '../api'
import { canonicalSha256 } from './canonical'
import type { PreviewBinding } from './ciscoPreview'

export const MANAGEMENT_INTENT_CONTRACT = 'cis-04b-management-intent-v1'
export const MANAGEMENT_CANDIDATE_CONTRACT = 'cis-04b-cisco-management-cli-candidate-v1'
export const MANAGEMENT_VALIDATION_CONTRACT = 'cis-04b-management-cli-validation-v1'
export const MANAGEMENT_SCOPE_HEADER = 'X-Management-Scope'
export const MANAGEMENT_EVIDENCE_REGISTRY_ID =
  'cis-04b-management-command-evidence-draft-v1'
export const MANAGEMENT_EVIDENCE_REGISTRY_FINGERPRINT =
  '7ad9d17396f8cd8ed2c18c70b3ca021a3932800d54b94eef9c5d22405694d640'
export const MANAGEMENT_EXPECTED_TOPICS = [
  'management-domain-name',
  'management-ssh-version',
  'management-rsa-key',
  'management-local-username',
  'management-vty-transport',
  'management-login-local',
  'management-aaa-new-model',
  'management-aaa-login-default',
  'management-console-auth',
] as const
const MANAGEMENT_PENDING_REVIEW_STATE = 'pending-independent-review'
const MANAGEMENT_REQUIRED_INTEGRITY = [
  'revision_hash', 'intent_binding', 'source_binding', 'evidence_registry',
  'expected_topic_set', 'candidate_ids_unique', 'candidate_evidence_binding',
  'candidate_status', 'candidate_fingerprints', 'summary_derived',
  'no_secret_text', 'safety',
] as const

export type ManagementStatus =
  | 'PLANNED' | 'VALIDATED' | 'BLOCKED' | 'NOT_IMPLEMENTED'
  | 'HARDWARE_NOT_VERIFIED'

export interface ManagementCredentialReference {
  reference: string | null
  present: boolean
  valid: boolean
  event_scoped: boolean
  secret_material_present: boolean
  secret_availability: string
  provider: string
  reason_codes: string[]
  value_not_returned: boolean
}

export interface ManagementIntent {
  management_intent_schema_version: number
  contract_id: string
  event_id: string
  revision_id: string
  revision_number: number
  revision_hash: string
  assignment_id: string
  identity: {
    assignment_id: string
    hostname: string
    role: string
    family: string | null
    exact_pid: string | null
    pid_evidence: string
    serial_verified: boolean
    software_image: string | null
    software_license: string | null
    stack_identity: string
  }
  management_vlan: number
  management_domain: string | null
  intended_status: ManagementStatus
  status: ManagementStatus
  validation_scope: string
  software_validation_status: string
  hardware_status: string
  not_implemented_capabilities: string[]
  reachability: {
    status: 'PLANNED' | 'BLOCKED'
    management_vlan: number
    vlan_declared: boolean
    management_ip: string | null
    management_subnet: string | null
    duplicate_ip: boolean
    reason_codes: string[]
  }
  ssh_policy: {
    status: 'PLANNED' | 'BLOCKED' | 'NOT_IMPLEMENTED'
    target_protocol: string
    telnet_enabled: boolean
    plaintext_management_auth: boolean
    sshv1_fallback_allowed: boolean
    rsa_key_state: string
    rsa_key_assumed: boolean
    reason_codes: string[]
  }
  authentication: {
    status: 'PLANNED' | 'BLOCKED' | 'NOT_IMPLEMENTED'
    method: string
    local_authentication_required: boolean
    local_fallback_required: boolean
    external_aaa_requested: boolean
    external_aaa_status: string
    credential_reference: ManagementCredentialReference
    reason_codes: string[]
  }
  console_recovery: {
    status: 'PLANNED' | 'BLOCKED'
    required: boolean
    local_recovery_account_required: boolean
    console_operation: string
    console_access_verified: boolean
    lockout_risk: string
    reason_codes: string[]
  }
  aaa: {
    status: 'NOT_IMPLEMENTED' | 'BLOCKED'
    mode: string
    external_servers: string[]
    deletion_or_auth_switch_generation: boolean
    reason_codes: string[]
  }
  evidence_registry_id: string
  evidence_registry_fingerprint: string
  evidence_status: string
  risk_codes: string[]
  reason_codes: string[]
  hardware_verified: boolean
  deployment_allowed: boolean
  device_connection: string
  intent_fingerprint: string
}

export interface ManagementValidationReport {
  validation_schema_version: number
  validation_contract_id: string
  source: {
    revision_uuid: string
    revision_number: number
    revision_hash: string
    management_intent_fingerprint: string
    evidence_registry_id: string
    evidence_registry_fingerprint: string
  }
  expected_source: {
    revision_uuid: string
    revision_number: number
    revision_hash: string
    management_intent_fingerprint: string
    evidence_registry_id: string
    evidence_registry_fingerprint: string
    assignment_id: string
  }
  assignment_id: string
  candidates: {
    candidate_id: string
    topic: string
    status: string
    independent_verdict: string
    candidate_text_present: boolean
    secret_text_present: boolean
    evidence_id: string
    evidence_review_state: string
    evidence_source_url: string
    secret_bearing: boolean
    evidence_digest_match: boolean
    blocking_reasons: string[]
  }[]
  summary: {
    total: number
    passed: number
    blocked: number
    failed: number
  }
  overall_status: string
  integrity: Record<string, boolean>
  safety: ManagementSafety
  report_fingerprint: string
}

export interface ManagementSafety {
  candidate_only: boolean
  read_only: boolean
  executable: boolean
  deployable: boolean
  deployment_allowed: boolean
  device_connection: string
  running_config_read: boolean
  device_writes_enabled: boolean
  full_config_generated: boolean
  cli: null
  deployment_artifact: null
  hardware_verified: boolean
  secrets_included: boolean
  secret_placeholder_included: boolean
}

export interface ManagementReview {
  intent: ManagementIntent
  report: ManagementValidationReport
}

const sha256 = /^[0-9a-f]{64}$/
const statuses = new Set<ManagementStatus>([
  'PLANNED', 'VALIDATED', 'BLOCKED', 'NOT_IMPLEMENTED', 'HARDWARE_NOT_VERIFIED',
])
const FORBIDDEN_SECRET_KEYS = new Set([
  'password', 'passphrase', 'secret', 'secret_value', 'credential_secret',
  'credential_value', 'private_key', 'privatekey', 'pre_shared_key',
])

function ordinaryRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown> : null
}

function canonicalWithoutKey(value: unknown, key: string): string | null {
  const record = ordinaryRecord(value)
  if (!record) return null
  const payload = { ...record }
  delete payload[key]
  return canonicalSha256(payload)
}

function expectedEvidenceId(topic: string, family: string | null): string | null {
  const prefix = family === 'catalyst-9300'
    ? 'mgmt-9300-' : family === 'catalyst-9200' ? 'mgmt-9200-' : null
  if (prefix === null || !topic.startsWith('management-')) return null
  return prefix + topic.slice('management-'.length) + '-v1'
}

function hasSecretMaterial(value: unknown, path = ''): boolean {
  if (Array.isArray(value)) return value.some((item, index) => hasSecretMaterial(item, path + '[' + index + ']'))
  const record = ordinaryRecord(value)
  if (!record) return false
  for (const [key, item] of Object.entries(record)) {
    if (FORBIDDEN_SECRET_KEYS.has(key.toLowerCase())) return true
    if (hasSecretMaterial(item, path + '.' + key)) return true
  }
  return false
}

function isoBinding(
  binding: PreviewBinding, eventId: string, revisionId: string,
  revisionNumber: number, revisionHash: string, assignmentId: string,
): boolean {
  return eventId === binding.eventId &&
    revisionId === binding.revision.id &&
    revisionNumber === binding.revision.number &&
    revisionHash === binding.revision.content_hash &&
    assignmentId === binding.assignment.assignmentId
}

export function parseManagementError(error: unknown) {
  if (error instanceof ApiError) {
    const detail = ordinaryRecord(error.detail)
    return {
      status: error.status,
      reasonCode: detail && typeof detail.reason_code === 'string' ? detail.reason_code : '',
      stage: detail && typeof detail.stage === 'string' ? detail.stage : '',
      failures: detail && Array.isArray(detail.failures) ? detail.failures.filter((item): item is string => typeof item === 'string') : [],
    }
  }
  return { status: null, reasonCode: '', stage: '', failures: [] as string[] }
}

async function getJson(path: string, signal?: AbortSignal): Promise<unknown> {
  const response = await fetch('/api/v1' + path, { signal })
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { detail?: unknown } | null
    throw new ApiError(response.status, body?.detail)
  }
  if (response.headers.get(MANAGEMENT_SCOPE_HEADER) !== 'full') {
    throw new ApiError(409, {
      reason_code: 'management-scope-not-full', stage: 'management',
      failures: ['management-scope-header'],
    })
  }
  return await response.json()
}

export async function fetchManagementReview(
  eventId: string, revisionId: string, assignmentId: string, signal?: AbortSignal,
): Promise<ManagementReview> {
  const base = '/events/' + encodeURIComponent(eventId) +
    '/plan-revisions/' + encodeURIComponent(revisionId) +
    '/assignments/' + encodeURIComponent(assignmentId)
  const [intent, report] = await Promise.all([
    getJson(base + '/management-intent', signal),
    getJson(base + '/management-cli-validation', signal),
  ])
  return { intent: intent as ManagementIntent, report: report as ManagementValidationReport }
}

function validateManagementReviewRaw(
  value: ManagementReview, binding: PreviewBinding,
): string[] {
  const problems: string[] = []
  const intent = value.intent
  const report = value.report
  if (hasSecretMaterial(value)) problems.push('management-secret-material')
  if (intent.management_intent_schema_version !== 1 ||
    intent.contract_id !== MANAGEMENT_INTENT_CONTRACT ||
    !statuses.has(intent.status) ||
    !statuses.has(intent.intended_status)) {
    problems.push('management-intent-contract')
  }
  const intentFingerprint = canonicalWithoutKey(intent, 'intent_fingerprint')
  if (!intent.intent_fingerprint || !sha256.test(intent.intent_fingerprint) ||
    intentFingerprint !== intent.intent_fingerprint) {
    problems.push('management-intent-fingerprint')
  }
  if (!isoBinding(
    binding, intent.event_id, intent.revision_id, intent.revision_number,
    intent.revision_hash, intent.assignment_id,
  )) problems.push('management-intent-binding')
  const revisionPlan = ordinaryRecord(binding.revision.plan)
  const revisionVlan = revisionPlan?.management_vlan
  if (
    !Number.isInteger(intent.management_vlan) ||
    intent.management_vlan < 1 || intent.management_vlan > 4094 ||
    !Number.isInteger(revisionVlan) ||
    intent.management_vlan !== revisionVlan ||
    intent.reachability.management_vlan !== intent.management_vlan
  ) {
    problems.push('management-vlan')
  }
  if (
    intent.identity.assignment_id !== binding.assignment.assignmentId ||
    intent.identity.hostname !== binding.assignment.hostname ||
    intent.identity.role !== binding.assignment.role ||
    intent.identity.family !== binding.assignment.family ||
    intent.identity.exact_pid !== binding.assignment.pid ||
    intent.identity.software_image !== binding.assignment.image ||
    intent.identity.software_license !== binding.assignment.license ||
    intent.identity.stack_identity !== binding.assignment.stackIdentity
  ) {
    problems.push('management-identity-binding')
  }
  if (!intent.ssh_policy || intent.ssh_policy.target_protocol !== 'sshv2' ||
    intent.ssh_policy.telnet_enabled !== false ||
    intent.ssh_policy.plaintext_management_auth !== false ||
    intent.ssh_policy.sshv1_fallback_allowed !== false ||
    intent.ssh_policy.rsa_key_assumed !== false) {
    problems.push('management-ssh-policy')
  }
  if (!intent.authentication || intent.authentication.method !== 'local-only' ||
    intent.authentication.local_authentication_required !== true ||
    intent.authentication.local_fallback_required !== true) {
    problems.push('management-authentication')
  }
  const credential = intent.authentication?.credential_reference
  if (!credential || credential.secret_material_present !== false ||
    credential.secret_availability !== 'not-verified' ||
    credential.value_not_returned !== true ||
    (credential.present && (!credential.valid || !credential.event_scoped)) ||
    (credential.reference !== null &&
      !credential.reference.startsWith('credref:' + binding.eventId + ':'))) {
    problems.push('management-credential-reference')
  }
  if (!intent.console_recovery || intent.console_recovery.required !== true ||
    intent.console_recovery.console_operation !== 'not-executed' ||
    intent.console_recovery.console_access_verified !== false) {
    problems.push('management-console-recovery')
  }
  if (intent.authentication.external_aaa_requested !== false ||
    !intent.aaa || intent.aaa.deletion_or_auth_switch_generation !== false) {
    problems.push('management-aaa')
  }
  if (intent.validation_scope !== 'software-planning-only' ||
    intent.software_validation_status !== 'BLOCKED' ||
    intent.hardware_status !== 'HARDWARE_NOT_VERIFIED') {
    problems.push('management-validation-scope')
  }
  if (intent.hardware_verified !== false || intent.deployment_allowed !== false ||
    intent.device_connection !== 'none') {
    problems.push('management-safety')
  }
  if (
    intent.evidence_registry_id !== MANAGEMENT_EVIDENCE_REGISTRY_ID ||
    intent.evidence_registry_fingerprint !==
      MANAGEMENT_EVIDENCE_REGISTRY_FINGERPRINT ||
    intent.evidence_status !== 'PENDING'
  ) {
    problems.push('management-pending-registry')
  }

  if (report.validation_schema_version !== 1 ||
    report.validation_contract_id !== MANAGEMENT_VALIDATION_CONTRACT) {
    problems.push('management-report-contract')
  }
  const reportFingerprint = canonicalWithoutKey(report, 'report_fingerprint')
  if (!report.report_fingerprint || !sha256.test(report.report_fingerprint) ||
    reportFingerprint !== report.report_fingerprint) {
    problems.push('management-report-fingerprint')
  }
  if (report.assignment_id !== binding.assignment.assignmentId ||
    report.expected_source.assignment_id !== binding.assignment.assignmentId ||
    report.source.management_intent_fingerprint !== intent.intent_fingerprint ||
    report.expected_source.management_intent_fingerprint !== intent.intent_fingerprint ||
    report.source.evidence_registry_id !== MANAGEMENT_EVIDENCE_REGISTRY_ID ||
    report.expected_source.evidence_registry_id !== MANAGEMENT_EVIDENCE_REGISTRY_ID ||
    report.source.evidence_registry_fingerprint !==
      MANAGEMENT_EVIDENCE_REGISTRY_FINGERPRINT ||
    report.expected_source.evidence_registry_fingerprint !==
      MANAGEMENT_EVIDENCE_REGISTRY_FINGERPRINT ||
    report.source.revision_uuid !== report.expected_source.revision_uuid ||
    report.source.revision_number !== report.expected_source.revision_number ||
    report.source.revision_hash !== report.expected_source.revision_hash) {
    problems.push('management-report-binding')
  }
  if (!isoBinding(
    binding, binding.eventId, report.source.revision_uuid,
    report.source.revision_number, report.source.revision_hash,
    report.assignment_id,
  )) problems.push('management-report-revision')
  const integrity = ordinaryRecord(report.integrity)
  if (!integrity || MANAGEMENT_REQUIRED_INTEGRITY.some(
    (key) => integrity[key] !== true,
  )) {
    problems.push('management-report-integrity')
  }
  if (report.summary.total !== report.candidates.length ||
    report.summary.total !== MANAGEMENT_EXPECTED_TOPICS.length ||
    report.summary.passed !== 0 ||
    report.summary.blocked !== MANAGEMENT_EXPECTED_TOPICS.length ||
    report.summary.failed !== 0 ||
    report.overall_status !== 'blocked') {
    problems.push('management-report-summary')
  }
  if (report.candidates.length !== MANAGEMENT_EXPECTED_TOPICS.length) {
    problems.push('management-topic-set')
  }
  const expectedTopics = new Set<string>(MANAGEMENT_EXPECTED_TOPICS)
  const seenTopics = new Set<string>()
  const ids = new Set<string>()
  for (const candidate of report.candidates) {
    if (!expectedTopics.has(candidate.topic) || seenTopics.has(candidate.topic)) {
      problems.push('management-topic-set')
    }
    seenTopics.add(candidate.topic)
    if (!candidate.candidate_id || ids.has(candidate.candidate_id)) {
      problems.push('management-candidate-duplicate')
    }
    ids.add(candidate.candidate_id)
    const expectedId = expectedEvidenceId(candidate.topic, binding.assignment.family)
    const expectedSecret = candidate.topic === 'management-local-username'
    if (
      expectedId === null ||
      candidate.evidence_id !== expectedId ||
      !candidate.evidence_source_url.startsWith('https://www.cisco.com/') ||
      candidate.evidence_digest_match !== true ||
      candidate.secret_bearing !== expectedSecret
    ) {
      problems.push('management-evidence-binding')
    }
    if (
      candidate.status !== 'blocked' ||
      candidate.independent_verdict !== 'blocked' ||
      candidate.evidence_review_state !== MANAGEMENT_PENDING_REVIEW_STATE ||
      candidate.candidate_text_present !== false ||
      candidate.secret_text_present !== false ||
      candidate.blocking_reasons.length === 0
    ) {
      problems.push('management-reviewed-claim')
    }
  }
  if (seenTopics.size !== MANAGEMENT_EXPECTED_TOPICS.length) {
    problems.push('management-topic-set')
  }
  const safety = report.safety
  if (!safety || safety.candidate_only !== true || safety.read_only !== true ||
    safety.executable !== false || safety.deployable !== false ||
    safety.deployment_allowed !== false || safety.device_connection !== 'none' ||
    safety.running_config_read !== false || safety.device_writes_enabled !== false ||
    safety.full_config_generated !== false || safety.cli !== null ||
    safety.hardware_verified !== false || safety.secrets_included !== false ||
    safety.secret_placeholder_included !== false) {
    problems.push('management-safety')
  }
  return [...new Set(problems)]
}

export function validateManagementReview(
  value: ManagementReview, binding: PreviewBinding,
): string[] {
  try {
    return validateManagementReviewRaw(value, binding)
  } catch {
    return ['management-contract']
  }
}
