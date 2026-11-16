import { translate } from '../messages'
import type { MessageKey } from '../messages'
import { ApiError, json, request } from '../api'

export type Value = null | boolean | number | string | Value[] | RecordValue
export type RecordValue = { [key: string]: Value }
export type Plan = RecordValue & { schema_version: 1; event_id: string; management_vlan: number }
export type Issue = { path: string; code: string; message: string; severity: 'ERROR' | 'WARNING' }
export type Status = 'VALID' | 'VALID_WITH_WARNINGS' | 'INVALID'
export type Summary = { id: string; number: number; content_hash: string; created_at: string; schema_version: number }
export type Revision = Summary & { plan: Plan; warnings: Issue[]; validation_errors: Issue[]; validation_status: Status }

const base = (id: string) => '/events/' + encodeURIComponent(id)
const history = (id: string) => base(id) + '/plan-revisions'
const revision = (id: string, rev: string) => history(id) + '/' + encodeURIComponent(rev)
export const seed = (id: string, signal?: AbortSignal) => request<Plan>(base(id) + '/plan/seed', { signal })
export const list = (id: string, signal?: AbortSignal) => request<Summary[]>(history(id), { signal })
export const read = (id: string, rev: string, signal?: AbortSignal) =>
  request<Revision>(revision(id, rev), { signal })
export const save = (plan: Plan, signal?: AbortSignal) =>
  request<Revision>(history(plan.event_id), { ...json(plan), signal })
export const exportUrl = (id: string, rev: string) => '/api/v1' + revision(id, rev) + '/export'
export function issuesFrom(error: unknown): Issue[] {
  if (!(error instanceof ApiError) || !Array.isArray(error.detail)) return []
  return error.detail.map((issue: Partial<Issue> & { loc?: (string | number)[]; type?: string; msg?: string }) => ({
    path: issue.path ?? issue.loc?.filter((part) => part !== 'body').join('.') ?? '',
    code: issue.code ?? issue.type ?? 'invalid_plan',
    message: issue.message ?? issue.msg ?? translate('en-US', 'thePlanCouldNotBeValidated'),
    severity: issue.severity ?? 'ERROR',
  }))
}
export async function validate(plan: Plan, signal?: AbortSignal) {
  try { return await request<Issue[]>(base(plan.event_id) + '/plan/validate', { ...json(plan), signal }) }
  catch (error) {
    const issues = issuesFrom(error)
    if (issues.length) return issues
    throw error
  }
}
export const issuesOf = (entry: Revision) => [...entry.validation_errors, ...entry.warnings]
export const statusOf = (issues: Issue[]): Status => issues.some((i) => i.severity === 'ERROR')
  ? 'INVALID' : issues.length ? 'VALID_WITH_WARNINGS' : 'VALID'
export function object(value: Value | undefined): RecordValue {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : {}
}
export function records(plan: Plan, key: string): RecordValue[] {
  const items = plan[key]
  return Array.isArray(items) ? items.map(object) : []
}
export function fingerprint(value: Value | undefined): string {
  return JSON.stringify(value, (_, current: unknown) => {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return current
    return Object.fromEntries(Object.entries(current).sort(([a], [b]) => a.localeCompare(b)))
  }) ?? ''
}
export class PlanImportError extends Error {
  constructor(readonly key: MessageKey) { super(translate('en-US', key)) }
}

export function parsePlan(text: string, eventId: string): Plan {
  let input: unknown
  try { input = JSON.parse(text) }
  catch { throw new PlanImportError('invalidPlanJson') }
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new PlanImportError('chooseAPlanJsonObject')
  const plan = input as Partial<Plan>
  if (plan.schema_version !== 1) throw new PlanImportError('unsupportedPlanSchema')
  if (plan.event_id !== eventId) throw new PlanImportError('thisPlanBelongsToAnotherEvent')
  return { management_vlan: 10, ...plan } as Plan
}
