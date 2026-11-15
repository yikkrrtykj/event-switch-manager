import { display, get, set } from './catalog'
import type { Field } from './catalog'
import { fingerprint, object, records } from './model'
import type { Plan, RecordValue, Value } from './model'

export const modeKey = 'settings.mode'
export type Operation = { kind: 'reset' } | { kind: 'set'; value: Value }
export type Operations = Record<string, Operation>
export type PortTarget = { index: number; item: RecordValue }
export type PortChange = { field: Field; before: Value | undefined; after: Value | undefined; operation: string }

export function isPortSetting(field: Field) {
  return field.key.startsWith('settings.') || field.key === 'lacp'
}

export function portMode(item: RecordValue, operations: Operations) {
  const mode = operations[modeKey]
  return mode?.kind === 'set' && mode.value !== null ? mode.value : get(item, modeKey)
}

export function portFieldApplies(field: Field, mode: Value | undefined) {
  if (field.when) return mode === field.when[1]
  if (field.key === 'settings.portfast' || field.key === 'settings.bpdu_guard') {
    return mode === 'access' || mode === 'trunk'
  }
  return true
}

function normalized(field: Field, value: Value | undefined) {
  return field.type === 'refs' && !Array.isArray(value) ? [] : value ?? null
}

export function commonPortValue(field: Field, targets: PortTarget[]) {
  const first = get(targets[0]?.item ?? {}, field.key)
  const mixed = targets.some(({ item }) =>
    fingerprint(normalized(field, get(item, field.key))) !== fingerprint(normalized(field, first)))
  return { value: mixed ? undefined : first, mixed }
}

export function describePortValue(plan: Plan, field: Field, value: Value | undefined) {
  if (value === '' && field.preserveEmpty) return 'Empty description'
  if (value == null) return isPortSetting(field) ? 'Platform default' : '—'
  if (Array.isArray(value) && value.length === 0) return 'None'
  return display(plan, field, value)
}

function reset(record: RecordValue, field: Field): RecordValue {
  if (field.key === 'lacp') {
    const next = { ...record }
    delete next.lacp
    return next
  }
  const settings = { ...object(record.settings) }
  delete settings[field.key.slice('settings.'.length)]
  return { ...record, settings }
}

function needsModeClear(field: Field, mode: Value | undefined, before: Value | undefined) {
  if (!portFieldApplies(field, mode)) return true
  return field.key === 'settings.portfast' &&
    ((before === 'edge' && mode !== 'access') || (before === 'edge-trunk' && mode !== 'trunk'))
}

export function editPort(item: RecordValue, base: RecordValue, fields: Field[], operations: Operations,
  permit: (field: Field) => boolean) {
  let next = base
  const mode = portMode(item, operations)
  const modeChanges = get(item, modeKey) !== mode
  const changes: PortChange[] = []
  for (const field of fields) {
    const before = get(item, field.key)
    const operation = permit(field) ? operations[field.key] : undefined
    let label = 'Keep'
    if (operation?.kind === 'reset') {
      next = reset(next, field)
      label = 'Reset'
    } else if (operation?.kind === 'set') {
      next = set(next, field.key, operation.value)
      label = 'Set'
    } else if (isPortSetting(field) && modeChanges && before != null &&
      needsModeClear(field, mode, before)) {
      next = reset(next, field)
      label = 'Clear on mode change'
    }
    const after = get(next, field.key)
    if (!isPortSetting(field) && fingerprint(before) !== fingerprint(after)) label = 'Set'
    if (label !== 'Clear on mode change' || fingerprint(normalized(field, before)) !== fingerprint(normalized(field, after))) {
      changes.push({ field, before, after, operation: label })
    }
  }
  return { next, changes }
}

const assignmentField: Field = { key: 'assignment_id', label: 'Device', reference: 'assignments' }
export const memberLabel = (item: RecordValue) => item.stack_member ? 'Stack member ' + String(item.stack_member) : 'Standalone'

export function physicalPortLabel(plan: Plan, item: RecordValue) {
  return { device: display(plan, assignmentField, item.assignment_id), member: memberLabel(item), name: String(item.name ?? 'New port') }
}

export function aggregatePortLabel(plan: Plan, item: RecordValue) {
  const logical = records(plan, 'logical_interfaces').find((entry) => entry.id === item.interface_id)
  return { device: display(plan, assignmentField, logical?.assignment_id), member: 'Aggregate',
    name: String(logical?.name ?? (item.number ? 'Port-Channel ' + String(item.number) : 'New Port-Channel')) }
}
