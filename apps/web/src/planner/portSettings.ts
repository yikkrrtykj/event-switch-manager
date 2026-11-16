import type { Translator } from '../messages'
import { display, get, set, withModelDefault } from './catalog'
import type { Field } from './catalog'
import { fingerprint, object, records } from './model'
import type { Plan, RecordValue, Value } from './model'

export const modeKey = 'settings.mode'
export type Operation = { kind: 'reset' } | { kind: 'set'; value: Value }
export type Operations = Record<string, Operation>
export type PortTarget = { index: number; item: RecordValue }
export type PortChange = { field: Field; before: Value | undefined; after: Value | undefined; operation: 'keep' | 'reset' | 'set' | 'clearList' | 'clearOnModeChange' }

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

export function canResetPortField(field: Field, hidden: boolean) {
  return field.key.startsWith('settings.') && field.key !== modeKey &&
    (field.modelDefault === undefined || hidden && field.type === 'refs')
}

function normalized(field: Field, value: Value | undefined) {
  if (field.type === 'refs') return Array.isArray(value) ? [...value].sort() : []
  return value ?? null
}

export function hasPortValue(value: Value | undefined) {
  return value != null && (!Array.isArray(value) || value.length > 0)
}

export function commonPortValue(field: Field, targets: PortTarget[]) {
  const first = withModelDefault(field, get(targets[0]?.item ?? {}, field.key))
  const mixed = targets.some(({ item }) =>
    fingerprint(normalized(field, withModelDefault(field, get(item, field.key)))) !== fingerprint(normalized(field, first)))
  return { value: mixed ? undefined : first, mixed }
}

export function describePortValue(t: Translator, plan: Plan, field: Field, value: Value | undefined) {
  value = withModelDefault(field, value)
  if (value === '' && field.preserveEmpty) return t('emptyDescription')
  if (value == null) return canResetPortField(field, false) ? t('platformDefault') : '—'
  if (Array.isArray(value) && value.length === 0) return t('none')
  return display(t, plan, field, value)
}

function reset(record: RecordValue, field: Field): RecordValue {
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
    let label: PortChange['operation'] = 'keep'
    if (operation?.kind === 'reset' && canResetPortField(field, !portFieldApplies(field, mode))) {
      if (hasPortValue(before)) next = reset(next, field)
      label = field.type === 'refs' ? 'clearList' : 'reset'
    } else if (operation?.kind === 'set') {
      next = set(next, field.key, operation.value)
      label = 'set'
    } else if (isPortSetting(field) && modeChanges && hasPortValue(before) &&
      needsModeClear(field, mode, before)) {
      next = reset(next, field)
      label = 'clearOnModeChange'
    }
    const after = get(next, field.key)
    if (!isPortSetting(field) && fingerprint(before) !== fingerprint(after)) label = 'set'
    changes.push({ field, before, after, operation: label })
  }
  return { next, changes }
}

const assignmentField: Field = { key: 'assignment_id', label: 'device', reference: 'assignments' }
export const memberLabel = (t: Translator, item: RecordValue) => item.stack_member ? t('stackMemberNumber', { number: String(item.stack_member) }) : t('standalone')

export function physicalPortLabel(t: Translator, plan: Plan, item: RecordValue) {
  return { device: display(t, plan, assignmentField, item.assignment_id), member: memberLabel(t, item), name: String(item.name ?? t('newPort')) }
}

export function aggregatePortLabel(t: Translator, plan: Plan, item: RecordValue) {
  const logical = records(plan, 'logical_interfaces').find((entry) => entry.id === item.interface_id)
  return { device: display(t, plan, assignmentField, logical?.assignment_id), member: t('aggregate'),
    name: String(logical?.name ?? (item.number ? t('portChannelNumber', { number: String(item.number) }) : t('newPortChannel'))) }
}
