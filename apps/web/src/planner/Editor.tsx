import { enumLabel } from '../messages'
import { describeIssue } from './diagnostics'
import { useMessages } from '../locale'
import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Button, Dialog, Input, Select } from '../components/ui'
import { defaults, get, options, set } from './catalog'
import type { Field } from './catalog'
import { fingerprint, object } from './model'
import type { Issue, Plan, RecordValue, Value } from './model'

type ChoiceState = { disabled?: (string | number)[] }
type FieldsProps = {
  fields: Field[]; plan: Plan; record: RecordValue; path: string; issues: Issue[]
  update: (record: RecordValue) => void
  choiceStates?: Record<string, ChoiceState>
  notes?: Record<string, ReactNode>
}
export function Fields({ fields, plan, record, path, issues, update, choiceStates, notes }: FieldsProps) {
  const { t, locale } = useMessages()
  const grid = useRef<HTMLDivElement>(null)
  useEffect(() => {
    for (const input of grid.current?.querySelectorAll('textarea') ?? []) {
      if (input.validity.customError) input.setCustomValidity(t('enterValidJson'))
    }
  }, [t])
  return <div className="field-grid" ref={grid}>{fields.map((field) => {
    if (field.when && get(record, field.when[0]) !== field.when[1]) return null
    const key = path + '.' + field.key
    const value = get(record, field.key)
    const change = (value: Value) => {
      let next = set(record, field.key, value)
      for (const dependent of fields) {
        if (dependent.when?.[0] === field.key && dependent.when[1] === value &&
          dependent.initial !== undefined && get(next, dependent.key) === undefined) {
          next = set(next, dependent.key, dependent.initial)
        }
      }
      update(next)
    }
    const entries = Array.isArray(value) ? value : []
    const available = field.reference ? options(plan, field.reference,
      (candidate) => field.accepts?.(candidate, record, plan) ?? true)
      : (field.choices ?? []).map((id) => ({ id, label: id === '' ? t('unspecified') : enumLabel(t, id, field.key) }))
    const disabledChoices = choiceStates?.[field.key]?.disabled ?? []
    const selection = (current: Value | undefined) => <>
      {!available.some((item) => item.id === '') && <option value="">
        {field.optional ? t('unspecified') : t('selectARecord')}</option>}
      {current != null && current !== '' && !available.some((item) => item.id === current) &&
        <option value={String(current)}>{t('unresolvedChoice', { value: String(current) })}</option>}
      {available.map((item) => <option key={item.id} value={item.id}
        disabled={disabledChoices.includes(item.id) || undefined}>{item.label}</option>)}
    </>
    const lookup = (id: string) => available.find((item) => String(item.id) === id)?.id ?? null
    const findings = issues.filter((issue) => issue.path === key)
    const note = notes?.[field.key]
    const attributes = {
      'data-field': key,
      'aria-invalid': findings.some((issue) => issue.severity === 'ERROR') || undefined,
      'aria-describedby': findings.length ? key + '-issues' : undefined,
      'aria-details': note ? key + '-note' : undefined,
    }
    if (field.type === 'refs' || field.type === 'records') {
      const nested = field.children ?? []
      return <fieldset className="compound" {...attributes} tabIndex={-1} key={key}>
        <legend>{t(field.label)}</legend>
        {entries.map((item, index) => <div className={field.type === 'refs' ? 'repeat-row' : 'nested-record'} key={index}>
          {field.type === 'records' ? <Fields fields={nested} record={object(item)} plan={plan}
            path={key + '.' + index} issues={issues} update={(next) => change(entries.map((old, i) => i === index ? next : old))} />
            : <>
              <Select aria-label={t('fieldItem', { field: t(field.label), number: index + 1 })} data-field={key + '.' + index} value={String(item ?? '')}
                required onChange={(event) => change(entries.map((old, i) => i === index ? lookup(event.target.value) : old))}>
                {selection(item)}
              </Select>
              {[-1, 1].map((delta) => <Button key={delta} disabled={index + delta < 0 || index + delta >= entries.length}
                aria-label={t(delta < 0 ? 'moveUp' : 'moveDown', { field: t(field.label), number: index + 1 })} onClick={() => {
                  const next = [...entries]
                  next.splice(index + delta, 0, ...next.splice(index, 1))
                  change(next)
                }}>{delta < 0 ? '↑' : '↓'}</Button>)}
            </>}
          <Button aria-label={t('removeFieldItem', { field: t(field.label), number: index + 1 })}
            onClick={() => change(entries.filter((_, i) => i !== index))}>{t('remove')}</Button>
        </div>)}
        {findings.length > 0 && <div id={key + '-issues'}>{findings.map((issue, index) =>
          <small key={index} className={issue.severity === 'ERROR' ? 'error-text' : 'muted'}>{describeIssue(issue, locale, t)}</small>)}</div>}
        {note && <div id={key + '-note'} className="field-note">{note}</div>}
        <Button onClick={() => change([...entries, field.type === 'records' ? defaults(nested) : null])}>{t('addEntry')}</Button>
      </fieldset>
    }
    return <div className={'field' + (field.type === 'json' ? ' span-all' : '')} key={key}>
      <label htmlFor={key}>{t(field.label)}</label>
      {field.type === 'choice' || field.type === 'ref' ? <Select id={key} {...attributes} value={String(value ?? '')}
        required={!field.optional} onChange={(event) => change(lookup(event.target.value))}>{selection(value)}</Select>
        : field.type === 'json' ? <textarea id={key} {...attributes} rows={4} defaultValue={value == null ? '' : JSON.stringify(value, null, 2)}
          onChange={(event) => {
            const input = event.target
            try { change(input.value.trim() ? JSON.parse(input.value) as Value : null); input.setCustomValidity('') }
            catch { input.setCustomValidity(t('enterValidJson')) }
          }} />
          : <Input id={key} {...attributes} type={field.type === 'number' ? 'number' : 'text'}
            maxLength={field.maxLength} required={!field.optional}
            value={String(value ?? '')} onChange={(event) => {
              const next = event.target.value
              change(!next && !field.preserveEmpty ? null : field.type === 'number' ? Number(next) : next)
            }} />}
      {findings.length > 0 && <div id={key + '-issues'}>{findings.map((issue, index) =>
        <small key={index} className={issue.severity === 'ERROR' ? 'error-text' : 'muted'}>{describeIssue(issue, locale, t)}</small>)}</div>}
      {note && <div id={key + '-note'} className="field-note">{note}</div>}
    </div>
  })}</div>
}

export function Editor({ title, source, fields, plan, issues, path, focus, commit, close, action, hint, children, onFormDirty }: {
  title: string; source: RecordValue; fields: Field[]; plan: Plan; issues: Issue[]; path: string; focus?: string
  commit: (record: RecordValue) => void; close: () => void; action?: string; hint?: string; children?: ReactNode
  onFormDirty: (dirty: boolean) => void
}) {
  const { t } = useMessages()
  const [record, update] = useState(source)
  const [invalidJson, setInvalidJson] = useState(false)
  const dirty = invalidJson || fingerprint(source) !== fingerprint(record)
  useEffect(() => { onFormDirty(dirty) }, [dirty, onFormDirty])
  useEffect(() => () => onFormDirty(false), [onFormDirty])
  const ref = useFieldFocus(focus)
  function cancel() {
    if (!dirty || window.confirm(t('discardEditsToThisForm'))) close()
  }
  return <Dialog title={title} onClose={cancel}>
    <form ref={ref} className="dialog-form"
      onChange={(event) => setInvalidJson([...event.currentTarget.querySelectorAll('textarea')]
        .some((input) => !input.validity.valid))}
      onSubmit={(event) => { event.preventDefault(); commit(record) }}>
      {children}
      {hint && <p className="muted">{hint}</p>}
      <Fields fields={fields} record={record} plan={plan} path={path} issues={issues} update={update} />
      <div className="actions"><Button onClick={cancel}>{t('cancel')}</Button><Button type="submit" primary>{action ?? t('applyToDraft')}</Button></div>
    </form>
  </Dialog>
}

export function useFieldFocus(focus?: string) {
  const ref = useRef<HTMLFormElement>(null)
  useEffect(() => {
    if (!focus) return
    const all = [...(ref.current?.querySelectorAll<HTMLElement>('[data-field]') ?? [])]
    const matching = all.find((item) => item.dataset.field === focus)
      ?? all.find((item) => item.dataset.field && focus.startsWith(item.dataset.field + '.'))
    matching?.focus()
  }, [focus])
  return ref
}
