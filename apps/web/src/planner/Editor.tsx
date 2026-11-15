import { useEffect, useRef, useState } from 'react'
import { Button, Dialog, Input, Select } from '../components/ui'
import { clean, defaults, get, options, set } from './catalog'
import type { Field } from './catalog'
import { fingerprint, object } from './model'
import type { Issue, Plan, RecordValue, Value } from './model'

type FieldsProps = { fields: Field[]; plan: Plan; record: RecordValue; path: string; issues: Issue[]; update: (record: RecordValue) => void }
function Fields({ fields, plan, record, path, issues, update }: FieldsProps) {
  return <div className="field-grid">{fields.map((field) => {
    if (field.when && get(record, field.when[0]) !== field.when[1]) return null
    const key = path + '.' + field.key
    const value = get(record, field.key)
    const change = (next: Value) => update(set(record, field.key, next))
    const entries = Array.isArray(value) ? value : []
    const available = field.reference ? options(plan, field.reference)
      : (field.choices ?? []).map((id) => ({ id, label: id || 'Unspecified' }))
    const selection = (current: Value | undefined) => <>
      {!available.some((item) => item.id === '') && <option value="">
        {field.optional ? 'Unspecified' : 'Select a record'}</option>}
      {current != null && current !== '' && !available.some((item) => item.id === current) &&
        <option value={String(current)}>{String(current)} (unresolved)</option>}
      {available.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
    </>
    const lookup = (id: string) => available.find((item) => String(item.id) === id)?.id ?? null
    const findings = issues.filter((issue) => issue.path === key)
    const attributes = { 'data-field': key, 'aria-invalid': findings.some((issue) => issue.severity === 'ERROR') || undefined }
    if (field.type === 'refs' || field.type === 'records') {
      const nested = field.children ?? []
      return <fieldset className="compound" {...attributes} tabIndex={-1} key={key}>
        <legend>{field.label}</legend>
        {entries.map((item, index) => <div className={field.type === 'refs' ? 'repeat-row' : 'nested-record'} key={index}>
          {field.type === 'records' ? <Fields fields={nested} record={object(item)} plan={plan}
            path={key + '.' + index} issues={issues} update={(next) => change(entries.map((old, i) => i === index ? next : old))} />
            : <>
              <Select aria-label={field.label + ' ' + (index + 1)} data-field={key + '.' + index} value={String(item ?? '')}
                required onChange={(event) => change(entries.map((old, i) => i === index ? lookup(event.target.value) : old))}>
                {selection(item)}
              </Select>
              {[-1, 1].map((delta) => <Button key={delta} disabled={index + delta < 0 || index + delta >= entries.length}
                aria-label={'Move ' + field.label + ' ' + (index + 1) + (delta < 0 ? ' up' : ' down')} onClick={() => {
                  const next = [...entries]
                  next.splice(index + delta, 0, ...next.splice(index, 1))
                  change(next)
                }}>{delta < 0 ? '↑' : '↓'}</Button>)}
            </>}
          <Button aria-label={'Remove ' + field.label + ' ' + (index + 1)}
            onClick={() => change(entries.filter((_, i) => i !== index))}>Remove</Button>
        </div>)}
        <Button onClick={() => change([...entries, field.type === 'records' ? defaults(nested) : null])}>Add entry</Button>
      </fieldset>
    }
    return <label className={'field' + (field.type === 'json' ? ' span-all' : '')} key={key}>
      <span>{field.label}</span>
      {field.type === 'choice' || field.type === 'ref' ? <Select {...attributes} value={String(value ?? '')}
        required={!field.optional} onChange={(event) => change(lookup(event.target.value))}>{selection(value)}</Select>
        : field.type === 'json' ? <textarea {...attributes} rows={4} defaultValue={value == null ? '' : JSON.stringify(value, null, 2)}
          onChange={(event) => {
            const input = event.target
            try { change(input.value.trim() ? JSON.parse(input.value) as Value : null); input.setCustomValidity('') }
            catch { input.setCustomValidity('Enter valid JSON.') }
          }} />
          : <Input {...attributes} type={field.type === 'number' ? 'number' : 'text'} required={!field.optional}
            value={String(value ?? '')} onChange={(event) => {
              const next = event.target.value
              change(!next ? null : field.type === 'number' ? Number(next) : next)
            }} />}
      {findings.map((issue, index) => <small key={index} className={issue.severity === 'ERROR' ? 'error-text' : 'muted'}>{issue.message}</small>)}
    </label>
  })}</div>
}

export function Editor({ title, source, fields, plan, issues, path, focus, commit, close, action = 'Apply to draft', hint }: {
  title: string; source: RecordValue; fields: Field[]; plan: Plan; issues: Issue[]; path: string; focus?: string
  commit: (record: RecordValue) => void; close: () => void; action?: string; hint?: string
}) {
  const [record, update] = useState(source)
  const ref = useRef<HTMLFormElement>(null)
  useEffect(() => {
    if (!focus) return
    const all = [...(ref.current?.querySelectorAll<HTMLElement>('[data-field]') ?? [])]
    const matching = all.find((item) => item.dataset.field === focus)
      ?? all.find((item) => item.dataset.field && focus.startsWith(item.dataset.field + '.'))
    matching?.focus()
  }, [focus])
  function cancel() {
    if (fingerprint(source) === fingerprint(record) || window.confirm('Discard edits to this form?')) close()
  }
  return <Dialog title={title} onClose={cancel}>
    <form ref={ref} className="dialog-form" onSubmit={(event) => { event.preventDefault(); commit(clean(record)) }}>
      {hint && <p className="muted">{hint}</p>}
      <Fields fields={fields} record={record} plan={plan} path={path} issues={issues} update={update} />
      <div className="actions"><Button onClick={cancel}>Cancel</Button><Button type="submit" primary>{action}</Button></div>
    </form>
  </Dialog>
}
