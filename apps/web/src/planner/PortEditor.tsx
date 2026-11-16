import { enumLabel } from '../messages'
import { describeIssue } from './diagnostics'
import { useMessages } from '../locale'
import { useEffect, useRef, useState } from 'react'
import { Badge, Button, Dialog, Select, Table } from '../components/ui'
import { get, set } from './catalog'
import type { Field } from './catalog'
import { Fields, useFieldFocus } from './Editor'
import { fingerprint } from './model'
import type { Issue, Plan, RecordValue } from './model'
import { aggregatePortLabel, canResetPortField, commonPortValue, describePortValue, editPort, hasPortValue, isPortSetting, modeKey,
  physicalPortLabel, portFieldApplies, portMode } from './portSettings'
import type { Operations, PortTarget } from './portSettings'

export function PortEditor({ title, targets, fields, plan, path, issues, focus, aggregate, batch, creating, commit, close, onFormDirty }: {
  title: string; targets: PortTarget[]; fields: Field[]; plan: Plan; path: string; issues: Issue[]; focus?: string
  aggregate?: boolean; batch?: boolean; creating?: boolean
  commit: (items: RecordValue[]) => void; close: () => void; onFormDirty: (dirty: boolean) => void
}) {
  const { t, locale } = useMessages()
  const original = targets[0]?.item ?? {}
  const [record, setRecord] = useState(original)
  const [operations, setOperations] = useState<Operations>({})
  const [review, setReview] = useState(false)
  const [showKept, setShowKept] = useState(false)
  const ref = useFieldFocus(focus)
  const reviewHeading = useRef<HTMLHeadingElement>(null)
  const dirty = Object.keys(operations).length > 0 || fingerprint(record) !== fingerprint(original)
  const modes = targets.map(({ item }) => portMode(item, operations))
  const label = aggregate ? aggregatePortLabel : physicalPortLabel
  const controls = fields.filter(isPortSetting)
  const identity = fields.filter((field) => !isPortSetting(field))
  const isAvailable = (field: Field) => modes.every((mode) => portFieldApplies(field, mode))
  const canResetHidden = (field: Field) => !batch && canResetPortField(field, true) &&
    hasPortValue(get(original, field.key)) && get(original, modeKey) === modes[0]
  const canApply = (field: Field) => isAvailable(field) ||
    (canResetHidden(field) && operations[field.key]?.kind === 'reset')
  const proposed = targets.map(({ item, index }) => {
    const edit = editPort(item, batch ? item : record, fields, operations, canApply)
    const target = label(t, plan, batch ? item : edit.next)
    return { index, ...target, ...edit, changed: fingerprint(edit.next) !== fingerprint(item) }
  })
  const changed = creating || proposed.some((item) => item.changed)
  const hasCleanup = proposed.some(({ changes }) => changes.some((change) => change.operation === 'clearOnModeChange'))
  const currentValues = new Map(controls.map((field) => [field.key, commonPortValue(field, targets)]))

  useEffect(() => { onFormDirty(dirty) }, [dirty, onFormDirty])
  useEffect(() => () => onFormDirty(false), [onFormDirty])
  useEffect(() => { if (review) reviewHeading.current?.focus() }, [review])

  function cancel() {
    if (!dirty || window.confirm(t('discardEditsToThisForm'))) close()
  }

  return <Dialog title={title} onClose={cancel}>
    <form className="dialog-form port-editor" ref={ref} onSubmit={(event) => {
      event.preventDefault()
      if (review) commit(proposed.map(({ next }) => next))
      else { setShowKept(false); setReview(true) }
    }}>
      {review ? <>
        <div className="section-head"><h3 tabIndex={-1} ref={reviewHeading}>{t('beforeAfter')}</h3>
          <label className="port-keep"><input type="checkbox" checked={showKept}
            onChange={(event) => setShowKept(event.target.checked)} /> {t('showKeptFields')}</label></div>
        {hasCleanup && <p className="feedback port-mode-warning" role="status">
          {t('modeCleanupWarning')}
        </p>}
        {!changed && <p className="muted">{t('noValuesWillChange')}</p>}
        <Table label={t('portChanges')}><thead><tr>
          <th scope="col">{t('device')}</th><th scope="col">{t('stackMember')}</th><th scope="col">{t('interface')}</th>
          <th scope="col">{t('field')}</th><th scope="col">{t('before')}</th><th scope="col">{t('after')}</th><th scope="col">{t('operation')}</th>
        </tr></thead><tbody>{proposed.map(({ index, device, member, name, changes }) => {
          const shown = changes.filter((change) => showKept || change.operation !== 'keep')
          return shown.length ? shown.map(({ field, before, after, operation }) => (
            <tr key={index + ':' + field.key}>
              <td>{device}</td><td>{member}</td><td className="data-mono">{name}</td><th scope="row">{t(field.label)}</th>
              <td>{describePortValue(t, plan, field, before)}</td><td>{describePortValue(t, plan, field, after)}</td>
              <td>{t(operation)}{currentValues.get(field.key)?.mixed && <small className="muted">{' · '}{t('mixedBeforeEdit')}</small>}</td>
            </tr>)) : <tr key={index}><td>{device}</td><td>{member}</td>
              <td className="data-mono">{name}</td><td colSpan={4}>{t('noChanges')}</td></tr>
        })}</tbody></Table>
      </> : <>
        {batch ? <Table label={t('targetPorts')}><thead><tr>
          <th scope="col">{t('device')}</th><th scope="col">{t('stackMember')}</th><th scope="col">{t('interface')}</th><th scope="col">{t('currentMode')}</th>
        </tr></thead><tbody>{targets.map(({ item, index }) => {
          const target = label(t, plan, item)
          return <tr key={index}><td>{target.device}</td><td>{target.member}</td>
            <td className="data-mono">{target.name}</td><td>{enumLabel(t, String(get(item, modeKey) ?? '—'), modeKey)}</td></tr>
        })}</tbody></Table> : <>
          {!creating && <p className="muted">{[label(t, plan, original).device, label(t, plan, original).member, label(t, plan, original).name].join(' · ')}</p>}
          <details open={creating || Boolean(focus && identity.some((field) => focus.startsWith(path + '.' + field.key))) || undefined}>
            <summary>{aggregate ? t('aggregateInterfaceAndMembers') : t('interfaceIdentity')}</summary>
            <Fields fields={identity} record={record} plan={plan} path={path} issues={issues} update={setRecord} />
          </details>
        </>}
        <div className="status-strip"><Badge tone="warning">{t('notVerified')}</Badge>
          <span className="muted">{t('portHardwareEvidence')}</span></div>
        <div className="port-settings-grid">{controls.map((field) => {
          const available = isAvailable(field)
          if (!available && !canResetHidden(field)) return null
          const operation = operations[field.key]
          const canReset = canResetPortField(field, !available)
          const { mixed, value: common } = currentValues.get(field.key)!
          const rawValue = operation?.kind === 'set' ? operation.value : operation ? undefined : common
          const choices = field.key === 'settings.portfast' ? field.choices?.filter((choice) =>
            choice === 'disabled' || modes.every((mode) => (mode === 'access' ? 'edge' : 'edge-trunk') === choice))
            : field.choices
          const permits = (value: unknown) => !choices || choices.some((choice) => choice === value)
          const incompatible = rawValue != null && !permits(rawValue)
          const current = operation?.kind === 'set' && incompatible ? undefined : rawValue
          const control: Field = { ...field, when: undefined, choices,
            optional: operation?.kind !== 'set' && field.modelDefault === undefined || field.preserveEmpty,
          }
          const key = path + '.' + field.key
          const after = operation?.kind ?? 'keep'
          const fieldIssues = issues.filter((issue) => issue.path === key)
          return <fieldset className="port-setting" key={field.key}>
            <legend>{t(field.label)}</legend>
            <div className="port-setting-action">
              <Select aria-label={t('fieldOperation', { field: t(field.label) })} value={after} onChange={(event) => {
                const action = event.target.value
                setOperations((previous) => {
                  const next = { ...previous }
                  if (action === 'keep') delete next[field.key]
                  if (action === 'reset' && canReset) next[field.key] = { kind: 'reset' }
                  if (action === 'set') next[field.key] = {
                    kind: 'set',
                    value: common != null && permits(common) ? common : (field.preserveEmpty ? '' : field.type === 'refs' ? [] : null),
                  }
                  return next
                })
              }}>
                <option value="keep">{t('keep')}</option>
                {canReset && <option value="reset">{field.type === 'refs' ? t('clearList') : t('reset')}</option>}
                {available && <option value="set">{t('set')}</option>}
              </Select>
              {mixed && <Badge>{t('mixed')}</Badge>}
              {canReset && !mixed && current == null && after === 'keep' && <small className="muted">{t('platformDefault')}</small>}
            </div>
            {operation?.kind === 'set' && incompatible &&
              <small className="error-text">{t('incompatiblePortValue')}</small>}
            {available && after !== 'reset' ?
              <Fields fields={[control]} plan={plan} record={set({}, field.key, current ?? null)} path={path}
                issues={issues} update={(next) => {
                  const value = get(next, field.key)
                  if (value !== undefined) setOperations((previous) => ({ ...previous, [field.key]: { kind: 'set', value } }))
                }} /> :
              <div data-field={key} tabIndex={-1} className="muted">
                {after === 'reset' ? field.type === 'refs' ? t('willClearTheList') : t('willUsePlatformDefault')
                  : t('unavailablePortSetting')}
                {fieldIssues.map((issue, index) => <div key={index} className={issue.severity === 'ERROR' ? 'error-text' : 'muted'}>{describeIssue(issue, locale, t)}</div>)}
              </div>}
          </fieldset>
        })}</div>
      </>}
      <div className="actions">
        <Button onClick={cancel}>{t('cancel')}</Button>
        {review && <Button onClick={() => setReview(false)}>{t('backToEdit')}</Button>}
        {!review && <Button primary type="submit" disabled={!changed && batch}>{t('previewChanges')}</Button>}
        {review && <Button primary type="submit" disabled={!changed && batch}>
          {hasCleanup ? t('confirmAndApplyToDraft') : batch ? t('applyPorts', { count: targets.length }) : t('applyToDraft')}
        </Button>}
      </div>
    </form>
  </Dialog>
}
