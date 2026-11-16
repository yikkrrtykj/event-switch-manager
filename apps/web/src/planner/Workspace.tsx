import { useEffect, useRef, useState } from 'react'
import type { EventRecord } from '../api'
import { Badge, Button, Dialog, Input, Loading, Select, Table } from '../components/ui'
import { message, severityLabel, statusLabel, validationCounts } from '../messages'
import type { Message, MessageKey } from '../messages'
import { useMessages } from '../locale'
import { describeIssue } from './diagnostics'
import { catalog, sectionRoute, sections } from './catalog'
import { PlanTable } from './PlanTable'
import type { Location } from './PlanTable'
import { exportUrl, fingerprint, issuesFrom, issuesOf, list, parsePlan, read, records, save, seed, statusOf, validate, PlanImportError } from './model'
import type { Issue, Plan, Revision, Status, Summary } from './model'

export function Validity({ status }: { status?: Status }) {
  const { t } = useMessages()
  const tone = status === 'INVALID' ? 'danger' : status === 'VALID_WITH_WARNINGS' ? 'warning'
    : status === 'VALID' ? 'success' : 'neutral'
  return <Badge tone={tone}>{statusLabel(t, status)}</Badge>
}

const tabs = ['addressing', 'transit', 'dhcp', 'egress', 'vpn']

export function Workspace({ event, section, navigate, onDirty }: {
  event: EventRecord; section: string; navigate: (route: string) => void; onDirty: (dirty: boolean, form?: boolean) => void
}) {
  const { t, locale } = useMessages()
  const [plan, setPlan] = useState<Plan>()
  const [baseline, setBaseline] = useState('')
  const [summary, setSummary] = useState<Summary[]>([])
  const [revision, setRevision] = useState<Revision>()
  const [historical, setHistorical] = useState(false)
  const [requiresValidation, setRequiresValidation] = useState(false)
  const [tableScope, setTableScope] = useState(0)
  const [status, setStatus] = useState<Status>()
  const [issues, setIssues] = useState<Issue[]>([])
  const [error, setError] = useState<MessageKey | Message | ''>('')
  const [notice, setNotice] = useState<MessageKey | Message | ''>('')
  const [busy, setBusy] = useState(false)
  const [formDirty, setFormDirty] = useState(false)
  const [reload, setReload] = useState(0)
  const [picked, setPicked] = useState<Location>()
  const [filter, setFilter] = useState('')
  const [diagnostics, setDiagnostics] = useState(false)
  const [dialog, setDialog] = useState<'history' | 'import' | 'json' | null>(null)
  const [comparison, setComparison] = useState<Revision>()
  const heading = useRef<HTMLHeadingElement>(null)
  const pending = useRef<AbortController>(null)
  const currentFingerprint = fingerprint(plan)
  const dirty = Boolean(plan && !historical && baseline !== currentFingerprint)

  useEffect(() => { onDirty(dirty || busy || formDirty, formDirty) }, [busy, dirty, formDirty, onDirty])
  useEffect(() => () => {
    pending.current?.abort()
    pending.current = null
    onDirty(false)
  }, [onDirty])
  useEffect(() => {
    const controller = new AbortController()
    const { signal } = controller
    void (async () => {
      try {
        const entries = await list(event.id, signal)
        if (signal.aborted) return
        const latest = entries.at(-1)
        const detail = latest ? await read(event.id, latest.id, signal) : undefined
        const data = detail?.plan ?? await seed(event.id, signal)
        if (signal.aborted) return
        setSummary(entries)
        setRevision(detail)
        setPlan(data)
        setBaseline(fingerprint(data))
        setStatus(detail?.validation_status)
        setIssues(detail ? issuesOf(detail) : [])
        setHistorical(detail?.validation_status === 'INVALID')
        setDiagnostics(detail?.validation_status === 'INVALID')
      } catch {
        if (!signal.aborted) setError('loadPlanError')
      }
    })()
    return () => controller.abort()
  }, [event.id, reload])

  function update(next: Plan) {
    setPlan(next)
    setStatus(undefined)
    setIssues([])
    setPicked(undefined)
    setNotice('')
    setError('')
  }

  function report(next: Issue[]) {
    setIssues(next)
    const outcome = statusOf(next)
    setStatus(outcome)
    if (next.length) setDiagnostics(true)
    return outcome
  }

  function startOperation() {
    const controller = new AbortController()
    pending.current = controller
    setBusy(true)
    return controller
  }

  function endOperation(controller: AbortController) {
    if (pending.current !== controller) return
    pending.current = null
    setBusy(false)
  }

  function closeHistory() {
    const controller = pending.current
    if (controller) {
      controller.abort()
      endOperation(controller)
    }
    setDialog(null)
  }

  async function finish(persist: boolean) {
    if (!plan || historical || pending.current ||
      (persist && (status === 'INVALID' || requiresValidation && status === undefined))) return
    const controller = startOperation()
    const { signal } = controller
    setNotice('')
    setError('')
    try {
      const checked = await validate(plan, signal)
      if (signal.aborted) return
      const outcome = report(checked)
      if (!persist || outcome === 'INVALID') {
        if (!checked.length) setNotice('planValidationPassed')
        return
      }
      const stored = await save(plan, signal)
      if (signal.aborted) return
      setSummary((current) => [...current.filter((item) => item.id !== stored.id), stored].sort((a, b) => a.number - b.number))
      loadRevision(stored, stored.validation_status === 'INVALID')
      if (stored.validation_status === 'INVALID') {
        setError('invalidHistoricalRevision')
      } else {
        setNotice(message('revisionSaved', { number: stored.number }))
      }
    } catch (failure) {
      if (signal.aborted) return
      const findings = issuesFrom(failure)
      if (findings.length) report(findings)
      else setError(persist ? 'saveRevisionError'
        : 'validatePlanError')
    } finally { endOperation(controller) }
  }

  function loadRevision(entry: Revision, readOnly: boolean) {
    const findings = issuesOf(entry)
    setPlan(entry.plan)
    setBaseline(fingerprint(entry.plan))
    setRevision(entry)
    setStatus(entry.validation_status)
    setIssues(findings)
    setPicked(undefined)
    setHistorical(readOnly)
    setRequiresValidation(false)
    setTableScope((current) => current + 1)
    setDiagnostics(findings.length > 0)
  }

  async function open(entry: Summary, compare: boolean) {
    if (pending.current || (!compare && dirty && !window.confirm(t('discardPlan')))) return
    const controller = startOperation()
    const { signal } = controller
    setError('')
    try {
      const detail = await read(event.id, entry.id, signal)
      if (signal.aborted) return
      if (compare) setComparison(detail)
      else {
        loadRevision(detail, true)
        setNotice('')
      }
    } catch {
      if (!signal.aborted) setError('openRevisionError')
    } finally {
      if (!signal.aborted) setDialog(null)
      endOperation(controller)
    }
  }

  function copyRevision() {
    if (!plan) return
    update(plan)
    setHistorical(false)
    setRequiresValidation(true)
    setTableScope((current) => current + 1)
    setNotice(message('copiedRevision', { number: revision?.number ?? '' }))
  }

  function locate(issue: Issue) {
    const path = issue.path.replace(/^\$\.?/, '').replace(/\[(\d+)\]/g, '.$1')
    const [key, item, ...rest] = path.split('.')
    if (key === 'management_vlan') {
      navigate('planner/addressing')
      requestAnimationFrame(() => document.getElementById('plan-vlan')?.focus())
      return
    }
    if (!key || key === 'event_id' || key === 'schema_version') {
      heading.current?.focus()
      return
    }
    let group = key
    let index = item && /^[0-9]+$/.test(item) ? Number(item) : undefined
    if (key === 'interfaces' && index !== undefined && plan) {
      const physical = records(plan, 'physical_interfaces').length
      group = index < physical ? 'physical_interfaces' : 'logical_interfaces'
      if (index >= physical) index -= physical
    }
    const spec = catalog.find((candidate) => candidate.key === group)
    const pane = Object.entries(sections).find(([, entry]) => entry.keys.includes(group))?.[0]
    if (!spec || !pane) { setDialog('json'); return }
    setPicked({ key: group, index: spec.single ? 0 : index,
      path: spec.single || index === undefined ? path : [group, index, ...rest].join('.') })
    navigate(sectionRoute(pane))
  }

  const pane = sections[section] ?? sections.addressing!
  const title = section === 'ports' || section === 'topology' ? t(pane.label) : t('planner')
  if (!plan) return <main id="main" className="shell screen">
    <h1>{title}</h1>
    <div className="panel">{error ? <>
      <p role="alert" className="error-text">{t(error)}</p>
      <Button onClick={() => { setError(''); setReload((value) => value + 1) }}>{t('retry')}</Button>
    </> : <Loading>{t('loadingEventPlan')}</Loading>}</div>
  </main>

  const errors = issues.filter((issue) => issue.severity === 'ERROR').length
  const filtered = issues.filter((issue) => !filter || issue.severity === filter)
  const locked = historical || busy
  return <main id="main" className="shell screen">
    <div className="page-head">
      <div><p className="breadcrumb">{event.name} <span aria-hidden="true">/</span> {t('eventWorkspace')}</p>
        <h1 tabIndex={-1} ref={heading}>{title}</h1></div>
      <div className="actions">
        <Button onClick={() => setDialog('history')} disabled={busy}>{t('revisionHistory')}</Button>
        <Button onClick={() => setDialog('import')} disabled={locked}>{t('importJson')}</Button>
        <Button onClick={() => setDialog('json')}>{t('viewJson')}</Button>
        <Button onClick={() => void finish(false)} disabled={locked}>{t('validatePlan')}</Button>
        {historical ? <Button primary onClick={copyRevision}>
          {t('copyToDraft')}</Button> : <Button primary onClick={() => void finish(true)} disabled={busy || status === 'INVALID' || requiresValidation && status === undefined}>
          {busy ? t('working') : t('saveRevision')}</Button>}
      </div>
    </div>

    <div className="plan-state">
      <div className="status-strip">
        <Validity status={status} /><Badge tone="warning">{t('hardwareNotVerified')}</Badge>
        <span role="status">{historical ? t('readOnlyRevision') : dirty ? t('unsavedChanges') : t('draftUpToDate')}</span>
      </div>
      {revision && <details className="revision-meta">
        <summary>{t(fingerprint(revision.plan) === currentFingerprint ? 'revisionNumber' : 'baseRevisionNumber', { number: revision.number })}</summary>
        <div className="metadata">
          <div>{t('revisionId')} <code>{revision.id}</code></div><div>SHA-256 <code>{revision.content_hash}</code></div>
          <Button onClick={() => void copy(revision.content_hash, setNotice, setError)}>{t('copyHash')}</Button>
          <a className="button-link" href={exportUrl(event.id, revision.id)} download={'revision-' + revision.number + '.json'}>{t('exportRevision')}</a>
        </div>
      </details>}
    </div>
    {notice && <p role="status" className="feedback success-text">{t(notice)}</p>}
    {error && <p role="alert" className="feedback error-text">{t(error)}</p>}

    <details className="diagnostics" open={diagnostics} onToggle={(event) => setDiagnostics(event.currentTarget.open)}>
      <summary>{t('validationResults')} <span>{validationCounts(t, errors, issues.length - errors)}</span></summary>
      {!issues.length ? <p className="muted">{status ? t('noValidationIssues') : t('validationPrompt')}</p>
        : <>
          <div className="filter-label">
            <label htmlFor="issue-severity">{t('severity')}</label>
            <Select id="issue-severity" value={filter} onChange={(event) => setFilter(event.target.value)}>
            <option value="">{t('all')}</option><option value="ERROR">{t('severityError')}</option><option value="WARNING">{t('severityWarning')}</option>
          </Select></div>
          <Table label={t('validationIssues')}><thead><tr><th scope="col">{t('severity')}</th><th scope="col">{t('code')}</th>
            <th scope="col">{t('message')}</th><th scope="col">{t('jsonFieldPath')}</th><th scope="col">{t('location')}</th>
          </tr></thead><tbody>{filtered.map((issue, index) =>
            <tr key={issue.code + index}><td><Badge tone={issue.severity === 'ERROR' ? 'danger' : 'warning'}>{severityLabel(t, issue.severity)}</Badge></td>
              <td><code>{issue.code}</code></td><td>{describeIssue(issue, locale, t)}</td><td><code>{issue.path || '$'}</code></td>
              <td><Button onClick={() => locate(issue)} aria-label={t('locateIssue', { code: issue.code, path: issue.path || t('planRoot') })}>{t('locate')}</Button></td>
            </tr>)}
            {!filtered.length && <tr><td colSpan={5}>{t('noIssuesMatchThisSeverity')}</td></tr>}</tbody></Table>
        </>}
    </details>

    {tabs.includes(section) && <nav className="tabs" aria-label={t('planSections')}>
      {tabs.map((item) => <a href={'#' + sectionRoute(item)} key={item} aria-current={item === section ? 'page' : undefined}
        onClick={(event) => { event.preventDefault(); navigate(sectionRoute(item)) }}>{t(sections[item]!.label)}</a>)}
    </nav>}
    {section === 'addressing' && <div className="plan-vlan"><label htmlFor="plan-vlan">{t('planManagementVlan')}</label>
      <Input id="plan-vlan" type="number" min={1} max={4094} readOnly={locked}
        value={plan.management_vlan ?? ''} onChange={(event) => update({ ...plan, management_vlan: Number(event.target.value) })} />
    </div>}
    <div className="collections">
      {catalog.filter((group) => pane?.keys.includes(group.key)).map((group) =>
        <PlanTable key={group.key + ':' + tableScope} group={group} plan={plan} issues={issues} location={picked} locked={locked} update={update}
          onFormDirty={setFormDirty} />)}
    </div>

    {dialog === 'history' && <Dialog title={t('revisionHistory')} onClose={closeHistory}>
      {!summary.length ? <p className="empty">{t('noRevisionsSavedForThisEvent')}</p>
        : <Table label={t('savedRevisions')}><thead><tr><th scope="col">{t('revision')}</th><th scope="col">{t('created')}</th>
          <th scope="col">SHA-256</th><th scope="col">{t('actions')}</th></tr></thead><tbody>
          {[...summary].reverse().map((entry) => <tr key={entry.id}>
            <td>#{entry.number}</td><td>{new Date(entry.created_at).toLocaleString(locale)}</td>
            <td><code title={entry.content_hash}>{entry.content_hash.slice(0, 12)}</code></td>
            <td><div className="row-actions">
              <Button disabled={busy} onClick={() => void open(entry, false)} aria-label={t('openRevision', { number: entry.number })}>{t('open')}</Button>
              <Button disabled={busy} onClick={() => void open(entry, true)} aria-label={t('compareRevision', { number: entry.number })}>{t('compare')}</Button>
              <a className="button-link" href={exportUrl(event.id, entry.id)} download={'revision-' + entry.number + '.json'}>{t('export')}</a>
            </div></td>
          </tr>)}</tbody></Table>}
    </Dialog>}
    {comparison && <Compare plan={plan} revision={comparison} close={() => setComparison(undefined)} />}
    {dialog === 'import' && <Import eventId={event.id} close={() => setDialog(null)} onFormDirty={setFormDirty} apply={(next) => {
      if (dirty && !window.confirm(t('replaceDraftConfirm'))) return
      update(next)
      setTableScope((current) => current + 1)
      setNotice('jsonLoadedIntoTheDraft')
      setDialog(null)
    }} />}
    {dialog === 'json' && <Dialog title={t('planJson')} onClose={() => setDialog(null)}>
      <div className="actions">
        <Button onClick={() => void copy(JSON.stringify(plan, null, 2), setNotice, setError).then((copied) => {
          if (copied) setDialog(null)
        })}>{t('copyJson')}</Button>
        {historical && revision
          ? <a className="button-link" href={exportUrl(event.id, revision.id)} download={'revision-' + revision.number + '.json'}>{t('exportJson')}</a>
          : <Button onClick={() => download(plan)}>{t('exportDraftJson')}</Button>}
      </div>
      <pre tabIndex={0}>{JSON.stringify(plan, null, 2)}</pre>
    </Dialog>}
  </main>
}

async function copy(value: string, success: (notice: MessageKey) => void, failure: (message: MessageKey) => void) {
  try {
    await navigator.clipboard.writeText(value)
    success('copiedToClipboard')
    return true
  } catch {
    failure('clipboardError')
    return false
  }
}

function download(plan: Plan) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(plan, null, 2)], { type: 'application/json' }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = 'event-plan-draft.json'
  anchor.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function Import({ eventId, close, apply, onFormDirty }: {
  eventId: string; close: () => void; apply: (plan: Plan) => void; onFormDirty: (dirty: boolean) => void
}) {
  const { t } = useMessages()
  const [data, setData] = useState('')
  const [error, setError] = useState<MessageKey | Message | ''>('')
  const fileRead = useRef(0)
  useEffect(() => { onFormDirty(Boolean(data)) }, [data, onFormDirty])
  useEffect(() => () => onFormDirty(false), [onFormDirty])

  function cancel() {
    if (!data || window.confirm(t('discardThisJsonImport'))) close()
  }

  return <Dialog title={t('importJson')} onClose={cancel}><form className="dialog-form" onSubmit={(event) => {
    event.preventDefault()
    try { apply(parsePlan(data, eventId)) }
    catch (failure) { setError(failure instanceof PlanImportError ? failure.key : 'invalidPlanJson') }
  }}>
    <label className="field">{t('jsonFile')}<Input type="file" accept=".json,application/json" onChange={(event) => {
      const file = event.target.files?.[0]
      const attempt = ++fileRead.current
      if (file) void file.text().then((text) => {
        if (fileRead.current === attempt) { setData(text); setError('') }
      }, () => {
        if (fileRead.current === attempt) setError('unableToReadTheSelectedFile')
      })
    }} /></label>
    <label className="field">{t('planJson')}<textarea value={data} rows={8} required onChange={(event) => {
      ++fileRead.current
      setData(event.target.value)
      setError('')
    }} /></label>
    {error && <p className="error-text" role="alert">{t(error)}</p>}
    <div className="actions"><Button onClick={cancel}>{t('cancel')}</Button><Button primary type="submit">{t('loadIntoDraft')}</Button></div>
  </form></Dialog>
}

function Compare({ plan, revision, close }: { plan: Plan; revision: Revision; close: () => void }) {
  const { t } = useMessages()
  const keys = [...new Set([...Object.keys(plan), ...Object.keys(revision.plan)])].sort()
    .filter((key) => fingerprint(plan[key]) !== fingerprint(revision.plan[key]))
  return <Dialog title={t('compareRevision', { number: revision.number })} onClose={close}>
    <div className="status-strip"><Validity status={revision.validation_status} /> <span>{t('changedSections', { count: keys.length })}</span></div>
    {keys.map((key) => {
      const title = catalog.find((item) => item.key === key)?.title
      return <details className="compare-section" key={key}>
        <summary>{title ? t(title) : key}</summary>
        <div className="compare-grid">{([[revision.plan, 'savedRevision'], [plan, 'currentWorkspace']] as const).map(([source, label]) =>
          <div key={label}><h3>{t(label)}</h3><pre tabIndex={0}>{JSON.stringify(source[key], null, 2) ?? t('absent')}</pre></div>)}</div>
      </details>
    })}
  </Dialog>
}
