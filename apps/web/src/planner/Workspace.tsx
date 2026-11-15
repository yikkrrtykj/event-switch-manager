import { useEffect, useRef, useState } from 'react'
import type { EventRecord } from '../api'
import { Badge, Button, Dialog, Input, Loading, Select, Table } from '../components/ui'
import { en } from '../messages'
import { catalog, sectionRoute, sections } from './catalog'
import { PlanTable } from './PlanTable'
import type { Location } from './PlanTable'
import { exportUrl, fingerprint, issuesFrom, issuesOf, list, parsePlan, read, records, save, seed, statusOf, validate } from './model'
import type { Issue, Plan, Revision, Status, Summary } from './model'

export function Validity({ status }: { status?: Status }) {
  const tone = status === 'INVALID' ? 'danger' : status === 'VALID_WITH_WARNINGS' ? 'warning'
    : status === 'VALID' ? 'success' : 'neutral'
  return <Badge tone={tone}>{status ?? en.unchecked}</Badge>
}

const tabs = ['addressing', 'transit', 'dhcp', 'egress', 'vpn']

export function Workspace({ event, section, navigate, onDirty }: {
  event: EventRecord; section: string; navigate: (route: string) => void; onDirty: (dirty: boolean) => void
}) {
  const [plan, setPlan] = useState<Plan>()
  const [baseline, setBaseline] = useState('')
  const [summary, setSummary] = useState<Summary[]>([])
  const [revision, setRevision] = useState<Revision>()
  const [historical, setHistorical] = useState(false)
  const [status, setStatus] = useState<Status>()
  const [issues, setIssues] = useState<Issue[]>([])
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const [reload, setReload] = useState(0)
  const [picked, setPicked] = useState<Location>()
  const [filter, setFilter] = useState('')
  const [diagnostics, setDiagnostics] = useState(false)
  const [dialog, setDialog] = useState<'history' | 'import' | 'json' | null>(null)
  const [comparison, setComparison] = useState<Revision>()
  const heading = useRef<HTMLHeadingElement>(null)
  const currentFingerprint = fingerprint(plan)
  const dirty = Boolean(plan && !historical && baseline !== currentFingerprint)

  useEffect(() => { onDirty(dirty || busy) }, [busy, dirty, onDirty])
  useEffect(() => () => onDirty(false), [onDirty])
  useEffect(() => {
    let active = true
    void (async () => {
      try {
        const entries = await list(event.id)
        const latest = entries.at(-1)
        const detail = latest ? await read(event.id, latest.id) : undefined
        const data = detail?.plan ?? await seed(event.id)
        if (!active) return
        setSummary(entries)
        setRevision(detail)
        setPlan(data)
        setBaseline(fingerprint(data))
        setStatus(detail?.validation_status)
        setIssues(detail ? issuesOf(detail) : [])
        setDiagnostics(detail?.validation_status === 'INVALID')
      } catch {
        if (active) setError('Unable to load the event plan. Retry to reconnect to the local API.')
      }
    })()
    return () => { active = false }
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

  async function finish(persist: boolean) {
    if (!plan || historical || busy) return
    setBusy(true)
    setNotice('')
    setError('')
    try {
      const checked = await validate(plan)
      const outcome = report(checked)
      if (!persist || outcome === 'INVALID') {
        if (!checked.length) setNotice('Plan validation passed.')
        return
      }
      const stored = await save(plan)
      setSummary((current) => [...current.filter((item) => item.id !== stored.id), stored].sort((a, b) => a.number - b.number))
      loadRevision(stored, stored.validation_status === 'INVALID')
      if (stored.validation_status === 'INVALID') {
        setError('The matching historical revision is currently invalid. Copy it to make corrections.')
      } else {
        setNotice('Revision ' + stored.number + ' saved.')
      }
    } catch (failure) {
      const findings = issuesFrom(failure)
      if (findings.length) report(findings)
      else setError(persist ? 'Unable to save the revision. Retry to check the local API.'
        : 'Unable to validate the plan. Retry to check the local API.')
    } finally { setBusy(false) }
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
    setDiagnostics(findings.length > 0)
  }

  async function open(entry: Summary, compare: boolean) {
    if (busy || (!compare && dirty && !window.confirm(en.discard))) return
    setBusy(true)
    setError('')
    try {
      const detail = await read(event.id, entry.id)
      if (compare) setComparison(detail)
      else {
        loadRevision(detail, true)
        setNotice('')
      }
    } catch {
      setError('Unable to open the revision. Retry from revision history.')
    } finally {
      setDialog(null)
      setBusy(false)
    }
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

  const pane = sections[section] ?? sections.addressing
  const title = section === 'ports' || section === 'topology' ? pane?.label : en.planner
  if (!plan) return <main id="main" className="shell screen">
    <h1>{title}</h1>
    <div className="panel">{error ? <>
      <p role="alert" className="error-text">{error}</p>
      <Button onClick={() => { setError(''); setReload((value) => value + 1) }}>Retry</Button>
    </> : <Loading>Loading event plan…</Loading>}</div>
  </main>

  const errors = issues.filter((issue) => issue.severity === 'ERROR').length
  const filtered = issues.filter((issue) => !filter || issue.severity === filter)
  const locked = historical || busy
  return <main id="main" className="shell screen">
    <div className="page-head">
      <div><p className="breadcrumb">{event.name} <span aria-hidden="true">/</span> Event workspace</p>
        <h1 tabIndex={-1} ref={heading}>{title}</h1></div>
      <div className="actions">
        <Button onClick={() => setDialog('history')} disabled={busy}>Revision history</Button>
        <Button onClick={() => setDialog('import')} disabled={locked}>Import JSON</Button>
        <Button onClick={() => setDialog('json')}>View JSON</Button>
        <Button onClick={() => void finish(false)} disabled={locked}>Validate plan</Button>
        {historical ? <Button primary onClick={() => { setHistorical(false); setNotice('Draft copied from revision ' + revision?.number + '.') }}>
          Copy to draft</Button> : <Button primary onClick={() => void finish(true)} disabled={busy || status === 'INVALID'}>
          {busy ? 'Working…' : 'Save revision'}</Button>}
      </div>
    </div>

    <div className="plan-state">
      <div className="status-strip">
        <Validity status={status} /><Badge tone="warning">{en.hardware}</Badge>
        <span role="status">{historical ? 'Read-only revision' : dirty ? 'Unsaved changes' : 'Draft up to date'}</span>
      </div>
      {revision && <details className="revision-meta">
        <summary>{fingerprint(revision.plan) === currentFingerprint ? 'Revision ' : 'Base revision '}{revision.number}</summary>
        <div className="metadata">
          <div>Revision ID <code>{revision.id}</code></div><div>SHA-256 <code>{revision.content_hash}</code></div>
          <Button onClick={() => void copy(revision.content_hash, setNotice, setError)}>Copy hash</Button>
          <a className="button-link" href={exportUrl(event.id, revision.id)} download={'revision-' + revision.number + '.json'}>Export revision</a>
        </div>
      </details>}
    </div>
    {notice && <p role="status" className="feedback success-text">{notice}</p>}
    {error && <p role="alert" className="feedback error-text">{error}</p>}

    <details className="diagnostics" open={diagnostics} onToggle={(event) => setDiagnostics(event.currentTarget.open)}>
      <summary>Validation results <span>{errors} errors · {issues.length - errors} warnings</span></summary>
      {!issues.length ? <p className="muted">{status ? 'No validation issues.' : 'Validate the draft to see field-level results.'}</p>
        : <>
          <label className="filter-label">Severity <Select value={filter} onChange={(event) => setFilter(event.target.value)}>
            <option value="">All</option><option value="ERROR">ERROR</option><option value="WARNING">WARNING</option>
          </Select></label>
          <Table label="Validation issues"><thead><tr><th scope="col">Severity</th><th scope="col">Code</th>
            <th scope="col">Message</th><th scope="col">JSON field path</th><th scope="col">Location</th>
          </tr></thead><tbody>{filtered.map((issue, index) =>
            <tr key={issue.code + index}><td><Badge tone={issue.severity === 'ERROR' ? 'danger' : 'warning'}>{issue.severity}</Badge></td>
              <td><code>{issue.code}</code></td><td>{issue.message}</td><td><code>{issue.path || '$'}</code></td>
              <td><Button onClick={() => locate(issue)} aria-label={'Locate ' + issue.code + ' at ' + (issue.path || 'plan')}>Locate</Button></td>
            </tr>)}
            {!filtered.length && <tr><td colSpan={5}>No issues match this severity.</td></tr>}</tbody></Table>
        </>}
    </details>

    {tabs.includes(section) && <nav className="tabs" aria-label="Plan sections">
      {tabs.map((item) => <a href={'#' + sectionRoute(item)} key={item} aria-current={item === section ? 'page' : undefined}
        onClick={(event) => { event.preventDefault(); navigate(sectionRoute(item)) }}>{sections[item]?.label}</a>)}
    </nav>}
    {section === 'addressing' && <div className="plan-vlan"><label htmlFor="plan-vlan">Plan management VLAN</label>
      <Input id="plan-vlan" type="number" min={1} max={4094} readOnly={locked}
        value={plan.management_vlan ?? ''} onChange={(event) => update({ ...plan, management_vlan: Number(event.target.value) })} />
    </div>}
    <div className="collections">
      {catalog.filter((group) => pane?.keys.includes(group.key)).map((group) =>
        <PlanTable key={group.key} group={group} plan={plan} issues={issues} location={picked} locked={locked} update={update} />)}
    </div>

    {dialog === 'history' && <Dialog title="Revision history" onClose={() => setDialog(null)}>
      {!summary.length ? <p className="empty">No revisions saved for this event.</p>
        : <Table label="Saved revisions"><thead><tr><th scope="col">Revision</th><th scope="col">Created</th>
          <th scope="col">SHA-256</th><th scope="col">Actions</th></tr></thead><tbody>
          {[...summary].reverse().map((entry) => <tr key={entry.id}>
            <td>#{entry.number}</td><td>{new Date(entry.created_at).toLocaleString()}</td>
            <td><code title={entry.content_hash}>{entry.content_hash.slice(0, 12)}</code></td>
            <td><div className="row-actions">
              <Button disabled={busy} onClick={() => void open(entry, false)} aria-label={'Open revision ' + entry.number}>Open</Button>
              <Button disabled={busy} onClick={() => void open(entry, true)} aria-label={'Compare revision ' + entry.number}>Compare</Button>
              <a className="button-link" href={exportUrl(event.id, entry.id)} download={'revision-' + entry.number + '.json'}>Export</a>
            </div></td>
          </tr>)}</tbody></Table>}
    </Dialog>}
    {comparison && <Compare plan={plan} revision={comparison} close={() => setComparison(undefined)} />}
    {dialog === 'import' && <Import eventId={event.id} close={() => setDialog(null)} apply={(next) => {
      if (dirty && !window.confirm('Replace the unsaved draft with this JSON plan?')) return
      update(next)
      setNotice('JSON loaded into the draft.')
      setDialog(null)
    }} />}
    {dialog === 'json' && <Dialog title="Plan JSON" onClose={() => setDialog(null)}>
      <div className="actions">
        <Button onClick={() => void copy(JSON.stringify(plan, null, 2), setNotice, setError).then((copied) => {
          if (copied) setDialog(null)
        })}>Copy JSON</Button>
        {historical && revision
          ? <a className="button-link" href={exportUrl(event.id, revision.id)} download={'revision-' + revision.number + '.json'}>Export JSON</a>
          : <Button onClick={() => download(plan)}>Export draft JSON</Button>}
      </div>
      <pre tabIndex={0}>{JSON.stringify(plan, null, 2)}</pre>
    </Dialog>}
  </main>
}

async function copy(value: string, success: (notice: string) => void, failure: (message: string) => void) {
  try {
    await navigator.clipboard.writeText(value)
    success('Copied to clipboard.')
    return true
  } catch {
    failure('Clipboard unavailable. Select the value and copy it with your keyboard.')
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

function Import({ eventId, close, apply }: { eventId: string; close: () => void; apply: (plan: Plan) => void }) {
  const [data, setData] = useState('')
  const [error, setError] = useState('')
  return <Dialog title="Import JSON" onClose={close}><form className="dialog-form" onSubmit={(event) => {
    event.preventDefault()
    try { apply(parsePlan(data, eventId)) }
    catch (failure) { setError(failure instanceof Error ? failure.message : 'Invalid plan JSON.') }
  }}>
    <label className="field">JSON file<Input type="file" accept=".json,application/json" onChange={(event) => {
      const file = event.target.files?.[0]
      if (file) void file.text().then(setData, () => setError('Unable to read the selected file.'))
    }} /></label>
    <label className="field">Plan JSON<textarea value={data} rows={8} required onChange={(event) => setData(event.target.value)} /></label>
    {error && <p className="error-text" role="alert">{error}</p>}
    <div className="actions"><Button onClick={close}>Cancel</Button><Button primary type="submit">Load into draft</Button></div>
  </form></Dialog>
}

function Compare({ plan, revision, close }: { plan: Plan; revision: Revision; close: () => void }) {
  const keys = [...new Set([...Object.keys(plan), ...Object.keys(revision.plan)])].sort()
    .filter((key) => fingerprint(plan[key]) !== fingerprint(revision.plan[key]))
  return <Dialog title={'Compare revision ' + revision.number} onClose={close}>
    <div className="status-strip"><Validity status={revision.validation_status} /> <span>{keys.length} changed sections</span></div>
    {keys.map((key) => <details className="compare-section" key={key}>
      <summary>{catalog.find((item) => item.key === key)?.title ?? key}</summary>
      <div className="compare-grid">{([[revision.plan, 'Saved revision'], [plan, 'Current workspace']] as const).map(([source, label]) =>
          <div key={label}><h3>{label}</h3><pre tabIndex={0}>{JSON.stringify(source[key], null, 2) ?? 'Absent'}</pre></div>)}</div>
    </details>)}
  </Dialog>
}
