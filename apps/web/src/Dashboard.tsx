import { useEffect, useState } from 'react'
import type { Dispatch, FormEvent, SetStateAction } from 'react'

import { createEvent, getDevices, getHealth } from './api'
import type { DeviceRecord, EventRecord, Health } from './api'
import { Badge, Button, Input, Loading, Select, Table } from './components/ui'
import { en } from './messages'
import { list, read, records } from './planner/model'
import type { Revision } from './planner/model'
import { Validity } from './planner/Workspace'

const roles = {
  core: 'Core',
  access: 'Access',
  'external-distribution': 'External / Distribution',
}

export function Dashboard({ events, setEvents, eventError, selectedId, setSelectedId, eventsOnly, retryEvents, navigate }: {
  events: EventRecord[] | null
  setEvents: Dispatch<SetStateAction<EventRecord[] | null>>
  eventError: string
  selectedId: string
  setSelectedId: (id: string) => void
  eventsOnly: boolean
  retryEvents: () => void
  navigate: (route: string) => void
}) {
  const [health, setHealth] = useState<Health | null>(null)
  const [healthUnavailable, setHealthUnavailable] = useState(false)
  const [inventory, setInventory] = useState<{
    eventId: string
    devices: DeviceRecord[] | null
  } | null>(null)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')

  useEffect(() => {
    let active = true
    void getHealth().then(
      (result) => { if (active) setHealth(result) },
      () => { if (active) setHealthUnavailable(true) },
    )
    return () => { active = false }
  }, [])

  useEffect(() => {
    if (!selectedId) return
    let active = true
    setInventory(null)
    void getDevices(selectedId).then(
      (devices) => { if (active) setInventory({ eventId: selectedId, devices }) },
      () => { if (active) setInventory({ eventId: selectedId, devices: null }) },
    )
    return () => { active = false }
  }, [selectedId])

  async function submitEvent(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const values = new FormData(form)
    const name = String(values.get('name') ?? '').trim()
    const management_vlan = Number(values.get('management_vlan'))
    if (!name) {
      setSaveError('Enter an event name.')
      return
    }

    setSaving(true)
    setSaveError('')
    try {
      const record = await createEvent({ name, management_vlan })
      setEvents((current) => [...(current ?? []), record])
      setSelectedId(record.id)
      form.reset()
    } catch {
      setSaveError('Unable to save the event. Check the local service and try again.')
    } finally {
      setSaving(false)
    }
  }

  const selected = events?.find((event) => event.id === selectedId)
  const devices = inventory?.eventId === selectedId ? inventory.devices : undefined

  return (
    <main id="main" className="shell screen">
        <div className="page-head">
          <h1>{eventsOnly ? en.events : en.dashboard}</h1>
          {selected && <div className="actions">
            <Button onClick={() => navigate('planner/addressing')}>Open network plan</Button>
            <Button onClick={() => navigate('devices')}>Manage planned devices</Button>
          </div>}
        </div>
        {!eventsOnly && <>
        <div className="status-grid grid gap-3 sm:grid-cols-3" aria-label="System status">
          <div className="status-tile">
            <span>Local API</span>
            <strong className={health ? 'ready' : ''} role="status">
              {health ? 'Connected' : healthUnavailable ? 'Unavailable' : 'Connecting'}
            </strong>
          </div>
          <div className="status-tile">
            <span>Planning database</span>
            <strong>{health ? 'Ready' : healthUnavailable ? 'Unavailable' : 'Checking'}</strong>
          </div>
          <div className="status-tile">
            <span>Device writes</span>
            <strong>{health ? health.device_writes_enabled ? 'Enabled' : 'Disabled' : 'Unknown'}</strong>
          </div>
        </div>

        {selected && <PlanSummary key={selected.id} event={selected} />}
        </>}
        <div className="workspace grid gap-5 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
          <section className="panel" aria-labelledby="events-title">
            <h2 id="events-title">Events</h2>
            {eventError && <><p role="alert">{eventError}</p><Button onClick={retryEvents}>Retry events</Button></>}
            {!eventError && events === null && <Loading>Loading events…</Loading>}
            {events?.length === 0 && <p>No events yet. Create one to start planning.</p>}
            {events && events.length > 0 && (
              <div className="event-picker">
                <label htmlFor="current-event">Selected event</label>
                <Select id="current-event" value={selectedId} onChange={(e) => setSelectedId(e.target.value)}>
                  {events.map((event) => <option key={event.id} value={event.id}>{event.name}</option>)}
                </Select>
              </div>
            )}
            {selected && (
              <>
                <h3>Device inventory</h3>
                <p>Management VLAN <strong>{selected.management_vlan}</strong></p>
                {devices === null && <p role="alert">Unable to load devices.</p>}
                {devices === undefined && <Loading>Loading devices…</Loading>}
                {devices?.length === 0 && <p>No devices recorded for this event.</p>}
                {devices && devices.length > 0 && (
                  <Table label="Device inventory">
                      <thead><tr><th scope="col">Hostname</th><th scope="col">Role</th><th scope="col">Management IP</th></tr></thead>
                      <tbody>
                        {devices.map((device) => (
                          <tr key={device.id}>
                            <td>{device.hostname}</td>
                            <td>{roles[device.role]}</td>
                            <td>{device.management_ip ?? '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                  </Table>
                )}
              </>
            )}
          </section>

          <section className="panel" aria-labelledby="new-event-title">
            <h2 id="new-event-title">Create event</h2>
            <form onSubmit={submitEvent}>
              <label htmlFor="event-name">Event name</label>
              <Input id="event-name" name="name" required maxLength={120} />
              <label htmlFor="management-vlan">Management VLAN</label>
              <Input id="management-vlan" name="management_vlan" type="number" required min={1} max={4094} defaultValue={10} />
              {saveError && <p role="alert">{saveError}</p>}
              <Button type="submit" primary disabled={saving || events === null}>{saving ? 'Creating…' : 'Create event'}</Button>
            </form>
          </section>
        </div>
    </main>
  )
}

function PlanSummary({ event }: { event: EventRecord }) {
  const [entry, setEntry] = useState<Revision | null>()
  const [error, setError] = useState(false)
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    let active = true
    void list(event.id).then((entries) => {
      const latest = entries.at(-1)
      return latest ? read(event.id, latest.id) : null
    }).then((detail) => { if (active) setEntry(detail) }, () => { if (active) setError(true) })
    return () => { active = false }
  }, [attempt, event.id])
  const planned = entry ? records(entry.plan, 'physical_devices') : []
  const pending = planned.filter((item) => !item.verified_serial).length
  const portsPending = entry ? records(entry.plan, 'physical_interfaces')
    .filter((item) => item.capability_status !== 'verified').length : 0
  return <section className="panel dashboard-plan" aria-label="Plan overview">
    <div className="section-head"><h2>{event.name}</h2><Badge tone="warning">{en.hardware}</Badge></div>
    {error ? <><p role="alert">Unable to load the latest revision.</p>
      <Button onClick={() => { setError(false); setAttempt((count) => count + 1) }}>Retry plan summary</Button></>
      : entry === undefined ? <Loading>Loading plan status…</Loading>
        : entry === null ? <p className="muted">No plan revisions saved.</p>
          : <dl className="plan-metrics">
            <div><dt>Latest revision</dt><dd>#{entry.number} <code>{entry.content_hash.slice(0, 10)}</code></dd></div>
            <div><dt>Planning status</dt><dd><Validity status={entry.validation_status} /></dd></div>
            <div><dt>Validation</dt><dd>{entry.validation_errors.length} errors · {entry.warnings.length} warnings</dd></div>
            <div><dt>Planned assignments</dt><dd>{records(entry.plan, 'assignments').length}</dd></div>
            <div><dt>Unverified</dt><dd>{pending} chassis · {portsPending} ports</dd></div>
          </dl>}
  </section>
}
