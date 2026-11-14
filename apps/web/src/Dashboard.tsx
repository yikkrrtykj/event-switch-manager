import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'

import { createEvent, getDevices, getEvents, getHealth } from './api'
import type { DeviceRecord, EventRecord, Health } from './api'

const roles = {
  core: 'Core',
  access: 'Access',
  'external-distribution': 'External / Distribution',
}

export function Dashboard() {
  const [health, setHealth] = useState<Health | null>(null)
  const [healthUnavailable, setHealthUnavailable] = useState(false)
  const [events, setEvents] = useState<EventRecord[] | null>(null)
  const [eventError, setEventError] = useState('')
  const [selectedId, setSelectedId] = useState('')
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
    void getEvents().then(
      (records) => {
        if (!active) return
        setEvents(records)
        setSelectedId((current) => current || records[0]?.id || '')
      },
      () => { if (active) setEventError('Unable to load events. Refresh to retry.') },
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
    <>
      <header className="masthead">
        <div className="shell masthead-inner">
          <span className="brand">Event Switch Manager</span>
          <span className="local-label">Local workspace</span>
        </div>
      </header>
      <main className="shell">
        <h1>Dashboard</h1>
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

        <div className="workspace grid gap-5 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
          <section className="panel" aria-labelledby="events-title">
            <h2 id="events-title">Events</h2>
            {eventError && <p role="alert">{eventError}</p>}
            {!eventError && events === null && <p role="status">Loading events…</p>}
            {events?.length === 0 && <p>No events yet. Create one to start planning.</p>}
            {events && events.length > 0 && (
              <div className="event-picker">
                <label htmlFor="current-event">Selected event</label>
                <select id="current-event" value={selectedId} onChange={(e) => setSelectedId(e.target.value)}>
                  {events.map((event) => <option key={event.id} value={event.id}>{event.name}</option>)}
                </select>
              </div>
            )}
            {selected && (
              <>
                <h3>Device inventory</h3>
                <p>Management VLAN <strong>{selected.management_vlan}</strong></p>
                {devices === null && <p role="alert">Unable to load devices.</p>}
                {devices === undefined && <p role="status">Loading devices…</p>}
                {devices?.length === 0 && <p>No devices recorded for this event.</p>}
                {devices && devices.length > 0 && (
                  <div className="overflow-x-auto">
                    <table>
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
                    </table>
                  </div>
                )}
              </>
            )}
          </section>

          <section className="panel" aria-labelledby="new-event-title">
            <h2 id="new-event-title">Create event</h2>
            <form onSubmit={submitEvent}>
              <label htmlFor="event-name">Event name</label>
              <input id="event-name" name="name" required maxLength={120} />
              <label htmlFor="management-vlan">Management VLAN</label>
              <input id="management-vlan" name="management_vlan" type="number" required min={1} max={4094} defaultValue={10} />
              {saveError && <p role="alert">{saveError}</p>}
              <button type="submit" disabled={saving || events === null}>{saving ? 'Creating…' : 'Create event'}</button>
            </form>
          </section>
        </div>
      </main>
    </>
  )
}
