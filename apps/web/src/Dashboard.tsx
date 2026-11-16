import { useEffect, useState } from 'react'
import type { Dispatch, FormEvent, SetStateAction } from 'react'

import { createEvent, getDevices, getHealth } from './api'
import type { DeviceRecord, EventRecord, Health } from './api'
import { Badge, Button, Input, Loading, Select, Table } from './components/ui'
import { validationCounts } from './messages'
import type { MessageKey } from './messages'
import { useMessages } from './locale'
import { list, read, records } from './planner/model'
import type { Revision } from './planner/model'
import { Validity } from './planner/Workspace'

const roles = {
  core: 'core',
  access: 'access',
  'external-distribution': 'externalDistribution',
} as const

export function Dashboard({ events, setEvents, eventError, selectedId, setSelectedId, eventsOnly, retryEvents, navigate }: {
  events: EventRecord[] | null
  setEvents: Dispatch<SetStateAction<EventRecord[] | null>>
  eventError: MessageKey | ''
  selectedId: string
  setSelectedId: (id: string) => void
  eventsOnly: boolean
  retryEvents: () => void
  navigate: (route: string) => void
}) {
  const { t } = useMessages()
  const [health, setHealth] = useState<Health | null>(null)
  const [healthUnavailable, setHealthUnavailable] = useState(false)
  const [inventory, setInventory] = useState<{
    eventId: string
    devices: DeviceRecord[] | null
  } | null>(null)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<MessageKey | ''>('')

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
      setSaveError('enterAnEventName')
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
      setSaveError('saveEventError')
    } finally {
      setSaving(false)
    }
  }

  const selected = events?.find((event) => event.id === selectedId)
  const devices = inventory?.eventId === selectedId ? inventory.devices : undefined

  return (
    <main id="main" className="shell screen">
        <div className="page-head">
          <h1>{eventsOnly ? t('events') : t('dashboard')}</h1>
          {selected && <div className="actions">
            <Button onClick={() => navigate('planner/addressing')}>{t('openNetworkPlan')}</Button>
            <Button onClick={() => navigate('devices')}>{t('managePlannedDevices')}</Button>
          </div>}
        </div>
        {!eventsOnly && <>
        <div className="status-grid grid gap-3 sm:grid-cols-3" aria-label={t('systemStatus')}>
          <div className="status-tile">
            <span>{t('localApi')}</span>
            <strong className={health ? 'ready' : ''} role="status">
              {health ? t('connected') : healthUnavailable ? t('unavailable') : t('connecting')}
            </strong>
          </div>
          <div className="status-tile">
            <span>{t('planningDatabase')}</span>
            <strong>{health ? t('ready') : healthUnavailable ? t('unavailable') : t('checking')}</strong>
          </div>
          <div className="status-tile">
            <span>{t('deviceWrites')}</span>
            <strong>{health ? health.device_writes_enabled ? t('enabled') : t('disabled') : t('unknown')}</strong>
          </div>
        </div>

        {selected && <PlanSummary key={selected.id} event={selected} />}
        </>}
        <div className="workspace grid gap-5 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
          <section className="panel" aria-labelledby="events-title">
            <h2 id="events-title">{t('events')}</h2>
            {eventError && <><p role="alert">{t(eventError)}</p><Button onClick={retryEvents}>{t('retryEvents')}</Button></>}
            {!eventError && events === null && <Loading>{t('loadingEvents')}</Loading>}
            {events?.length === 0 && <p>{t('emptyEvents')}</p>}
            {events && events.length > 0 && (
              <div className="event-picker">
                <label htmlFor="current-event">{t('selectedEvent')}</label>
                <Select id="current-event" value={selectedId} onChange={(e) => setSelectedId(e.target.value)}>
                  {events.map((event) => <option key={event.id} value={event.id}>{event.name}</option>)}
                </Select>
              </div>
            )}
            {selected && (
              <>
                <h3>{t('deviceInventory')}</h3>
                <p>{t('managementVlan')} <strong>{selected.management_vlan}</strong></p>
                {devices === null && <p role="alert">{t('unableToLoadDevices')}</p>}
                {devices === undefined && <Loading>{t('loadingDevices')}</Loading>}
                {devices?.length === 0 && <p>{t('noDevicesRecordedForThisEvent')}</p>}
                {devices && devices.length > 0 && (
                  <Table label={t('deviceInventory')}>
                      <thead><tr><th scope="col">{t('hostname')}</th><th scope="col">{t('role')}</th><th scope="col">{t('managementIp')}</th></tr></thead>
                      <tbody>
                        {devices.map((device) => (
                          <tr key={device.id}>
                            <td>{device.hostname}</td>
                            <td>{t(roles[device.role])}</td>
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
            <h2 id="new-event-title">{t('createEvent')}</h2>
            <form onSubmit={submitEvent}>
              <label htmlFor="event-name">{t('eventName')}</label>
              <Input id="event-name" name="name" required maxLength={120} />
              <label htmlFor="management-vlan">{t('managementVlan')}</label>
              <Input id="management-vlan" name="management_vlan" type="number" required min={1} max={4094} defaultValue={10} />
              {saveError && <p role="alert">{t(saveError)}</p>}
              <Button type="submit" primary disabled={saving || events === null}>{saving ? t('creating') : t('createEvent')}</Button>
            </form>
          </section>
        </div>
    </main>
  )
}

function PlanSummary({ event }: { event: EventRecord }) {
  const { t } = useMessages()
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
  return <section className="panel dashboard-plan" aria-label={t('planOverview')}>
    <div className="section-head"><h2>{event.name}</h2><Badge tone="warning">{t('hardwareNotVerified')}</Badge></div>
    {error ? <><p role="alert">{t('unableToLoadTheLatestRevision')}</p>
      <Button onClick={() => { setError(false); setAttempt((count) => count + 1) }}>{t('retryPlanSummary')}</Button></>
      : entry === undefined ? <Loading>{t('loadingPlanStatus')}</Loading>
        : entry === null ? <p className="muted">{t('noPlanRevisionsSaved')}</p>
          : <dl className="plan-metrics">
            <div><dt>{t('latestRevision')}</dt><dd>#{entry.number} <code>{entry.content_hash.slice(0, 10)}</code></dd></div>
            <div><dt>{t('planningStatus')}</dt><dd><Validity status={entry.validation_status} /></dd></div>
            <div><dt>{t('validation')}</dt><dd>{validationCounts(t, entry.validation_errors.length, entry.warnings.length)}</dd></div>
            <div><dt>{t('plannedAssignments')}</dt><dd>{records(entry.plan, 'assignments').length}</dd></div>
            <div><dt>{t('unverified')}</dt><dd>{t('unverifiedCounts', {
              chassis: t('chassisCount', { count: pending }), ports: t('portCount', { count: portsPending }),
            })}</dd></div>
          </dl>}
  </section>
}
