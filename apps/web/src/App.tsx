import { useEffect, useRef, useState } from 'react'
import { getEvents } from './api'
import type { EventRecord } from './api'
import { Button, Loading, Select } from './components/ui'
import { Dashboard } from './Dashboard'
import { en } from './messages'
import { sections } from './planner/catalog'
import { Workspace } from './planner/Workspace'

const destinations = [
  ['dashboard', en.dashboard], ['events', en.events], ['planner/addressing', en.planner],
  ['devices', en.devices], ['ports', en.ports],
] as const
const workspace = (route: string) => route.startsWith('planner/') || route === 'devices' || route === 'ports'
function hashRoute() {
  const route = window.location.hash.slice(1)
  if (route === 'planner') return 'planner/addressing'
  if (route.startsWith('planner/') && Object.hasOwn(sections, route.slice(8)) && !['topology', 'ports'].includes(route.slice(8))) return route
  return destinations.some(([key]) => key === route) ? route : 'dashboard'
}
function href(route: string) { return route === 'dashboard' ? '#' : '#' + route }

export function App() {
  const [route, setRoute] = useState(hashRoute)
  const [events, setEvents] = useState<EventRecord[] | null>(null)
  const [selectedId, setSelectedId] = useState('')
  const [error, setError] = useState('')
  const [attempt, setAttempt] = useState(0)
  const dirty = useRef(false)
  const current = useRef(route)
  const mark = useRef((value: boolean) => { dirty.current = value })
  const selected = events?.find((event) => event.id === selectedId)
  const inWorkspace = workspace(route)
  const section = route === 'devices' ? 'topology' : route === 'ports' ? 'ports' : route.slice(8)

  useEffect(() => {
    let active = true
    void getEvents().then((items) => {
      if (!active) return
      setEvents(items)
      setSelectedId((id) => items.some((event) => event.id === id) ? id : items[0]?.id ?? '')
    }, () => { if (active) setError('Unable to load events. Retry to reconnect to the local API.') })
    return () => { active = false }
  }, [attempt])
  useEffect(() => {
    function back() {
      const next = hashRoute()
      if (dirty.current && workspace(current.current) && !workspace(next) && !window.confirm(en.discard)) {
        window.history.pushState(null, '', href(current.current))
        return
      }
      if (!workspace(next)) dirty.current = false
      current.current = next
      setRoute(next)
    }
    function leaving(event: BeforeUnloadEvent) {
      if (dirty.current) { event.preventDefault(); event.returnValue = true }
    }
    window.addEventListener('hashchange', back)
    window.addEventListener('beforeunload', leaving)
    return () => {
      window.removeEventListener('hashchange', back)
      window.removeEventListener('beforeunload', leaving)
    }
  }, [])

  function navigate(next: string) {
    if (route === next) return
    if (dirty.current && inWorkspace && !workspace(next) && !window.confirm(en.discard)) return
    if (!workspace(next)) dirty.current = false
    current.current = next
    window.history.pushState(null, '', href(next))
    setRoute(next)
    if ((route === 'dashboard' || route === 'events') || !workspace(next)) {
      window.scrollTo({ top: 0 })
      requestAnimationFrame(() => document.getElementById('main')?.focus())
    }
  }

  function select(id: string) {
    if (id === selectedId || (inWorkspace && dirty.current && !window.confirm(en.discard))) return
    dirty.current = false
    setSelectedId(id)
  }

  function retryEvents() { setError(''); setAttempt((value) => value + 1) }
  return <>
    <a className="skip-link" href="#main" onClick={(event) => {
      event.preventDefault()
      const main = document.getElementById('main')
      main?.setAttribute('tabindex', '-1')
      main?.focus()
    }}>Skip to content</a>
    <header className="masthead">
      <div className="shell masthead-inner">
        <a className="brand" href="#" onClick={(event) => { event.preventDefault(); navigate('dashboard') }}><span className="brand-mark" aria-hidden="true" />{en.brand}</a>
        <nav className="primary-nav" aria-label="Workspace">
          {destinations.map(([key, label]) => <a key={key} href={href(key)}
            aria-current={route === key || key.startsWith('planner/') && route.startsWith('planner/') ? 'page' : undefined}
            onClick={(event) => { event.preventDefault(); navigate(key) }}>{label}</a>)}
        </nav>
        {inWorkspace && events && events.length > 0 ? <div className="event-context">
          <label htmlFor="workspace-event">Event</label>
          <Select id="workspace-event" value={selectedId} onChange={(event) => select(event.target.value)}>
            {events.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}
          </Select>
        </div> : <span className="local-label">Local workspace</span>}
      </div>
    </header>
    {inWorkspace ? selected
      ? <Workspace key={selected.id} event={selected} section={section} onDirty={mark.current} navigate={navigate} />
      : <main id="main" className="shell screen"><h1>{route === 'ports' ? en.ports : route === 'devices' ? en.devices : en.planner}</h1>
        <div className="panel">{error
          ? <><p role="alert">{error}</p><Button onClick={retryEvents}>Retry events</Button></>
          : events ? <><p className="empty">{en.select}</p><Button primary onClick={() => navigate('events')}>Go to Events</Button></>
            : <Loading>Loading events…</Loading>}</div></main>
      : <Dashboard events={events} setEvents={setEvents} eventError={error} selectedId={selectedId} setSelectedId={select}
        eventsOnly={route === 'events'} retryEvents={retryEvents} navigate={navigate} />}
  </>
}
