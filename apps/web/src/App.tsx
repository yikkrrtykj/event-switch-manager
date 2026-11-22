import { useEffect, useRef, useState } from 'react'
import { getEvents } from './api'
import type { EventRecord } from './api'
import { Button, Loading, Select } from './components/ui'
import { Dashboard } from './Dashboard'
import type { MessageKey } from './messages'
import { LanguageSelect, useMessages } from './locale'
import { sections } from './planner/catalog'
import { L3ReviewWorkspace } from './planner/L3ReviewWorkspace'
import { Workspace } from './planner/Workspace'

const destinations = [
  ['dashboard', 'dashboard'], ['events', 'events'], ['planner/addressing', 'planner'],
  ['devices', 'devices'], ['ports', 'ports'], ['l3-review', 'l3Review'],
] as const
const workspace = (route: string) => route.startsWith('planner/') || route === 'devices' || route === 'ports'
const eventContext = (route: string) => workspace(route) || route === 'l3-review'
function hashRoute() {
  const route = window.location.hash.slice(1)
  if (route === 'planner') return 'planner/addressing'
  if (route === 'l3-review') return route
  if (route.startsWith('planner/') && Object.hasOwn(sections, route.slice(8)) && !['topology', 'ports'].includes(route.slice(8))) return route
  return destinations.some(([key]) => key === route) ? route : 'dashboard'
}
function href(route: string) { return route === 'dashboard' ? '#' : '#' + route }

export function App() {
  const { t } = useMessages()
  const [route, setRoute] = useState(hashRoute)
  const [events, setEvents] = useState<EventRecord[] | null>(null)
  const [selectedId, setSelectedId] = useState('')
  const [error, setError] = useState<MessageKey | ''>('')
  const [attempt, setAttempt] = useState(0)
  const dirty = useRef(false)
  const formDirty = useRef(false)
  const current = useRef(route)
  const mark = useRef((value: boolean, form = false) => {
    dirty.current = value
    formDirty.current = form
  })
  const selected = events?.find((event) => event.id === selectedId)
  const inWorkspace = workspace(route)
  const inEventContext = eventContext(route)
  const section = route === 'devices' ? 'topology' : route === 'ports' ? 'ports' : route.slice(8)

  useEffect(() => {
    let active = true
    void getEvents().then((items) => {
      if (!active) return
      setEvents(items)
      setSelectedId((id) => items.some((event) => event.id === id) ? id : items[0]?.id ?? '')
    }, () => { if (active) setError('loadEventsError') })
    return () => { active = false }
  }, [attempt])
  useEffect(() => {
    function back() {
      const next = hashRoute()
      if (next !== current.current && dirty.current && workspace(current.current) &&
        (!workspace(next) || formDirty.current) && !window.confirm(t('discardPlan'))) {
        window.history.pushState(null, '', href(current.current))
        return
      }
      if (!workspace(next)) mark.current(false)
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
  }, [t])

  function navigate(next: string) {
    if (route === next) return
    if (dirty.current && inWorkspace && (!workspace(next) || formDirty.current) && !window.confirm(t('discardPlan'))) return
    if (!workspace(next)) mark.current(false)
    current.current = next
    window.history.pushState(null, '', href(next))
    setRoute(next)
    if ((route === 'dashboard' || route === 'events') || !workspace(next)) {
      window.scrollTo({ top: 0 })
      requestAnimationFrame(() => document.getElementById('main')?.focus())
    }
  }

  function select(id: string) {
    if (id === selectedId || (inWorkspace && dirty.current && !window.confirm(t('discardPlan')))) return
    mark.current(false)
    setSelectedId(id)
  }

  function retryEvents() { setError(''); setAttempt((value) => value + 1) }
  return <>
    <a className="skip-link" href="#main" onClick={(event) => {
      event.preventDefault()
      const main = document.getElementById('main')
      main?.setAttribute('tabindex', '-1')
      main?.focus()
    }}>{t('skipToContent')}</a>
    <header className="masthead">
      <div className="shell masthead-inner">
        <a className="brand" href="#" onClick={(event) => { event.preventDefault(); navigate('dashboard') }}><span className="brand-mark" aria-hidden="true" />{t('brand')}</a>
        <nav className="primary-nav" aria-label={t('workspace')}>
          {destinations.map(([key, label]) => <a key={key} href={href(key)}
            aria-current={route === key || key.startsWith('planner/') && route.startsWith('planner/') ? 'page' : undefined}
            onClick={(event) => { event.preventDefault(); navigate(key) }}>{t(label)}</a>)}
        </nav>
        {inEventContext && events && events.length > 0 ? <div className="event-context">
          <label htmlFor="workspace-event">{t('event')}</label>
          <Select id="workspace-event" value={selectedId} onChange={(event) => select(event.target.value)}>
            {events.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}
          </Select>
        </div> : <span className="local-label">{t('localWorkspace')}</span>}
        <LanguageSelect />
      </div>
    </header>
    {inWorkspace ? selected
      ? <Workspace key={selected.id} event={selected} section={section} onDirty={mark.current} navigate={navigate} />
      : <main id="main" className="shell screen"><h1>{route === 'ports' ? t('ports') : route === 'devices' ? t('devices') : t('planner')}</h1>
        <div className="panel">{error
          ? <><p role="alert">{t(error)}</p><Button onClick={retryEvents}>{t('retryEvents')}</Button></>
          : events ? <><p className="empty">{t('selectEventPrompt')}</p><Button primary onClick={() => navigate('events')}>{t('goToEvents')}</Button></>
            : <Loading>{t('loadingEvents')}</Loading>}</div></main>
      : route === 'l3-review' ? selected
        ? <L3ReviewWorkspace key={selected.id} event={selected} navigate={navigate} />
        : <main id="main" className="shell screen"><h1>{t('l3Review')}</h1><div className="panel">
          {error ? <><p role="alert">{t(error)}</p><Button onClick={retryEvents}>{t('retryEvents')}</Button></>
            : events ? <><p className="empty">{t('selectEventPrompt')}</p><Button primary onClick={() => navigate('events')}>{t('goToEvents')}</Button></>
              : <Loading>{t('loadingEvents')}</Loading>}</div></main>
        : <Dashboard events={events} setEvents={setEvents} eventError={error} selectedId={selectedId} setSelectedId={select}
          eventsOnly={route === 'events'} retryEvents={retryEvents} navigate={navigate} />}
  </>
}
