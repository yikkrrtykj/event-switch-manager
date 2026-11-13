export interface Health {
  status: 'ok'
  database: 'ready'
  device_writes_enabled: boolean
}

export interface EventRecord {
  id: string
  name: string
  management_vlan: number
}

export type EventInput = Omit<EventRecord, 'id'>

export interface DeviceRecord {
  id: string
  event_id: string
  hostname: string
  family: string
  role: 'core' | 'access' | 'external-distribution'
  model: string | null
  location: string | null
  management_ip: string | null
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch('/api/v1' + path, options)
  if (!response.ok) {
    throw new Error('Request failed (HTTP ' + response.status + ').')
  }
  return (await response.json()) as T
}

export const getHealth = () => request<Health>('/health')
export const getEvents = () => request<EventRecord[]>('/events')
export const getDevices = (eventId: string) =>
  request<DeviceRecord[]>('/events/' + encodeURIComponent(eventId) + '/devices')

export const createEvent = (input: EventInput) =>
  request<EventRecord>('/events', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  })
