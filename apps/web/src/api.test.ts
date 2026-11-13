import { afterEach, describe, expect, it, vi } from 'vitest'

import { createEvent, getDevices, getHealth } from './api'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('planning API client', () => {
  it('loads health from the local API', async () => {
    const health = { status: 'ok', database: 'ready', device_writes_enabled: false }
    const fetch = vi.fn().mockResolvedValue(Response.json(health))
    vi.stubGlobal('fetch', fetch)
    await expect(getHealth()).resolves.toEqual(health)
    expect(fetch).toHaveBeenCalledWith('/api/v1/health', undefined)
  })

  it('posts the selected management VLAN', async () => {
    const event = { name: 'Finals', management_vlan: 120 }
    const fetch = vi.fn().mockResolvedValue(Response.json({ ...event, id: 'test' }))
    vi.stubGlobal('fetch', fetch)
    await expect(createEvent(event)).resolves.toMatchObject(event)
    expect(fetch).toHaveBeenCalledWith('/api/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event),
    })
  })

  it('surfaces HTTP errors and scopes inventory to the selected event', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(null, { status: 404 }))
    vi.stubGlobal('fetch', fetch)
    await expect(getDevices('missing')).rejects.toThrow('404')
    expect(fetch).toHaveBeenCalledWith('/api/v1/events/missing/devices', undefined)
  })
})
