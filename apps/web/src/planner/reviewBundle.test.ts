import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  fetchReviewBundle,
  filenameFromDisposition,
  reviewBundleFilename,
  reviewBundleUrl,
  safeFilenamePart,
} from './reviewBundle'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('Cisco review bundle download', () => {
  it('builds a sanitized event/device/revision filename', () => {
    const name = reviewBundleFilename(
      'Finals / 2026', 'L3 Core #1', 7, 'event-1234',
    )
    expect(name).toBe('cisco-config-review-Finals-2026-L3-Core-1-r7.json')
    expect(name).not.toMatch(/[\\/:*?"<>| ]/)
    expect(name.endsWith('.json')).toBe(true)
    expect(safeFilenamePart('中文事件', 'event-fallback')).toBe('event-fallback')
  })

  it('extracts only the basename from Content-Disposition', () => {
    expect(filenameFromDisposition(
      'attachment; filename="cisco-config-review-A-B-r2.json"',
    )).toBe('cisco-config-review-A-B-r2.json')
    expect(filenameFromDisposition(
      'attachment; filename="../../unsafe.json"',
    )).toBe('unsafe.json')
    expect(filenameFromDisposition(null)).toBeNull()
  })

  it('binds the download URL to the exact event/revision/assignment', () => {
    expect(reviewBundleUrl('event a', 'rev/b', 'assignment c')).toBe(
      '/api/v1/events/event%20a/plan-revisions/rev%2Fb/assignments/assignment%20c/cisco-review-bundle',
    )
  })

  it('uses server content digest and filename when downloading', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{"ok":true}', {
      status: 200,
      headers: {
        'Content-Disposition': 'attachment; filename="server-review.json"',
        'X-Cisco-Review-Bundle-Content-Digest': 'a'.repeat(64),
      },
    }))
    vi.stubGlobal('fetch', fetchMock)
    const value = await fetchReviewBundle('event', 'revision', 'assignment')
    expect(value.filename).toBe('server-review.json')
    expect(value.contentDigest).toBe('a'.repeat(64))
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/events/event/plan-revisions/revision/assignments/assignment/cisco-review-bundle',
      expect.objectContaining({ headers: { Accept: 'application/json' } }),
    )
  })

  it('rejects a non-success response instead of downloading it', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ detail: { reason_code: 'review-bundle-integrity' } }),
      { status: 409, headers: { 'Content-Type': 'application/json' } },
    )))
    await expect(fetchReviewBundle('event', 'revision', 'assignment'))
      .rejects.toMatchObject({ status: 409 })
  })
})
