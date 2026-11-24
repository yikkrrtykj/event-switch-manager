import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  canDownloadReviewBundle,
  fetchReviewBundle,
  filenameFromDisposition,
  isReviewBundleAssignment,
  reviewBundleFilename,
  reviewBundleUrl,
  safeFilenamePart,
} from './reviewBundle'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('Cisco review bundle eligibility', () => {
  const ready = {
    hasRevision: true,
    ready: true,
    loading: false,
    previewBroken: false,
  }

  it('allows only Core Catalyst 9300/9200 assignments', () => {
    expect(isReviewBundleAssignment({ isCore: true, family: 'catalyst-9300' })).toBe(true)
    expect(isReviewBundleAssignment({ isCore: true, family: 'catalyst-9200' })).toBe(true)
    expect(isReviewBundleAssignment({ isCore: true, family: 'catalyst-3850' })).toBe(false)
    expect(isReviewBundleAssignment({ isCore: true, family: 'catalyst-2960x' })).toBe(false)
    expect(isReviewBundleAssignment({ isCore: true, family: 'catalyst-c1000' })).toBe(false)
    expect(isReviewBundleAssignment({ isCore: false, family: 'catalyst-9300' })).toBe(false)
    expect(isReviewBundleAssignment(undefined)).toBe(false)
  })

  it('requires a saved revision, ready previews and no integrity failure', () => {
    const assignment = { isCore: true, family: 'catalyst-9300' }
    expect(canDownloadReviewBundle(assignment, ready)).toBe(true)
    expect(canDownloadReviewBundle(assignment, { ...ready, hasRevision: false })).toBe(false)
    expect(canDownloadReviewBundle(assignment, { ...ready, ready: false })).toBe(false)
    expect(canDownloadReviewBundle(assignment, { ...ready, loading: true })).toBe(false)
    expect(canDownloadReviewBundle(assignment, { ...ready, previewBroken: true })).toBe(false)
    expect(canDownloadReviewBundle(
      { isCore: true, family: 'catalyst-3850' }, ready,
    )).toBe(false)
    expect(canDownloadReviewBundle(
      { isCore: false, family: 'catalyst-9300' }, ready,
    )).toBe(false)
  })
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
