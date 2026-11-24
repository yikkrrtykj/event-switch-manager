import { ApiError } from '../api'

export const REVIEW_BUNDLE_CONTRACT = 'cis-04b-cisco-config-review-bundle-v1'
export const REVIEW_BUNDLE_PATH = '/cisco-review-bundle'

export interface ReviewBundleDownload {
  blob: Blob
  filename: string
  contentDigest: string
}

const UNSAFE_FILENAME = /[^A-Za-z0-9._-]+/g

export function safeFilenamePart(value: string, fallback: string): string {
  const cleaned = value.replace(UNSAFE_FILENAME, '-').replace(/^[-._]+|[-._]+$/g, '')
  return cleaned.slice(0, 64) || fallback
}

export function reviewBundleFilename(
  eventName: string, hostname: string, revisionNumber: number, eventId: string,
): string {
  const event = safeFilenamePart(eventName, 'event-' + eventId.slice(0, 8))
  const device = safeFilenamePart(hostname, 'device')
  return 'cisco-config-review-' + event + '-' + device + '-r' + revisionNumber + '.json'
}

export function filenameFromDisposition(value: string | null): string | null {
  if (!value) return null
  const match = /filename\s*=\s*"([^"]+)"|filename\s*=\s*([^;]+)/i.exec(value)
  const candidate = match?.[1] ?? match?.[2]?.trim()
  if (!candidate) return null
  const basename = candidate.split(/[\\/]/).at(-1)?.trim() || ''
  return safeFilenamePart(basename, 'cisco-config-review-report.json')
}

export function reviewBundleUrl(
  eventId: string, revisionId: string, assignmentId: string,
): string {
  return (
    '/api/v1/events/' + encodeURIComponent(eventId) +
    '/plan-revisions/' + encodeURIComponent(revisionId) +
    '/assignments/' + encodeURIComponent(assignmentId) + REVIEW_BUNDLE_PATH
  )
}

export async function fetchReviewBundle(
  eventId: string, revisionId: string, assignmentId: string,
  signal?: AbortSignal, fallbackFilename = 'cisco-config-review-report.json',
): Promise<ReviewBundleDownload> {
  const response = await fetch(reviewBundleUrl(eventId, revisionId, assignmentId), {
    signal,
    headers: { Accept: 'application/json' },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { detail?: unknown } | null
    throw new ApiError(response.status, body?.detail)
  }
  const blob = await response.blob()
  const disposition = response.headers.get('content-disposition')
  const filename = filenameFromDisposition(disposition) ?? fallbackFilename
  return {
    blob,
    filename,
    contentDigest: response.headers.get('x-cisco-review-bundle-content-digest') ?? '',
  }
}

export function downloadReviewBundle(value: ReviewBundleDownload): void {
  const url = URL.createObjectURL(value.blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = value.filename
  anchor.rel = 'noopener'
  document.body.append(anchor)
  anchor.click()
  anchor.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
