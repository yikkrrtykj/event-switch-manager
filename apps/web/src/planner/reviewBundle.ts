import { ApiError } from '../api'

export const REVIEW_BUNDLE_CONTRACT = 'cis-04b-cisco-config-review-bundle-v1'
export const REVIEW_BUNDLE_PATH = '/cisco-review-bundle'

export interface ReviewBundleAssignment {
  isCore: boolean
  family: string
}

export interface ReviewBundleUiState {
  hasRevision: boolean
  ready: boolean
  loading: boolean
  previewBroken: boolean
}

export function isReviewBundleAssignment(
  assignment: ReviewBundleAssignment | undefined,
): boolean {
  return Boolean(
    assignment?.isCore &&
    (assignment.family === 'catalyst-9300' ||
      assignment.family === 'catalyst-9200'),
  )
}

export function canDownloadReviewBundle(
  assignment: ReviewBundleAssignment | undefined,
  state: ReviewBundleUiState,
): boolean {
  return Boolean(
    state.hasRevision && state.ready && !state.loading &&
    !state.previewBroken && isReviewBundleAssignment(assignment),
  )
}

export interface ReviewBundleDownload {
  blob: Blob
  filename: string
  contentDigest: string
}

const UNSAFE_FILENAME = /[^A-Za-z0-9._-]+/g
const UNSAFE_COMPLETE_FILENAME = /[^A-Za-z0-9._-]+/g
export const MAX_SAFE_FILENAME_LENGTH = 200
export const FALLBACK_REVIEW_FILENAME = 'cisco-config-review-report.json'

export function safeFilenamePart(value: string, fallback: string): string {
  const cleaned = value.replace(UNSAFE_FILENAME, '-').replace(/^[-._]+|[-._]+$/g, '')
  return cleaned.slice(0, 64) || fallback
}

/** Sanitize a complete server filename without truncating its revision/extension. */
export function safeCompleteFilename(value: string): string | null {
  const basename = value.split(/[\\/]/).at(-1)?.trim() ?? ''
  if (!basename) return null
  const cleaned = basename
    .replace(UNSAFE_COMPLETE_FILENAME, '-')
    .replace(/^[-._]+|[-._]+$/g, '')
  if (
    !cleaned ||
    cleaned.length > MAX_SAFE_FILENAME_LENGTH ||
    !/\.json$/i.test(cleaned)
  ) {
    return null
  }
  return cleaned
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
  return safeCompleteFilename(candidate)
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
  const safeFallback = safeCompleteFilename(fallbackFilename) ??
    FALLBACK_REVIEW_FILENAME
  const filename = filenameFromDisposition(disposition) ?? safeFallback
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
