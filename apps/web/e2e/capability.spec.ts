import { randomUUID } from 'node:crypto'
import { expect, test } from '@playwright/test'
import type { APIRequestContext, Page } from '@playwright/test'
import type { Plan, Revision } from '../src/planner/model'

const api = '/api/v1/events'
const headers = { Origin: 'http://127.0.0.1:8765' }
const revisions = (id: string) => api + '/' + id + '/plan-revisions'

async function createEvent(request: APIRequestContext, name: string) {
  const response = await request.post(api, { headers, data: { name, management_vlan: 10 } })
  expect(response.status()).toBe(201)
  return (await response.json() as { id: string }).id
}

async function planRecord(request: APIRequestContext, data: Plan) {
  const response = await request.post(revisions(data.event_id), { headers, data })
  expect(response.status(), await response.text()).toBe(200)
  return await response.json() as Revision
}

async function openWorkspace(page: Page, id: string, route = 'ports') {
  await page.goto('/?e2e-event=' + encodeURIComponent(id) + '#' + route)
  const context = page.getByLabel('Event', { exact: true })
  await expect(context).toBeVisible()
  await context.selectOption(id)
  await expect(page.getByRole('button', { name: 'Revision history' })).toBeEnabled()
}

function capabilityPlan(
  eventId: string,
  options: { image?: string; pidA?: string; pidB?: string } = {},
): Plan {
  const { image = '17.12.4', pidA = 'C9300L-24P-4X', pidB = 'C9300L-24T-4G' } = options
  const deviceA = randomUUID()
  const deviceB = randomUUID()
  const assignmentA = randomUUID()
  const assignmentB = randomUUID()
  return {
    schema_version: 1, event_id: eventId, management_vlan: 10,
    vlans: [{ id: 10, name: 'Management', purpose: 'management' }, { id: 20, name: 'Players' }],
    physical_devices: [
      { id: deviceA, vendor: 'cisco', model: pidA, verified_serial: 'SYN-CAP-A-' + deviceA.slice(0, 8) },
      { id: deviceB, vendor: 'cisco', model: pidB, verified_serial: 'SYN-CAP-B-' + deviceB.slice(0, 8) },
    ],
    assignments: [
      { id: assignmentA, hostname: 'Cap-Access-A', role: 'access', family: 'catalyst-9300',
        physical_device_id: deviceA, software: { image, license: 'Network Advantage' } },
      { id: assignmentB, hostname: 'Cap-Access-B', role: 'access', family: 'catalyst-9300',
        physical_device_id: deviceB, software: { image, license: 'Network Advantage' } },
    ],
    physical_interfaces: [
      { id: randomUUID(), assignment_id: assignmentA, physical_device_id: deviceA,
        name: 'Gi1/0/1', settings: { mode: 'access', access_vlan: 20 } },
      { id: randomUUID(), assignment_id: assignmentB, physical_device_id: deviceB,
        name: 'Gi1/0/2', settings: { mode: 'access', access_vlan: 20 } },
    ],
  }
}

function fakePreview(speed: number | string | null, verdict: string, reason: string) {
  const labels: Record<string, string> = {
    supported: 'speed-documented', unsupported: 'speed-outside-port-range', unknown: 'speed-required',
  }
  return {
    source: 'unsaved-draft',
    draft_fingerprint: 'd'.repeat(64),
    input_fingerprint: 'i'.repeat(64),
    decisions: [{
      capability_id: 'speed', verdict, reason_code: labels[verdict] ?? reason,
      reason: 'Deterministic test evidence.', evidence: [], affected: {
        event_id: 'event', assignment_id: 'assignment', physical_device_id: null,
        interface_id: 'interface', interface_name: 'Gi1/0/1', stack_member: null,
        sku: 'C9300L-24P-4X', software: '17.12.4', license: 'Network Advantage',
      },
      port_groups: [], verification: 'not-verified', deployment_status: 'blocked',
      blocks_deployment: true,
      deployment_blockers: ['deployment-generation-disabled', 'hardware-not-verified',
        'draft-not-persisted'],
    }],
    requested_speed: speed,
  }
}

test('previews documented capability and flags stale draft evidence', async ({ page, request }, info) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic capability preview')
  const saved = await planRecord(request, capabilityPlan(id))
  const exportUrl = revisions(id) + '/' + saved.id + '/export'
  const historical = await request.get(exportUrl)
  const historicalBody = await historical.body()
  await openWorkspace(page, id)
  await page.getByRole('button', { name: 'Edit port Gi1/0/1', exact: true }).click()
  const modal = page.getByRole('dialog', { name: 'Edit port', exact: true })
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel).toBeVisible()
  await expect(panel.getByText('SUPPORTED', { exact: true }).first()).toBeVisible()
  await expect(panel.getByText('NOT VERIFIED', { exact: true }).first()).toBeVisible()
  await expect(panel.getByText('Deployment blocked')).toBeVisible()

  await page.route('**/api/v1/events/*/plan/capability-preview', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 700))
    await route.continue()
  })
  await modal.getByLabel('Speed (Mbps)', { exact: true }).selectOption('1000')
  await expect(modal.getByText('Stale', { exact: true }).first()).toBeVisible()
  await expect(modal.getByText('Stale', { exact: true })).toHaveCount(0)
  await expect(panel.getByText('SUPPORTED', { exact: true }).first()).toBeVisible()
  await page.unroute('**/api/v1/events/*/plan/capability-preview')

  for (const width of [320, 800, 1280, 1440, 1920]) {
    await page.setViewportSize({ width, height: 1000 })
    await expect(modal).toBeVisible()
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width + 1)
    expect(await modal.evaluate((node) => node.scrollWidth - node.clientWidth)).toBeLessThanOrEqual(1)
    await modal.evaluate((node) => node.scrollTo(0, 0))
    await page.screenshot({ path: info.outputPath('capability-' + width + '.png') })
  }

  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const review = modal.getByRole('table', { name: 'Capability evidence by target' })
  await expect(review.getByRole('columnheader', { name: 'Intended setting', exact: true })).toBeVisible()
  await expect(review.getByRole('columnheader', { name: 'Verdict', exact: true })).toBeVisible()
  await expect(review.getByRole('columnheader', { name: 'Verification', exact: true })).toBeVisible()
  await expect(review.getByText('NOT VERIFIED', { exact: true }).first()).toBeVisible()
  await modal.getByRole('button', { name: 'Back to edit', exact: true }).click()

  const after = await request.get(exportUrl)
  expect(await after.body()).toEqual(historicalBody)
  expect(after.headers().etag).toBe(historical.headers().etag)
  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)
})

test('renders ROMMON software capability as UNKNOWN while hardware stays documented', async ({ page, request }) => {
  test.setTimeout(60_000)
  const id = await createEvent(request, 'Synthetic ROMMON capability')
  const saved = await planRecord(request, capabilityPlan(id, { image: '17.12.2r' }))
  expect(saved.content_hash).toHaveLength(64)
  await openWorkspace(page, id)
  await page.getByRole('button', { name: 'Edit port Gi1/0/1', exact: true }).click()
  const modal = page.getByRole('dialog', { name: 'Edit port', exact: true })
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel.getByText(/ROMMON/i).first()).toBeVisible()
  await expect(panel.getByText('SUPPORTED', { exact: true }).first()).toBeVisible()
  await expect(panel.getByText('UNKNOWN', { exact: true }).first()).toBeVisible()
  await expect(panel.getByText('NOT VERIFIED', { exact: true }).first()).toBeVisible()
})

test('evaluates mixed batch targets per interface and ignores an older response', async ({ page, request }, info) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic capability batch')
  await planRecord(request, capabilityPlan(id))
  await openWorkspace(page, id)
  await page.getByLabel('Select port Gi1/0/1', { exact: true }).check()
  await page.getByLabel('Select port Gi1/0/2', { exact: true }).check()
  await page.getByRole('button', { name: 'Batch edit (2)', exact: true }).click()
  const modal = page.getByRole('dialog', { name: 'Batch edit 2 ports', exact: true })
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel.locator('.capability-target')).toHaveCount(2)
  await expect(panel.getByText('SUPPORTED', { exact: true }).first()).toBeVisible()
  await expect(panel.getByText('UNSUPPORTED', { exact: true }).first()).toBeVisible()
  await panel.scrollIntoViewIfNeeded()
  await page.screenshot({ path: info.outputPath('capability-batch-mixed.png') })

  await page.route('**/api/v1/events/*/plan/capability-preview', async (route) => {
    const body = route.request().postDataJSON() as {
      plan: Plan; interface_id: string
    }
    const port = (body.plan.physical_interfaces as Record<string, unknown>[]).find(
      (item) => item.id === body.interface_id,
    )
    const settings = port?.settings as Record<string, unknown> | undefined
    const speed = settings?.speed
    if (speed === 1000) await new Promise((resolve) => setTimeout(resolve, 900))
    const verdict = speed === 2500 ? 'unsupported' : speed === 1000 ? 'supported' : 'unknown'
    await route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify(fakePreview(speed as number | string | null, verdict, 'test')),
    })
  })
  const speed = modal.getByLabel('Speed (Mbps)', { exact: true })
  await speed.selectOption('1000')
  await page.waitForTimeout(260)
  await speed.selectOption('2500')
  await page.waitForTimeout(1_200)
  await expect(panel.getByText('UNSUPPORTED', { exact: true })).toHaveCount(2)
  await expect(panel.getByText('SUPPORTED', { exact: true })).toHaveCount(0)
})

test('does not reuse a successful result when the capability service fails', async ({ page, request }) => {
  test.setTimeout(60_000)
  const id = await createEvent(request, 'Synthetic capability failure')
  await planRecord(request, capabilityPlan(id))
  await openWorkspace(page, id)
  await page.getByRole('button', { name: 'Edit port Gi1/0/1', exact: true }).click()
  const modal = page.getByRole('dialog', { name: 'Edit port', exact: true })
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel.getByText('SUPPORTED', { exact: true }).first()).toBeVisible()
  await page.route('**/api/v1/events/*/plan/capability-preview', (route) => route.abort())
  await modal.getByLabel('Speed (Mbps)', { exact: true }).selectOption('1000')
  await expect(panel.getByText('Capability evidence is unavailable for this draft or service. This target is UNKNOWN; no previous result is reused.')).toBeVisible()
  await expect(panel.getByText('UNKNOWN', { exact: true }).first()).toBeVisible()
  await expect(panel.getByText('SUPPORTED', { exact: true })).toHaveCount(0)
})

test('switches locale without changing the draft capability query', async ({ page, request }) => {
  test.setTimeout(60_000)
  const id = await createEvent(request, 'Synthetic capability locale')
  await planRecord(request, capabilityPlan(id))
  const requests: string[] = []
  page.on('request', (request_) => {
    if (request_.url().includes('/plan/capability-preview')) requests.push(request_.postData() ?? '')
  })
  await openWorkspace(page, id)
  await page.getByRole('button', { name: 'Edit port Gi1/0/1', exact: true }).click()
  const modal = page.getByRole('dialog', { name: 'Edit port', exact: true })
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel.getByText('SUPPORTED', { exact: true }).first()).toBeVisible()
  const before = requests.length
  const last = requests.at(-1)
  await modal.locator('.dialog-locale select').selectOption('zh-CN')
  const localized = page.locator('dialog[open]')
  await expect(localized.getByText('Cisco 能力证据')).toBeVisible()
  await expect(localized.getByText('能力摘要')).toBeVisible()
  await page.waitForTimeout(400)
  expect(requests.length).toBe(before)
  expect(requests.at(-1)).toBe(last)
  await localized.locator('.dialog-locale select').selectOption('en-US')
  await expect(localized.getByText('Cisco capability evidence')).toBeVisible()
})
