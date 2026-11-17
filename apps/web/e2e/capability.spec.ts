import { randomUUID } from 'node:crypto'
import { expect, test } from '@playwright/test'
import type { APIRequestContext, Page, Request } from '@playwright/test'
import type { Plan, RecordValue, Revision } from '../src/planner/model'

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
  await expect(page.getByRole('button', { name: 'Revision history' }))
    .toBeEnabled({ timeout: 20_000 })
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

function channelPlan(eventId: string, options: { mode?: 'access' | 'trunk' } = {}): Plan {
  const device = randomUUID()
  const assignment = randomUUID()
  const first = randomUUID()
  const second = randomUUID()
  const third = randomUUID()
  const aggregate = randomUUID()
  const settings: RecordValue = options.mode === 'access'
    ? { mode: 'access', access_vlan: 20 }
    : { mode: 'trunk', native_vlan: 10, allowed_vlans: [10, 20] }
  return {
    schema_version: 1, event_id: eventId, management_vlan: 10,
    vlans: [{ id: 10, name: 'Management', purpose: 'management' }, { id: 20, name: 'Players' }],
    physical_devices: [{
      id: device, vendor: 'cisco', model: 'C9300L-24P-4X',
      verified_serial: 'SYN-CH-' + device.slice(0, 8),
    }],
    assignments: [{
      id: assignment, hostname: 'Cap-Channel', role: 'access', family: 'catalyst-9300',
      physical_device_id: device,
      software: { image: '17.12.4', license: 'Network Advantage' },
    }],
    physical_interfaces: [
      { id: first, assignment_id: assignment, physical_device_id: device,
        name: 'Gi1/0/1', settings },
      { id: second, assignment_id: assignment, physical_device_id: device,
        name: 'Gi1/0/2', settings },
      { id: third, assignment_id: assignment, physical_device_id: device,
        name: 'Gi1/0/3', settings },
    ],
    logical_interfaces: [{
      id: aggregate, assignment_id: assignment, name: 'Port-channel1', kind: 'port-channel',
    }],
    port_channels: [{
      interface_id: aggregate, number: 1, member_ids: [first, second], settings,
      lacp: 'active',
    }],
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

test('port-channel preview uses the proposed channel record', async ({ page, request }) => {
  test.setTimeout(60_000)
  const id = await createEvent(request, 'Synthetic channel capability')
  const saved = await planRecord(request, channelPlan(id))
  const exportUrl = revisions(id) + '/' + saved.id + '/export'
  const historical = await request.get(exportUrl)
  const historicalBody = await historical.body()
  type PreviewBody = { plan: Plan; interface_id?: string | null }
  type PreviewResult = {
    draft_fingerprint: string
    input_fingerprint: string
    decisions: { affected: { interface_id: string | null } }[]
  }
  type PreviewExchange = { body: PreviewBody; response?: PreviewResult }
  const exchanges: PreviewExchange[] = []
  const pending = new Map<Request, PreviewExchange>()
  const channelIn = (body: PreviewBody) =>
    (body.plan.port_channels as Record<string, unknown>[])[0]!
  page.on('request', (entry) => {
    if (!entry.url().includes('/plan/capability-preview')) return
    const exchange: PreviewExchange = { body: entry.postDataJSON() as PreviewBody }
    exchanges.push(exchange)
    pending.set(entry, exchange)
  })
  page.on('response', async (response) => {
    if (!response.url().includes('/plan/capability-preview')) return
    const exchange = pending.get(response.request())
    if (!exchange) return
    exchange.response = await response.json() as PreviewResult
    pending.delete(response.request())
  })
  await page.route('**/api/v1/events/*/plan/capability-preview', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 400))
    await route.continue()
  })
  await openWorkspace(page, id)
  await page.getByRole('button', { name: 'Edit Port-Channel 1', exact: true }).click()
  const modal = page.getByRole('dialog', { name: 'Edit Port-Channel', exact: true })
  const operation = modal.getByLabel('LACP mode operation', { exact: true })
  const mode = modal.getByLabel('LACP mode', { exact: true })
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(operation).toHaveValue('keep')
  await expect(mode).toHaveValue('active')
  await expect.poll(() => exchanges.filter((exchange) =>
    channelIn(exchange.body).lacp === 'active' && exchange.response).length,
  { timeout: 10_000 }).toBe(2)
  const initial = exchanges.filter((exchange) =>
    channelIn(exchange.body).lacp === 'active' && exchange.response)
  for (const exchange of initial) {
    expect(exchange.response!.decisions.every((decision) =>
      decision.affected.interface_id === exchange.body.interface_id)).toBe(true)
  }
  const initialByInterface = new Map(initial.map((exchange) =>
    [exchange.body.interface_id!, exchange.response!] as const))
  expect([...initialByInterface.keys()]).toHaveLength(2)
  const initialChannel = channelIn(initial[0]!.body)
  expect(initialChannel.lacp).toBe('active')
  expect(initialChannel.member_ids).toHaveLength(2)
  await expect(panel.getByText('Unsaved draft', { exact: true }).first()).toBeVisible()

  await operation.selectOption('set')
  await mode.selectOption('passive')
  await expect(modal.getByText('Stale', { exact: true }).first()).toBeVisible()
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const row = modal.getByRole('table', { name: 'Port changes' }).getByRole('row', { name: / LACP mode / })
  await expect(row.getByRole('cell').nth(3)).toHaveText('active')
  await expect(row.getByRole('cell').nth(4)).toHaveText('passive')
  await modal.getByRole('button', { name: 'Back to edit', exact: true }).click()
  await expect.poll(() => exchanges.filter((exchange) =>
    channelIn(exchange.body).lacp === 'passive' && exchange.response).length,
  { timeout: 10_000 }).toBe(2)
  const latest = exchanges.filter((exchange) =>
    channelIn(exchange.body).lacp === 'passive' && exchange.response)
  const latestByInterface = new Map(latest.map((exchange) =>
    [exchange.body.interface_id!, exchange.response!] as const))
  expect([...latestByInterface.keys()].sort()).toEqual([...initialByInterface.keys()].sort())
  for (const [interfaceId, before] of initialByInterface) {
    const after = latestByInterface.get(interfaceId)!
    expect(after.draft_fingerprint).not.toBe(before.draft_fingerprint)
    expect(after.input_fingerprint).not.toBe(before.input_fingerprint)
  }
  const latestChannel = channelIn(latest[0]!.body)
  expect(latestChannel.lacp).toBe('passive')
  expect(latestChannel.member_ids).toEqual(initialChannel.member_ids)
  expect(latestChannel.settings).toMatchObject({ mode: 'trunk', native_vlan: 10, allowed_vlans: [10, 20] })
  for (const exchange of latest) {
    expect(exchange.response!.decisions.every((decision) =>
      decision.affected.interface_id === exchange.body.interface_id)).toBe(true)
  }
  await expect(modal.getByText('Stale', { exact: true })).toHaveCount(0)
  await expect(panel.getByText('SUPPORTED', { exact: true }).first()).toBeVisible()
  await page.unroute('**/api/v1/events/*/plan/capability-preview')

  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  await modal.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  await page.getByRole('button', { name: 'View JSON', exact: true }).click()
  const draft = JSON.parse(await page.getByRole('dialog').locator('pre').textContent() ?? '{}') as Plan
  expect((draft.port_channels as Record<string, unknown>[])[0]).toMatchObject({
    lacp: 'passive', member_ids: latestChannel.member_ids,
  })
  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)
  const unchanged = await request.get(exportUrl)
  expect(await unchanged.body()).toEqual(historicalBody)
  expect(unchanged.headers().etag).toBe(historical.headers().etag)
})

test('port-channel capability requests track LACP values, Keep and member changes', async ({ page, request }) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic channel edits')
  const plan = channelPlan(id)
  const thirdId = String((plan.physical_interfaces as Record<string, unknown>[])[2]!.id)
  const saved = await planRecord(request, plan)
  const savedMembers = ((saved.plan.port_channels as Record<string, unknown>[])[0]!
    .member_ids as string[]).slice()
  const previewBodies: { plan: Plan }[] = []
  page.on('request', (entry) => {
    if (entry.url().includes('/plan/capability-preview')) {
      previewBodies.push(entry.postDataJSON() as { plan: Plan })
    }
  })
  await openWorkspace(page, id)
  await page.getByRole('button', { name: 'Edit Port-Channel 1', exact: true }).click()
  const modal = page.getByRole('dialog', { name: 'Edit Port-Channel', exact: true })
  const operation = modal.getByLabel('LACP mode operation', { exact: true })
  const mode = modal.getByLabel('LACP mode', { exact: true })
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  const channel = () => (previewBodies.at(-1)!.plan.port_channels as Record<string, unknown>[])[0]!
  await expect.poll(() => previewBodies.length).toBe(2)
  expect(channel().lacp).toBe('active')
  expect((channel().member_ids as string[])).toHaveLength(2)

  await operation.selectOption('set')
  await mode.selectOption('passive')
  await expect.poll(() => previewBodies.length).toBe(4)
  expect(channel().lacp).toBe('passive')
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const changes = () => modal.getByRole('table', { name: 'Port changes' }).getByRole('row', { name: / LACP mode / })
  await expect(changes().getByRole('cell').nth(3)).toHaveText('active')
  await expect(changes().getByRole('cell').nth(4)).toHaveText('passive')
  await modal.getByRole('button', { name: 'Back to edit', exact: true }).click()

  await mode.selectOption('static')
  await expect.poll(() => previewBodies.length).toBe(6)
  expect(channel().lacp).toBe('static')
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  await expect(changes().getByRole('cell').nth(3)).toHaveText('active')
  await expect(changes().getByRole('cell').nth(4)).toHaveText('static')
  await modal.getByRole('button', { name: 'Back to edit', exact: true }).click()

  await operation.selectOption('keep')
  await expect.poll(() => previewBodies.length).toBe(8)
  expect(channel().lacp).toBe('active')
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  await modal.getByRole('checkbox', { name: 'Show kept fields', exact: true }).check()
  await expect(changes().getByRole('cell').nth(3)).toHaveText('active')
  await expect(changes().getByRole('cell').nth(4)).toHaveText('active')
  await expect(changes().getByRole('cell').nth(5)).toHaveText('Keep')
  await modal.getByRole('button', { name: 'Back to edit', exact: true }).click()

  await operation.selectOption('set')
  await mode.selectOption('passive')
  await expect.poll(() => previewBodies.length).toBe(10)
  expect(channel().lacp).toBe('passive')

  await modal.getByText('Aggregate interface and members', { exact: true }).click()
  await modal.getByRole('button', { name: 'Remove Member ports 2', exact: true }).click()
  await expect.poll(() => previewBodies.length).toBe(11)
  expect((channel().member_ids as string[])).toEqual([savedMembers[0]!])
  await expect(panel.locator('.capability-target')).toHaveCount(1)

  const memberPorts = modal.getByRole('group', { name: 'Member ports', exact: true })
  await memberPorts.getByRole('button', { name: 'Add entry', exact: true }).click()
  await memberPorts.getByLabel('Member ports 2', { exact: true }).selectOption(thirdId)
  await expect.poll(() => previewBodies.length).toBe(13)
  expect(channel().member_ids).toEqual([savedMembers[0]!, thirdId])
  expect(channel().lacp).toBe('passive')
  await expect(panel.locator('.capability-target')).toHaveCount(2)

  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  await modal.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  await page.getByRole('button', { name: 'View JSON', exact: true }).click()
  const draft = JSON.parse(await page.getByRole('dialog').locator('pre').textContent() ?? '{}') as Plan
  expect((draft.port_channels as Record<string, unknown>[])[0]).toMatchObject({
    lacp: 'passive', member_ids: [savedMembers[0]!, thirdId],
  })
  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)
})

test('port-channel mode and STP preview uses the proposed channel settings', async ({ page, request }) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic channel mode STP')
  const plan = channelPlan(id, { mode: 'access' })
  await planRecord(request, plan)
  const previewBodies: { plan: Plan }[] = []
  const previewResponses: { decisions: { deployment_blockers: string[] }[] }[] = []
  page.on('request', (entry) => {
    if (entry.url().includes('/plan/capability-preview')) {
      previewBodies.push(entry.postDataJSON() as { plan: Plan })
    }
  })
  page.on('response', async (response) => {
    if (response.url().includes('/plan/capability-preview')) {
      previewResponses.push(await response.json() as {
        decisions: { deployment_blockers: string[] }[]
      })
    }
  })
  await openWorkspace(page, id)
  await page.getByRole('button', { name: 'Edit Port-Channel 1', exact: true }).click()
  const modal = page.getByRole('dialog', { name: 'Edit Port-Channel', exact: true })
  await expect.poll(() => previewBodies.length).toBe(2)
  const channel = () => (previewBodies.at(-1)!.plan.port_channels as Record<string, unknown>[])[0]!
  expect(channel().settings).toMatchObject({ mode: 'access', access_vlan: 20 })

  await modal.getByLabel('PortFast operation', { exact: true }).selectOption('set')
  await modal.getByLabel('PortFast', { exact: true }).selectOption('edge')
  await modal.getByLabel('BPDU Guard operation', { exact: true }).selectOption('set')
  await modal.getByLabel('BPDU Guard', { exact: true }).selectOption('enabled')
  await expect.poll(() => previewBodies.some((body) => {
    const settings = (body.plan.port_channels as Record<string, unknown>[])[0]!.settings as Record<string, unknown>
    return settings.portfast === 'edge' && settings.bpdu_guard === 'enabled'
  })).toBe(true)

  await modal.getByLabel('Mode operation', { exact: true }).selectOption('set')
  await modal.getByLabel('Mode', { exact: true }).selectOption('trunk')
  await modal.getByLabel('PortFast', { exact: true }).selectOption('edge-trunk')
  const allowed = modal.getByRole('group', { name: 'Allowed VLANs', exact: true })
  await allowed.getByRole('button', { name: 'Add entry', exact: true }).click()
  await allowed.getByLabel('Allowed VLANs 1', { exact: true }).selectOption('10')
  await allowed.getByRole('button', { name: 'Add entry', exact: true }).click()
  await allowed.getByLabel('Allowed VLANs 2', { exact: true }).selectOption('20')
  await expect.poll(() => previewBodies.some((body) => {
    const settings = (body.plan.port_channels as Record<string, unknown>[])[0]!.settings as Record<string, unknown>
    const vlans = settings.allowed_vlans as number[]
    return settings.mode === 'trunk' && settings.access_vlan == null && settings.bpdu_guard === 'enabled'
      && settings.portfast === 'edge-trunk'
      && Array.isArray(vlans) && vlans.includes(10) && vlans.includes(20)
  })).toBe(true)
  const trunkBody = previewBodies.find((body) => {
    const settings = (body.plan.port_channels as Record<string, unknown>[])[0]!.settings as Record<string, unknown>
    const vlans = settings.allowed_vlans as number[]
    return settings.mode === 'trunk' && settings.access_vlan == null && settings.bpdu_guard === 'enabled'
      && settings.portfast === 'edge-trunk'
      && Array.isArray(vlans) && vlans.includes(10) && vlans.includes(20)
  })!
  expect((trunkBody.plan.port_channels as Record<string, unknown>[])[0]!.lacp).toBe('active')
  await expect.poll(() => previewResponses.some((response) =>
    response.decisions.some((decision) => decision.deployment_blockers.includes('plan-invalid')),
  )).toBe(true)

  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const row = modal.getByRole('table', { name: 'Port changes' }).getByRole('row', { name: /Mode/ })
  await expect(row.getByRole('cell').nth(3)).toHaveText('access')
  await expect(row.getByRole('cell').nth(4)).toHaveText('trunk')
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
