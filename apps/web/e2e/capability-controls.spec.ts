import { randomUUID } from 'node:crypto'
import { expect, test } from '@playwright/test'
import type { APIRequestContext, Locator, Page, Request } from '@playwright/test'
import type { Plan, RecordValue } from '../src/planner/model'

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
  return await response.json() as { id: string; content_hash: string }
}

async function openWorkspace(page: Page, id: string, route = 'ports') {
  await page.goto('/?e2e-event=' + encodeURIComponent(id) + '#' + route)
  const context = page.getByLabel('Event', { exact: true })
  await expect(context).toBeVisible()
  await context.selectOption(id)
  await expect(page.getByRole('button', { name: 'Revision history' }))
    .toBeEnabled({ timeout: 20_000 })
}

async function openPort(page: Page, name: string) {
  await page.getByRole('button', { name: 'Edit port ' + name, exact: true }).click()
  const modal = page.getByRole('dialog', { name: 'Edit port', exact: true })
  await expect(modal).toBeVisible()
  return modal
}

async function closeEditor(page: Page, modal: Locator) {
  page.once('dialog', (prompt) => void prompt.accept())
  await modal.getByRole('button', { name: /^Close Edit/, exact: false }).click()
  await expect(modal).toHaveCount(0)
}

async function viewDraft(page: Page) {
  await page.getByRole('button', { name: 'View JSON', exact: true }).click()
  const dialog = page.getByRole('dialog', { name: 'Plan JSON', exact: true })
  await expect(dialog).toBeVisible()
  const draft = JSON.parse(await dialog.locator('pre').textContent() ?? '{}') as Plan
  await dialog.getByRole('button', { name: 'Close Plan JSON', exact: true }).click()
  await expect(dialog).toHaveCount(0)
  return draft
}

async function tabTo(page: Page, target: Locator) {
  for (let step = 0; step < 120; step += 1) {
    await page.keyboard.press('Tab')
    if (await target.evaluate((node) => node === document.activeElement).catch(() => false)) return
  }
  throw new Error('The control was not reachable with Tab.')
}

function settingsOf(plan: Plan, name: string): Record<string, unknown> {
  const port = (plan.physical_interfaces as RecordValue[])
    .find((item) => item.name === name)!
  return (port.settings ?? {}) as Record<string, unknown>
}

function standalonePlan(eventId: string, options: {
  imageA?: string; licenseA?: string; imageB?: string; licenseB?: string
} = {}): Plan {
  const deviceA = randomUUID()
  const deviceB = randomUUID()
  const assignmentA = randomUUID()
  const assignmentB = randomUUID()
  const serial = (prefix: string, id: string) => 'E2E-CTRL-' + prefix + '-' + id.slice(0, 8)
  return {
    schema_version: 1, event_id: eventId, management_vlan: 10,
    vlans: [{ id: 10, name: 'Management', purpose: 'management' },
      { id: 20, name: 'Players' }],
    physical_devices: [
      { id: deviceA, vendor: 'cisco', model: 'C9300L-24P-4X', verified_serial: serial('A', deviceA) },
      { id: deviceB, vendor: 'cisco', model: 'C9300L-24T-4G', verified_serial: serial('B', deviceB) },
    ],
    assignments: [
      { id: assignmentA, hostname: 'Ctrl-PoE-A', role: 'access', family: 'catalyst-9300',
        physical_device_id: deviceA,
        software: { image: options.imageA ?? '17.12.4', license: options.licenseA ?? 'Network Advantage' } },
      { id: assignmentB, hostname: 'Ctrl-Copper-B', role: 'access', family: 'catalyst-9300',
        physical_device_id: deviceB,
        software: { image: options.imageB ?? '17.12.4', license: options.licenseB ?? 'Network Advantage' } },
    ],
    physical_interfaces: [
      { id: randomUUID(), assignment_id: assignmentA, physical_device_id: deviceA,
        name: 'Gi1/0/1', settings: { mode: 'access', access_vlan: 20 } },
      { id: randomUUID(), assignment_id: assignmentA, physical_device_id: deviceA,
        name: 'Te1/1/1', settings: { mode: 'access', access_vlan: 20 } },
      { id: randomUUID(), assignment_id: assignmentB, physical_device_id: deviceB,
        name: 'Gi1/0/2', settings: { mode: 'access', access_vlan: 20 } },
      { id: randomUUID(), assignment_id: assignmentB, physical_device_id: deviceB,
        name: 'Gi1/1/1', settings: { mode: 'access', access_vlan: 20 } },
    ],
  }
}

function mixedStackPlan(eventId: string): Plan {
  const poe = randomUUID()
  const copper = randomUUID()
  const assignment = randomUUID()
  return {
    schema_version: 1, event_id: eventId, management_vlan: 10,
    vlans: [{ id: 10, name: 'Management', purpose: 'management' },
      { id: 20, name: 'Players' }],
    physical_devices: [
      { id: poe, vendor: 'cisco', model: 'C9300L-24P-4X',
        verified_serial: 'E2E-STACK-P-' + poe.slice(0, 8) },
      { id: copper, vendor: 'cisco', model: 'C9300L-24T-4G',
        verified_serial: 'E2E-STACK-C-' + copper.slice(0, 8) },
    ],
    assignments: [{
      id: assignment, hostname: 'Ctrl-Stack', role: 'access', family: 'catalyst-9300',
      physical_device_id: poe,
      software: { image: '17.12.4', license: 'Network Advantage' },
    }],
    stacks: [{
      assignment_id: assignment,
      members: [
        { number: 1, physical_device_id: poe, state: 'ready' },
        { number: 2, physical_device_id: copper, state: 'ready' },
      ],
    }],
    physical_interfaces: [
      { id: randomUUID(), assignment_id: assignment, physical_device_id: poe,
        name: 'Gi1/0/1', stack_member: 1, settings: { mode: 'access', access_vlan: 20 } },
      { id: randomUUID(), assignment_id: assignment, physical_device_id: copper,
        name: 'Gi2/0/1', stack_member: 2, settings: { mode: 'access', access_vlan: 20 } },
    ],
  }
}

function mixedStackChannelPlan(eventId: string): Plan {
  const firstDevice = randomUUID()
  const secondDevice = randomUUID()
  const assignment = randomUUID()
  const first = randomUUID()
  const second = randomUUID()
  const aggregate = randomUUID()
  const settings = { mode: 'access', access_vlan: 20 }
  return {
    schema_version: 1, event_id: eventId, management_vlan: 10,
    vlans: [{ id: 10, name: 'Management', purpose: 'management' },
      { id: 20, name: 'Players' }],
    physical_devices: [
      { id: firstDevice, vendor: 'cisco', model: 'C9300L-24P-4X',
        verified_serial: 'E2E-STK-CH-' + firstDevice.slice(0, 8) },
      // The second chassis has no exact PID and no verified serial, so only this
      // member's capability result is UNKNOWN while the first one is documented.
      { id: secondDevice, vendor: 'cisco', model: 'Catalyst 9300' },
    ],
    assignments: [{ id: assignment, hostname: 'Ctrl-Stack-Channel', role: 'access',
      family: 'catalyst-9300', physical_device_id: firstDevice,
      software: { image: '17.12.4', license: 'Network Advantage' } }],
    stacks: [{
      assignment_id: assignment,
      members: [
        { number: 1, physical_device_id: firstDevice, state: 'ready' },
        { number: 2, physical_device_id: secondDevice, state: 'ready' },
      ],
    }],
    physical_interfaces: [
      { id: first, assignment_id: assignment, physical_device_id: firstDevice,
        name: 'Gi1/0/1', stack_member: 1, settings },
      { id: second, assignment_id: assignment, physical_device_id: secondDevice,
        name: 'Gi2/0/1', stack_member: 2, settings },
    ],
    logical_interfaces: [{ id: aggregate, assignment_id: assignment,
      name: 'Port-channel1', kind: 'port-channel' }],
    port_channels: [{ interface_id: aggregate, number: 1, member_ids: [first],
      settings, lacp: 'active' }],
  }
}

function sfp28Plan(eventId: string): Plan {
  const device = randomUUID()
  const assignment = randomUUID()
  return {
    schema_version: 1, event_id: eventId, management_vlan: 10,
    vlans: [{ id: 10, name: 'Management', purpose: 'management' },
      { id: 20, name: 'Players' }],
    physical_devices: [{ id: device, vendor: 'cisco', model: 'C9300X-24Y',
      verified_serial: 'E2E-SFP28-' + device.slice(0, 8) }],
    assignments: [{ id: assignment, hostname: 'Ctrl-SFP28', role: 'access',
      family: 'catalyst-9300', physical_device_id: device,
      software: { image: '17.12.4', license: 'Network Advantage' } }],
    physical_interfaces: [{ id: randomUUID(), assignment_id: assignment,
      physical_device_id: device, name: 'TwentyFiveGigE1/0/1',
      settings: { mode: 'access', access_vlan: 20 } }],
  }
}

function channelPlan(eventId: string, options: { image?: string } = {}): Plan {
  const device = randomUUID()
  const assignment = randomUUID()
  const first = randomUUID()
  const second = randomUUID()
  const third = randomUUID()
  const aggregate = randomUUID()
  const settings = { mode: 'access', access_vlan: 20 }
  return {
    schema_version: 1, event_id: eventId, management_vlan: 10,
    vlans: [{ id: 10, name: 'Management', purpose: 'management' },
      { id: 20, name: 'Players' }],
    physical_devices: [{ id: device, vendor: 'cisco', model: 'C9300L-24P-4X',
      verified_serial: 'E2E-CHANNEL-' + device.slice(0, 8) }],
    assignments: [{ id: assignment, hostname: 'Ctrl-Channel', role: 'access',
      family: 'catalyst-9300', physical_device_id: device,
      software: { image: options.image ?? '17.12.4', license: 'Network Advantage' } }],
    physical_interfaces: [
      { id: first, assignment_id: assignment, physical_device_id: device,
        name: 'Gi1/0/1', settings },
      { id: second, assignment_id: assignment, physical_device_id: device,
        name: 'Gi1/0/2', settings },
      { id: third, assignment_id: assignment, physical_device_id: device,
        name: 'Gi1/0/3', settings },
    ],
    logical_interfaces: [{ id: aggregate, assignment_id: assignment,
      name: 'Port-channel1', kind: 'port-channel' }],
    port_channels: [{ interface_id: aggregate, number: 1, member_ids: [first, second],
      settings, lacp: 'active' }],
  }
}

async function previewDraft(
  request: APIRequestContext, eventId: string, plan: Plan,
  assignmentId: string, interfaceId: string, capabilities: string[],
) {
  const response = await request.post(api + '/' + eventId + '/plan/capability-preview', {
    headers,
    data: { plan, assignment_id: assignmentId, interface_id: interfaceId, capabilities },
  })
  expect(response.status(), await response.text()).toBe(200)
  return await response.json() as {
    draft_fingerprint: string
    input_fingerprint: string
    decisions: {
      capability_id: string; verdict: string; reason_code: string
      port_groups: { medium: string; rates: number[] }[]
    }[]
  }
}

function decisionOf(preview: Awaited<ReturnType<typeof previewDraft>>, capability: string) {
  return preview.decisions.find((entry) => entry.capability_id === capability)!
}

type PreviewExchange = {
  body: { plan: Plan; interface_id?: string | null }
  response?: {
    draft_fingerprint: string
    input_fingerprint: string
    decisions: {
      capability_id: string
      verdict: string
      reason_code: string
      affected: { interface_id: string | null }
    }[]
  }
}

function captureCapabilityPreviews(page: Page) {
  const exchanges: PreviewExchange[] = []
  const pending = new Map<Request, PreviewExchange>()
  page.on('request', (entry) => {
    if (!entry.url().includes('/plan/capability-preview')) return
    const exchange: PreviewExchange = {
      body: entry.postDataJSON() as PreviewExchange['body'],
    }
    exchanges.push(exchange)
    pending.set(entry, exchange)
  })
  page.on('response', (response) => {
    if (!response.url().includes('/plan/capability-preview')) return
    const exchange = pending.get(response.request())
    if (!exchange) return
    pending.delete(response.request())
    void response.json().then((body) => {
      exchange.response = body as PreviewExchange['response']
    }).catch(() => undefined)
  })
  return exchanges
}

function channelMembersOf(plan: Plan) {
  return ((plan.port_channels as RecordValue[])[0]!.member_ids as string[]).slice()
}

async function channelMembersFromRevision(
  request: APIRequestContext, eventId: string, revisionId: string,
) {
  const revision = await (await request.get(revisions(eventId) + '/' + revisionId)).json() as {
    plan: Plan
  }
  return channelMembersOf(revision.plan)
}

function membersAre(plan: Plan, expected: string[]) {
  const members = channelMembersOf(plan)
  return members.length === expected.length &&
    expected.every((id) => members.includes(id))
}

function interfaceName(plan: Plan, interfaceId: string) {
  const port = (plan.physical_interfaces as RecordValue[])
    .find((item) => item.id === interfaceId)
  return String(port?.name ?? interfaceId)
}

async function openChannelEditor(page: Page) {
  await page.getByRole('button', { name: 'Edit Port-Channel 1', exact: true }).click()
  const modal = page.getByRole('dialog', { name: 'Edit Port-Channel', exact: true })
  await expect(modal).toBeVisible()
  return modal
}

async function openChannelMembers(modal: Locator) {
  await modal.getByText('Aggregate interface and members', { exact: true }).click()
  return modal.getByRole('group', { name: 'Member ports', exact: true })
}

test('blocks static PoE on documented non-PoE hardware and keeps it out of the draft', async ({ page, request }, info) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic PoE control block')
  const plan = standalonePlan(id)
  const saved = await planRecord(request, plan)
  const exportUrl = revisions(id) + '/' + saved.id + '/export'
  const historical = await request.get(exportUrl)
  const historicalBody = await historical.body()
  const historicalEtag = historical.headers().etag
  const assignments = plan.assignments as RecordValue[]
  const interfaces = plan.physical_interfaces as RecordValue[]
  const copperB = interfaces.find((item) => item.name === 'Gi1/0/2')!
  const preview = await previewDraft(request, id, plan, String(assignments[1]!.id!),
    String(copperB.id!), ['poe', 'speed', 'duplex'])
  expect(decisionOf(preview, 'poe')).toMatchObject({
    verdict: 'unsupported', reason_code: 'poe-unsupported',
  })
  expect(decisionOf(preview, 'poe').port_groups[0]!.rates).toEqual([10, 100, 1000])
  expect(decisionOf(preview, 'speed').port_groups[0]!.medium).toBe('copper-rj45')

  await openWorkspace(page, id)
  const modal = await openPort(page, 'Gi1/0/2')
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel.getByText('UNSUPPORTED', { exact: true }).first()).toBeVisible()
  await modal.getByLabel('PoE mode operation', { exact: true }).selectOption('set')
  const value = modal.getByLabel('PoE mode', { exact: true })
  await expect(value.locator('option[value="static"]')).toBeDisabled()
  const matrix = modal.locator('[data-control-matrix="settings.poe_mode"]')
  await expect(matrix).toBeVisible()
  const blocked = matrix.locator('[data-control-candidate="settings.poe_mode:static"]')
  await expect(blocked).toHaveAttribute('data-control-outcome', 'blocked')
  await expect(blocked.getByText(/Blocked for: .*Ctrl-Copper-B/)).toBeVisible()
  await expect(blocked.getByText(/does not provide PoE/)).toBeVisible()
  await expect(value).toHaveAttribute('aria-details', /settings\.poe_mode-note$/)
  const operation = modal.getByLabel('PoE mode operation', { exact: true })
  await tabTo(page, operation)
  await expect(operation).toHaveCSS('outline-style', 'solid')
  for (const width of [320, 800, 1280, 1440, 1920]) {
    await page.setViewportSize({ width, height: 1000 })
    await expect(modal).toBeVisible()
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width + 1)
    expect(await modal.evaluate((node) => node.scrollWidth - node.clientWidth)).toBeLessThanOrEqual(1)
    await page.screenshot({ path: info.outputPath('control-poe-' + width + '.png') })
  }
  await page.setViewportSize({ width: 1280, height: 900 })
  await expect(value).toBeVisible()
  await closeEditor(page, modal)

  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)
  const after = await request.get(exportUrl)
  expect(await after.body()).toEqual(historicalBody)
  expect(after.headers().etag).toBe(historicalEtag)
  await expect(page.getByText('Unsaved changes', { exact: true })).toHaveCount(0)
})

test('allows a documented PoE candidate and records matching Before / After data', async ({ page, request }) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic PoE control allow')
  const plan = standalonePlan(id)
  const saved = await planRecord(request, plan)
  const exportUrl = revisions(id) + '/' + saved.id + '/export'
  const original = await request.get(exportUrl)
  const originalBody = await original.body()
  const originalEtag = original.headers().etag
  await openWorkspace(page, id)
  const modal = await openPort(page, 'Gi1/0/1')
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel.getByText('SUPPORTED', { exact: true }).first()).toBeVisible()
  await expect(modal.locator('[data-control-matrix="settings.poe_mode"]')).toHaveCount(0)

  await modal.getByLabel('PoE mode operation', { exact: true }).selectOption('set')
  await modal.getByLabel('PoE mode', { exact: true }).selectOption('static')
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const changes = modal.getByRole('table', { name: 'Port changes' })
  const row = changes.getByRole('row', { name: /PoE mode/ })
  await expect(row.getByRole('cell').nth(3)).toHaveText('Platform default')
  await expect(row.getByRole('cell').nth(4)).toHaveText('static')
  const controls = modal.getByRole('table', { name: 'Capability controls for the proposed change' })
  const controlRow = controls.getByRole('row', { name: /PoE mode/ })
  await expect(controlRow).toHaveAttribute('data-control-outcome', 'allowed')
  await expect(controlRow.getByText('Documented', { exact: true })).toBeVisible()
  await modal.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  const draft = await viewDraft(page)
  expect(settingsOf(draft, 'Gi1/0/1')).toMatchObject({ poe_mode: 'static', mode: 'access' })
  await page.getByRole('button', { name: 'Save revision', exact: true }).click()
  await expect(page.getByText('Revision 2 saved.', { exact: true })).toBeVisible({ timeout: 15_000 })
  const history = await (await request.get(revisions(id))).json() as { id: string; number: number }[]
  expect(history).toHaveLength(2)
  const latest = await (await request.get(revisions(id) + '/' + history[1]!.id)).json() as {
    plan: Plan; content_hash: string
  }
  expect(settingsOf(latest.plan, 'Gi1/0/1')).toMatchObject({ poe_mode: 'static' })
  expect(latest.content_hash).toHaveLength(64)
  const unchanged = await request.get(exportUrl)
  expect(await unchanged.body()).toEqual(originalBody)
  expect(unchanged.headers().etag).toBe(originalEtag)
})

test('judges mixed Stack members per target and never silently updates the blocked member', async ({ page, request }) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic mixed PoE batch')
  const plan = mixedStackPlan(id)
  await planRecord(request, plan)
  await openWorkspace(page, id)
  const memberOne = page.getByLabel('Select port Gi1/0/1', { exact: true })
  const memberTwo = page.getByLabel('Select port Gi2/0/1', { exact: true })
  await memberOne.check()
  await memberTwo.check()
  await page.getByRole('button', { name: 'Batch edit (2)', exact: true }).click()
  const modal = page.getByRole('dialog', { name: 'Batch edit 2 ports', exact: true })
  await modal.getByLabel('PoE mode operation', { exact: true }).selectOption('set')
  const value = modal.getByLabel('PoE mode', { exact: true })
  await expect(value.locator('option[value="static"]')).toBeDisabled()
  const matrix = modal.locator('[data-control-matrix="settings.poe_mode"]')
  const blocked = matrix.locator('[data-control-candidate="settings.poe_mode:static"]')
  await expect(blocked).toHaveAttribute('data-control-outcome', 'blocked')
  await expect(blocked.getByText(/Blocked for: .*Gi2\/0\/1/)).toBeVisible()
  await expect(blocked.getByText(/Documented support for: .*Gi1\/0\/1/)).toBeVisible()
  await page.once('dialog', (prompt) => void prompt.accept())
  await modal.getByRole('button', { name: /^Close Batch edit/, exact: false }).click()
  await expect(modal).toHaveCount(0)

  if (await memberTwo.isChecked()) await memberTwo.uncheck()
  await expect(memberOne).toBeChecked()
  await page.getByRole('button', { name: 'Batch edit (1)', exact: true }).click()
  const single = page.getByRole('dialog', { name: 'Batch edit 1 port', exact: true })
  await single.getByLabel('PoE mode operation', { exact: true }).selectOption('set')
  await single.getByLabel('PoE mode', { exact: true }).selectOption('static')
  await single.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const controls = single.getByRole('table', { name: 'Capability controls for the proposed change' })
  await expect(controls.getByRole('row', { name: /PoE mode/ })).toHaveAttribute('data-control-outcome', 'allowed')
  await single.getByRole('button', { name: 'Apply to 1 port', exact: true }).click()
  const draft = await viewDraft(page)
  expect(settingsOf(draft, 'Gi1/0/1')).toMatchObject({ poe_mode: 'static' })
  expect(settingsOf(draft, 'Gi2/0/1').poe_mode).toBeNull()
})

test('rejects a speed outside the documented copper range and keeps SFP UNKNOWN', async ({ page, request }) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic speed control')
  const plan = standalonePlan(id)
  await planRecord(request, plan)
  const assignments = plan.assignments as RecordValue[]
  const interfaces = plan.physical_interfaces as RecordValue[]
  const copper = interfaces.find((item) => item.name === 'Gi1/0/2')!
  const outOfRange = {
    ...plan,
    physical_interfaces: (plan.physical_interfaces as RecordValue[]).map((item) =>
      item.name === 'Gi1/0/2'
        ? { ...item, settings: { ...(item.settings as RecordValue), speed: 2500 } }
        : item),
  }
  const preview = await previewDraft(request, id, outOfRange, String(assignments[1]!.id!),
    String(copper.id!), ['speed'])
  expect(decisionOf(preview, 'speed')).toMatchObject({
    verdict: 'unsupported', reason_code: 'speed-outside-port-range',
  })
  expect(decisionOf(preview, 'speed').port_groups[0]!.rates).toEqual([10, 100, 1000])

  await openWorkspace(page, id)
  const copperModal = await openPort(page, 'Gi1/0/2')
  await copperModal.getByLabel('Speed (Mbps) operation', { exact: true }).selectOption('set')
  const speed = copperModal.getByLabel('Speed (Mbps)', { exact: true })
  await expect(speed.locator('option[value="2500"]')).toBeDisabled()
  await expect(speed.locator('option[value="10000"]')).toBeDisabled()
  await expect(speed.locator('option[value="1000"]')).toBeEnabled()
  const copperMatrix = copperModal.locator('[data-control-matrix="settings.speed"]')
  await expect(copperMatrix.locator('[data-control-candidate="settings.speed:2500"]'))
    .toHaveAttribute('data-control-outcome', 'blocked')
  await expect(copperMatrix.locator('[data-control-candidate="settings.speed:2500"]').getByText(/exceeds the port rating/)).toBeVisible()
  await closeEditor(page, copperModal)

  const sfpModal = await openPort(page, 'Gi1/1/1')
  const panel = sfpModal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel.getByText('UNKNOWN', { exact: true }).first()).toBeVisible()
  await sfpModal.getByLabel('Speed (Mbps) operation', { exact: true }).selectOption('set')
  const sfpSpeed = sfpModal.getByLabel('Speed (Mbps)', { exact: true })
  await expect(sfpSpeed.locator('option[value="2500"]')).toBeDisabled()
  await expect(sfpSpeed.locator('option[value="1000"]')).toBeEnabled()
  const sfpMatrix = sfpModal.locator('[data-control-matrix="settings.speed"]')
  await expect(sfpMatrix.locator('[data-control-candidate="settings.speed:1000"]'))
    .toHaveAttribute('data-control-outcome', 'warning')
  await expect(sfpMatrix.locator('[data-control-candidate="settings.speed:1000"]').getByText(/transceiver is required/)).toBeVisible()
  await sfpSpeed.selectOption('1000')
  await sfpModal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const controls = sfpModal.getByRole('table', { name: 'Capability controls for the proposed change' })
  await expect(controls.getByRole('row', { name: /Speed/ })).toHaveAttribute('data-control-outcome', 'warning')
  await sfpModal.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  const draft = await viewDraft(page)
  expect(settingsOf(draft, 'Gi1/1/1')).toMatchObject({ speed: 1000 })
  expect(settingsOf(draft, 'Gi1/0/2')).toMatchObject({ mode: 'access' })
})

test('keeps SFP28 candidates UNKNOWN inside the documented range and blocks rates above it', async ({ page, request }) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic SFP28 control')
  const plan = sfp28Plan(id)
  await planRecord(request, plan)
  await openWorkspace(page, id)
  const modal = await openPort(page, 'TwentyFiveGigE1/0/1')
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel.getByText('UNKNOWN', { exact: true }).first()).toBeVisible()
  await modal.getByLabel('Speed (Mbps) operation', { exact: true }).selectOption('set')
  const speed = modal.getByLabel('Speed (Mbps)', { exact: true })
  await expect(speed.locator('option[value="40000"]')).toBeDisabled()
  await expect(speed.locator('option[value="25000"]')).toBeEnabled()
  const matrix = modal.locator('[data-control-matrix="settings.speed"]')
  for (const rate of [1000, 10000, 25000]) {
    await expect(matrix.locator('[data-control-candidate="settings.speed:' + rate + '"]'))
      .toHaveAttribute('data-control-outcome', 'warning')
  }
  await expect(matrix.locator('[data-control-candidate="settings.speed:40000"]'))
    .toHaveAttribute('data-control-outcome', 'blocked')
  await speed.selectOption('25000')
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  await modal.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  const draft = await viewDraft(page)
  expect(settingsOf(draft, 'TwentyFiveGigE1/0/1')).toMatchObject({ speed: 25000 })
})

test('links Duplex candidates to the proposed Speed and the documented medium', async ({ page, request }) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic duplex control')
  const plan = standalonePlan(id)
  await planRecord(request, plan)
  await openWorkspace(page, id)
  const modal = await openPort(page, 'Gi1/0/2')
  await modal.getByLabel('Speed (Mbps) operation', { exact: true }).selectOption('set')
  await modal.getByLabel('Speed (Mbps)', { exact: true }).selectOption('1000')
  await modal.getByLabel('Duplex operation', { exact: true }).selectOption('set')
  const duplex = modal.getByLabel('Duplex', { exact: true })
  await expect(duplex.locator('option[value="half"]')).toBeDisabled()
  const matrix = modal.locator('[data-control-matrix="settings.duplex"]')
  await expect(matrix.locator('[data-control-candidate="settings.duplex:half"]'))
    .toHaveAttribute('data-control-outcome', 'blocked')
  await expect(matrix.locator('[data-control-candidate="settings.duplex:half"]').getByText(/1 Gbps requires full duplex/)).toBeVisible()
  await expect(duplex.locator('option[value="full"]')).toBeEnabled()
  await modal.getByLabel('Speed (Mbps)', { exact: true }).selectOption('100')
  await expect(duplex.locator('option[value="half"]')).toBeEnabled()
  await duplex.selectOption('half')
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const changes = modal.getByRole('table', { name: 'Port changes' })
  const speedRow = changes.getByRole('row', { name: /Speed \(Mbps\)/ })
  await expect(speedRow.getByRole('cell').nth(4)).toHaveText('100')
  const duplexRow = changes.getByRole('row', { name: /Duplex/ })
  await expect(duplexRow.getByRole('cell').nth(4)).toHaveText('half')
  await modal.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  const draft = await viewDraft(page)
  expect(settingsOf(draft, 'Gi1/0/2')).toMatchObject({ speed: 100, duplex: 'half' })
})

test('keeps ROMMON evidence warning-only and saves UNKNOWN planning intent', async ({ page, request }) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic ROMMON control')
  const plan = standalonePlan(id, { imageB: '17.12.2r' })
  const saved = await planRecord(request, plan)
  const exportUrl = revisions(id) + '/' + saved.id + '/export'
  const original = await request.get(exportUrl)
  const originalBody = await original.body()
  await openWorkspace(page, id)
  const modal = await openPort(page, 'Gi1/0/2')
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel.getByText(/ROMMON/i).first()).toBeVisible()
  await expect(modal.getByLabel('PoE mode', { exact: true }).locator('option[value="static"]'))
    .toBeDisabled()
  await modal.getByLabel('Speed (Mbps) operation', { exact: true }).selectOption('set')
  const speed = modal.getByLabel('Speed (Mbps)', { exact: true })
  await expect(speed.locator('option[value="2500"]')).toBeEnabled()
  const matrix = modal.locator('[data-control-matrix="settings.speed"]')
  await expect(matrix.locator('[data-control-candidate="settings.speed:2500"]'))
    .toHaveAttribute('data-control-outcome', 'warning')
  await speed.selectOption('2500')
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const controls = modal.getByRole('table', { name: 'Capability controls for the proposed change' })
  await expect(controls.getByRole('row', { name: /Speed/ })).toHaveAttribute('data-control-outcome', 'warning')
  await expect(modal.getByRole('button', { name: 'Apply to draft', exact: true })).toBeEnabled()
  await modal.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  await page.getByRole('button', { name: 'Save revision', exact: true }).click()
  await expect(page.getByText('Revision 2 saved.', { exact: true })).toBeVisible({ timeout: 15_000 })
  const history = await (await request.get(revisions(id))).json() as { id: string }[]
  const latest = await (await request.get(revisions(id) + '/' + history[1]!.id)).json() as { plan: Plan }
  expect(settingsOf(latest.plan, 'Gi1/0/2')).toMatchObject({ speed: 2500 })
  const unchanged = await request.get(exportUrl)
  expect(await unchanged.body()).toEqual(originalBody)
})

test('rejudges the controls after License and interface evidence changes', async ({ page, request }) => {
  test.setTimeout(120_000)
  const id = await createEvent(request, 'Synthetic license and interface rejudge')
  const plan = standalonePlan(id)
  await planRecord(request, plan)
  await openWorkspace(page, id)
  const first = await openPort(page, 'Gi1/0/1')
  await first.getByLabel('Speed (Mbps) operation', { exact: true }).selectOption('set')
  await expect(first.getByLabel('Speed (Mbps)', { exact: true }).locator('option[value="2500"]'))
    .toBeDisabled()
  await expect(first.getByLabel('PoE mode', { exact: true }).locator('option[value="static"]'))
    .toBeEnabled()
  await closeEditor(page, first)

  await page.getByRole('link', { name: 'Devices / Topology', exact: true }).click()
  await page.getByRole('button', { name: 'Edit assignment Ctrl-PoE-A', exact: true }).click()
  const assignmentDialog = page.getByRole('dialog', { name: 'Edit assignment', exact: true })
  await assignmentDialog.getByLabel('Software profile (JSON)', { exact: true })
    .fill(JSON.stringify({ image: '17.12.4', license: 'LAN Base' }))
  await assignmentDialog.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  await page.getByRole('link', { name: 'Port Editor', exact: true }).click()
  const second = await openPort(page, 'Gi1/0/1')
  await second.getByLabel('Speed (Mbps) operation', { exact: true }).selectOption('set')
  await expect(second.getByLabel('Speed (Mbps)', { exact: true }).locator('option[value="2500"]'))
    .toBeEnabled()
  const licenseMatrix = second.locator('[data-control-matrix="settings.speed"]')
  await expect(licenseMatrix.locator('[data-control-candidate="settings.speed:2500"]'))
    .toHaveAttribute('data-control-outcome', 'warning')
  await second.getByText('Interface identity', { exact: true }).click()
  await second.getByLabel('Interface name', { exact: true }).fill('Te1/1/1')
  await expect(second.getByLabel('PoE mode operation', { exact: true }).locator('option[value="set"]'))
    .toBeEnabled()
  await second.getByLabel('PoE mode operation', { exact: true }).selectOption('set')
  await expect(second.getByLabel('PoE mode', { exact: true }).locator('option[value="static"]'))
    .toBeDisabled({ timeout: 15_000 })
  const mediaMatrix = second.locator('[data-control-matrix="settings.speed"]')
  await expect(mediaMatrix.locator('[data-control-candidate="settings.speed:1000"]'))
    .toHaveAttribute('data-control-outcome', 'warning')
  await closeEditor(page, second)
  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)
})

test('rejudges the target after a PID change and blocks Apply until the proposal changes', async ({ page, request }) => {
  test.setTimeout(120_000)
  const id = await createEvent(request, 'Synthetic PID change rejudge')
  const plan = standalonePlan(id)
  await planRecord(request, plan)
  const assignments = plan.assignments as RecordValue[]
  const devices = plan.physical_devices as RecordValue[]
  await openWorkspace(page, id)
  const modal = await openPort(page, 'Gi1/0/1')
  await modal.getByLabel('PoE mode operation', { exact: true }).selectOption('set')
  await expect(modal.getByLabel('PoE mode', { exact: true }).locator('option[value="static"]'))
    .toBeEnabled()
  await modal.getByLabel('PoE mode', { exact: true }).selectOption('static')
  await modal.getByText('Interface identity', { exact: true }).click()
  await modal.getByLabel('Interface name', { exact: true }).fill('Gi1/0/9')
  await modal.getByLabel('Device assignment', { exact: true }).selectOption(String(assignments[1]!.id!))
  await modal.getByLabel('Physical chassis', { exact: true }).selectOption(String(devices[1]!.id!))
  await expect(modal.getByLabel('PoE mode', { exact: true }).locator('option[value="static"]'))
    .toBeDisabled({ timeout: 20_000 })
  const matrix = modal.locator('[data-control-matrix="settings.poe_mode"]')
  await expect(matrix.locator('[data-control-candidate="settings.poe_mode:static"]'))
    .toHaveAttribute('data-control-outcome', 'blocked')
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const alert = modal.getByRole('alert').filter({ hasText: 'Apply is blocked' })
  await expect(alert).toBeVisible()
  await expect(modal.getByRole('button', { name: 'Apply to draft', exact: true })).toBeDisabled()
  const controls = modal.getByRole('table', { name: 'Capability controls for the proposed change' })
  await expect(controls.getByRole('row', { name: /PoE mode/ })).toHaveAttribute('data-control-outcome', 'blocked')
  await modal.getByRole('button', { name: 'Back to edit', exact: true }).click()
  await closeEditor(page, modal)
  const draft = await viewDraft(page)
  expect(settingsOf(draft, 'Gi1/0/1').poe_mode).toBeNull()
  expect(settingsOf(draft, 'Gi1/0/1').mode).toBe('access')
  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)
})

test('does not reuse a stale verdict and rechecks Apply after the API recovers', async ({ page, request }) => {
  test.setTimeout(120_000)
  const id = await createEvent(request, 'Synthetic stale verdict control')
  const plan = standalonePlan(id)
  await planRecord(request, plan)
  await openWorkspace(page, id)
  const modal = await openPort(page, 'Gi1/0/2')
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel.getByText('UNSUPPORTED', { exact: true }).first()).toBeVisible()
  await page.route('**/api/v1/events/*/plan/capability-preview', (route) => route.abort())
  await modal.getByLabel('Speed (Mbps) operation', { exact: true }).selectOption('set')
  await modal.getByLabel('Speed (Mbps)', { exact: true }).selectOption('1000')
  await expect(panel.getByText(/Capability evidence is unavailable/)).toBeVisible({ timeout: 15_000 })
  const poeOperation = modal.getByLabel('PoE mode operation', { exact: true })
  await poeOperation.selectOption('set')
  const poe = modal.getByLabel('PoE mode', { exact: true })
  await expect(poe.locator('option[value="static"]')).toBeEnabled()
  await expect(modal.locator('[data-control-matrix="settings.poe_mode"]'))
    .toHaveAttribute('data-control-outcome', 'pending')
  await poe.selectOption('static')
  await page.unroute('**/api/v1/events/*/plan/capability-preview')
  await modal.getByLabel('Speed (Mbps)', { exact: true }).selectOption('100')
  await expect(poe.locator('option[value="static"]')).toBeDisabled({ timeout: 20_000 })
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const alert = modal.getByRole('alert').filter({ hasText: 'Apply is blocked' })
  await expect(alert).toBeVisible()
  await expect(modal.getByRole('button', { name: 'Apply to draft', exact: true })).toBeDisabled()
  await modal.getByRole('button', { name: 'Back to edit', exact: true }).click()
  await closeEditor(page, modal)
  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)
  const draft = await viewDraft(page)
  expect(settingsOf(draft, 'Gi1/0/2').poe_mode).toBeNull()
})

test('ignores an older capability response when a newer target replaces it', async ({ page, request }) => {
  test.setTimeout(120_000)
  const id = await createEvent(request, 'Synthetic control response race')
  const plan = standalonePlan(id)
  await planRecord(request, plan)
  await page.route('**/api/v1/events/*/plan/capability-preview', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 800))
    await route.continue()
  })
  await openWorkspace(page, id)
  const modal = await openPort(page, 'Gi1/0/2')
  await modal.getByText('Interface identity', { exact: true }).click()
  await modal.getByLabel('Interface name', { exact: true }).fill('Gi1/1/1')
  const speed = modal.getByLabel('Speed (Mbps)', { exact: true })
  await expect(speed.locator('option[value="2500"]')).toBeDisabled({ timeout: 20_000 })
  await expect(modal.getByLabel('Speed (Mbps) operation', { exact: true })).toBeVisible()
  const matrix = modal.locator('[data-control-matrix="settings.speed"]')
  await expect(matrix.locator('[data-control-candidate="settings.speed:1000"]'))
    .toHaveAttribute('data-control-outcome', 'warning')
  await expect(matrix.locator('[data-control-candidate="settings.speed:1000"]')
    .getByText(/Documented support for/)).toHaveCount(0)
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel.getByText('UNKNOWN', { exact: true }).first()).toBeVisible()
  await page.unroute('**/api/v1/events/*/plan/capability-preview')
  await modal.getByLabel('PoE mode operation', { exact: true }).selectOption('set')
  await expect(modal.getByLabel('PoE mode', { exact: true }).locator('option[value="static"]'))
    .toBeDisabled()
  await closeEditor(page, modal)
})

test('separates static aggregation from LACP negotiation in the Port-Channel editor', async ({ page, request }) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic channel control')
  const plan = channelPlan(id)
  await planRecord(request, plan)
  const interfaces = plan.physical_interfaces as RecordValue[]
  const channelAssignment = (plan.assignments as RecordValue[])[0]!
  const channelPreview = await previewDraft(request, id, plan, String(channelAssignment.id!),
    String(interfaces[0]!.id!), ['lacp', 'port-channel'])
  expect(decisionOf(channelPreview, 'lacp').verdict).toBe('supported')
  expect(decisionOf(channelPreview, 'port-channel').verdict).toBe('supported')
  await openWorkspace(page, id)
  await page.getByRole('button', { name: 'Edit Port-Channel 1', exact: true }).click()
  const modal = page.getByRole('dialog', { name: 'Edit Port-Channel', exact: true })
  const operation = modal.getByLabel('LACP mode operation', { exact: true })
  const mode = modal.getByLabel('LACP mode', { exact: true })
  await operation.selectOption('set')
  await mode.selectOption('static')
  await expect(modal.locator('[data-control-matrix="lacp"]')).toHaveCount(0)
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const controls = modal.getByRole('table', { name: 'Capability controls for the proposed change' })
  await expect(controls.getByRole('row', { name: /LACP mode/ }).first())
    .toHaveAttribute('data-control-outcome', 'allowed')
  await modal.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  const draft = await viewDraft(page)
  expect((draft.port_channels as RecordValue[])[0]!.lacp).toBe('static')
})

test('localizes capability controls and exposes the short screen-reader note', async ({ page, request }) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic localized control')
  const plan = standalonePlan(id)
  await planRecord(request, plan)
  await openWorkspace(page, id)
  const modal = await openPort(page, 'Gi1/0/2')
  await modal.locator('.dialog-locale select').selectOption('zh-CN')
  const localized = page.locator('dialog[open]')
  await localized.getByLabel('PoE 模式操作', { exact: true }).selectOption('set')
  await expect(localized.getByText('能力控件限制', { exact: true })).toBeVisible()
  await expect(localized.getByText('候选值可用性', { exact: true }).first()).toBeVisible()
  await expect(localized.getByText('硬阻止', { exact: true }).first()).toBeVisible()
  const matrix = localized.locator('[data-control-matrix="settings.poe_mode"]')
  await expect(matrix.getByText(/阻止目标/)).toBeVisible()
  const poe = localized.getByLabel('PoE 模式', { exact: true })
  await expect(poe.locator('option[value="static"]')).toBeDisabled()
  await expect(poe).toHaveAttribute('aria-details', /settings\.poe_mode-note$/)
  await expect(localized.getByText('未验证', { exact: true }).first()).toBeVisible()
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await expect(localized.getByRole('button', { name: '预览变更', exact: true }))
    .toHaveCSS('transition-duration', '0s')
  await localized.locator('.dialog-locale select').selectOption('en-US')
  await expect(page.locator('dialog[open]').getByText('Capability controls', { exact: true })).toBeVisible()
  await closeEditor(page, modal)
})

test('preserves a historical UNSUPPORTED value and lets the operator repair it', async ({ page, request }) => {
  test.setTimeout(120_000)
  const id = await createEvent(request, 'Synthetic historical control')
  const plan = standalonePlan(id)
  const interfaces = plan.physical_interfaces as RecordValue[]
  const copperB = interfaces.find((item) => item.name === 'Gi1/0/2')!
  ;(copperB.settings as RecordValue).poe_mode = 'static'
  const saved = await planRecord(request, plan)
  const exportUrl = revisions(id) + '/' + saved.id + '/export'
  const historical = await request.get(exportUrl)
  const historicalBody = await historical.body()
  const historicalEtag = historical.headers().etag
  const stored = await (await request.get(revisions(id) + '/' + saved.id)).json() as { plan: Plan }
  expect(settingsOf(stored.plan, 'Gi1/0/2').poe_mode).toBe('static')
  await openWorkspace(page, id)
  const modal = await openPort(page, 'Gi1/0/2')
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel.getByText('UNSUPPORTED', { exact: true }).first()).toBeVisible()
  const poe = modal.getByLabel('PoE mode', { exact: true })
  await expect(poe).toHaveValue('static')
  await expect(poe.locator('option[value="static"]')).toBeDisabled()
  const matrix = modal.locator('[data-control-matrix="settings.poe_mode"]')
  await expect(matrix.locator('[data-control-candidate="settings.poe_mode:static"]'))
    .toHaveAttribute('data-control-outcome', 'blocked')
  await expect(modal.getByText(/Stored PoE mode value static/)).toBeVisible()
  await modal.getByLabel('PoE mode operation', { exact: true }).selectOption('reset')
  await expect(modal.locator('[data-control-notice="settings.poe_mode"]')
    .getByText(/platform default PoE behavior/)).toBeVisible()
  await expect(modal.getByRole('alert').filter({ hasText: 'Apply is blocked' })).toHaveCount(0)
  await modal.getByLabel('PoE mode operation', { exact: true }).selectOption('set')
  await poe.selectOption('never')
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const controls = modal.getByRole('table', { name: 'Capability controls for the proposed change' })
  const controlRow = controls.getByRole('row', { name: /PoE mode/ })
  await expect(controlRow).toHaveAttribute('data-control-outcome', 'allowed')
  await expect(modal.getByRole('button', { name: 'Apply to draft', exact: true })).toBeEnabled()
  await modal.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  const draft = await viewDraft(page)
  expect(settingsOf(draft, 'Gi1/0/2').poe_mode).toBe('never')
  expect(settingsOf(draft, 'Gi1/0/1')).toMatchObject({ mode: 'access' })
  await page.getByRole('button', { name: 'Save revision', exact: true }).click()
  await expect(page.getByText('Revision 2 saved.', { exact: true })).toBeVisible({ timeout: 15_000 })
  const history = await (await request.get(revisions(id))).json() as { id: string }[]
  expect(history).toHaveLength(2)
  const unchanged = await request.get(exportUrl)
  expect(await unchanged.body()).toEqual(historicalBody)
  expect(unchanged.headers().etag).toBe(historicalEtag)
  const first = await (await request.get(revisions(id) + '/' + saved.id)).json() as {
    id: string; content_hash: string; plan: Plan
  }
  expect(first.id).toBe(saved.id)
  expect(first.content_hash).toHaveLength(64)
  expect(settingsOf(first.plan, 'Gi1/0/2').poe_mode).toBe('static')
})

test('keeps static aggregation editable when LACP evidence is UNKNOWN', async ({ page, request }) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic channel unknown control')
  const plan = channelPlan(id, { image: '17.12.2r' })
  await planRecord(request, plan)
  const interfaces = plan.physical_interfaces as RecordValue[]
  const assignment = (plan.assignments as RecordValue[])[0]!
  const preview = await previewDraft(request, id, plan, String(assignment.id!),
    String(interfaces[0]!.id!), ['lacp', 'port-channel'])
  expect(decisionOf(preview, 'lacp').verdict).toBe('unknown')
  await openWorkspace(page, id)
  await page.getByRole('button', { name: 'Edit Port-Channel 1', exact: true }).click()
  const modal = page.getByRole('dialog', { name: 'Edit Port-Channel', exact: true })
  await modal.getByLabel('LACP mode operation', { exact: true }).selectOption('set')
  const mode = modal.getByLabel('LACP mode', { exact: true })
  await expect(mode.locator('option[value="static"]')).toBeEnabled()
  const matrix = modal.locator('[data-control-matrix="lacp"]')
  await expect(matrix).toHaveAttribute('data-control-outcome', 'warning')
  await expect(matrix.locator('[data-control-candidate="lacp:static"]'))
    .toHaveAttribute('data-control-outcome', 'warning')
  await mode.selectOption('static')
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const controls = modal.getByRole('table', { name: 'Capability controls for the proposed change' })
  await expect(controls.getByRole('row', { name: /LACP mode/ }).first())
    .toHaveAttribute('data-control-outcome', 'warning')
  await expect(modal.getByRole('button', { name: 'Apply to draft', exact: true })).toBeEnabled()
  await modal.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  const draft = await viewDraft(page)
  expect((draft.port_channels as RecordValue[])[0]!.lacp).toBe('static')
})

test('judges member-only Port-Channel changes per added member and applies the exact draft', async ({ page, request }, info) => {
  test.setTimeout(120_000)
  const id = await createEvent(request, 'Synthetic channel membership controls')
  const plan = channelPlan(id)
  const saved = await planRecord(request, plan)
  const exportUrl = revisions(id) + '/' + saved.id + '/export'
  const historical = await request.get(exportUrl)
  const historicalBody = await historical.body()
  const historicalEtag = historical.headers().etag
  const interfaces = plan.physical_interfaces as RecordValue[]
  const [first, , third] = interfaces.map((item) => String(item.id))
  const initialMembers = await channelMembersFromRevision(request, id, saved.id)
  expect(initialMembers).toHaveLength(2)
  const expectedAfterAdd = [...initialMembers, third!]
  const assignmentId = String((plan.assignments as RecordValue[])[0]!.id!)
  const range = await previewDraft(request, id, plan, assignmentId, first!,
    ['lacp', 'port-channel'])
  expect(decisionOf(range, 'lacp').verdict).toBe('supported')
  expect(decisionOf(range, 'port-channel').verdict).toBe('supported')
  const exchanges = captureCapabilityPreviews(page)
  await openWorkspace(page, id)
  const modal = await openChannelEditor(page)
  const members = await openChannelMembers(modal)
  await members.getByRole('button', { name: 'Add entry', exact: true }).click()
  await members.getByLabel('Member ports 3', { exact: true }).selectOption(third!)
  const membership = modal.locator('[data-control-membership="change"]')
  await expect(membership).toHaveAttribute('data-control-membership-outcome', 'allowed')
  await expect(membership.locator('[data-control-member="' + third + '"]'))
    .toHaveAttribute('data-control-outcome', 'allowed')
  await page.screenshot({ path: info.outputPath('channel-membership-add-1280.png') })
  await expect.poll(() => exchanges.filter((exchange) =>
    membersAre(exchange.body.plan, expectedAfterAdd) && exchange.response).length,
  { timeout: 10_000 }).toBe(3)
  const current = exchanges.filter((exchange) =>
    membersAre(exchange.body.plan, expectedAfterAdd) && exchange.response)
  for (const exchange of current) {
    expect(exchange.response!.decisions.every((decision) =>
      decision.affected.interface_id === exchange.body.interface_id)).toBe(true)
    expect(channelMembersOf(exchange.body.plan)).toEqual(expectedAfterAdd)
  }
  const proposedPlan = {
    ...plan,
    port_channels: (plan.port_channels as RecordValue[]).map((channel) => ({
      ...channel,
      member_ids: expectedAfterAdd,
    })),
  }
  const beforeChange = await previewDraft(request, id, plan, assignmentId, first!,
    ['port-channel'])
  const afterChange = await previewDraft(request, id, proposedPlan, assignmentId, first!,
    ['port-channel'])
  expect(afterChange.draft_fingerprint).not.toBe(beforeChange.draft_fingerprint)
  expect(afterChange.input_fingerprint).not.toBe(beforeChange.input_fingerprint)
  expect(current[0]!.response!.draft_fingerprint).not.toBe(beforeChange.draft_fingerprint)
  await expect(modal.locator('.capability-target')).toHaveCount(3)

  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const changes = modal.getByRole('table', { name: 'Port changes' })
  const memberRow = changes.getByRole('row', { name: /Member ports/ })
  await expect(memberRow.getByRole('cell').nth(3)).not.toContainText('Gi1/0/3')
  await expect(memberRow.getByRole('cell').nth(4)).toContainText('Gi1/0/3')
  const controls = modal.getByRole('table', { name: 'Capability controls for the proposed change' })
  const controlRow = controls.getByRole('row', { name: /Member ports/ })
  await expect(controlRow).toHaveAttribute('data-control-outcome', 'allowed')
  await expect(controlRow.getByRole('cell').nth(2)).toHaveText('Gi1/0/3')
  await modal.getByRole('button', { name: 'Apply to draft', exact: true }).click()

  const draft = await viewDraft(page)
  expect(channelMembersOf(draft)).toEqual(expectedAfterAdd)
  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)
  const unchanged = await request.get(exportUrl)
  expect(await unchanged.body()).toEqual(historicalBody)
  expect(unchanged.headers().etag).toBe(historicalEtag)
  await page.getByRole('button', { name: 'Save revision', exact: true }).click()
  await expect(page.getByText('Revision 2 saved.', { exact: true })).toBeVisible({ timeout: 15_000 })
  const history = await (await request.get(revisions(id))).json() as { id: string }[]
  expect(history).toHaveLength(2)
  const canonicalMembers = await channelMembersFromRevision(request, id, history[1]!.id)
  const removedMember = canonicalMembers[1]!
  const expectedRemaining = canonicalMembers.filter((member) => member !== removedMember)
  const stillUnchanged = await request.get(exportUrl)
  expect(await stillUnchanged.body()).toEqual(historicalBody)
  expect(stillUnchanged.headers().etag).toBe(historicalEtag)

  const reopened = await openChannelEditor(page)
  await openChannelMembers(reopened)
  await reopened.getByRole('button', { name: 'Remove Member ports 2', exact: true }).click()
  const removal = reopened.locator('[data-control-membership="change"]')
  await expect(removal).toHaveAttribute('data-control-membership-outcome', 'allowed')
  await expect(removal).toContainText(/member\(s\) removed/)
  await reopened.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const removedRow = reopened.getByRole('table', { name: 'Port changes' })
    .getByRole('row', { name: /Member ports/ })
  await expect(removedRow.getByRole('cell').nth(3)).toContainText(interfaceName(plan, removedMember))
  await expect(removedRow.getByRole('cell').nth(4)).not.toContainText(interfaceName(plan, removedMember))
  await reopened.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  const repaired = await viewDraft(page)
  expect(channelMembersOf(repaired)).toEqual(expectedRemaining)
  expect(await (await request.get(revisions(id))).json()).toHaveLength(2)
})

test('keeps UNKNOWN added-member evidence editable while combining proposed LACP and Port-Channel', async ({ page, request }, info) => {
  test.setTimeout(120_000)
  const id = await createEvent(request, 'Synthetic channel membership UNKNOWN')
  const plan = channelPlan(id, { image: '17.12.2r' })
  const saved = await planRecord(request, plan)
  const exportUrl = revisions(id) + '/' + saved.id + '/export'
  const historical = await request.get(exportUrl)
  const historicalBody = await historical.body()
  const historicalEtag = historical.headers().etag
  const interfaces = plan.physical_interfaces as RecordValue[]
  const third = String(interfaces[2]!.id!)
  const exchanges = captureCapabilityPreviews(page)
  await openWorkspace(page, id)
  const modal = await openChannelEditor(page)
  const members = await openChannelMembers(modal)
  await members.getByRole('button', { name: 'Add entry', exact: true }).click()
  await members.getByLabel('Member ports 3', { exact: true }).selectOption(third)
  const membership = modal.locator('[data-control-membership="change"]')
  await expect(membership).toHaveAttribute('data-control-membership-outcome', 'warning', { timeout: 15_000 })
  await expect(membership.locator('[data-control-member="' + third + '"]'))
    .toHaveAttribute('data-control-outcome', 'warning')
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel.getByText('UNKNOWN', { exact: true }).first()).toBeVisible()
  await page.screenshot({ path: info.outputPath('channel-membership-unknown-1280.png') })
  await expect.poll(() => exchanges.filter((exchange) => {
    const channel = (exchange.body.plan.port_channels as RecordValue[])[0]!
    const ids = (channel.member_ids as string[])
    return ids.includes(third) && exchange.response
  }).length, { timeout: 10_000 }).toBeGreaterThan(0)
  const unknownExchange = exchanges.find((exchange) => {
    const channel = (exchange.body.plan.port_channels as RecordValue[])[0]!
    return (channel.member_ids as string[]).includes(third) && exchange.response
  })!
  const channelDecisions = unknownExchange.response!.decisions
    .filter((decision) => decision.capability_id === 'port-channel' || decision.capability_id === 'lacp')
  expect(channelDecisions.length).toBeGreaterThan(0)
  for (const decision of channelDecisions) {
    expect(decision.verdict).toBe('unknown')
    expect(decision.reason_code).toBe('software-is-rommon')
  }

  await modal.getByLabel('LACP mode operation', { exact: true }).selectOption('set')
  await modal.getByLabel('LACP mode', { exact: true }).selectOption('active')
  await expect(membership.getByText(/LACP negotiation evidence is also required/)).toBeVisible()
  await expect(membership).toHaveAttribute('data-control-membership-outcome', 'warning')
  await modal.getByLabel('LACP mode', { exact: true }).selectOption('static')
  await expect(membership.getByText(/LACP negotiation evidence is also required/)).toHaveCount(0)
  await expect(membership).toHaveAttribute('data-control-membership-outcome', 'warning')
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const controls = modal.getByRole('table', { name: 'Capability controls for the proposed change' })
  await expect(controls.getByRole('row', { name: /Member ports/ }))
    .toHaveAttribute('data-control-outcome', 'warning')
  await expect(modal.getByRole('button', { name: 'Apply to draft', exact: true })).toBeEnabled()
  await modal.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  const draft = await viewDraft(page)
  expect((draft.port_channels as RecordValue[])[0]!.lacp).toBe('static')
  expect(channelMembersOf(draft)).toContain(third)
  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)
  await page.getByRole('button', { name: 'Save revision', exact: true }).click()
  await expect(page.getByText('Revision 2 saved.', { exact: true })).toBeVisible({ timeout: 15_000 })
  const unchanged = await request.get(exportUrl)
  expect(await unchanged.body()).toEqual(historicalBody)
  expect(unchanged.headers().etag).toBe(historicalEtag)
})

test('replacement members and late responses cannot restore the old evidence', async ({ page, request }) => {
  test.setTimeout(120_000)
  const id = await createEvent(request, 'Synthetic channel membership replacement')
  const plan = channelPlan(id)
  const saved = await planRecord(request, plan)
  const exportUrl = revisions(id) + '/' + saved.id + '/export'
  const historical = await request.get(exportUrl)
  const historicalBody = await historical.body()
  const historicalEtag = historical.headers().etag
  const interfaces = plan.physical_interfaces as RecordValue[]
  const [, , third] = interfaces.map((item) => String(item.id))
  const initialMembers = await channelMembersFromRevision(request, id, saved.id)
  expect(initialMembers).toHaveLength(2)
  const removedMember = initialMembers[1]!
  const expectedProposed = [initialMembers[0]!, third!]
  await page.route('**/api/v1/events/*/plan/capability-preview', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 700))
    await route.continue()
  })
  const exchanges = captureCapabilityPreviews(page)
  await openWorkspace(page, id)
  const modal = await openChannelEditor(page)
  const members = await openChannelMembers(modal)
  await modal.getByRole('button', { name: 'Remove Member ports 2', exact: true }).click()
  await members.getByRole('button', { name: 'Add entry', exact: true }).click()
  await members.getByLabel('Member ports 2', { exact: true }).selectOption(third!)
  const membership = modal.locator('[data-control-membership="change"]')
  await expect(membership).toHaveAttribute('data-control-membership-outcome', 'allowed', { timeout: 20_000 })
  await expect(membership.locator('[data-control-member="' + third + '"]'))
    .toHaveAttribute('data-control-outcome', 'allowed')
  await expect(modal.locator('.capability-target')).toHaveCount(2)
  await expect.poll(() => exchanges.filter((exchange) =>
    membersAre(exchange.body.plan, expectedProposed) && exchange.response).length,
  { timeout: 20_000 }).toBe(2)
  const replaced = exchanges.filter((exchange) =>
    membersAre(exchange.body.plan, expectedProposed) && exchange.response)
  for (const exchange of replaced) {
    expect(exchange.response!.decisions.every((decision) =>
      decision.affected.interface_id === exchange.body.interface_id)).toBe(true)
    expect(channelMembersOf(exchange.body.plan)).toEqual(expectedProposed)
  }
  await page.waitForTimeout(1_200)
  await expect(modal.locator('.capability-target')).toHaveCount(2)
  await expect(membership.locator('[data-control-member]')).toHaveCount(1)
  await expect(membership.locator('[data-control-member="' + removedMember + '"]')).toHaveCount(0)
  await expect(membership).toHaveAttribute('data-control-membership-outcome', 'allowed')
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const memberRow = modal.getByRole('table', { name: 'Port changes' })
    .getByRole('row', { name: /Member ports/ })
  await expect(memberRow.getByRole('cell').nth(3))
    .toContainText(interfaceName(plan, removedMember))
  await expect(memberRow.getByRole('cell').nth(4)).toContainText(interfaceName(plan, third!))
  await expect(memberRow.getByRole('cell').nth(4))
    .not.toContainText(interfaceName(plan, removedMember))
  const controls = modal.getByRole('table', { name: 'Capability controls for the proposed change' })
  await expect(controls.getByRole('row', { name: /Member ports/ })
    .getByRole('cell').nth(2)).toHaveText(interfaceName(plan, third!))
  await modal.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  const draft = await viewDraft(page)
  expect(channelMembersOf(draft)).toEqual(expectedProposed)
  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)
  const unchanged = await request.get(exportUrl)
  expect(await unchanged.body()).toEqual(historicalBody)
  expect(unchanged.headers().etag).toBe(historicalEtag)
})

test('allows a member-order-only change without capability evidence or dropped members', async ({ page, request }) => {
  test.setTimeout(90_000)
  const id = await createEvent(request, 'Synthetic channel member order')
  const plan = channelPlan(id)
  const saved = await planRecord(request, plan)
  const exportUrl = revisions(id) + '/' + saved.id + '/export'
  const historical = await request.get(exportUrl)
  const historicalBody = await historical.body()
  const historicalEtag = historical.headers().etag
  const initialMembers = await channelMembersFromRevision(request, id, saved.id)
  expect(initialMembers).toHaveLength(2)
  const expectedSwapped = [initialMembers[1]!, initialMembers[0]!]
  await openWorkspace(page, id)
  const modal = await openChannelEditor(page)
  await openChannelMembers(modal)
  await modal.getByRole('button', { name: 'Move Member ports 2 up', exact: true }).click()
  const membership = modal.locator('[data-control-membership="change"]')
  await expect(membership).toHaveAttribute('data-control-membership-outcome', 'allowed')
  await expect(membership.locator('[data-control-member]')).toHaveCount(0)
  await expect(membership).toContainText(/Member order changed/)
  await expect(modal.getByRole('alert').filter({ hasText: 'Apply is blocked' })).toHaveCount(0)
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const memberRow = modal.getByRole('table', { name: 'Port changes' })
    .getByRole('row', { name: /Member ports/ })
  await expect(memberRow.getByRole('cell').nth(3)).toContainText(interfaceName(plan, initialMembers[0]!))
  await expect(memberRow.getByRole('cell').nth(4)).toContainText(interfaceName(plan, initialMembers[1]!))
  await modal.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  const draft = await viewDraft(page)
  expect(channelMembersOf(draft)).toEqual(expectedSwapped)
  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)
  const unchanged = await request.get(exportUrl)
  expect(await unchanged.body()).toEqual(historicalBody)
  expect(unchanged.headers().etag).toBe(historicalEtag)
})

test('judges a mixed Stack member by its own evidence instead of the first member', async ({ page, request }) => {
  test.setTimeout(120_000)
  const id = await createEvent(request, 'Synthetic mixed Stack channel member')
  const plan = mixedStackChannelPlan(id)
  const saved = await planRecord(request, plan)
  const exportUrl = revisions(id) + '/' + saved.id + '/export'
  const historical = await request.get(exportUrl)
  const historicalBody = await historical.body()
  const historicalEtag = historical.headers().etag
  const interfaces = plan.physical_interfaces as RecordValue[]
  const second = String(interfaces[1]!.id!)
  const assignmentId = String((plan.assignments as RecordValue[])[0]!.id!)
  const firstDecision = await previewDraft(request, id, plan, assignmentId,
    String(interfaces[0]!.id!), ['port-channel'])
  expect(decisionOf(firstDecision, 'port-channel').verdict).toBe('supported')
  const secondDecision = await previewDraft(request, id, plan, assignmentId,
    second, ['port-channel'])
  expect(decisionOf(secondDecision, 'port-channel').verdict).toBe('unknown')
  expect(decisionOf(secondDecision, 'port-channel').reason_code).toBe('identity-incomplete')
  await openWorkspace(page, id)
  const modal = await openChannelEditor(page)
  const members = await openChannelMembers(modal)
  await members.getByRole('button', { name: 'Add entry', exact: true }).click()
  await members.getByLabel('Member ports 2', { exact: true }).selectOption(second)
  const membership = modal.locator('[data-control-membership="change"]')
  await expect(membership).toHaveAttribute('data-control-membership-outcome', 'warning', { timeout: 15_000 })
  await expect(membership.locator('[data-control-member="' + second + '"]'))
    .toHaveAttribute('data-control-outcome', 'warning')
  await expect(membership.locator('[data-control-member]')).toHaveCount(1)
  const panel = modal.getByRole('region', { name: 'Cisco capability evidence' })
  await expect(panel.locator('.capability-target')).toHaveCount(2)
  await expect(panel.getByText('SUPPORTED', { exact: true }).first()).toBeVisible()
  await expect(panel.getByText('UNKNOWN', { exact: true }).first()).toBeVisible()
  await expect(modal.getByRole('alert').filter({ hasText: 'Apply is blocked' })).toHaveCount(0)
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const controls = modal.getByRole('table', { name: 'Capability controls for the proposed change' })
  const row = controls.getByRole('row', { name: /Member ports/ })
  await expect(row).toHaveAttribute('data-control-outcome', 'warning')
  await expect(row.getByRole('cell').nth(2)).toHaveText('Gi2/0/1')
  await expect(modal.getByRole('button', { name: 'Apply to draft', exact: true })).toBeEnabled()
  await modal.getByRole('button', { name: 'Apply to draft', exact: true }).click()
  const draft = await viewDraft(page)
  expect(channelMembersOf(draft)).toHaveLength(2)
  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)
  await page.getByRole('button', { name: 'Save revision', exact: true }).click()
  await expect(page.getByText('Revision 2 saved.', { exact: true })).toBeVisible({ timeout: 15_000 })
  const unchanged = await request.get(exportUrl)
  expect(await unchanged.body()).toEqual(historicalBody)
  expect(unchanged.headers().etag).toBe(historicalEtag)
})
