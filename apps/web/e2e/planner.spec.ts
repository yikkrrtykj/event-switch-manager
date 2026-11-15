import { createHash, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { expect, test } from '@playwright/test'
import type { APIRequestContext, Page } from '@playwright/test'
import type { Plan, RecordValue, Revision, Summary } from '../src/planner/model'

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
async function openWorkspace(page: Page, id: string, route = 'planner/addressing') {
  await page.goto('/?e2e-event=' + encodeURIComponent(id) + '#' + route)
  const context = page.getByLabel('Event', { exact: true })
  await expect(context).toBeVisible()
  await context.selectOption(id)
  await expect(page.getByRole('button', { name: 'Revision history' })).toBeEnabled()
}
async function importJson(page: Page, value: string) {
  await page.getByRole('button', { name: 'Import JSON' }).click()
  await page.getByRole('textbox', { name: 'Plan JSON' }).fill(value)
  await page.getByRole('button', { name: 'Load into draft' }).click()
}
async function addVlan(page: Page, id: number, name: string) {
  await page.getByRole('button', { name: 'Add VLAN', exact: true }).click()
  await page.getByLabel('VLAN ID', { exact: true }).fill(String(id))
  await page.getByLabel('Name', { exact: true }).fill(name)
  await page.getByRole('button', { name: 'Apply to draft' }).click()
}
async function addSubnet(page: Page, cidr: string) {
  await page.getByRole('button', { name: 'Add subnet', exact: true }).click()
  await page.getByLabel('VLAN', { exact: true }).selectOption('20')
  await page.getByLabel('IPv4 CIDR').fill(cidr)
  await page.getByRole('button', { name: 'Apply to draft' }).click()
}

test('edits VLAN and IP, locates a conflict and preserves the saved revision on JSON round trip', async ({ page, request }) => {
  const eventId = await createEvent(request, 'Synthetic addressing')
  await openWorkspace(page, eventId)
  await addVlan(page, 10, 'Management')
  await addVlan(page, 20, 'Players')
  await addSubnet(page, '192.168.20.0/24')
  await addSubnet(page, '192.168.20.128/25')
  await expect(page.getByText('Unsaved changes', { exact: true })).toBeVisible()
  page.once('dialog', (dialog) => dialog.dismiss())
  await page.getByRole('link', { name: 'Events', exact: true }).click()
  await expect(page).toHaveURL(/#planner\/addressing/)
  await page.getByRole('button', { name: 'Validate plan' }).click()
  await expect(page.getByText('INVALID', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Save revision' })).toBeDisabled()
  expect(await (await request.get(revisions(eventId))).json()).toEqual([])
  await page.getByRole('button', { name: /Locate subnet_overlap/ }).click()
  await expect(page.getByLabel('IPv4 CIDR')).toBeFocused()
  await page.getByLabel('IPv4 CIDR').fill('192.168.21.0/24')
  await page.getByRole('button', { name: 'Apply to draft' }).click()
  await page.getByRole('button', { name: 'Edit VLAN 20' }).click()
  await page.getByLabel('Name', { exact: true }).fill('Players stage')
  await page.getByRole('button', { name: 'Apply to draft' }).click()
  await page.getByRole('button', { name: 'Save revision' }).click()
  await expect(page.getByText('Revision 1 saved.')).toBeVisible()
  const summary = (await (await request.get(revisions(eventId))).json() as Summary[])[0]
  expect(summary).toBeDefined()
  const entry = summary!
  await page.getByText('Revision 1', { exact: true }).click()
  await expect(page.getByText(entry.id, { exact: true })).toBeVisible()
  await expect(page.getByText(entry.content_hash, { exact: true })).toBeVisible()
  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('link', { name: 'Export revision' }).click()
  const download = await downloadPromise
  const payload = await readFile(await download.path(), 'utf8')
  expect(createHash('sha256').update(payload).digest('hex')).toBe(entry.content_hash)
  await importJson(page, payload)
  await page.getByRole('button', { name: 'Save revision' }).click()
  await expect(page.getByText('Revision 1 saved.')).toBeVisible()
  expect(await (await request.get(revisions(eventId))).json()).toEqual([entry])
  const other = await createEvent(request, 'Synthetic isolation')
  await page.reload()
  await page.getByLabel('Event', { exact: true }).selectOption(other)
  await expect(page.getByRole('button', { name: 'Add VLAN', exact: true })).toBeVisible()
  await expect(page.getByText('Players stage')).toHaveCount(0)
  await importJson(page, payload)
  await expect(page.getByRole('alert')).toHaveText('This plan belongs to another event.')
})

function stackPlan(eventId: string): Plan {
  const first = randomUUID()
  const second = randomUUID()
  const assignment = randomUUID()
  return {
    event_id: eventId, schema_version: 1, management_vlan: 10,
    vlans: [{ id: 10, name: 'Management', purpose: 'management' }, { id: 20, name: 'Players' }],
    subnets: [{ id: randomUUID(), vlan: 20, network: '192.168.20.0/24' }],
    physical_devices: [{ id: first, vendor: 'cisco', model: 'Catalyst 9300' },
      { id: second, vendor: 'cisco', model: 'Catalyst 9300' }],
    assignments: [{ id: assignment, hostname: 'Synthetic-Core', role: 'core', family: 'catalyst-9300',
      physical_device_id: first, management_ip: '192.168.10.11', location: 'Control room' }],
    stacks: [{ assignment_id: assignment, members: [
      { number: 1, physical_device_id: first }, { number: 2, physical_device_id: second },
    ] }],
    physical_interfaces: [first, second].map((id, index) => ({
      id: randomUUID(), assignment_id: assignment, physical_device_id: id, name: 'Gi' + (index + 1) + '/0/7',
      stack_member: index + 1, settings: { mode: 'access', access_vlan: 20 },
    })),
  }
}

test('groups real interface names by Stack member and saves a warning-only bulk edit', async ({ page, request }) => {
  const id = await createEvent(request, 'Synthetic Stack')
  const plan = stackPlan(id)
  const port = portsOf(plan)[0]!
  port.settings = { ...port.settings as RecordValue, description: 'Synthetic patch panel A',
    admin_state: 'down', speed: 'auto', duplex: 'full', poe_mode: 'never', portfast: 'disabled', bpdu_guard: 'disabled' }
  const fixture = await planRecord(request, plan)
  expect(fixture.validation_status).toBe('VALID_WITH_WARNINGS')
  await openWorkspace(page, id, 'ports')
  await expect(page.getByRole('row', { name: /Synthetic-Core · Stack member 2/ })).toBeVisible()
  await expect(page.getByRole('row', { name: /Gi1\/0\/7.*UNVERIFIED/ })).toBeVisible()
  await page.getByLabel('Filter ports by Stack member').selectOption('1')
  await expect(page.getByRole('checkbox', { name: 'Select port Gi2/0/7' })).toHaveCount(0)
  await page.getByLabel('Filter ports by Stack member').selectOption('')
  await page.getByRole('checkbox', { name: 'Select all visible ports' }).check()
  await page.getByRole('button', { name: 'Batch edit (2)' }).click()
  await page.getByLabel('Mode', { exact: true }).selectOption('trunk')
  await page.getByRole('button', { name: 'Add entry' }).click()
  await page.getByRole('combobox', { name: 'Allowed VLANs 1', exact: true }).selectOption('20')
  await previewPorts(page, 'Confirm and apply to draft')
  await expect(page.getByRole('row', { name: /Gi2\/0\/7.*trunk/ })).toBeVisible()
  await page.getByRole('button', { name: 'Validate plan' }).click()
  await expect(page.getByText('VALID_WITH_WARNINGS', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Save revision' })).toBeEnabled()
  await page.getByRole('button', { name: 'Save revision' }).click()
  await expect(page.getByText('Revision 2 saved.')).toBeVisible()
  const stored = await request.get(revisions(id))
  const current = (await stored.json() as Summary[]).at(-1)!
  const latest = await (await request.get(revisions(id) + '/' + current.id)).json() as Revision
  expect(latest.plan.physical_interfaces).toEqual(expect.arrayContaining([
    expect.objectContaining({ name: 'Gi1/0/7', settings: expect.objectContaining({
      mode: 'trunk', allowed_vlans: [20], description: 'Synthetic patch panel A', admin_state: 'down',
      speed: 'auto', duplex: 'full', poe_mode: 'never', portfast: 'disabled', bpdu_guard: 'disabled',
    }) }),
    expect.objectContaining({ name: 'Gi2/0/7', settings: expect.objectContaining({ mode: 'trunk', allowed_vlans: [20] }) }),
  ]))
  await page.getByRole('button', { name: 'Revision history' }).click()
  await page.getByRole('button', { name: 'Compare revision 1' }).click()
  await expect(page.getByRole('dialog', { name: 'Compare revision 1' })).toContainText('Physical ports')
})

test('reads an INVALID historical revision without offering a direct save', async ({ page, request }) => {
  const first = await createEvent(request, 'Synthetic legacy revision')
  const second = await createEvent(request, 'Synthetic asset registration')
  const chassis = randomUUID()
  const legacy = await planRecord(request, { event_id: first, schema_version: 1, management_vlan: 10,
    physical_devices: [{ id: chassis, vendor: 'cisco' }] })
  await planRecord(request, { event_id: second, schema_version: 1, management_vlan: 10,
    physical_devices: [{ id: chassis, vendor: 'hillstone', verified_serial: 'SYN-PLANNER-FW' }] })
  const exported = await request.get(revisions(first) + '/' + legacy.id + '/export')
  const bytes = await exported.body()
  const tag = exported.headers().etag
  expect(createHash('sha256').update(bytes).digest('hex')).toBe(legacy.content_hash)
  expect(tag).toBe('"' + legacy.content_hash + '"')
  const exact = await request.post(revisions(first), { headers, data: JSON.parse(bytes.toString('utf8')) })
  expect(exact.status()).toBe(200)
  expect(await exact.json()).toMatchObject({ id: legacy.id, validation_status: 'INVALID' })

  await openWorkspace(page, first, 'devices')
  await expect(page.getByText('Read-only revision', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Revision history' }).click()
  await page.getByRole('button', { name: 'Open revision 1' }).click()
  await expect(page.getByText('Read-only revision', { exact: true })).toBeVisible()
  await expect(page.getByText('INVALID', { exact: true })).toBeVisible()
  await expect(page.getByText('physical_identity', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Save revision' })).toHaveCount(0)
  await page.getByText('Revision 1', { exact: true }).click()
  await expect(page.getByText(legacy.content_hash, { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Copy to draft' }).click()
  await expect(page.getByText('NOT VALIDATED', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Save revision' })).toBeDisabled()
  await page.getByRole('button', { name: 'Validate plan' }).click()
  await expect(page.getByText('INVALID', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Save revision' })).toBeDisabled()
  await page.getByRole('button', { name: 'Edit chassis cisco' }).click()
  await page.getByLabel('Vendor', { exact: true }).selectOption('hillstone')
  await page.getByRole('button', { name: 'Apply to draft' }).click()
  await expect(page.getByRole('button', { name: 'Save revision' })).toBeDisabled()
  await page.getByRole('button', { name: 'Validate plan' }).click()
  await expect(page.getByText('VALID_WITH_WARNINGS', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Save revision' }).click()
  await expect(page.getByText('Revision 2 saved.')).toBeVisible()
  const original = await request.get(revisions(first) + '/' + legacy.id)
  expect(await original.json()).toMatchObject({ id: legacy.id, number: 1, content_hash: legacy.content_hash })
  const unchanged = await request.get(revisions(first) + '/' + legacy.id + '/export')
  expect(await unchanged.body()).toEqual(bytes)
  expect(unchanged.headers().etag).toBe(tag)
})

test('captures responsive workbench views and keyboard, contrast, motion and data states', async ({ page, request }, info) => {
  test.setTimeout(75_000)
  const id = await createEvent(request, 'Synthetic tournament — screenshot data')
  await planRecord(request, stackPlan(id))
  await openWorkspace(page, id)
  for (const width of [1280, 1440, 1920, 800, 320]) {
    await page.setViewportSize({ width, height: 850 })
    await expect(page.getByRole('table', { name: 'VLANs', exact: true })).toBeVisible()
    await expect(page.getByRole('cell', { name: '192.168.20.0/24', exact: true })).toHaveCSS('position', 'static')
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width + 1)
    await page.screenshot({ path: info.outputPath('planner-' + width + '.png'), fullPage: true })
  }
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.emulateMedia({ reducedMotion: 'reduce' })
  const primary = page.getByRole('button', { name: 'Save revision' })
  await expect(primary).toHaveCSS('transition-duration', '0s')
  const contrast = await primary.evaluate((node) => {
    const style = getComputedStyle(node)
    const luminance = (color: string) => {
      const channels = color.match(/[\d.]+/g)!.slice(0, 3).map((part) => {
        const value = Number(part) / 255
        return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4
      })
      return (channels[0] ?? 0) * 0.2126 + (channels[1] ?? 0) * 0.7152 + (channels[2] ?? 0) * 0.0722
    }
    const a = luminance(style.color)
    const b = luminance(style.backgroundColor)
    return (Math.max(a, b) + .05) / (Math.min(a, b) + .05)
  })
  expect(contrast).toBeGreaterThanOrEqual(4.5)
  await page.getByRole('link', { name: 'Port Editor', exact: true }).click()
  const ports = page.locator('[data-slot="table-container"][aria-label="Physical ports"]')
  await expect(ports.getByRole('row', { name: /Gi2\/0\/7/ })).toBeVisible()
  expect(await ports.evaluate((element) => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1)
  await page.screenshot({ path: info.outputPath('ports-1440.png'), fullPage: true })
  await page.goto('/')
  await page.keyboard.press('Tab')
  await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused()
  await expect(page.getByRole('link', { name: 'Skip to content' })).toHaveCSS('outline-style', 'solid')
  await page.keyboard.press('Enter')
  await expect(page.locator('main')).toBeFocused()

  let release: () => void = () => {}
  const suspended = new Promise<void>((resolve) => { release = resolve })
  // Hold the revision list for one event to capture the loading state before a controlled failure.
  await page.route('**' + revisions(id), async (route) => {
    await suspended
    await route.fulfill({ status: 503, json: { detail: 'Synthetic outage' } })
  }, { times: 1 })
  await page.getByRole('link', { name: 'Network Planner', exact: true }).click()
  await page.getByLabel('Event', { exact: true }).selectOption(id)
  try {
    await expect(page.getByText('Loading event plan…')).toBeVisible()
    await page.screenshot({ path: info.outputPath('loading-1440.png') })
  } finally { release() }
  await expect(page.getByRole('alert')).toContainText('Unable to load the event plan.')
  await page.screenshot({ path: info.outputPath('error-1440.png') })
  await page.getByRole('button', { name: 'Retry', exact: true }).click()
  await expect(page.getByRole('table', { name: 'VLANs', exact: true })).toBeVisible()

  const empty = await createEvent(request, 'Synthetic empty state')
  await openWorkspace(page, empty)
  await expect(page.getByText('No records yet.').first()).toBeVisible()
  await page.screenshot({ path: info.outputPath('empty-1440.png'), fullPage: true })
})


function portsOf(plan: Plan) {
  return plan.physical_interfaces as RecordValue[]
}

test('resets port selections on filters, event and revision changes and saves only confirmed targets', async ({ page, request }, info) => {
  const id = await createEvent(request, 'Synthetic selection scope')
  const other = await createEvent(request, 'Synthetic separate port scope')
  const plan = stackPlan(id)
  const external = randomUUID()
  const chassis = randomUUID()
  plan.physical_devices = [...plan.physical_devices as RecordValue[], { id: chassis, vendor: 'cisco' }]
  plan.assignments = [...plan.assignments as RecordValue[], {
    id: external, hostname: 'Synthetic-Access', role: 'access', physical_device_id: chassis,
  }]
  plan.vlans = [...plan.vlans as RecordValue[], { id: 30, name: 'Observers' }]
  const firstPort = portsOf(plan)[0]!
  plan.physical_interfaces = [
    { ...firstPort, settings: { mode: 'trunk', native_vlan: 10, allowed_vlans: [10, 20] } },
    portsOf(plan)[1]!,
    { ...firstPort, id: randomUUID(), name: 'Gi1/0/9' },
    {
      id: randomUUID(), assignment_id: external, physical_device_id: chassis, name: 'Gi0/1',
      settings: { mode: 'trunk', native_vlan: 20, allowed_vlans: [10, 20] },
    },
  ]
  const baseline = await planRecord(request, plan)
  await planRecord(request, { ...plan, vlans: (plan.vlans as RecordValue[]).map((vlan) =>
    vlan.id === 20 ? { ...vlan, name: 'Players next' } : vlan) })
  await planRecord(request, stackPlan(other))

  await openWorkspace(page, id, 'ports')
  const member = page.getByLabel('Filter ports by Stack member')
  const device = page.getByLabel('Filter ports by device')
  const search = page.getByRole('searchbox', { name: 'Search Physical ports' })
  const port = (name: string) => page.getByRole('checkbox', { name: 'Select port ' + name, exact: true })
  const cleared = () => expect(page.getByRole('button', { name: 'Batch edit (0)' })).toBeDisabled()

  await member.selectOption('1')
  await port('Gi1/0/7').check()
  await member.selectOption('2')
  await cleared()
  await expect(port('Gi2/0/7')).not.toBeChecked()
  await member.selectOption('')
  await expect(port('Gi1/0/7')).not.toBeChecked()

  await port('Gi1/0/7').check()
  await device.selectOption(external)
  await cleared()
  await expect(port('Gi0/1')).not.toBeChecked()
  await device.selectOption('')
  await port('Gi2/0/7').check()
  await search.fill('Gi0/1')
  await cleared()
  await search.fill('')
  await expect(port('Gi2/0/7')).not.toBeChecked()

  await port('Gi1/0/7').check()
  await page.getByLabel('Event', { exact: true }).selectOption(other)
  await expect(port('Gi1/0/7')).toBeVisible()
  await cleared()
  await page.getByLabel('Event', { exact: true }).selectOption(id)
  await port('Gi1/0/7').check()
  await page.getByRole('button', { name: 'Revision history' }).click()
  await page.getByRole('button', { name: 'Open revision 1' }).click()
  await expect(page.getByText('Read-only revision', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Copy to draft' }).click()
  await cleared()
  await expect(port('Gi1/0/7')).not.toBeChecked()

  await port('Gi1/0/7').check()
  await port('Gi0/1').check()
  await page.getByRole('button', { name: 'Batch edit (2)' }).click()
  const targets = page.getByRole('table', { name: 'Target ports' })
  await expect(targets.getByRole('row', { name: /Synthetic-Core Stack member 1 Gi1\/0\/7/ })).toBeVisible()
  await expect(targets.getByRole('row', { name: /Synthetic-Access Standalone Gi0\/1/ })).toBeVisible()
  await expect(targets.getByText('Gi2/0/7', { exact: true })).toHaveCount(0)
  await page.screenshot({ path: info.outputPath('confirmed-port-targets.png') })
  await expect(page.getByLabel('Mode', { exact: true })).toHaveValue('trunk')
  await expect(page.getByLabel('Allowed VLANs 1', { exact: true })).toHaveValue('10')
  await expect(page.getByLabel('Allowed VLANs 2', { exact: true })).toHaveValue('20')
  await page.getByRole('button', { name: 'Add entry', exact: true }).click()
  await page.getByLabel('Allowed VLANs 3', { exact: true }).selectOption('30')
  await previewPorts(page, 'Apply to 2 ports')
  await cleared()
  await expect(page.getByRole('button', { name: 'Save revision' })).toBeDisabled()
  await page.getByRole('button', { name: 'Validate plan' }).click()
  await expect(page.getByText('VALID_WITH_WARNINGS', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Save revision' }).click()
  await expect(page.getByText('Revision 3 saved.')).toBeVisible()

  const history = await (await request.get(revisions(id))).json() as Summary[]
  const latest = await (await request.get(revisions(id) + '/' + history.at(-1)!.id)).json() as Revision
  const originals = portsOf(baseline.plan)
  expect(portsOf(latest.plan)).toHaveLength(originals.length)
  const edited = new Set(['Gi1/0/7', 'Gi0/1'])
  for (const original of originals) {
    const saved = portsOf(latest.plan).find((item) => item.id === original.id)
    expect(saved).toEqual(edited.has(String(original.name)) ? {
      ...original, settings: { ...original.settings as RecordValue, allowed_vlans: [10, 20, 30] },
    } : original)
  }
  expect((await (await request.get(revisions(other))).json() as Summary[])).toHaveLength(1)
})


async function holdResponse(page: Page, url: string) {
  let captured!: () => void
  let resume!: () => void
  let done!: () => void
  const arrived = new Promise<void>((resolve) => { captured = resolve })
  const hold = new Promise<void>((resolve) => { resume = resolve })
  const completed = new Promise<void>((resolve) => { done = resolve })
  await page.route(url, async (route) => {
    try {
      const response = await route.fetch()
      captured()
      await hold
      await route.fulfill({ response })
    } catch {
      // The browser can cancel the intercepted request when the operation is abandoned.
    } finally { done() }
  }, { times: 1 })
  return { arrived, release: async () => { resume(); await completed } }
}

test('a dismissed revision read cannot replace the next revision', async ({ page, request }) => {
  const id = await createEvent(request, 'Synthetic revision race')
  const first = await planRecord(request, {
    event_id: id, schema_version: 1, management_vlan: 10, vlans: [{ id: 10, name: 'Older VLAN' }],
  })
  await planRecord(request, {
    ...first.plan, vlans: [{ id: 10, name: 'Current VLAN' }],
  })
  await openWorkspace(page, id)
  const older = await holdResponse(page, '**' + revisions(id) + '/' + first.id)
  try {
    await page.getByRole('button', { name: 'Revision history' }).click()
    await page.getByRole('button', { name: 'Open revision 1' }).click()
    await older.arrived
    await page.keyboard.press('Escape')
    await page.getByRole('button', { name: 'Revision history' }).click()
    await page.getByRole('button', { name: 'Open revision 2' }).click()
    await expect(page.getByText('Read-only revision', { exact: true })).toBeVisible()
  } finally { await older.release() }
  await expect(page.getByRole('cell', { name: 'Current VLAN', exact: true })).toBeVisible()
  await expect(page.getByText('Older VLAN', { exact: true })).toHaveCount(0)
  await expect(page.getByText('Revision 2', { exact: true })).toBeVisible()
})

test('switching events during pre-save validation abandons the pending save', async ({ page, request }) => {
  const first = await createEvent(request, 'Synthetic pending save')
  const second = await createEvent(request, 'Synthetic destination event')
  await planRecord(request, {
    event_id: first, schema_version: 1, management_vlan: 10, vlans: [{ id: 10, name: 'Old event VLAN' }],
  })
  await planRecord(request, {
    event_id: second, schema_version: 1, management_vlan: 10, vlans: [{ id: 10, name: 'New event VLAN' }],
  })
  await openWorkspace(page, first)
  await page.getByRole('button', { name: 'Edit VLAN 10' }).click()
  await page.getByLabel('Name', { exact: true }).fill('Abandoned draft VLAN')
  await page.getByRole('button', { name: 'Apply to draft' }).click()
  const check = await holdResponse(page, '**' + api + '/' + first + '/plan/validate')
  const sent: string[] = []
  page.on('request', (req) => {
    if (req.method() === 'POST' && new URL(req.url()).pathname === revisions(first)) sent.push(req.url())
  })
  try {
    await page.getByRole('button', { name: 'Save revision' }).click()
    await check.arrived
    page.once('dialog', (dialog) => dialog.accept())
    await page.getByLabel('Event', { exact: true }).selectOption(second)
    await expect(page.getByRole('cell', { name: 'New event VLAN', exact: true })).toBeVisible()
  } finally { await check.release() }
  await expect(page.getByRole('cell', { name: 'New event VLAN', exact: true })).toBeVisible()
  await expect(page.getByText('Abandoned draft VLAN', { exact: true })).toHaveCount(0)
  expect(sent).toEqual([])
  expect(await (await request.get(revisions(first))).json()).toHaveLength(1)
  expect(await (await request.get(revisions(second))).json()).toHaveLength(1)
})

function auditPlan(eventId: string): Plan {
  const [core1, core2, fw, core, firewall, coreTransit, fwTransit, member1, member2,
    primaryWan, secondaryWan, transitSvi, mgmtSvi, aggregate, link, subnet, pool, reservation,
    uplinkTrack, backupTrack, tunnelTrack, primary, backup, tunnel, returnRoute,
    vpnRoute, drop, defaultRoute, sbr, pbr, snat1, snat2, exempt] = Array.from({ length: 33 }, () => randomUUID()) as string[]
  const access = { mode: 'access', access_vlan: 9 }
  const trunk = { mode: 'trunk', native_vlan: 10, allowed_vlans: [10, 20] }
  const id = (value: string | undefined) => value!
  return {
    event_id: eventId, schema_version: 1, management_vlan: 10,
    physical_devices: [{ id: id(core1), vendor: 'cisco' }, { id: id(core2), vendor: 'cisco' }, { id: id(fw), vendor: 'hillstone' }],
    assignments: [
      { id: id(core), hostname: 'Audit-Core', role: 'core', physical_device_id: id(core1),
        software: { image: 'SYN-17.12', license: 'SYN-ADV', capabilities: [] } },
      { id: id(firewall), hostname: 'Audit-FW', role: 'access', physical_device_id: id(fw) },
    ],
    stacks: [{ assignment_id: id(core), members: [{ number: 1, physical_device_id: id(core1) },
      { number: 2, physical_device_id: id(core2) }] }],
    physical_interfaces: [
      { id: id(coreTransit), assignment_id: id(core), physical_device_id: id(core1), name: 'Gi1/0/1', stack_member: 1, settings: access },
      { id: id(fwTransit), assignment_id: id(firewall), physical_device_id: id(fw), name: 'ethernet0/0', settings: access },
      { id: id(member1), assignment_id: id(core), physical_device_id: id(core1), name: 'Gi1/0/2', stack_member: 1, settings: trunk },
      { id: id(member2), assignment_id: id(core), physical_device_id: id(core2), name: 'Gi2/0/2', stack_member: 2, settings: trunk },
      { id: id(primaryWan), assignment_id: id(firewall), physical_device_id: id(fw), name: 'ethernet0/1', settings: { mode: 'routed', address: '192.0.2.2/30' } },
      { id: id(secondaryWan), assignment_id: id(firewall), physical_device_id: id(fw), name: 'ethernet0/2', settings: { mode: 'routed', address: '198.51.100.2/30' } },
    ],
    logical_interfaces: [
      { id: id(transitSvi), assignment_id: id(core), name: 'Vlan9', kind: 'svi', vlan: 9, address: '10.0.0.1/30' },
      { id: id(mgmtSvi), assignment_id: id(core), name: 'Vlan10', kind: 'svi', vlan: 10, address: '192.168.10.1/24' },
      { id: id(aggregate), assignment_id: id(core), name: 'Port-channel1', kind: 'port-channel' },
    ],
    port_channels: [{ interface_id: id(aggregate), number: 1, member_ids: [id(member1), id(member2)], settings: trunk }],
    links: [{ id: id(link), endpoints: [id(coreTransit), id(fwTransit)] }],
    vlans: [{ id: 9, name: 'Transit', purpose: 'transit' }, { id: 10, name: 'Management', purpose: 'management' }, { id: 20, name: 'Players' }],
    subnets: [{ id: id(subnet), vlan: 10, network: '192.168.10.0/24' }],
    gateways: [{ subnet_id: id(subnet), address: '192.168.10.1', svi_id: id(mgmtSvi) }],
    dhcp_pools: [{ id: id(pool), subnet_id: id(subnet), start: '192.168.10.20', end: '192.168.10.40' }],
    dhcp_reservations: [{ id: id(reservation), subnet_id: id(subnet), address: '192.168.10.10', client_mac: '02:00:00:00:00:01' }],
    dhcp_relays: [{ subnet_id: id(subnet), svi_id: id(mgmtSvi), servers: ['192.168.10.5'] }],
    transit: { core_assignment_id: id(core), hillstone_assignment_id: id(firewall), core_port_id: id(coreTransit),
      hillstone_port_id: id(fwTransit), core_svi_id: id(transitSvi), network: '10.0.0.0/30', core_ip: '10.0.0.1', hillstone_ip: '10.0.0.2' },
    tracks: [{ id: id(uplinkTrack), target: '192.0.2.1' }, { id: id(backupTrack), target: '198.51.100.1' },
      { id: id(tunnelTrack), target: '10.0.1.2', tunnel_id: id(tunnel) }],
    isps: [
      { id: id(primary), name: 'Primary', assignment_id: id(firewall), interface_id: id(primaryWan), address: '192.0.2.2/30', gateway: '192.0.2.1',
        track_id: id(uplinkTrack), routed_public_blocks: [{ network: '203.0.113.8/29', reason: 'Synthetic routed block' }] },
      { id: id(backup), name: 'Secondary', assignment_id: id(firewall), interface_id: id(secondaryWan), address: '198.51.100.2/30',
        gateway: '198.51.100.1', track_id: id(backupTrack) },
    ],
    ipsec_tunnels: [{ id: id(tunnel), name: 'Audit VPN', assignment_id: id(firewall), isp_id: id(primary),
      peer: '203.0.113.2', inside: '10.0.1.1/30', remote_gateway: '10.0.1.2', track_id: id(tunnelTrack) }],
    vpn_remote_prefixes: [{ tunnel_id: id(tunnel), network: '172.16.20.0/24' }],
    static_routes: [
      { id: id(returnRoute), assignment_id: id(firewall), destination: '192.168.0.0/16', next_hop: { kind: 'ip', address: '10.0.0.1' } },
      { id: id(vpnRoute), assignment_id: id(firewall), destination: '172.16.20.0/24', next_hop: { kind: 'tunnel', tunnel_id: id(tunnel) },
        activation: { kind: 'track', track_id: id(tunnelTrack), state: 'up' } },
      { id: id(drop), assignment_id: id(firewall), destination: '172.16.20.0/24', next_hop: { kind: 'discard' }, preference: 200, activation: { kind: 'always' } },
    ],
    default_routes: [{ id: id(defaultRoute), assignment_id: id(core), next_hop: { kind: 'ip', address: '10.0.0.2' } }],
    source_routes: [{ id: id(sbr), assignment_id: id(firewall), source_vlan: 20, isp_priority: [id(primary), id(backup)] }],
    policy_routes: [{ id: id(pbr), assignment_id: id(firewall), source_vlan: 20, priority: 10, destination: '172.16.20.0/24', tunnel_id: id(tunnel) }],
    snat: [
      { id: id(snat1), assignment_id: id(firewall), source_vlan: 20, isp_id: id(primary), translated_ip: '192.0.2.2' },
      { id: id(snat2), assignment_id: id(firewall), source_vlan: 20, isp_id: id(backup), translated_ip: '198.51.100.2' },
    ],
    nat_exemptions: [{ id: id(exempt), assignment_id: id(firewall), source_vlan: 20, destination: '172.16.20.0/24', tunnel_id: id(tunnel) }],
  }
}

test('saves a consistent network through the planner forms and preserves untouched plan data', async ({ page, request }) => {
  test.setTimeout(60_000)
  const id = await createEvent(request, 'Synthetic plan editor round trip')
  const original = await planRecord(request, auditPlan(id))
  await openWorkspace(page, id, 'planner/dhcp')
  const apply = () => page.getByRole('button', { name: 'Apply to draft' }).click()
  const edit = (name: string | RegExp) => page.getByRole('button', { name }).click()
  const records = (plan: Plan, key: string) => plan[key] as RecordValue[]

  await edit(/^Edit pool/)
  await page.getByLabel('Lease seconds', { exact: true }).fill('7200')
  await apply()
  await edit(/^Edit relay/)
  await page.getByLabel('Relay server addresses (JSON array)', { exact: true }).fill('["192.168.10.6","192.168.10.7"]')
  await apply()

  await page.getByRole('link', { name: 'Transit', exact: true }).click()
  await edit('Edit transit 9 — Transit')
  const coreSvi = page.getByLabel('Core SVI', { exact: true })
  await expect(coreSvi.locator('option').filter({ hasText: 'Port-channel1' })).toHaveCount(0)
  await apply()

  await page.getByRole('link', { name: 'ISP & NAT', exact: true }).click()
  await edit('Edit Track 192.0.2.1')
  await page.getByLabel('Interval seconds', { exact: true }).fill('8')
  await apply()
  await edit('Edit ISP Primary')
  await expect(page.getByLabel('WAN interface', { exact: true }).locator('option')
    .filter({ hasText: 'Audit-Core' })).toHaveCount(0)
  await page.getByLabel('Name', { exact: true }).fill('Primary planned')
  await apply()
  await edit(/^Edit SBR rule/)
  await page.getByRole('button', { name: 'Move ISP failover order 2 up', exact: true }).click()
  await apply()
  const primary = records(original.plan, 'isps').find((entry) => entry.name === 'Primary')!
  const sourceNatRow = page.getByRole('row', { name: /Primary planned.*192\.0\.2\.2/ })
  await sourceNatRow.getByRole('button', { name: /^Edit SNAT rule/ }).click()
  await page.getByLabel('Translated IPv4 address', { exact: true }).fill('203.0.113.10')
  await apply()

  await page.getByRole('link', { name: 'VPN & routing', exact: true }).click()
  await edit('Edit tunnel Audit VPN')
  await page.getByLabel('Tunnel state', { exact: true }).selectOption('up')
  await apply()
  await page.getByRole('row', { name: /172\.16\.20\.0\/24.*tunnel/ })
    .getByRole('button', { name: 'Edit static route 172.16.20.0/24' }).click()
  await page.getByLabel('Preference', { exact: true }).fill('2')
  await apply()
  await edit(/^Edit PBR rule/)
  await page.getByLabel('When tunnel is down', { exact: true }).selectOption('route-table')
  await apply()
  await edit(/^Edit NAT exemption/)
  await apply()

  await page.getByRole('link', { name: 'Devices / Topology', exact: true }).click()
  await edit('Edit assignment Audit-Core')
  await page.getByLabel('Location', { exact: true }).fill('A desk')
  await apply()
  await edit(/^Edit Stack Audit-Core/)
  await expect(page.getByLabel('Member number', { exact: true })).toHaveCount(2)
  await apply()
  await page.getByRole('link', { name: 'Port Editor', exact: true }).click()
  await edit('Edit Port-Channel 1')
  await page.getByText('Aggregate interface and members', { exact: true }).click()
  await expect(page.getByLabel('Port-Channel interface', { exact: true }).locator('option')
    .filter({ hasText: 'Vlan9' })).toHaveCount(0)
  await page.getByLabel('LACP mode', { exact: true }).selectOption('passive')
  await previewPorts(page)
  await page.getByRole('button', { name: 'Save revision' }).click()
  await expect(page.getByText('Revision 2 saved.')).toBeVisible()

  const expected = structuredClone(original.plan)
  records(expected, 'dhcp_pools')[0]!.lease_seconds = 7200
  records(expected, 'dhcp_relays')[0]!.servers = ['192.168.10.6', '192.168.10.7']
  records(expected, 'tracks').find((entry) => entry.target === '192.0.2.1')!.interval_seconds = 8
  records(expected, 'isps').find((entry) => entry.id === primary.id)!.name = 'Primary planned'
  records(expected, 'source_routes')[0]!.isp_priority = [...records(expected, 'source_routes')[0]!.isp_priority as string[]].reverse()
  records(expected, 'snat').find((entry) => entry.isp_id === primary.id)!.translated_ip = '203.0.113.10'
  records(expected, 'ipsec_tunnels')[0]!.state = 'up'
  records(expected, 'static_routes').find((entry) => (entry.next_hop as RecordValue).kind === 'tunnel')!.preference = 2
  records(expected, 'policy_routes')[0]!.on_tunnel_down = 'route-table'
  records(expected, 'assignments').find((entry) => entry.hostname === 'Audit-Core')!.location = 'A desk'
  records(expected, 'port_channels')[0]!.lacp = 'passive'

  const summaries = await (await request.get(revisions(id))).json() as Summary[]
  const latest = await (await request.get(revisions(id) + '/' + summaries.at(-1)!.id)).json() as Revision
  // The backend canonicalizes set-like collections independently of the UI table order.
  for (const [key, value] of Object.entries(expected)) {
    if (Array.isArray(value)) {
      expect(latest.plan[key], key).toHaveLength(value.length)
      expect(latest.plan[key], key).toEqual(expect.arrayContaining(value))
    } else {
      expect(latest.plan[key], key).toEqual(value)
    }
  }
  expect(latest.validation_status).toBe('VALID_WITH_WARNINGS')
})


async function previewPorts(page: Page, action = 'Apply to draft') {
  await page.getByRole('button', { name: 'Preview changes', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Before / After' })).toBeFocused()
  await page.getByRole('button', { name: action, exact: true }).click()
}

async function checkedSave(page: Page, request: APIRequestContext, id: string, number: number, total = number) {
  await page.getByRole('button', { name: 'Validate plan', exact: true }).click()
  await expect(page.getByText('VALID_WITH_WARNINGS', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Save revision', exact: true }).click()
  await expect(page.getByText('Revision ' + number + ' saved.', { exact: true })).toBeVisible()
  const list = await (await request.get(revisions(id))).json() as Summary[]
  expect(list).toHaveLength(total)
  const entry = list.find((item) => item.number === number)
  expect(entry).toBeDefined()
  const read = await request.get(revisions(id) + '/' + entry!.id)
  expect(read.status()).toBe(200)
  return await read.json() as Revision
}

function settingsOf(plan: Plan, name: string) {
  return portsOf(plan).find((item) => item.name === name)!.settings as RecordValue
}

test('edits all port settings and persists Keep, Reset, Set and empty descriptions', async ({ page, request }, info) => {
  test.setTimeout(70_000)
  const id = await createEvent(request, 'Synthetic single port configuration')
  const saved = await planRecord(request, stackPlan(id))
  const exportUrl = revisions(id) + '/' + saved.id + '/export'
  const before = await request.get(exportUrl)
  const historical = await before.body()
  const hash = createHash('sha256').update(historical).digest('hex')
  expect(hash).toBe(saved.content_hash)
  expect(before.headers().etag).toBe('"' + hash + '"')
  await openWorkspace(page, id, 'ports')
  const edit = page.getByRole('button', { name: 'Edit port Gi1/0/7', exact: true })
  await edit.click()
  const modal = page.getByRole('dialog', { name: 'Edit port', exact: true })
  const setting = (name: string) => modal.getByLabel(name, { exact: true })
  const close = modal.getByRole('button', { name: 'Close Edit port', exact: true })
  await expect(close).toBeFocused()
  await page.keyboard.press('Tab')
  await expect(modal.locator('summary')).toBeFocused()
  await expect(modal.locator('summary')).toHaveCSS('outline-style', 'solid')
  await page.emulateMedia({ reducedMotion: 'reduce' })
  const preview = modal.getByRole('button', { name: 'Preview changes', exact: true })
  await expect(preview).toHaveCSS('transition-duration', '0s')
  const contrast = await preview.evaluate((node) => {
    const style = getComputedStyle(node)
    const luminance = (color: string) => color.match(/[\d.]+/g)!.slice(0, 3).map(Number)
      .map((channel) => channel / 255)
      .map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
      .reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index]!, 0)
    const levels = [luminance(style.color), luminance(style.backgroundColor)]
    return (Math.max(...levels) + .05) / (Math.min(...levels) + .05)
  })
  expect(contrast).toBeGreaterThanOrEqual(4.5)
  await expect(modal.getByText('NOT VERIFIED', { exact: true })).toBeVisible()
  await setting('Description').fill('Players patch panel 7')
  await setting('Administrative state').selectOption('up')
  await setting('Speed (Mbps)').selectOption('1000')
  await setting('Duplex').selectOption('full')
  await setting('PoE mode').selectOption('static')
  await setting('PortFast').selectOption('edge')
  await setting('BPDU Guard').selectOption('enabled')
  await setting('Access VLAN').selectOption('10')

  for (const width of [1280, 1440, 1920, 800, 320]) {
    await page.setViewportSize({ width, height: 1000 })
    await expect(modal).toBeVisible()
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width + 1)
    expect(await modal.evaluate((node) => node.scrollWidth - node.clientWidth)).toBeLessThanOrEqual(1)
    await close.evaluate((node) => { node.closest('dialog')?.scrollTo(0, 0) })
    await page.screenshot({ path: info.outputPath('single-port-' + width + '.png') })
    if (width === 320) {
      await preview.scrollIntoViewIfNeeded()
      await page.screenshot({ path: info.outputPath('single-port-320-actions.png') })
    }
  }
  await page.setViewportSize({ width: 1440, height: 900 })
  await previewPorts(page)
  const first = await checkedSave(page, request, id, 2)
  expect(settingsOf(first.plan, 'Gi1/0/7')).toMatchObject({
    mode: 'access', access_vlan: 10, description: 'Players patch panel 7', admin_state: 'up',
    speed: 1000, duplex: 'full', poe_mode: 'static', portfast: 'edge', bpdu_guard: 'enabled',
  })
  expect(settingsOf(first.plan, 'Gi2/0/7')).toEqual(settingsOf(saved.plan, 'Gi2/0/7'))

  await edit.click()
  await expect(setting('Duplex operation')).toHaveValue('keep')
  await setting('PoE mode operation').selectOption('reset')
  await setting('Speed (Mbps)').selectOption('auto')
  await setting('Description').fill('')
  await previewPorts(page)
  const second = await checkedSave(page, request, id, 3)
  expect(settingsOf(second.plan, 'Gi1/0/7')).toMatchObject({
    description: '', speed: 'auto', poe_mode: null, duplex: 'full', admin_state: 'up',
    mode: 'access', portfast: 'edge', bpdu_guard: 'enabled',
  })
  expect(second.content_hash).not.toBe(first.content_hash)
  const exported = await request.get(revisions(id) + '/' + second.id + '/export')
  const stored = settingsOf(await exported.json() as Plan, 'Gi1/0/7')
  expect(stored).not.toHaveProperty('poe_mode')
  expect(stored).toMatchObject({ description: '', speed: 'auto' })
  const original = await request.get(exportUrl)
  expect(await original.body()).toEqual(historical)
  expect(original.headers().etag).toBe(before.headers().etag)
  expect(await (await request.get(revisions(id) + '/' + saved.id)).json()).toMatchObject({
    id: saved.id, content_hash: hash,
  })
})

test('previews a Mixed Shutdown edit across devices and Stack members without touching other fields', async ({ page, request }, info) => {
  test.setTimeout(60_000)
  const id = await createEvent(request, 'Synthetic mixed port intent')
  const other = await createEvent(request, 'Synthetic independent port intent')
  const plan = stackPlan(id)
  const [first, second] = portsOf(plan)
  first!.settings = { mode: 'access', access_vlan: 20, admin_state: 'down', description: 'Hold', speed: 'auto' }
  second!.settings = { mode: 'access', access_vlan: 20, admin_state: 'up', description: 'Desk', poe_mode: 'never' }
  const standalone = randomUUID()
  const chassis = randomUUID()
  const untouched = { ...first!, id: randomUUID(), name: 'Gi1/0/9' }
  plan.assignments = [...plan.assignments as RecordValue[], {
    id: standalone, hostname: 'Synthetic-Edge', role: 'access', physical_device_id: chassis,
  }]
  plan.physical_devices = [...plan.physical_devices as RecordValue[], { id: chassis, vendor: 'cisco' }]
  plan.physical_interfaces = [first!, second!, untouched, {
    id: randomUUID(), assignment_id: standalone, physical_device_id: chassis, name: 'Gi0/1',
    settings: { mode: 'access', access_vlan: 10, description: 'Patch A', speed: 1000, duplex: 'full' },
  }]
  const original = await planRecord(request, plan)
  await planRecord(request, stackPlan(other))
  await openWorkspace(page, id, 'ports')
  await page.setViewportSize({ width: 1440, height: 1000 })
  for (const name of ['Gi1/0/7', 'Gi2/0/7', 'Gi0/1']) {
    await page.getByRole('checkbox', { name: 'Select port ' + name, exact: true }).check()
  }
  await page.getByRole('button', { name: 'Batch edit (3)', exact: true }).click()
  const modal = page.getByRole('dialog', { name: 'Batch edit 3 ports' })
  const admin = modal.getByRole('group', { name: 'Administrative state', exact: true })
  await expect(admin.getByText('Mixed', { exact: true })).toBeVisible()
  await expect(admin.getByLabel('Administrative state operation', { exact: true })).toHaveValue('keep')
  await page.screenshot({ path: info.outputPath('mixed-values.png') })
  await admin.getByLabel('Administrative state', { exact: true }).selectOption('down')
  await modal.getByRole('button', { name: 'Preview changes', exact: true }).click()
  const changes = modal.getByRole('table', { name: 'Port changes' })
  await expect(changes.getByRole('row', { name: /Stack member 2 Gi2\/0\/7 Administrative state up down Set/ })).toBeVisible()
  await expect(changes.getByRole('row', { name: /Synthetic-Edge Standalone Gi0\/1 Administrative state Platform default down Set/ })).toBeVisible()
  await expect(changes.getByText('Gi1/0/9', { exact: true })).toHaveCount(0)
  await page.screenshot({ path: info.outputPath('batch-before-after.png') })
  await modal.getByRole('checkbox', { name: 'Show kept fields' }).check()
  await expect(changes.getByRole('row', { name: /Gi2\/0\/7 Description Desk Desk Keep/ })).toBeVisible()
  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)

  page.once('dialog', (prompt) => prompt.dismiss())
  await page.keyboard.press('Escape')
  await expect(modal).toBeVisible()
  page.once('dialog', (prompt) => prompt.accept())
  await modal.getByRole('button', { name: 'Cancel', exact: true }).click()
  await expect(modal).toHaveCount(0)
  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)

  await page.getByRole('button', { name: 'Batch edit (3)', exact: true }).click()
  await modal.getByLabel('Administrative state', { exact: true }).selectOption('down')
  await previewPorts(page, 'Apply to 3 ports')
  await expect(page.getByText('Unsaved changes', { exact: true })).toBeVisible()
  page.once('dialog', (prompt) => prompt.dismiss())
  await page.getByLabel('Event', { exact: true }).selectOption(other)
  await expect(page.getByLabel('Event', { exact: true })).toHaveValue(id)
  await expect(page.getByText('Unsaved changes', { exact: true })).toBeVisible()
  expect(await (await request.get(revisions(id))).json()).toHaveLength(1)
  const latest = await checkedSave(page, request, id, 2)
  for (const port of portsOf(original.plan)) {
    const name = String(port.name)
    const expected = settingsOf(original.plan, name)
    expect(settingsOf(latest.plan, name)).toEqual(port.id === untouched.id ? expected : { ...expected, admin_state: 'down' })
  }
  for (const name of ['Gi1/0/7', 'Gi2/0/7']) {
    await page.getByRole('checkbox', { name: 'Select port ' + name, exact: true }).check()
  }
  await page.getByRole('button', { name: 'Batch edit (2)', exact: true }).click()
  const reset = page.getByRole('dialog', { name: 'Batch edit 2 ports' })
  await reset.getByLabel('Administrative state operation', { exact: true }).selectOption('reset')
  await reset.getByRole('button', { name: 'Preview changes', exact: true }).click()
  await expect(reset.getByRole('row', { name: /Gi2\/0\/7 Administrative state down Platform default Reset/ })).toBeVisible()
  await reset.getByRole('button', { name: 'Apply to 2 ports', exact: true }).click()
  const resetRevision = await checkedSave(page, request, id, 3)
  for (const name of ['Gi1/0/7', 'Gi2/0/7', 'Gi0/1', 'Gi1/0/9']) {
    const retained = settingsOf(latest.plan, name)
    expect(settingsOf(resetRevision.plan, name)).toEqual(name.endsWith('/7') ? { ...retained, admin_state: null } : retained)
  }
  expect(await (await request.get(revisions(other))).json()).toHaveLength(1)
})

test('confirms incompatible VLAN, IP and STP cleanup before applying each mode change', async ({ page, request }, info) => {
  test.setTimeout(60_000)
  const id = await createEvent(request, 'Synthetic mode changes')
  const plan = stackPlan(id)
  portsOf(plan)[0]!.settings = { mode: 'access', access_vlan: 20, portfast: 'edge', bpdu_guard: 'enabled', description: 'Keep me' }
  await planRecord(request, plan)
  await openWorkspace(page, id, 'ports')
  const edit = page.getByRole('button', { name: 'Edit port Gi1/0/7', exact: true })
  const modal = page.getByRole('dialog', { name: 'Edit port', exact: true })
  const setting = (name: string) => modal.getByLabel(name, { exact: true })
  const preview = modal.getByRole('button', { name: 'Preview changes', exact: true })
  const confirm = modal.getByRole('button', { name: 'Confirm and apply to draft', exact: true })
  const changes = modal.getByRole('table', { name: 'Port changes' })

  await edit.click()
  await setting('PortFast operation').selectOption('set')
  await setting('Mode').selectOption('trunk')
  await expect(setting('PortFast')).toHaveValue('')
  await preview.click()
  await expect(setting('PortFast')).toBeVisible()
  await setting('PortFast operation').selectOption('keep')
  await setting('Native VLAN').selectOption('10')
  for (const [index, vlan] of ['10', '20'].entries()) {
    await modal.getByRole('button', { name: 'Add entry', exact: true }).click()
    await setting('Allowed VLANs ' + (index + 1)).selectOption(vlan)
  }
  await preview.click()
  await expect(changes.getByRole('row', { name: /Access VLAN 20 .*Platform default Clear on mode change/ })).toBeVisible()
  await expect(changes.getByRole('row', { name: /PortFast edge Platform default Clear on mode change/ })).toBeVisible()
  await confirm.click()
  const trunk = await checkedSave(page, request, id, 2)
  expect(settingsOf(trunk.plan, 'Gi1/0/7')).toMatchObject({
    mode: 'trunk', access_vlan: null, native_vlan: 10, allowed_vlans: [10, 20], portfast: null, bpdu_guard: 'enabled',
  })

  await edit.click()
  await setting('Mode').selectOption('routed')
  await expect(setting('PortFast')).toHaveCount(0)
  await expect(setting('BPDU Guard')).toHaveCount(0)
  await setting('IPv4 address / prefix').fill('10.10.10.1/24')
  await preview.click()
  await expect(changes.getByRole('row', { name: /Native VLAN .*Clear on mode change/ })).toBeVisible()
  await expect(changes.getByRole('row', { name: /Allowed VLANs .* None Clear on mode change/ })).toBeVisible()
  await expect(changes.getByRole('row', { name: /BPDU Guard enabled Platform default Clear on mode change/ })).toBeVisible()
  const changeRegion = modal.getByRole('region', { name: 'Port changes', exact: true })
  expect(await changeRegion.evaluate((node) => node.scrollWidth - node.clientWidth)).toBeLessThanOrEqual(1)
  await page.screenshot({ path: info.outputPath('confirm-mode-cleanup.png') })
  await confirm.click()
  const routed = await checkedSave(page, request, id, 3)
  expect(settingsOf(routed.plan, 'Gi1/0/7')).toMatchObject({
    mode: 'routed', address: '10.10.10.1/24', native_vlan: null, allowed_vlans: [], bpdu_guard: null, description: 'Keep me',
  })

  await edit.click()
  await setting('Mode').selectOption('access')
  await setting('Access VLAN').selectOption('20')
  await preview.click()
  await expect(changes.getByRole('row', { name: /IPv4 address \/ prefix 10.10.10.1\/24 Platform default Clear on mode change/ })).toBeVisible()
  await confirm.click()
  const access = await checkedSave(page, request, id, 4)
  expect(settingsOf(access.plan, 'Gi1/0/7')).toMatchObject({ mode: 'access', access_vlan: 20, address: null, description: 'Keep me' })
})

test('keeps Port-Channel hardware settings scoped and blocks unsafe channel and Transit drafts', async ({ page, request }, info) => {
  test.setTimeout(55_000)
  const id = await createEvent(request, 'Synthetic port safety validation')
  const initial = await planRecord(request, auditPlan(id))
  await openWorkspace(page, id, 'ports')
  await page.getByRole('button', { name: 'Edit Port-Channel 1', exact: true }).click()
  const channel = page.getByRole('dialog', { name: 'Edit Port-Channel', exact: true })
  for (const field of ['Speed (Mbps)', 'Duplex', 'PoE mode']) {
    await expect(channel.getByLabel(field, { exact: true })).toHaveCount(0)
    await expect(channel.getByLabel(field + ' operation', { exact: true })).toHaveCount(0)
  }
  await channel.getByLabel('LACP mode', { exact: true }).selectOption('passive')
  await channel.getByLabel('Description', { exact: true }).fill('Aggregate for players')
  await channel.getByLabel('PortFast', { exact: true }).selectOption('edge-trunk')
  await previewPorts(page)
  const saved = await checkedSave(page, request, id, 2)
  expect((saved.plan.port_channels as RecordValue[])[0]).toMatchObject({
    lacp: 'passive', member_ids: (initial.plan.port_channels as RecordValue[])[0]!.member_ids,
    settings: { description: 'Aggregate for players', portfast: 'edge-trunk', speed: null, duplex: null, poe_mode: null },
  })

  for (const [name, field, value] of [
    ['Gi1/0/2', 'Speed (Mbps)', '10000'],
    ['Gi2/0/2', 'Duplex', 'half'],
    ['Gi1/0/1', 'Administrative state', 'down'],
  ] as const) {
    await page.getByRole('button', { name: 'Edit port ' + name, exact: true }).click()
    await page.getByLabel(field, { exact: true }).selectOption(value)
    await previewPorts(page)
  }
  const response = page.waitForResponse((res) => res.request().method() === 'POST' && res.url().endsWith('/plan/validate'))
  await page.getByRole('button', { name: 'Validate plan', exact: true }).click()
  const findings = await response
  expect(findings.status()).toBe(200)
  expect(await findings.json()).toEqual(expect.arrayContaining([
    expect.objectContaining({ code: 'port_channel_speed_duplex_conflict', severity: 'ERROR', path: expect.stringMatching(/\.settings\.speed$/) }),
    expect.objectContaining({ code: 'port_channel_speed_duplex_conflict', severity: 'ERROR', path: expect.stringMatching(/\.settings\.duplex$/) }),
    expect.objectContaining({ code: 'transit_port_shutdown', severity: 'ERROR', path: expect.stringMatching(/\.settings\.admin_state$/) }),
    expect.objectContaining({ code: 'port_setting_unverified', severity: 'WARNING' }),
  ]))
  await expect(page.getByRole('button', { name: 'Save revision', exact: true })).toBeDisabled()
  await expect(page.getByText('INVALID', { exact: true })).toBeVisible()
  await expect(page.getByRole('table', { name: 'Validation issues' }).getByText('WARNING', { exact: true }).first()).toBeVisible()
  await page.screenshot({ path: info.outputPath('port-errors-and-warnings.png'), fullPage: true })
  for (const [code, path, field] of [
    ['port_channel_speed_duplex_conflict', 'settings.speed', 'Speed (Mbps)'],
    ['transit_port_shutdown', 'settings.admin_state', 'Administrative state'],
  ] as const) {
    const details = page.getByRole('table', { name: 'Validation issues' })
    await details.getByRole('row').filter({ hasText: code }).filter({ hasText: path })
      .getByRole('button', { name: /^Locate/ }).click()
    const dialog = page.getByRole('dialog', { name: 'Edit port', exact: true })
    const control = dialog.getByLabel(field, { exact: true })
    await expect(control).toBeFocused()
    await expect(control).toHaveAttribute('aria-invalid', 'true')
    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click()
  }
  const portfastWarning = page.getByRole('table', { name: 'Validation issues' }).getByRole('row')
    .filter({ hasText: 'port_setting_unverified' }).filter({ hasText: 'settings.portfast' })
  await portfastWarning.getByRole('button', { name: /^Locate/ }).click()
  const portfast = channel.getByLabel('PortFast', { exact: true })
  await expect(portfast).toBeFocused()
  await expect(portfast).not.toHaveAttribute('aria-invalid', 'true')
  await expect(channel.getByText('Verify spanning-tree support and edge role on the actual interface')).toBeVisible()
  await channel.getByRole('button', { name: 'Cancel', exact: true }).click()
  expect(await (await request.get(revisions(id))).json()).toHaveLength(2)
})


test('Plan API materializes an omitted LACP mode as active and rejects null', async ({ request }) => {
  const id = await createEvent(request, 'Synthetic LACP API defaults')
  const raw = auditPlan(id)
  const channel = (raw.port_channels as RecordValue[])[0]!
  channel.lacp = 'passive'
  const before = await planRecord(request, raw)
  expect((before.plan.port_channels as RecordValue[])[0]!.lacp).toBe('passive')

  delete channel.lacp
  const omitted = await planRecord(request, raw)
  expect(omitted.id).not.toBe(before.id)
  expect(omitted.content_hash).not.toBe(before.content_hash)
  expect((omitted.plan.port_channels as RecordValue[])[0]!.lacp).toBe('active')
  const url = revisions(id) + '/' + omitted.id
  const read = await request.get(url)
  expect(read.status()).toBe(200)
  expect((await read.json() as Revision).plan.port_channels).toEqual(omitted.plan.port_channels)
  const exported = await request.get(url + '/export')
  expect(exported.headers().etag).toBe('"' + omitted.content_hash + '"')
  expect(((await exported.json() as Plan).port_channels as RecordValue[])[0]!.lacp).toBe('active')

  channel.lacp = 'active'
  const explicit = await planRecord(request, raw)
  expect(explicit.id).toBe(omitted.id)
  expect(explicit.content_hash).toBe(omitted.content_hash)
  channel.lacp = null
  const rejected = await request.post(revisions(id), { headers, data: raw })
  expect(rejected.status()).toBe(422)
  expect((await rejected.json()).detail).toEqual(expect.arrayContaining([
    expect.objectContaining({ loc: ['body', 'port_channels', 0, 'lacp'] }),
  ]))
  expect(await (await request.get(revisions(id))).json()).toHaveLength(2)
})

test('previews and saves explicit LACP values while Keep preserves the existing mode', async ({ page, request }, info) => {
  test.setTimeout(60_000)
  const id = await createEvent(request, 'Synthetic LACP intent')
  const raw = auditPlan(id)
  const source = (raw.port_channels as RecordValue[])[0]!
  source.lacp = 'passive'
  const original = await planRecord(request, raw)
  const originalUrl = revisions(id) + '/' + original.id
  const originalExport = await request.get(originalUrl + '/export')
  const originalBytes = await originalExport.body()
  expect(createHash('sha256').update(originalBytes).digest('hex')).toBe(original.content_hash)
  expect(originalExport.headers().etag).toBe('"' + original.content_hash + '"')

  await openWorkspace(page, id, 'ports')
  const edit = page.getByRole('button', { name: 'Edit Port-Channel 1', exact: true })
  const modal = page.getByRole('dialog', { name: 'Edit Port-Channel', exact: true })
  const operation = modal.getByLabel('LACP mode operation', { exact: true })
  const mode = modal.getByLabel('LACP mode', { exact: true })
  const preview = modal.getByRole('button', { name: 'Preview changes', exact: true })
  const apply = modal.getByRole('button', { name: 'Apply to draft', exact: true })
  async function expectLacpPreview(before: string, after: string, action: 'Keep' | 'Set') {
    const row = modal.getByRole('table', { name: 'Port changes' }).getByRole('row', { name: / LACP mode / })
    const cells = row.getByRole('cell')
    await expect(cells.nth(3)).toHaveText(before)
    await expect(cells.nth(4)).toHaveText(after)
    await expect(cells.nth(5)).toHaveText(action)
  }

  await edit.click()
  await expect(operation.locator('option')).toHaveText(['Keep', 'Set'])
  for (const field of ['Mode', 'Allowed VLANs']) {
    await expect(modal.getByLabel(field + ' operation', { exact: true }).locator('option')).toHaveText(['Keep', 'Set'])
  }
  await expect(operation).toHaveValue('keep')
  await expect(mode).toHaveValue('passive')
  await modal.getByLabel('Description', { exact: true }).fill('Keep the bundle protocol')
  await preview.click()
  await modal.getByRole('checkbox', { name: 'Show kept fields' }).check()
  await expectLacpPreview('passive', 'passive', 'Keep')
  await apply.click()
  const kept = await checkedSave(page, request, id, 2)
  const expected = {
    ...(original.plan.port_channels as RecordValue[])[0]!,
    settings: { ...source.settings as RecordValue, description: 'Keep the bundle protocol' },
  }
  expect((kept.plan.port_channels as RecordValue[])[0]).toMatchObject(expected)

  let previous = 'passive'
  for (const [index, value] of ['active', 'static', 'passive'].entries()) {
    await edit.click()
    await expect(mode).toHaveValue(previous)
    await operation.selectOption('set')
    await mode.selectOption(value)
    await preview.click()
    await expectLacpPreview(previous, value, 'Set')
    if (value === 'active') await page.screenshot({ path: info.outputPath('lacp-passive-to-active.png') })
    await apply.click()
    const persisted = value === 'passive'
      ? await checkedSave(page, request, id, kept.number, 4)
      : await checkedSave(page, request, id, index + 3)
    expect((persisted.plan.port_channels as RecordValue[])[0]).toEqual({
      ...(kept.plan.port_channels as RecordValue[])[0]!, lacp: value,
    })
    if (value === 'passive') expect(persisted.id).toBe(kept.id)
    previous = value
  }

  delete source.lacp
  await importJson(page, JSON.stringify(raw))
  const channels = page.getByRole('table', { name: 'Port-Channels', exact: true })
  await expect(channels.getByRole('cell', { name: 'active', exact: true })).toBeVisible()
  await edit.click()
  await expect(operation).toHaveValue('keep')
  await expect(operation.locator('option')).toHaveText(['Keep', 'Set'])
  await expect(mode).toHaveValue('active')
  await modal.getByLabel('Description', { exact: true }).fill('Keep the model default')
  await preview.click()
  await modal.getByRole('checkbox', { name: 'Show kept fields' }).check()
  await expectLacpPreview('active', 'active', 'Keep')
  await apply.click()
  const saving = page.waitForRequest((req) => req.method() === 'POST' && req.url().endsWith(revisions(id)))
  const imported = await checkedSave(page, request, id, 5)
  const sent = (await saving).postDataJSON() as Plan
  expect((sent.port_channels as RecordValue[])[0]).not.toHaveProperty('lacp')
  expect((imported.plan.port_channels as RecordValue[])[0]!.lacp).toBe('active')

  const unchanged = await request.get(originalUrl + '/export')
  expect(await unchanged.body()).toEqual(originalBytes)
  expect(unchanged.headers().etag).toBe(originalExport.headers().etag)
  expect(await (await request.get(originalUrl)).json()).toMatchObject({
    id: original.id, content_hash: original.content_hash, plan: { port_channels: original.plan.port_channels },
  })
})
