import { createHash, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { expect, test } from '@playwright/test'
import type { APIRequestContext, Page } from '@playwright/test'
import type { Plan, Revision, Summary } from '../src/planner/model'

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
  await page.goto('/#' + route)
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
  const fixture = await planRecord(request, stackPlan(id))
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
  await page.getByLabel('Allowed VLANs 1').selectOption('20')
  await page.getByRole('button', { name: 'Apply to 2 ports' }).click()
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
    expect.objectContaining({ name: 'Gi1/0/7', settings: expect.objectContaining({ mode: 'trunk', allowed_vlans: [20] }) }),
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
  await openWorkspace(page, first, 'devices')
  await page.getByRole('button', { name: 'Revision history' }).click()
  await page.getByRole('button', { name: 'Open revision 1' }).click()
  await expect(page.getByText('Read-only revision', { exact: true })).toBeVisible()
  await expect(page.getByText('INVALID', { exact: true })).toBeVisible()
  await expect(page.getByText('physical_identity', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Save revision' })).toHaveCount(0)
  await page.getByText('Revision 1', { exact: true }).click()
  await expect(page.getByText(legacy.content_hash, { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Copy to draft' }).click()
  await expect(page.getByRole('button', { name: 'Save revision' })).toBeDisabled()
})

test('captures responsive workbench views and keyboard, contrast, motion and data states', async ({ page, request }, info) => {
  test.setTimeout(75_000)
  const id = await createEvent(request, 'Synthetic tournament — screenshot data')
  await planRecord(request, stackPlan(id))
  await openWorkspace(page, id)
  for (const width of [1280, 1440, 1920, 800, 320]) {
    await page.setViewportSize({ width, height: 850 })
    await expect(page.getByRole('table', { name: 'VLANs', exact: true })).toBeVisible()
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
