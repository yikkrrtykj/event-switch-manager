import { randomUUID } from 'node:crypto'

import { expect, test } from '@playwright/test'
import type { APIRequestContext, Page, Route } from '@playwright/test'

const origin = 'http://127.0.0.1:8765'
const headers = { Origin: origin }
const events = '/api/v1/events'
const revisions = (eventId: string) => events + '/' + eventId + '/plan-revisions'

type JsonRecord = Record<string, unknown>
type SavedRevision = { id: string; number: number; content_hash: string }

function id() { return randomUUID() }

async function createEvent(request: APIRequestContext, name: string) {
  const response = await request.post(events, { headers, data: { name, management_vlan: 10 } })
  expect(response.status()).toBe(201)
  return (await response.json() as { id: string }).id
}

type CiscoCoreOptions = {
  pid?: string
  family?: string
  image?: string
  license?: string
}

function ciscoPlan(
  eventId: string, withDhcp = true, options: CiscoCoreOptions = {},
): JsonRecord {
  const {
    pid = 'C9300L-24P-4X',
    family = 'catalyst-9300',
    image = '17.12.4',
    license = 'Network Advantage',
  } = options
  const coreAssignment = id()
  const accessAssignment = id()
  const firewallAssignment = id()
  const coreDevice = id()
  const accessDevice = id()
  const firewallDevice = id()
  const coreTransitPort = id()
  const coreTrunkPort = id()
  const accessPort = id()
  const firewallTransitPort = id()
  const firewallRoutedPort = id()
  const vlan9Svi = id()
  const vlan10Svi = id()
  const vlan20Svi = id()
  const subnet10 = id()
  const subnet20 = id()
  const pool20 = id()
  const defaultRoute = id()
  const returnGateway = id()
  const returnPlayers = id()
  const link = id()
  const serialSuffix = id().slice(0, 8)
  const plan: JsonRecord = {
    schema_version: 1,
    event_id: eventId,
    management_vlan: 10,
    physical_devices: [
      { id: coreDevice, vendor: 'cisco', model: pid, verified_serial: 'R49-CORE-' + serialSuffix },
      { id: accessDevice, vendor: 'cisco', model: 'C9300L-24T-4G', verified_serial: 'R49-ACCESS-' + serialSuffix },
      { id: firewallDevice, vendor: 'hillstone', model: 'SG6000', verified_serial: 'R49-FW-' + serialSuffix },
    ],
    assignments: [
      { id: coreAssignment, hostname: 'L3-Core', role: 'core', family,
        physical_device_id: coreDevice, software: { image, license } },
      { id: accessAssignment, hostname: 'L2-Access', role: 'access', family: 'catalyst-9300',
        physical_device_id: accessDevice, software: { image: '17.12.4', license: 'Network Advantage' },
        management_ip: '192.168.10.2' },
      { id: firewallAssignment, hostname: 'L3-FW', role: 'external-distribution',
        physical_device_id: firewallDevice },
    ],
    physical_interfaces: [
      { id: coreTransitPort, assignment_id: coreAssignment, physical_device_id: coreDevice,
        name: 'Gi1/0/1', settings: { mode: 'access', access_vlan: 9, admin_state: 'up' } },
      { id: coreTrunkPort, assignment_id: coreAssignment, physical_device_id: coreDevice,
        name: 'Gi1/0/2', settings: { mode: 'trunk', allowed_vlans: [9, 10, 20], admin_state: 'up' } },
      { id: accessPort, assignment_id: accessAssignment, physical_device_id: accessDevice,
        name: 'Gi1/0/1', settings: { mode: 'access', access_vlan: 20, admin_state: 'up' } },
      { id: firewallTransitPort, assignment_id: firewallAssignment, physical_device_id: firewallDevice,
        name: 'ethernet0/0', settings: { mode: 'access', access_vlan: 9, admin_state: 'up' } },
      { id: firewallRoutedPort, assignment_id: firewallAssignment, physical_device_id: firewallDevice,
        name: 'ethernet0/1', settings: { mode: 'routed', address: '198.51.100.2/30' } },
    ],
    logical_interfaces: [
      { id: vlan9Svi, assignment_id: coreAssignment, name: 'Vlan9', kind: 'svi', vlan: 9, address: '10.0.0.1/30' },
      { id: vlan10Svi, assignment_id: coreAssignment, name: 'Vlan10', kind: 'svi', vlan: 10, address: '192.168.10.1/24' },
      { id: vlan20Svi, assignment_id: coreAssignment, name: 'Vlan20', kind: 'svi', vlan: 20, address: '192.168.20.1/24' },
    ],
    vlans: [
      { id: 9, name: 'Transit', purpose: 'transit' },
      { id: 10, name: 'Management', purpose: 'management' },
      { id: 20, name: 'Players' },
    ],
    subnets: [
      { id: subnet10, vlan: 10, network: '192.168.10.0/24' },
      { id: subnet20, vlan: 20, network: '192.168.20.0/24' },
    ],
    gateways: [
      { subnet_id: subnet10, address: '192.168.10.1', svi_id: vlan10Svi },
      { subnet_id: subnet20, address: '192.168.20.1', svi_id: vlan20Svi },
    ],
    dhcp_pools: withDhcp ? [{ id: pool20, subnet_id: subnet20, start: '192.168.20.100', end: '192.168.20.150' }] : [],
    dhcp_relays: withDhcp ? [{ subnet_id: subnet20, svi_id: vlan20Svi, servers: ['192.168.10.5'] }] : [],
    vlan_access_policies: [],
    links: [{ id: link, endpoints: [coreTransitPort, firewallTransitPort] }],
    static_routes: [
      { id: returnGateway, assignment_id: firewallAssignment, destination: '192.168.10.0/24',
        next_hop: { kind: 'ip', address: '10.0.0.1' } },
      { id: returnPlayers, assignment_id: firewallAssignment, destination: '192.168.20.0/24',
        next_hop: { kind: 'ip', address: '10.0.0.1' } },
      { id: id(), assignment_id: coreAssignment, destination: '10.200.0.0/24',
        next_hop: { kind: 'ip', address: '10.0.0.2' }, preference: 1 },
    ],
    default_routes: [{ id: defaultRoute, assignment_id: coreAssignment,
      next_hop: { kind: 'ip', address: '10.0.0.2' }, preference: 1 }],
    transit: {
      core_assignment_id: coreAssignment, hillstone_assignment_id: firewallAssignment,
      core_port_id: coreTransitPort, hillstone_port_id: firewallTransitPort,
      core_svi_id: vlan9Svi, vlan: 9, network: '10.0.0.0/30',
      core_ip: '10.0.0.1', hillstone_ip: '10.0.0.2',
    },
  }
  return plan
}

async function savePlan(request: APIRequestContext, plan: JsonRecord) {
  const response = await request.post(revisions(plan.event_id as string), { headers, data: plan })
  expect(response.status(), await response.text()).toBe(200)
  return await response.json() as SavedRevision
}

async function preparedEvent(
  request: APIRequestContext, name: string, withDhcp = true,
  options: CiscoCoreOptions = {},
) {
  const eventId = await createEvent(request, name)
  const plan = ciscoPlan(eventId, withDhcp, options)
  const revision = await savePlan(request, plan)
  return { eventId, plan, revision }
}

function c9200CandidatePlan(plan: JsonRecord): JsonRecord {
  const copy = structuredClone(plan)
  const assignments = copy.assignments as JsonRecord[]
  const core = assignments.find((item) => item.hostname === 'L3-Core')!
  copy.transit = null
  copy.default_routes = []
  copy.static_routes = (copy.static_routes as JsonRecord[]).filter(
    (route) => route.assignment_id === core.id,
  )
  for (const route of copy.static_routes as JsonRecord[]) {
    route.next_hop = { kind: 'ip', address: '192.168.10.2' }
  }
  return copy
}

async function preparedC9200CandidateEvent(
  request: APIRequestContext, name: string,
) {
  const eventId = await createEvent(request, name)
  const plan = c9200CandidatePlan(ciscoPlan(eventId, false, {
    pid: 'C9200L-24P-4X', family: 'catalyst-9200',
  }))
  const revision = await savePlan(request, plan)
  return { eventId, plan, revision }
}


async function preparedManagementEvent(
  request: APIRequestContext, name: string,
) {
  const eventId = await createEvent(request, name)
  const plan = ciscoPlan(eventId, false)
  const core = (plan.assignments as JsonRecord[])[0]!
  core.management_ip = '192.168.10.3'
  core.management_domain = 'example.com'
  core.credential_reference = 'credref:' + eventId + ':netops'
  const revision = await savePlan(request, plan)
  return { eventId, plan, revision }
}
async function openPreview(page: Page, eventId: string, name = 'Cisco Config Preview') {
  await page.goto('/#cisco-preview')
  const eventSelect = page.getByLabel('Event', { exact: true })
  await expect(eventSelect).toBeVisible()
  await eventSelect.selectOption(eventId)
  await expect(page.getByRole('heading', { name, exact: true })).toBeVisible()
  const assignmentSelect = page.locator('#cisco-assignment')
  await expect(assignmentSelect).toBeVisible({ timeout: 20_000 })
  await expect(assignmentSelect.locator('option')).toHaveCount(2, { timeout: 20_000 })
  await expect(assignmentSelect.locator('option:checked')).toContainText('L3-Core')
}

function candidateCount(page: Page) {
  return page.getByRole('table', { name: 'Layer 2 candidates' }).locator('tbody tr')
}

async function watchBrowserErrors(page: Page) {
  const pageErrors: string[] = []
  page.on('pageerror', (error) => { pageErrors.push(String(error)) })
  await page.addInitScript(() => {
    const target = window as unknown as { __r50Unhandled?: string[] }
    target.__r50Unhandled = []
    window.addEventListener('unhandledrejection', (event) => {
      target.__r50Unhandled!.push(String(event.reason))
    })
  })
  return pageErrors
}

async function unhandledErrors(page: Page) {
  return await page.evaluate(() => {
    const target = window as unknown as { __r50Unhandled?: string[] }
    return target.__r50Unhandled ?? []
  })
}

async function holdCoreValidation(route: Route, coreId: string, releases: (() => void)[]) {
  if (route.request().url().includes(coreId)) {
    await new Promise<void>((resolve) => { releases.push(resolve) })
  }
  try { await route.continue() } catch { /* the page may have aborted this request */ }
}

async function hasL2CandidateTable(page: Page) {
  return await page.evaluate(() =>
    Boolean(document.querySelector('[aria-label="Layer 2 review"] table[aria-label="Layer 2 candidates"]')),
  )
}

test('shows a unified read-only L2 and L3 review bound to one saved revision', async ({ page, request }) => {
  const { eventId, revision } = await preparedEvent(request, 'R49 unified preview')
  await openPreview(page, eventId)
  const assignmentSelect = page.locator('#cisco-assignment')
  await expect(assignmentSelect).toBeVisible()
  await expect(assignmentSelect.locator('option:checked')).toContainText('L3-Core')
  await expect(page.locator('.cisco-metadata').first()).toContainText(revision.content_hash)
  await expect(page.locator('.cisco-status-card').filter({ hasText: 'Overall review' })).toContainText('PARTIAL')
  await expect(page.locator('.cisco-status-card').filter({ hasText: 'L2 review' })).toContainText('PARTIAL')
  await expect(page.locator('.cisco-status-card').filter({ hasText: 'L3 review' })).toContainText('PARTIAL')

  const l2Region = page.getByRole('region', { name: 'Layer 2 review' })
  await expect(l2Region).toContainText('Planned Layer 2 intent')
  await expect(l2Region).toContainText('DISPLAY ONLY')
  const l2Table = page.getByRole('table', { name: 'Layer 2 candidates' })
  await expect(l2Table).toBeVisible()
  expect(await candidateCount(page).count()).toBeGreaterThan(0)
  const l3Table = page.getByRole('table', { name: 'Layer 3 candidates' })
  await expect(l3Table).toBeVisible()
  expect(await l3Table.locator('tbody tr').count()).toBe(10)

  const l2PassRow = l2Table.locator('tbody tr').filter({ hasText: 'access-vlan' }).first()
  await l2PassRow.getByText('Details', { exact: true }).click()
  await expect(l2PassRow.locator('pre.cisco-command')).toContainText('switchport access vlan')
  const l3PassRow = l3Table.locator('tbody tr').filter({ hasText: 'ip-routing' }).first()
  await l3PassRow.getByText('Details', { exact: true }).click()
  await expect(l3PassRow.locator('pre.cisco-command')).toContainText('ip routing')

  const dhcpRow = l3Table.locator('tbody tr').filter({ hasText: 'dhcp-helper-address' }).first()
  await dhcpRow.getByText('Details', { exact: true }).click()
  await expect(dhcpRow.getByText('Command text is withheld for this candidate.', { exact: true })).toBeVisible()
  await expect(dhcpRow.locator('pre')).toHaveCount(0)
  await expect(page.getByText('DHCP Helper blocked', { exact: true })).toBeVisible()
  await expect(page.locator('.cisco-source-panel')).toContainText('27d9c46f610b974de5570fb13e115260e2d109475a8d967704de9bb9ca6ef00b')
  await expect(page.locator('.cisco-source-panel')).toContainText('5abd0c57c0a825d77893e6287b76024517b5eb24d42bf061ab34c685b79c1ad8')
  await expect(page.getByRole('button', { name: /execute|deploy|copy all|generate script|download/i })).toHaveCount(0)
  await expect(page.getByRole('link', { name: /download|deploy|execute/i })).toHaveCount(0)
  await expect(assignmentSelect.locator('option')).toHaveCount(2)
})

test('shows reviewed C9200 L3 candidates in unified preview', async ({ page, request }) => {
  const { eventId } = await preparedC9200CandidateEvent(
    request, 'R57 C9200 unified preview',
  )
  await openPreview(page, eventId)
  const l3Card = page.locator('.cisco-status-card').filter({ hasText: 'L3 review' })
  await expect(l3Card).toContainText('PARTIAL')
  const l3Region = page.getByRole('region', { name: 'Layer 3 review' })
  await expect(l3Region).not.toContainText('This platform has no independently reviewed L3 command evidence')
  await expect(l3Region).toContainText('Reviewed C9200 L3 evidence — software candidates only')
  const l3Table = page.getByRole('table', { name: 'Layer 3 candidates' })
  await expect(l3Table).toBeVisible()
  await expect(l3Table.locator('tbody tr')).toHaveCount(8)
  await expect(l3Table.getByText('PASS', { exact: true })).toHaveCount(6)
  await expect(l3Table.getByText('CANDIDATE', { exact: true })).toHaveCount(6)
  await expect(page.locator('.cisco-source-panel')).toContainText(
    'cis-03-c9200-l3-command-evidence-v1',
  )
  await expect(page.locator('.cisco-source-panel')).toContainText(
    '2c73c8b39100622360c6bfab935d995d8fb884dd999b6df0ae744a7be7cec876',
  )
  const ipRow = l3Table.locator('tbody tr').filter({ hasText: 'ip-routing' }).first()
  await ipRow.getByText('Details', { exact: true }).click()
  await expect(ipRow.locator('pre.cisco-command')).toContainText('ip routing')
  const routeRow = l3Table.locator('tbody tr').filter({ hasText: 'static-route' }).first()
  await routeRow.getByText('Details', { exact: true }).click()
  await expect(routeRow.locator('pre.cisco-command')).toContainText('ip route 10.200.0.0')
  await expect(page.getByRole('button', { name: /execute|deploy|copy all|generate script|download/i }))
    .toHaveCount(0)

  for (const width of [390, 1366, 1920]) {
    await page.setViewportSize({ width, height: 900 })
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth))
      .toBeLessThanOrEqual(1)
  }
})

test('keeps C9200 default route plan blocked without CLI', async ({ page, request }) => {
  const { eventId } = await preparedEvent(
    request, 'R57 C9200 default blocked', false,
    { pid: 'C9200L-24P-4X', family: 'catalyst-9200' },
  )
  await openPreview(page, eventId)
  const l3Region = page.getByRole('region', { name: 'Layer 3 review' })
  const l3Table = page.getByRole('table', { name: 'Layer 3 candidates' })
  await expect(l3Table.locator('tbody tr')).toHaveCount(9)
  await expect(l3Table.getByText('PASS', { exact: true })).toHaveCount(0)
  await expect(l3Region.locator('pre.cisco-command')).toHaveCount(0)
  const defaultRow = l3Table.locator('tbody tr').filter({ hasText: 'default-route' }).first()
  await defaultRow.getByText('Details', { exact: true }).click()
  await expect(defaultRow.getByText('Command text is withheld for this candidate.', { exact: true })).toBeVisible()
  await expect(defaultRow.locator('pre')).toHaveCount(0)
})

test('shows L3 as not applicable for a non-Core Cisco assignment', async ({ page, request }) => {
  const { eventId, plan } = await preparedEvent(request, 'R49 non-core L3')
  const accessId = String((plan.assignments as JsonRecord[])[1]!.id)
  await openPreview(page, eventId)
  await page.locator('#cisco-assignment').selectOption(accessId)
  const l3Card = page.locator('.cisco-status-card').filter({ hasText: 'L3 review' })
  await expect(l3Card).toContainText('N/A')
  await expect(page.getByRole('region', { name: 'Layer 3 review' })).toContainText('Layer 3 review is not applicable')
  await expect(page.getByRole('table', { name: 'Layer 3 candidates' })).toHaveCount(0)
})

test('fails closed when L2 source or integrity fields are missing', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R49 L2 integrity')
  let candidateCalls = 0
  await page.route('**/l2-cli-candidates', (route) => {
    candidateCalls += 1
    return route.fulfill({ status: 500, json: { detail: 'candidate endpoint must not be called' } })
  })
  await page.route('**/l2-cli-validation', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as JsonRecord
    delete (body.integrity as JsonRecord).expected_source_match
    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', 'X-Validation-Scope': 'full' },
      body: JSON.stringify(body),
    })
  })
  await openPreview(page, eventId)
  await expect(page.getByRole('region', { name: 'Layer 2 review' })).toContainText('Data binding is inconsistent')
  await expect(page.getByRole('region', { name: 'Layer 2 review' })).toContainText('l2-report-integrity')
  await expect(page.getByRole('table', { name: 'Layer 2 candidates' })).toHaveCount(0)
  await expect.poll(() => candidateCalls).toBe(0)
})

test('fails closed when a selected Core L2 validation returns assignment-not-found', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R49 Core L2 404', false)
  let l2CandidateCalls = 0
  await page.route('**/l2-cli-candidates', (route) => {
    l2CandidateCalls += 1
    return route.fulfill({ status: 500, json: { detail: 'L2 candidate endpoint must not be called' } })
  })
  await page.route('**/l2-cli-validation', (route) => route.fulfill({
    status: 404,
    json: { detail: { reason_code: 'assignment-not-found', stage: 'preview' } },
  }))
  await openPreview(page, eventId)
  const l2Region = page.getByRole('region', { name: 'Layer 2 review' })
  await expect(l2Region).toContainText('Validation failed')
  await expect(l2Region).toContainText('The Event, saved revision or assignment was not found.')
  await expect(page.locator('.cisco-status-card').filter({ hasText: 'L2 review' })).toContainText('FAIL')
  const overallCard = page.locator('.cisco-status-card').filter({ hasText: 'Overall review' })
  await expect(overallCard.locator('[data-slot="badge"]')).toHaveText('FAIL')
  await expect(page.getByRole('table', { name: 'Layer 2 candidates' })).toHaveCount(0)
  await expect(l2Region.locator('pre.cisco-command')).toHaveCount(0)
  await expect.poll(() => l2CandidateCalls).toBe(0)
})

test('fails closed when a saved Core L3 validation is ineligible', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R49 Core L3 409', false)
  let l3CandidateCalls = 0
  await page.route('**/l3-cli-candidates', (route) => {
    l3CandidateCalls += 1
    return route.fulfill({ status: 500, json: { detail: 'L3 candidate endpoint must not be called' } })
  })
  await page.route('**/l3-cli-validation', (route) => route.fulfill({
    status: 409,
    json: { detail: { reason_code: 'assignment-not-eligible-for-l3-cli', stage: 'assignment' } },
  }))
  await openPreview(page, eventId)
  const l3Region = page.getByRole('region', { name: 'Layer 3 review' })
  await expect(l3Region).toContainText('Validation failed')
  await expect(l3Region).toContainText('assignment-not-eligible-for-l3-cli')
  await expect(page.locator('.cisco-status-card').filter({ hasText: 'L3 review' })).toContainText('FAIL')
  const overallCard = page.locator('.cisco-status-card').filter({ hasText: 'Overall review' })
  await expect(overallCard.locator('[data-slot="badge"]')).toHaveText('FAIL')
  await expect(page.getByRole('table', { name: 'Layer 3 candidates' })).toHaveCount(0)
  await expect(l3Region.locator('pre.cisco-command')).toHaveCount(0)
  await expect.poll(() => l3CandidateCalls).toBe(0)
})

test('supports Chinese labels and three responsive viewports', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R49 i18n responsive')
  await page.setViewportSize({ width: 390, height: 844 })
  await openPreview(page, eventId, 'Cisco Config Preview')
  await page.getByLabel('Language').selectOption('zh-CN')
  await expect(page.getByRole('heading', { name: 'Cisco 配置预览', exact: true })).toBeVisible()
  await expect(page.locator('.cisco-status-card').filter({ hasText: '整体审阅' })).toContainText('部分通过')
  const management = page.getByRole('region', { name: '管理 / SSHv2 / 认证' })
  await expect(management).toBeVisible()
  await expect(management).toContainText('管理 VLAN')
  await expect(management).toContainText('凭据引用')
  await expect(management).toContainText('Secret 可用性未验证')
  const assembly = page.getByRole('region', { name: '设备配置整合' })
  await expect(assembly).toBeVisible()
  await expect(assembly).toContainText('不完整')
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1)
  const region = page.locator('.cisco-subsystem').first().locator('[data-slot="table-container"]')
  await expect(region).toHaveAttribute('tabindex', '0')
  await region.focus()
  await expect(region).toBeFocused()
  await page.screenshot({ path: 'test-results/cisco-preview-zh-390.png', fullPage: true })
  for (const width of [1366, 1920]) {
    await page.setViewportSize({ width, height: width === 1366 ? 900 : 1080 })
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1)
    await page.screenshot({ path: 'test-results/cisco-preview-zh-' + width + '.png', fullPage: true })
  }
})

test('shows an L2 BLOCKED state with an L3 PASS without claiming overall PASS', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R49 L2 blocked L3 pass', false)
  await openPreview(page, eventId)
  await expect(page.locator('.cisco-status-card').filter({ hasText: 'L2 review' })).toContainText('PARTIAL')
  await expect(page.locator('.cisco-status-card').filter({ hasText: 'L3 review' })).toContainText('PASS')
  await expect(page.locator('.cisco-status-card').filter({ hasText: 'Overall review' })).toContainText('PARTIAL')
  await expect(page.getByRole('table', { name: 'Layer 2 candidates' }).locator('tbody tr').filter({ hasText: 'BLOCKED' }).first()).toBeVisible()
  await expect(page.getByRole('table', { name: 'Layer 3 candidates' })).toBeVisible()
  await expect(page.getByText('DHCP Helper blocked', { exact: true })).toHaveCount(0)
})

test('rejects a missing L2 source field before requesting candidates', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R49 missing L2 source')
  let candidateCalls = 0
  await page.route('**/l2-cli-candidates', (route) => {
    candidateCalls += 1
    return route.fulfill({ status: 500, json: { detail: 'candidate endpoint must not be called' } })
  })
  await page.route('**/l2-cli-validation', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as JsonRecord
    delete (body.source as JsonRecord).saved_revision_uuid
    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', 'X-Validation-Scope': 'full' },
      body: JSON.stringify(body),
    })
  })
  await openPreview(page, eventId)
  await expect(page.getByRole('region', { name: 'Layer 2 review' })).toContainText('Data binding is inconsistent')
  await expect(page.getByRole('region', { name: 'Layer 2 review' })).toContainText('l2-source-contract')
  await expect.poll(() => candidateCalls).toBe(0)
})

test('rejects a revision or assignment mismatch before requesting candidates', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R49 binding mismatch')
  let candidateCalls = 0
  await page.route('**/l2-cli-candidates', (route) => {
    candidateCalls += 1
    return route.fulfill({ status: 500, json: { detail: 'candidate endpoint must not be called' } })
  })
  await page.route('**/l2-cli-validation', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as JsonRecord
    ;(body.source as JsonRecord).saved_revision_uuid = '99999999-9999-4999-8999-999999999999'
    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', 'X-Validation-Scope': 'full' },
      body: JSON.stringify(body),
    })
  })
  await openPreview(page, eventId)
  await expect(page.getByRole('region', { name: 'Layer 2 review' })).toContainText('Data binding is inconsistent')
  await expect(page.getByRole('region', { name: 'Layer 2 review' })).toContainText('l2-source-binding')
  await expect.poll(() => candidateCalls).toBe(0)
})

test('rejects an L3 registry mismatch before requesting L3 candidates', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R49 L3 registry mismatch')
  let l3CandidateCalls = 0
  await page.route('**/l3-cli-candidates', (route) => {
    l3CandidateCalls += 1
    return route.fulfill({ status: 500, json: { detail: 'L3 candidate endpoint must not be called' } })
  })
  await page.route('**/l3-cli-validation', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as JsonRecord
    ;(body.source as JsonRecord).command_evidence_registry_fingerprint = '0'.repeat(64)
    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', 'X-Validation-Scope': 'full' },
      body: JSON.stringify(body),
    })
  })
  await openPreview(page, eventId)
  await expect(page.getByRole('region', { name: 'Layer 3 review' })).toContainText('Data binding is inconsistent')
  await expect(page.getByRole('region', { name: 'Layer 3 review' })).toContainText('source-binding')
  await expect.poll(() => l3CandidateCalls).toBe(0)
})

test('shows a general 404 as an error instead of a fake PASS or N/A', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R49 404')
  await page.route('**/l2-cli-validation', (route) => route.fulfill({
    status: 404,
    json: { detail: { reason_code: 'saved-revision-not-found', stage: 'revision' } },
  }))
  await openPreview(page, eventId)
  await expect(page.getByRole('region', { name: 'Layer 2 review' })).toContainText('Validation failed')
  await expect(page.getByRole('region', { name: 'Layer 2 review' })).toContainText('The Event, saved revision or assignment was not found.')
  await expect(page.locator('.cisco-status-card').filter({ hasText: 'Overall review' })).toContainText('FAIL')
})

test('does not render an old L2 response after the assignment changes', async ({ page, request }) => {
  const { eventId, plan } = await preparedEvent(request, 'R50 stale response')
  const coreId = String((plan.assignments as JsonRecord[])[0]!.id)
  const accessId = String((plan.assignments as JsonRecord[])[1]!.id)
  const pageErrors = await watchBrowserErrors(page)
  let release: (() => void) | null = null
  let held = false
  await page.route('**/l2-cli-validation', async (route) => {
    const url = route.request().url()
    if (!held && url.includes(coreId)) {
      held = true
      await new Promise<void>((resolve) => { release = resolve })
    }
    try { await route.continue() } catch { /* the page may have aborted the stale request */ }
  })
  await openPreview(page, eventId)
  await expect.poll(() => release !== null).toBe(true)
  await page.locator('#cisco-assignment').selectOption(accessId)
  await expect(page.locator('.cisco-metadata').first()).toContainText(accessId)
  await expect(page.getByRole('table', { name: 'Layer 2 candidates' })).toBeVisible()
  release!()
  await page.waitForLoadState('networkidle')
  expect(pageErrors).toEqual([])
  expect(await unhandledErrors(page)).toEqual([])
  await expect(page.locator('.cisco-metadata').first()).toContainText(accessId)
  await expect(page.locator('.cisco-metadata').first()).not.toContainText(coreId)
  await expect(page.getByRole('table', { name: 'Layer 2 candidates' }).locator('tbody tr').filter({ hasText: 'L3-Core' })).toHaveCount(0)
})

test('immediately invalidates loaded candidates when the assignment changes', async ({ page, request }) => {
  const { eventId, plan } = await preparedEvent(request, 'R50 post-load assignment')
  const coreId = String((plan.assignments as JsonRecord[])[0]!.id)
  const accessId = String((plan.assignments as JsonRecord[])[1]!.id)
  const pageErrors = await watchBrowserErrors(page)
  const releases: (() => void)[] = []
  await page.route('**/l2-cli-validation', (route) => holdCoreValidation(route, accessId, releases))
  await page.route('**/l3-cli-validation', (route) => holdCoreValidation(route, accessId, releases))
  await openPreview(page, eventId)
  await expect(page.locator('.cisco-metadata').first()).toContainText(coreId)
  await expect(page.getByRole('table', { name: 'Layer 2 candidates' })).toBeVisible()
  await page.locator('#cisco-assignment').selectOption(accessId)
  expect(await hasL2CandidateTable(page)).toBe(false)
  await expect(page.getByRole('region', { name: 'Layer 2 review' })).toContainText('Loading L2 review')
  await expect.poll(() => releases.length).toBe(1)
  for (const release of releases) release()
  await page.waitForLoadState('networkidle')
  expect(pageErrors).toEqual([])
  expect(await unhandledErrors(page)).toEqual([])
  await expect(page.locator('.cisco-metadata').first()).toContainText(accessId)
  await expect(page.getByRole('table', { name: 'Layer 2 candidates' })).toBeVisible()
})

test('does not render an old revision response after the revision changes', async ({ page, request }) => {
  const { eventId, plan, revision: first } = await preparedEvent(request, 'R50 stale revision')
  const changed = structuredClone(plan)
  const core = (changed.assignments as JsonRecord[]).find((item) => item.role === 'core')!
  ;(changed.static_routes as JsonRecord[]).push({
    id: id(), assignment_id: core.id, destination: '10.201.0.0/24',
    next_hop: { kind: 'ip', address: '10.0.0.2' }, preference: 1,
  })
  const second = await savePlan(request, changed)
  expect(second.id).not.toBe(first.id)
  const pageErrors = await watchBrowserErrors(page)
  let release: (() => void) | null = null
  let held = false
  await page.route('**/l2-cli-validation', async (route) => {
    if (!held && route.request().url().includes(second.id)) {
      held = true
      await new Promise<void>((resolve) => { release = resolve })
    }
    try { await route.continue() } catch { /* the page may have aborted the stale request */ }
  })
  await openPreview(page, eventId)
  await expect.poll(() => release !== null).toBe(true)
  await page.locator('#cisco-revision').selectOption(first.id)
  await expect(page.locator('.cisco-metadata').first()).toContainText(first.id)
  release!()
  await page.waitForLoadState('networkidle')
  expect(pageErrors).toEqual([])
  expect(await unhandledErrors(page)).toEqual([])
  await expect(page.locator('#cisco-revision')).toHaveValue(first.id)
  await expect(page.locator('.cisco-metadata').first()).toContainText(first.id)
  await expect(page.locator('.cisco-metadata').first()).not.toContainText(second.id)
})

test('immediately invalidates loaded candidates when the revision changes', async ({ page, request }) => {
  const { eventId, plan, revision: first } = await preparedEvent(request, 'R50 post-load revision')
  const changed = structuredClone(plan)
  const core = (changed.assignments as JsonRecord[]).find((item) => item.role === 'core')!
  ;(changed.static_routes as JsonRecord[]).push({
    id: id(), assignment_id: core.id, destination: '10.202.0.0/24',
    next_hop: { kind: 'ip', address: '10.0.0.2' }, preference: 1,
  })
  const corePort = (changed.physical_interfaces as JsonRecord[]).find(
    (port) => port.assignment_id === core.id && port.name === 'Gi1/0/1',
  )!
  corePort.settings = { ...(corePort.settings as JsonRecord), description: 'R50 post-load revision' }
  const second = await savePlan(request, changed)
  const pageErrors = await watchBrowserErrors(page)
  const releases: (() => void)[] = []
  await page.route('**/l2-cli-validation', (route) => holdCoreValidation(route, first.id, releases))
  await page.route('**/l3-cli-validation', (route) => holdCoreValidation(route, first.id, releases))
  await openPreview(page, eventId)
  await expect(page.locator('.cisco-metadata').first()).toContainText(second.id)
  await expect(page.getByRole('table', { name: 'Layer 2 candidates' })).toBeVisible()
  await page.locator('#cisco-revision').selectOption(first.id)
  expect(await hasL2CandidateTable(page)).toBe(false)
  await expect.poll(() => releases.length).toBe(2)
  for (const release of releases) release()
  await page.waitForLoadState('networkidle')
  expect(pageErrors).toEqual([])
  expect(await unhandledErrors(page)).toEqual([])
  await expect(page.locator('#cisco-revision')).toHaveValue(first.id)
  await expect(page.locator('.cisco-metadata').first()).toContainText(first.id)
})

test('leaves the page during in-flight validation without unhandled errors', async ({ page, request }) => {
  const { eventId, plan } = await preparedEvent(request, 'R50 leave page')
  const coreId = String((plan.assignments as JsonRecord[])[0]!.id)
  const pageErrors = await watchBrowserErrors(page)
  const releases: (() => void)[] = []
  await page.route('**/l2-cli-validation', (route) => holdCoreValidation(route, coreId, releases))
  await page.route('**/l3-cli-validation', (route) => holdCoreValidation(route, coreId, releases))
  await openPreview(page, eventId)
  await expect.poll(() => releases.length).toBe(2)
  await page.goto('/#planner/addressing')
  for (const release of releases) release()
  await page.waitForLoadState('networkidle')
  expect(pageErrors).toEqual([])
  expect(await unhandledErrors(page)).toEqual([])
  await expect(page.getByRole('heading', { name: 'Network Planner', exact: true })).toBeVisible()
})

test('withholds command text from a tampered candidate document', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R49 tampered candidate')
  await page.route('**/l2-cli-candidates', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as JsonRecord
    const candidate = (body.candidates as JsonRecord[]).find((item) => item.status === 'blocked')
    expect(candidate).toBeDefined()
    candidate!.candidate_text = 'switchport mode access'
    await route.fulfill({ status: 200, json: body })
  })
  await openPreview(page, eventId)
  await expect(page.getByRole('region', { name: 'Layer 2 review' })).toContainText('Data binding is inconsistent')
  await expect(page.getByRole('region', { name: 'Layer 2 review' })).toContainText('l2-candidate-text')
  await expect(page.getByRole('region', { name: 'Layer 2 review' }).locator('pre.cisco-command')).toHaveCount(0)
})

test('switches assignment during in-flight L2 and L3 validation without unhandled errors', async ({ page, request }) => {
  const { eventId, plan } = await preparedEvent(request, 'R50 in-flight assignment')
  const coreId = String((plan.assignments as JsonRecord[])[0]!.id)
  const accessId = String((plan.assignments as JsonRecord[])[1]!.id)
  const pageErrors = await watchBrowserErrors(page)
  const releases: (() => void)[] = []
  await page.route('**/l2-cli-validation', (route) => holdCoreValidation(route, coreId, releases))
  await page.route('**/l3-cli-validation', (route) => holdCoreValidation(route, coreId, releases))
  await openPreview(page, eventId)
  await expect.poll(() => releases.length).toBe(2)
  await page.locator('#cisco-assignment').selectOption(accessId)
  await expect(page.locator('.cisco-metadata').first()).toContainText(accessId)
  await expect(page.getByRole('region', { name: 'Layer 3 review' })).toContainText('not applicable')
  for (const release of releases) release()
  await page.waitForLoadState('networkidle')
  expect(pageErrors).toEqual([])
  expect(await unhandledErrors(page)).toEqual([])
  await expect(page.getByRole('table', { name: 'Layer 2 candidates' })).toBeVisible()
  await expect(page.getByRole('region', { name: 'Layer 2 review' }).locator('table').filter({ hasText: 'L3-Core' })).toHaveCount(0)
})

test('shows a stable 409 error and hides command text', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R49 409')
  await page.route('**/l2-cli-validation', (route) => route.fulfill({
    status: 409,
    json: { detail: { reason_code: 'validation-integrity-failure', stage: 'validation', failures: ['source-mismatch'] } },
  }))
  await openPreview(page, eventId)
  await expect(page.getByRole('region', { name: 'Layer 2 review' })).toContainText('Validation failed')
  await expect(page.getByRole('region', { name: 'Layer 2 review' })).toContainText('validation-integrity-failure')
  await expect(page.getByRole('table', { name: 'Layer 2 candidates' })).toHaveCount(0)
  await expect(page.getByRole('region', { name: 'Layer 2 review' }).locator('pre.cisco-command')).toHaveCount(0)
})

test('shows device configuration assembly chapters and cross-layer checks for C9200', async ({ page, request }) => {
  const { eventId } = await preparedC9200CandidateEvent(request, 'R59 C9200 assembly')
  await openPreview(page, eventId)
  const panel = page.getByRole('region', { name: 'Device configuration assembly' })
  await expect(panel).toBeVisible()
  await expect(panel).toContainText('This device configuration is NOT COMPLETE.')
  const chapters = panel.getByRole('table', { name: 'Configuration chapters' })
  await expect(chapters.locator('tbody tr')).toHaveCount(12)
  const ipRow = chapters.locator('tbody tr').filter({ hasText: 'ip-routing' }).first()
  await expect(ipRow).toContainText('VALIDATED SECTION')
  const sviRow = chapters.locator('tbody tr').filter({ hasText: 'svi' }).first()
  await expect(sviRow).toContainText('PARTIAL')
  const dhcpRow = chapters.locator('tbody tr').filter({ hasText: 'dhcp' }).first()
  await expect(dhcpRow).toContainText('NOT APPLICABLE')
  const managementRow = chapters.locator('tbody tr').filter({ hasText: 'management-auth-ssh' }).first()
  await expect(managementRow).toContainText('BLOCKED')
  const checks = panel.getByRole('table', { name: 'Cross-layer checks' })
  await expect(checks.locator('tbody tr')).toHaveCount(11)
  const chapter = panel.locator('.cisco-assembly-chapter').filter({ hasText: 'ip-routing' }).first()
  await chapter.locator('summary').click()
  await expect(chapter.locator('pre.cisco-command')).toContainText('ip routing')
  await expect(panel).toContainText('No combined command script is generated')
  await expect(panel.getByRole('button', { name: /copy all|execute|deploy/i })).toHaveCount(0)

  for (const width of [390, 1366, 1920]) {
    await page.setViewportSize({ width, height: 900 })
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth))
      .toBeLessThanOrEqual(1)
  }
})

test('clears the old device assembly when the selected assignment changes', async ({ page, request }) => {
  const { eventId, plan } = await preparedEvent(request, 'R59 assembly switch')
  const accessId = String((plan.assignments as JsonRecord[])[1]!.id)
  await openPreview(page, eventId)
  const panel = page.getByRole('region', { name: 'Device configuration assembly' })
  await expect(panel.getByRole('table', { name: 'Configuration chapters' })).toBeVisible()
  const chapter = panel.locator('.cisco-assembly-chapter').filter({ hasText: 'ip-routing' }).first()
  await chapter.locator('summary').click()
  await expect(chapter.locator('pre.cisco-command')).toContainText('ip routing')
  await page.locator('#cisco-assignment').selectOption(accessId)
  await expect(page.locator('#cisco-assignment')).toHaveValue(accessId)
  await expect(panel.getByRole('table', { name: 'Configuration chapters' })).toBeVisible()
  await expect(panel).not.toContainText('ip routing')
  const row = panel.getByRole('table', { name: 'Configuration chapters' })
    .locator('tbody tr').filter({ hasText: 'ip-routing' }).first()
  await expect(row).toContainText('NOT APPLICABLE')
})

test('shows C9300 assembly completeness without claiming a complete configuration', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R59 C9300 assembly')
  await openPreview(page, eventId)
  const panel = page.getByRole('region', { name: 'Device configuration assembly' })
  await expect(panel).toBeVisible()
  await expect(panel).toContainText('This device configuration is NOT COMPLETE.')
  const chapters = panel.getByRole('table', { name: 'Configuration chapters' })
  await expect(chapters.locator('tbody tr')).toHaveCount(12)
  const dhcpRow = chapters.locator('tbody tr').filter({ hasText: 'dhcp' }).first()
  await expect(dhcpRow).toContainText('BLOCKED')
  const managementRow = chapters.locator('tbody tr').filter({ hasText: 'management-auth-ssh' }).first()
  await expect(managementRow).toContainText('BLOCKED')
  await expect(panel.getByRole('table', { name: 'Cross-layer checks' })).toContainText('BLOCKED')
  await expect(panel.getByText('Hardware is NOT VERIFIED', { exact: false })).toBeVisible()
  await expect(panel.getByRole('button', { name: /copy all|execute|deploy/i })).toHaveCount(0)
})

test('keeps unsupported C9200-style platforms assembly fail-closed with no CLI text', async ({ page, request }) => {
  const { eventId } = await preparedEvent(
    request, 'R59 unsupported assembly', false,
    { pid: 'WS-C2960X-24TS-L', family: 'catalyst-2960x', image: '15.2(7)E', license: 'LAN Base' },
  )
  await openPreview(page, eventId)
  const panel = page.getByRole('region', { name: 'Device configuration assembly' })
  await expect(panel).toBeVisible()
  await expect(panel).toContainText('This device configuration is NOT COMPLETE.')
  await expect(panel.locator('pre.cisco-command')).toHaveCount(0)
  await expect(panel).toContainText('NOT IMPLEMENTED')
  await expect(panel.getByRole('button', { name: /copy all|execute|deploy/i })).toHaveCount(0)
})

test('rejects tampered assembly source fingerprints and hides chapter CLI', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R59 tampered assembly')
  await page.route('**/config-assembly-preview', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as JsonRecord
    const source = body.source as JsonRecord
    source.l2_render_fingerprint = 'tampered'
    await route.fulfill({ status: 200, headers: response.headers(), json: body })
  })
  await openPreview(page, eventId)
  const panel = page.getByRole('region', { name: 'Device configuration assembly' })
  await expect(panel).toContainText('Data binding is inconsistent')
  await expect(panel.locator('pre.cisco-command')).toHaveCount(0)
})
function assemblySection(body: JsonRecord, sectionId: string): JsonRecord {
  const section = (body.sections as JsonRecord[]).find((item) => item.section_id === sectionId)
  expect(section).toBeDefined()
  return section!
}

function assemblyCandidate(section: JsonRecord): JsonRecord {
  const candidate = (section.candidates as JsonRecord[]).find((item) => item.status === 'candidate')
  expect(candidate).toBeDefined()
  return candidate!
}

async function interceptAssembly(
  page: Page, mutate: (body: JsonRecord) => void,
) {
  await page.route('**/config-assembly-preview', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as JsonRecord
    mutate(body)
    await route.fulfill({ status: 200, headers: response.headers(), json: body })
  })
}

async function expectAssemblyWithheld(page: Page) {
  const panel = page.getByRole('region', { name: 'Device configuration assembly' })
  await expect(panel).toBeVisible()
  await expect(panel).toContainText('Data binding is inconsistent')
  await expect(panel).toContainText('Command text withheld')
  await expect(panel.locator('pre.cisco-command')).toHaveCount(0)
}

test('withholds assembly CLI when the independent L2 report fails', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R59A L2 report failure')
  await page.route('**/l2-cli-validation', (route) => route.fulfill({
    status: 500,
    json: { detail: { reason_code: 'forced-l2-failure', stage: 'validation', failures: ['forced'] } },
  }))
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('withholds assembly CLI when the Core L3 report fails', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R59A L3 report failure')
  await page.route('**/l3-cli-validation', (route) => route.fulfill({
    status: 500,
    json: { detail: { reason_code: 'forced-l3-failure', stage: 'validation', failures: ['forced'] } },
  }))
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('withholds assembly CLI when the L2 candidate document is unavailable', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R59A L2 document failure')
  await page.route('**/l2-cli-candidates', (route) => route.fulfill({
    status: 409,
    json: { detail: { reason_code: 'forced-document-failure', stage: 'candidate', failures: ['forced'] } },
  }))
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('rejects a replaced assembly command even when the source fingerprint strings stay unchanged', async ({ page, request }) => {
  const { eventId } = await preparedC9200CandidateEvent(request, 'R59A replaced command')
  await interceptAssembly(page, (body) => {
    const candidate = assemblyCandidate(assemblySection(body, 'ip-routing'))
    candidate.candidate_text = 'ip route 203.0.113.0 255.255.255.0 192.168.10.2'
  })
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('rejects a valid-shaped but mismatched assembly candidate fingerprint', async ({ page, request }) => {
  const { eventId } = await preparedC9200CandidateEvent(request, 'R59A candidate fingerprint')
  await interceptAssembly(page, (body) => {
    const candidate = assemblyCandidate(assemblySection(body, 'ip-routing'))
    candidate.candidate_fingerprint = '0'.repeat(64)
  })
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('rejects changed assembly category and target while keeping the candidate ID', async ({ page, request }) => {
  const { eventId } = await preparedC9200CandidateEvent(request, 'R59A category target')
  await interceptAssembly(page, (body) => {
    const candidate = assemblyCandidate(assemblySection(body, 'ip-routing'))
    candidate.category = 'static-route'
    candidate.target_name = 'Vlan999'
  })
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('rejects injected CLI on a blocked assembly candidate', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R59A blocked CLI')
  await interceptAssembly(page, (body) => {
    const section = assemblySection(body, 'dhcp')
    const blocked = (section.candidates as JsonRecord[]).find((item) => item.status === 'blocked')
    expect(blocked).toBeDefined()
    blocked!.candidate_text = 'ip helper-address 192.168.10.5'
  })
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('rejects a duplicate assembly candidate across chapters', async ({ page, request }) => {
  const { eventId } = await preparedC9200CandidateEvent(request, 'R59A duplicate candidate')
  await interceptAssembly(page, (body) => {
    const source = assemblySection(body, 'ip-routing')
    const candidate = assemblyCandidate(source)
    const target = assemblySection(body, 'svi')
    ;(target.candidates as JsonRecord[]).push(structuredClone(candidate))
  })
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('rejects a forged Cross-layer ID and a changed Cross-layer status', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R59A cross layer tamper')
  await interceptAssembly(page, (body) => {
    const checks = body.cross_layer_checks as JsonRecord[]
    checks[0]!.check_id = 'forged-cross-layer-check'
    const dhcp = checks.find((item) => item.check_id === 'dhcp-relay-issue-30')
    expect(dhcp).toBeDefined()
    dhcp!.status = 'PASS'
  })
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('rejects a required chapter converted to NOT_APPLICABLE and a forged COMPLETE claim', async ({ page, request }) => {
  const { eventId } = await preparedC9200CandidateEvent(request, 'R59A completeness claim')
  await interceptAssembly(page, (body) => {
    const management = assemblySection(body, 'management-auth-ssh')
    management.status = 'NOT_APPLICABLE'
    management.applicability = 'NOT_APPLICABLE'
    management.required = false
    const completeness = body.completeness as JsonRecord
    completeness.complete = true
    completeness.status = 'VALIDATED_SECTION'
  })
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('rejects inconsistent assembly statistics', async ({ page, request }) => {
  const { eventId } = await preparedC9200CandidateEvent(request, 'R59A statistics')
  await interceptAssembly(page, (body) => {
    const section = assemblySection(body, 'vlan-definitions')
    section.candidate_count = Number(section.candidate_count) + 2
  })
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('rejects an assembly response bound to a different saved revision', async ({ page, request }) => {
  const { eventId, revision } = await preparedC9200CandidateEvent(request, 'R59A revision mismatch')
  const otherRevision = id()
  expect(otherRevision).not.toBe(revision.id)
  await interceptAssembly(page, (body) => {
    const source = body.source as JsonRecord
    source.revision_id = otherRevision
  })
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('withholds non-core assembly L3 CLI injected outside the N/A contract', async ({ page, request }) => {
  const { eventId, plan } = await preparedEvent(request, 'R59A non-core injection')
  const accessId = String((plan.assignments as JsonRecord[])[1]!.id)
  await page.route('**/config-assembly-preview', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as JsonRecord
    if ((body.identity as JsonRecord).assignment_id === accessId) {
      const section = assemblySection(body, 'ip-routing')
      section.candidates = [{
        candidate_id: 'cand-0000000000000099',
        source_layer: 'l3',
        category: 'ip-routing',
        target_kind: 'device',
        target_name: 'L2-Access',
        status: 'candidate',
        verdict: 'pass',
        candidate_text: 'ip routing',
        risk_class: 'R2',
        requires_field_verification: false,
        blocking_reasons: [],
        candidate_fingerprint: '0'.repeat(64),
      }]
      section.candidate_count = 1
      section.passed_count = 1
      section.status = 'VALIDATED_SECTION'
      section.required = true
    }
    await route.fulfill({ status: 200, headers: response.headers(), json: body })
  })
  await openPreview(page, eventId)
  await page.locator('#cisco-assignment').selectOption(accessId)
  await expect(page.locator('#cisco-assignment')).toHaveValue(accessId)
  const panel = page.getByRole('region', { name: 'Device configuration assembly' })
  await expect(panel.locator('pre.cisco-command')).toHaveCount(0)
  await expect(panel).toContainText('Data binding is inconsistent')
})
test('withholds assembly CLI when the independent L2 report is structurally invalid', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R59A L2 invalid report')
  await page.route('**/l2-cli-validation', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as JsonRecord
    body.report_fingerprint = '0'.repeat(64)
    await route.fulfill({ status: 200, headers: response.headers(), json: body })
  })
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('withholds assembly CLI when the L3 report integrity is invalid', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R59A L3 invalid report')
  await page.route('**/l3-cli-validation', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as JsonRecord
    ;(body.integrity as JsonRecord).document_fingerprint = false
    await route.fulfill({ status: 200, headers: response.headers(), json: body })
  })
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('withholds assembly CLI when the L3 candidate document is unavailable', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R59A L3 document failure')
  await page.route('**/l3-cli-candidates', (route) => route.fulfill({
    status: 409,
    json: { detail: { reason_code: 'forced-l3-document-failure', stage: 'candidate', failures: ['forced'] } },
  }))
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('rejects a structurally valid but forged assembly content hash and changed command', async ({ page, request }) => {
  const { eventId } = await preparedC9200CandidateEvent(request, 'R59A forged assembly hash')
  await interceptAssembly(page, (body) => {
    const candidate = assemblyCandidate(assemblySection(body, 'ip-routing'))
    candidate.candidate_text = 'hostname FORGED'
    body.assembly_fingerprint = '1'.repeat(64)
  })
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('rejects an assembly response bound to a different assignment', async ({ page, request }) => {
  const { eventId } = await preparedC9200CandidateEvent(request, 'R59A assignment mismatch')
  await interceptAssembly(page, (body) => {
    ;(body.source as JsonRecord).assignment_id = id()
  })
  await openPreview(page, eventId)
  await expectAssemblyWithheld(page)
})

test('keeps a non-Core L2 assembly review with L3 N/A and no L3 CLI', async ({ page, request }) => {
  const { eventId, plan } = await preparedEvent(request, 'R59A non-core assembly')
  const accessId = String((plan.assignments as JsonRecord[])[1]!.id)
  await openPreview(page, eventId)
  await page.locator('#cisco-assignment').selectOption(accessId)
  await expect(page.locator('#cisco-assignment')).toHaveValue(accessId)
  const panel = page.getByRole('region', { name: 'Device configuration assembly' })
  await expect(panel.getByRole('table', { name: 'Configuration chapters' })).toBeVisible()
  await expect(panel).toContainText('This device configuration is NOT COMPLETE.')
  const l3Section = panel.getByRole('table', { name: 'Configuration chapters' })
    .locator('tbody tr').filter({ hasText: 'ip-routing' }).first()
  await expect(l3Section).toContainText('NOT APPLICABLE')
  await expect(panel.locator('pre.cisco-command').filter({ hasText: 'ip routing' })).toHaveCount(0)
})

test('does not restore a late Core assembly after switching to a non-Core assignment', async ({ page, request }) => {
  const { eventId, plan } = await preparedEvent(request, 'R59A late assembly')
  const coreId = String((plan.assignments as JsonRecord[])[0]!.id)
  const accessId = String((plan.assignments as JsonRecord[])[1]!.id)
  let releaseCore: (() => void) | undefined
  await page.route('**/config-assembly-preview', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as JsonRecord
    if ((body.identity as JsonRecord).assignment_id === coreId) {
      await new Promise<void>((resolve) => { releaseCore = resolve })
    }
    await route.fulfill({ status: 200, headers: response.headers(), json: body })
  })
  await openPreview(page, eventId)
  await expect.poll(() => releaseCore !== undefined).toBe(true)
  await page.locator('#cisco-assignment').selectOption(accessId)
  const panel = page.getByRole('region', { name: 'Device configuration assembly' })
  await expect(panel.getByRole('table', { name: 'Configuration chapters' })).toBeVisible()
  releaseCore!()
  await page.waitForTimeout(150)
  await expect(panel.locator('pre.cisco-command').filter({ hasText: 'ip routing' })).toHaveCount(0)
})
test('shows a blocked management/SSHv2 review without secret or CLI text', async ({ page, request }) => {
  const { eventId } = await preparedManagementEvent(request, 'R61 management reviewed')
  await openPreview(page, eventId)
  const panel = page.getByRole('region', { name: 'Management / SSHv2 / Authentication' })
  await expect(panel).toBeVisible()
  await expect(panel).toContainText('BLOCKED')
  await expect(panel).toContainText('example.com')
  await expect(panel).toContainText('192.168.10.3')
  await expect(panel).toContainText('Opaque reference present')
  await expect(panel).toContainText('Secret availability NOT VERIFIED')
  await expect(panel).toContainText('PENDING independent review')
  const table = panel.getByRole('table', { name: 'Management command candidates' })
  await expect(table.locator('tbody tr')).toHaveCount(9)
  await expect(panel.locator('pre.cisco-command')).toHaveCount(0)
  await expect(panel).not.toContainText('credref:')
  await expect(panel).not.toContainText('netops')
  await expect(page.getByRole('button', { name: /copy all|execute|deploy/i })).toHaveCount(0)
})

test('does not retain previous management credential metadata after assignment change', async ({ page, request }) => {
  const { eventId, plan } = await preparedManagementEvent(request, 'R61 management switch')
  const accessId = String((plan.assignments as JsonRecord[])[1]!.id)
  await openPreview(page, eventId)
  const panel = page.getByRole('region', { name: 'Management / SSHv2 / Authentication' })
  await expect(panel).toContainText('example.com')
  await page.locator('#cisco-assignment').selectOption(accessId)
  await expect(page.locator('#cisco-assignment')).toHaveValue(accessId)
  await expect(panel).toBeVisible()
  await expect(panel).not.toContainText('example.com')
  await expect(panel).toContainText('Missing')
  await expect(panel.locator('pre.cisco-command')).toHaveCount(0)
})

test('rejects a management response carrying a forbidden secret field', async ({ page, request }) => {
  const { eventId } = await preparedManagementEvent(request, 'R61 management secret')
  await page.route('**/management-cli-validation', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as JsonRecord
    body['pass' + 'word'] = 'fixture-value'
    await route.fulfill({ status: 200, headers: response.headers(), json: body })
  })
  await openPreview(page, eventId)
  const panel = page.getByRole('region', { name: 'Management / SSHv2 / Authentication' })
  await expect(panel).toBeVisible()
  await expect(panel).toContainText('Data binding is inconsistent')
  await expect(page.locator('body')).not.toContainText('fixture-value')
  await expect(panel.locator('pre.cisco-command')).toHaveCount(0)
})
test('rejects a management VLAN not bound to the selected Saved Revision', async ({ page, request }) => {
  const { eventId } = await preparedManagementEvent(request, 'R61A management vlan')
  await page.route('**/management-intent', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as JsonRecord
    body.management_vlan = 20
    await route.fulfill({ status: 200, headers: response.headers(), json: body })
  })
  await openPreview(page, eventId)
  const panel = page.getByRole('region', { name: 'Management / SSHv2 / Authentication' })
  await expect(panel).toBeVisible()
  await expect(panel).toContainText('Data binding is inconsistent')
  await expect(panel).toContainText('management-vlan')
  await expect(panel.locator('pre.cisco-command')).toHaveCount(0)
})

test('rejects a forged reviewed management candidate', async ({ page, request }) => {
  const { eventId } = await preparedManagementEvent(request, 'R61A management forged')
  await page.route('**/management-cli-validation', async (route) => {
    const response = await route.fetch()
    const body = await response.json() as JsonRecord
    const candidates = body.candidates as JsonRecord[]
    candidates[0]!.status = 'candidate'
    candidates[0]!.independent_verdict = 'pass'
    candidates[0]!.evidence_review_state = 'independently-reviewed'
    candidates[0]!.candidate_text_present = true
    body.summary = { total: 9, passed: 1, blocked: 8, failed: 0 }
    body.overall_status = 'partial'
    await route.fulfill({ status: 200, headers: response.headers(), json: body })
  })
  await openPreview(page, eventId)
  const panel = page.getByRole('region', { name: 'Management / SSHv2 / Authentication' })
  await expect(panel).toBeVisible()
  await expect(panel).toContainText('Data binding is inconsistent')
  await expect(panel.locator('pre.cisco-command')).toHaveCount(0)
})
test('rebinds management metadata when the Saved Revision changes', async ({ page, request }) => {
  const { eventId, plan } = await preparedManagementEvent(request, 'R61A management revision')
  const secondPlan = structuredClone(plan)
  const secondCore = (secondPlan.assignments as JsonRecord[])[0]!
  secondCore.management_domain = 'second.example.com'
  const second = await savePlan(request, secondPlan)
  await openPreview(page, eventId)
  const panel = page.getByRole('region', { name: 'Management / SSHv2 / Authentication' })
  await expect(panel).toContainText('second.example.com')
  const firstRevision = await request.get(
    '/api/v1/events/' + eventId + '/plan-revisions',
    { headers: { Origin: 'http://127.0.0.1:8765' } },
  )
  const revisions = await firstRevision.json() as JsonRecord[]
  const first = revisions.find((item) => String(item.id) !== second.id)!
  await page.locator('#cisco-revision').selectOption(String(first.id))
  await expect(panel).toContainText('example.com')
  await expect(panel).not.toContainText('second.example.com')
  await expect(panel.locator('pre.cisco-command')).toHaveCount(0)
})
