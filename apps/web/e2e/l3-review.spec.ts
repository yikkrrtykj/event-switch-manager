import { randomUUID } from 'node:crypto'

import { expect, test } from '@playwright/test'
import type { APIRequestContext, Page } from '@playwright/test'

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

type CorePlanOptions = {
  pid?: string
  family?: string
  image?: string
  license?: string
  withRelay?: boolean
}

function l3Plan(eventId: string, options: CorePlanOptions = {}): JsonRecord {
  const {
    pid = 'C9300L-24P-4X',
    family = 'catalyst-9300',
    image = '17.12.4',
    license = 'Network Advantage',
    withRelay = true,
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
  return {
    schema_version: 1,
    event_id: eventId,
    management_vlan: 10,
    physical_devices: [
      { id: coreDevice, vendor: 'cisco', model: pid, verified_serial: 'R44-CORE-' + serialSuffix },
      { id: accessDevice, vendor: 'cisco', model: 'C9300L-24T-4G', verified_serial: 'R44-ACCESS-' + serialSuffix },
      { id: firewallDevice, vendor: 'hillstone', model: 'SG6000', verified_serial: 'R44-FW-' + serialSuffix },
    ],
    assignments: [
      { id: coreAssignment, hostname: 'L3-Core', role: 'core', family,
        physical_device_id: coreDevice, software: { image, license } },
      { id: accessAssignment, hostname: 'L3-Access', role: 'access', family: 'catalyst-9300',
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
    dhcp_pools: withRelay
      ? [{ id: pool20, subnet_id: subnet20, start: '192.168.20.100', end: '192.168.20.150' }]
      : [],
    dhcp_relays: withRelay
      ? [{ subnet_id: subnet20, svi_id: vlan20Svi, servers: ['192.168.10.5'] }]
      : [],
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
}

async function savePlan(request: APIRequestContext, plan: JsonRecord) {
  const response = await request.post(revisions(plan.event_id as string), { headers, data: plan })
  expect(response.status(), await response.text()).toBe(200)
  return await response.json() as SavedRevision
}

function secondRevisionPlan(plan: JsonRecord): JsonRecord {
  const copy = structuredClone(plan)
  const routes = copy.static_routes as JsonRecord[]
  routes.push({
    id: id(), assignment_id: (copy.assignments as JsonRecord[])[0]!.id,
    destination: '10.201.0.0/24', next_hop: { kind: 'ip', address: '10.0.0.2' }, preference: 1,
  })
  return copy
}

async function openReview(page: Page, eventId: string) {
  await page.goto('/#l3-review')
  const eventSelect = page.getByLabel('Event', { exact: true })
  await expect(eventSelect).toBeVisible()
  await eventSelect.selectOption(eventId)
  await expect(page.getByRole('heading', { name: 'L3 Review', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Independent validation report' })).toBeVisible()
}

async function preparedEvent(
  request: APIRequestContext, name: string, options: CorePlanOptions = {},
) {
  const eventId = await createEvent(request, name)
  const plan = l3Plan(eventId, options)
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

async function preparedC9200Event(request: APIRequestContext, name: string) {
  const eventId = await createEvent(request, name)
  const plan = c9200CandidatePlan(l3Plan(eventId, {
    pid: 'C9200L-24P-4X', family: 'catalyst-9200', withRelay: false,
  }))
  const revision = await savePlan(request, plan)
  return { eventId, plan, revision }
}

async function preparedC9200SentinelEvent(request: APIRequestContext, name: string) {
  return preparedEvent(request, name, {
    pid: 'C9200L-24P-4X', family: 'catalyst-9200', image: '17.12.5',
    withRelay: false,
  })
}

async function injectValidationResponse(
  page: Page, mutate: (report: JsonRecord) => void,
): Promise<() => number> {
  let candidateCalls = 0
  await page.route('**/l3-cli-validation', async (route) => {
    const response = await route.fetch()
    const report = await response.json() as JsonRecord
    mutate(report)
    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', 'X-Validation-Scope': 'full' },
      body: JSON.stringify(report),
    })
  })
  await page.route('**/l3-cli-candidates', async (route) => {
    candidateCalls += 1
    await route.fulfill({ status: 500, json: { detail: 'candidate endpoint must not be called' } })
  })
  return () => candidateCalls
}

async function openInjectedReview(page: Page, eventId: string) {
  await page.goto('/#l3-review')
  await page.getByLabel('Event', { exact: true }).selectOption(eventId)
  await expect(page.getByRole('heading', { name: 'L3 data binding is inconsistent' })).toBeVisible()
  await expect(page.locator('pre.l3-command')).toHaveCount(0)
  await expect(page.getByRole('button', { name: /execute|deploy|copy all|generate script|download (?:config|configuration|cli|script|full)/i })).toHaveCount(0)
}

test('shows a saved revision read-only 9 PASS / 1 BLOCKED review', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R44 L3 UI')
  await openReview(page, eventId)

  const counts = page.locator('dl.l3-counts')
  await expect(counts.locator('div').filter({ hasText: /^Total/ })).toContainText('10')
  await expect(counts.locator('div').filter({ hasText: /^Passed/ })).toContainText('9')
  await expect(counts.locator('div').filter({ hasText: /^Failed/ })).toContainText('0')
  await expect(counts.locator('div').filter({ hasText: /^BLOCKED/ })).toContainText('1')
  await expect(page.getByText('PARTIAL', { exact: true })).toBeVisible()

  const table = page.getByRole('table', { name: 'Candidates' })
  await expect(table).toBeVisible()
  await expect(table.locator('tbody tr')).toHaveCount(10)
  await expect(table.getByText('PASS', { exact: true })).toHaveCount(9)
  await expect(table.locator('tbody tr').filter({ hasText: 'BLOCKED' })).toHaveCount(1)
  await page.setViewportSize({ width: 1366, height: 900 })
  await page.screenshot({ path: 'test-results/l3-review-en-1366.png', fullPage: true })

  await page.getByLabel('Category filter').selectOption('dhcp-helper-address')
  await expect(table.locator('tbody tr')).toHaveCount(1)
  await expect(counts.locator('div').filter({ hasText: /^Total/ })).toContainText('10')
  await page.getByLabel('Category filter').selectOption('')
  await page.getByLabel('Status filter').selectOption('blocked')
  await expect(table.locator('tbody tr')).toHaveCount(1)
  await page.getByLabel('Status filter').selectOption('')

  const passRow = table.locator('tbody tr').filter({ hasText: 'ip-routing' })
  await passRow.getByText('Details', { exact: true }).click()
  await expect(passRow.getByText('ip routing', { exact: true })).toBeVisible()

  const dhcpRow = table.locator('tbody tr').filter({ hasText: 'dhcp-helper-address' })
  await dhcpRow.getByText('Details', { exact: true }).click()
  await expect(dhcpRow.getByText('Command text unavailable or withheld for this candidate.')).toBeVisible()
  await expect(dhcpRow.locator('pre')).toHaveCount(0)
  await expect(page.getByText('DHCP Helper blocked', { exact: true })).toBeVisible()
  await expect(page.getByText('BLOCKED · Evidence PENDING · License UNRESOLVED', { exact: false })).toBeVisible()

  await expect(page.getByRole('button', { name: /execute|deploy|copy all|generate script|download (?:config|configuration|cli|script|full)/i })).toHaveCount(0)
  await expect(page.getByRole('link', { name: /download (?:config|configuration|cli|script|full)|deploy|execute/i })).toHaveCount(0)
})

test('shows a real C9200 saved revision with reviewed L3 candidates', async ({ page, request }) => {
  const { eventId, plan, revision } = await preparedC9200Event(request, 'R57 C9200 reviewed review')
  const assignmentId = String((plan.assignments as JsonRecord[])[0]!.id)
  const validation = await request.get(
    events + '/' + eventId + '/plan-revisions/' + revision.id +
    '/assignments/' + assignmentId + '/l3-cli-validation',
    { headers },
  )
  expect(validation.status(), await validation.text()).toBe(200)
  expect(validation.headers()['x-validation-scope']).toBe('full')
  const report = await validation.json() as JsonRecord
  const source = report.source as JsonRecord
  const summary = report.summary as JsonRecord
  expect(source.command_evidence_registry_id).toBe('cis-03-c9200-l3-command-evidence-v1')
  expect(source.command_evidence_registry_fingerprint).toBe(
    '2c73c8b39100622360c6bfab935d995d8fb884dd999b6df0ae744a7be7cec876',
  )
  expect(report.overall_status).toBe('partial')
  expect(summary).toMatchObject({ total: 8, passed: 6, failed: 0, blocked: 2 })
  expect((report.candidates as JsonRecord[]).some(
    (item) => (item.evidence as JsonRecord).review_state === 'independently-reviewed',
  )).toBe(true)

  await openReview(page, eventId)
  const counts = page.locator('dl.l3-counts')
  await expect(counts.locator('div').filter({ hasText: /^Total/ })).toContainText('8')
  await expect(counts.locator('div').filter({ hasText: /^Passed/ })).toContainText('6')
  await expect(counts.locator('div').filter({ hasText: /^BLOCKED/ })).toContainText('2')
  await expect(page.getByText('PARTIAL', { exact: true })).toBeVisible()
  await expect(page.getByText('Platform evidence unreviewed', { exact: true })).toHaveCount(0)
  await expect(page.getByText('C9200 evidence reviewed (AI documentation)', { exact: true })).toBeVisible()
  const table = page.getByRole('table', { name: 'Candidates' })
  await expect(table.locator('tbody tr')).toHaveCount(8)
  await expect(table.getByText('PASS', { exact: true })).toHaveCount(6)
  await expect(table.getByText('CANDIDATE', { exact: true })).toHaveCount(6)
  await expect(page.getByRole('button', { name: /execute|deploy|copy all|generate script|download (?:config|configuration|cli|script|full)/i }))
    .toHaveCount(0)

  const ipRow = table.locator('tbody tr').filter({ hasText: 'ip-routing' }).first()
  await ipRow.getByText('Details', { exact: true }).click()
  await expect(ipRow.locator('pre.l3-command')).toContainText('ip routing')
  const sviRow = table.locator('tbody tr').filter({ hasText: 'svi-interface' }).first()
  await sviRow.getByText('Details', { exact: true }).click()
  await expect(sviRow.locator('pre.l3-command')).toContainText('interface Vlan')
  const routeRow = table.locator('tbody tr').filter({ hasText: 'static-route' }).first()
  await routeRow.getByText('Details', { exact: true }).click()
  await expect(routeRow.locator('pre.l3-command')).toContainText('ip route 10.200.0.0')

  for (const width of [390, 1366, 1920]) {
    await page.setViewportSize({ width, height: 900 })
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth))
      .toBeLessThanOrEqual(1)
  }
})

test('keeps an unknown C9200 release on the sentinel and hides CLI', async ({ page, request }) => {
  const { eventId, plan, revision } = await preparedC9200SentinelEvent(
    request, 'R57 unknown C9200 release',
  )
  const assignmentId = String((plan.assignments as JsonRecord[])[0]!.id)
  const validation = await request.get(
    events + '/' + eventId + '/plan-revisions/' + revision.id +
    '/assignments/' + assignmentId + '/l3-cli-validation',
    { headers },
  )
  expect(validation.status(), await validation.text()).toBe(200)
  const report = await validation.json() as JsonRecord
  expect((report.source as JsonRecord).command_evidence_registry_id).toBe(
    'cis-03-l1-command-evidence-unreviewed-v1',
  )
  await openReview(page, eventId)
  await expect(page.getByText('Platform evidence unreviewed', { exact: true })).toBeVisible()
  await expect(page.locator('pre.l3-command')).toHaveCount(0)
  await expect(page.getByRole('table', { name: 'Candidates' }).getByText('PASS', { exact: true }))
    .toHaveCount(0)
})

test('rebinds to reviewed C9200 candidates when switching from 9300', async ({ page, request }) => {
  const r9300 = await preparedEvent(request, 'R57 switch 9300')
  const r9200 = await preparedC9200Event(request, 'R57 switch 9200')
  await openReview(page, r9300.eventId)
  const passRow = page.getByRole('table', { name: 'Candidates' })
    .locator('tbody tr').filter({ hasText: 'ip-routing' }).first()
  await passRow.getByText('Details', { exact: true }).click()
  await expect(passRow.locator('pre.l3-command')).toContainText('ip routing')

  await page.getByLabel('Event', { exact: true }).selectOption(r9200.eventId)
  await expect(page.locator('dl.l3-counts')).toContainText('8')
  await expect(page.locator('dl.l3-counts')).toContainText('6')
  await expect(page.getByRole('table', { name: 'Candidates' }).getByText('PASS', { exact: true }))
    .toHaveCount(6)
  await expect(page.getByText('Platform evidence unreviewed', { exact: true })).toHaveCount(0)
})

test('rejects a 9300 report that claims the unreviewed sentinel', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R52A sentinel on 9300')
  const candidateCalls = await injectValidationResponse(page, (report) => {
    const source = report.source as JsonRecord
    source.command_evidence_registry_id = 'cis-03-l1-command-evidence-unreviewed-v1'
    source.command_evidence_registry_fingerprint =
      '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'
  })
  await openInjectedReview(page, eventId)
  await expect.poll(candidateCalls).toBe(0)
})

test('rejects a C9200 report that claims the 9300 registry', async ({ page, request }) => {
  const { eventId } = await preparedC9200Event(request, 'R52A 9300 on C9200')
  const candidateCalls = await injectValidationResponse(page, (report) => {
    const source = report.source as JsonRecord
    source.command_evidence_registry_id = 'cis-03-l1-command-evidence-v1'
    source.command_evidence_registry_fingerprint =
      '27d9c46f610b974de5570fb13e115260e2d109475a8d967704de9bb9ca6ef00b'
  })
  await openInjectedReview(page, eventId)
  await expect.poll(candidateCalls).toBe(0)
})

test('rejects a forged Registry ID', async ({ page, request }) => {
  const { eventId } = await preparedC9200Event(request, 'R52A forged registry')
  let candidateCalls = 0
  await page.route('**/l3-cli-validation', async (route) => {
    const response = await route.fetch()
    const report = await response.json() as JsonRecord
    const source = report.source as JsonRecord
    source.command_evidence_registry_id = 'arbitrary-forged-registry'
    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', 'X-Validation-Scope': 'full' },
      body: JSON.stringify(report),
    })
  })
  await page.route('**/l3-cli-candidates', (route) => {
    candidateCalls += 1
    return route.fulfill({ status: 500, json: { detail: 'must not be called' } })
  })
  await openInjectedReview(page, eventId)
  await expect.poll(() => candidateCalls).toBe(0)
})

test('rejects a correct Registry ID with the wrong fingerprint', async ({ page, request }) => {
  const { eventId } = await preparedC9200Event(request, 'R52A wrong fingerprint')
  let candidateCalls = 0
  await page.route('**/l3-cli-validation', async (route) => {
    const response = await route.fetch()
    const report = await response.json() as JsonRecord
    const source = report.source as JsonRecord
    source.command_evidence_registry_fingerprint = '0'.repeat(64)
    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', 'X-Validation-Scope': 'full' },
      body: JSON.stringify(report),
    })
  })
  await page.route('**/l3-cli-candidates', (route) => {
    candidateCalls += 1
    return route.fulfill({ status: 500, json: { detail: 'must not be called' } })
  })
  await openInjectedReview(page, eventId)
  await expect.poll(() => candidateCalls).toBe(0)
})

test('rejects a sentinel report containing a PASS candidate', async ({ page, request }) => {
  const { eventId } = await preparedC9200SentinelEvent(request, 'R52A sentinel PASS')
  const candidateCalls = await injectValidationResponse(page, (report) => {
    const candidates = report.candidates as JsonRecord[]
    candidates[0]!.independent_verdict = 'pass'
    const summary = report.summary as JsonRecord
    summary.passed = 1
    summary.blocked = Number(summary.blocked) - 1
  })
  await openInjectedReview(page, eventId)
  await expect.poll(candidateCalls).toBe(0)
})

for (const [field, value] of [
  ['family', 'catalyst-9300'],
  ['exact_pid', 'C9300L-24P-4X'],
  ['software_image', '17.12.5'],
  ['software_license', 'Network Essentials'],
] as const) {
  test(`rejects a C9200 report with a changed ${field}`, async ({ page, request }) => {
    const { eventId } = await preparedC9200Event(request, `R52A device ${field}`)
    const candidateCalls = await injectValidationResponse(page, (report) => {
      ;(report.device as JsonRecord)[field] = value
    })
    await openInjectedReview(page, eventId)
    await expect.poll(candidateCalls).toBe(0)
  })
}

test('rejects a sentinel candidate document that injects CLI text', async ({ page, request }) => {
  const { eventId } = await preparedC9200SentinelEvent(request, 'R52A sentinel CLI')
  await page.route('**/l3-cli-candidates', async (route) => {
    const response = await route.fetch()
    const document = await response.json() as JsonRecord
    const candidates = document.candidates as JsonRecord[]
    candidates[0]!.status = 'candidate'
    candidates[0]!.candidate_text = 'ip routing'
    const summary = document.summary as JsonRecord
    summary.candidates = 1
    summary.blocked = Number(summary.blocked) - 1
    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(document),
    })
  })
  await page.goto('/#l3-review')
  await page.getByLabel('Event', { exact: true }).selectOption(eventId)
  await expect(page.getByRole('heading', { name: 'L3 data binding is inconsistent' })).toBeVisible()
  await expect(page.locator('pre.l3-command')).toHaveCount(0)
})

test('clears old results when revision and event change', async ({ page, request }) => {
  const { eventId, plan } = await preparedEvent(request, 'R44 switches')
  const second = await savePlan(request, secondRevisionPlan(plan))
  const emptyEvent = await createEvent(request, 'R44 empty event')
  await openReview(page, eventId)

  const revisionSelect = page.locator('#l3-revision')
  await revisionSelect.selectOption(second.id)
  await expect(page.getByText('Saved revision #2', { exact: true })).toBeVisible()
  await expect(page.getByText('ip routing', { exact: true })).toHaveCount(0)

  await page.getByLabel('Event', { exact: true }).selectOption(emptyEvent)
  await expect(page.getByRole('heading', { name: 'No saved revisions', exact: true })).toBeVisible()
  await expect(page.getByText('Saved revision #2', { exact: true })).toHaveCount(0)
  await expect(page.getByText('dhcp-helper-address', { exact: true })).toHaveCount(0)
})

test('requires confirmation when leaving a dirty planner for L3 Review', async ({ page, request }) => {
  const eventId = await createEvent(request, 'R44 dirty guard')
  await page.goto('/#planner/addressing')
  await page.getByLabel('Event', { exact: true }).selectOption(eventId)
  const vlan = page.getByLabel('Plan management VLAN')
  await expect(vlan).toBeVisible()
  await vlan.fill('11')
  await expect(page.getByText('Unsaved changes', { exact: true })).toBeVisible()

  page.once('dialog', (dialog) => dialog.dismiss())
  await page.getByRole('link', { name: 'L3 Review', exact: true }).click()
  await expect(page).toHaveURL(/#planner\/addressing/)
  await expect(vlan).toHaveValue('11')

  page.once('dialog', (dialog) => dialog.accept())
  await page.getByRole('link', { name: 'L3 Review', exact: true }).click()
  await expect(page).toHaveURL(/#l3-review$/)
})

test('shows an explicit state when the saved revision has no Cisco Core', async ({ page, request }) => {
  const eventId = await createEvent(request, 'R44 no core')
  const seeded = await request.get(events + '/' + eventId + '/plan/seed', { headers })
  expect(seeded.status(), await seeded.text()).toBe(200)
  await savePlan(request, await seeded.json() as JsonRecord)
  await page.goto('/#l3-review')
  await page.getByLabel('Event', { exact: true }).selectOption(eventId)
  await expect(page.getByRole('heading', { name: 'No Cisco Core assignment', exact: true })).toBeVisible()
  await expect(page.getByRole('table', { name: 'Candidates' })).toHaveCount(0)
})

test('rejects a validation response missing an integrity field', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R45 integrity injection')
  const candidateCalls = await injectValidationResponse(page, (report) => {
    delete (report.integrity as JsonRecord).candidate_set
  })
  await openInjectedReview(page, eventId)
  await expect(page.getByText('One or more report integrity checks are not true.')).toBeVisible()
  await expect.poll(candidateCalls).toBe(0)
})

test('rejects source fields missing from both ExpectedSource and ActualSource', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R45 source injection')
  const candidateCalls = await injectValidationResponse(page, (report) => {
    delete (report.expected_source as JsonRecord).baseline_revision_hash
    delete (report.source as JsonRecord).baseline_revision_hash
  })
  await openInjectedReview(page, eventId)
  await expect.poll(candidateCalls).toBe(0)
})

test('shows a stable reason code when validation is rejected', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R44 rejected')
  await page.route('**/l3-cli-validation', (route) => route.fulfill({
    status: 409,
    json: { detail: { reason_code: 'assignment-not-eligible-for-l3-cli', stage: 'assignment', failures: ['not-eligible'] } },
  }))
  await page.goto('/#l3-review')
  await page.getByLabel('Event', { exact: true }).selectOption(eventId)
  await expect(page.getByRole('heading', { name: 'Unable to load the L3 review' })).toBeVisible()
  await expect(page.getByText('The selected Assignment is not eligible for L3 CLI review.')).toBeVisible()
  await expect(page.getByText('assignment-not-eligible-for-l3-cli', { exact: true })).toBeVisible()
})

test('keeps a valid report when the candidate document is not reviewable', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R44 candidate unavailable')
  await page.route('**/l3-cli-candidates', (route) => route.fulfill({
    status: 409,
    json: { detail: { reason_code: 'candidate-document-not-reviewable', stage: 'candidate', failures: ['candidate-failed'] } },
  }))
  await openReview(page, eventId)
  await expect(page.getByRole('heading', { name: 'Candidate document unavailable for review' })).toBeVisible()
  await expect(page.getByText('candidate-document-not-reviewable', { exact: true })).toBeVisible()
  await expect(page.locator('dl.l3-counts')).toContainText('10')
  await expect(page.locator('.l3-candidate-section')).toBeVisible()
  await expect(page.locator('.l3-candidate-section pre.l3-command')).toHaveCount(0)
  const dhcpRow = page.getByRole('table', { name: 'Candidates' }).locator('tbody tr').filter({ hasText: 'dhcp-helper-address' })
  await dhcpRow.getByText('Details', { exact: true }).click()
  await expect(dhcpRow.locator('pre')).toHaveCount(0)
})

test('supports Chinese labels and narrow keyboard-scrollable layout', async ({ page, request }) => {
  const { eventId } = await preparedEvent(request, 'R44 i18n responsive')
  await page.setViewportSize({ width: 390, height: 844 })
  await openReview(page, eventId)
  await page.getByLabel('Language').selectOption('zh-CN')
  await expect(page.getByRole('heading', { name: '三层配置审阅', exact: true })).toBeVisible()
  await expect(page.getByText('部分通过', { exact: true })).toBeVisible()
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  expect(overflow).toBeLessThanOrEqual(1)
  const tableRegion = page.locator('.l3-candidate-section [data-slot="table-container"]')
  await expect(tableRegion).toBeVisible()
  await expect(tableRegion).toHaveAttribute('tabindex', '0')
  await tableRegion.focus()
  await expect(tableRegion).toBeFocused()
  await page.getByRole('link', { name: '三层配置审阅', exact: true }).focus()
  await expect(page.getByRole('link', { name: '三层配置审阅', exact: true })).toBeFocused()
  await page.screenshot({ path: 'test-results/l3-review-zh-390.png', fullPage: true })
  await page.setViewportSize({ width: 1366, height: 900 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1)
  await page.screenshot({ path: 'test-results/l3-review-zh-1366.png', fullPage: true })
  await page.setViewportSize({ width: 1920, height: 1080 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1)
  await page.screenshot({ path: 'test-results/l3-review-zh-1920.png', fullPage: true })
})
