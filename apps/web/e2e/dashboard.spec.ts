import { expect, test } from '@playwright/test'

test('creates an event and displays its persisted inventory', async ({ page, request }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  await expect(page.getByText('Connected', { exact: true })).toBeVisible()
  await expect(page.getByText('Disabled', { exact: true })).toBeVisible()

  await page.getByLabel('Event name').fill('Finals')
  await page.getByLabel('Management VLAN').fill('120')
  await page.getByRole('button', { name: 'Create event' }).click()
  await expect(page.getByLabel('Selected event')).toHaveText('Finals')
  await expect(page.getByText('No devices recorded for this event.')).toBeVisible()

  const eventId = await page.getByLabel('Selected event').inputValue()
  const response = await request.post('/api/v1/events/' + eventId + '/devices', {
    headers: { Origin: 'http://127.0.0.1:8765' },
    data: { hostname: 'Finals-Core', family: 'catalyst-9300', role: 'core' },
  })
  expect(response.status()).toBe(201)

  await page.reload()
  await page.getByLabel('Selected event').selectOption(eventId)
  await expect(page.getByRole('row', { name: /Finals-Core/ })).toBeVisible()
  await expect(page.getByText('120', { exact: true })).toBeVisible()

  await page.getByLabel('Event name').fill('Rehearsal')
  await page.getByRole('button', { name: 'Create event' }).click()
  const selectedEvent = page.getByLabel('Selected event')
  await expect(selectedEvent.locator('option:checked')).toHaveText('Rehearsal')
  await expect(page.getByText('No devices recorded for this event.')).toBeVisible()
  await expect(page.getByRole('row', { name: /Finals-Core/ })).toHaveCount(0)

  await selectedEvent.selectOption(eventId)
  await expect(page.getByRole('row', { name: /Finals-Core/ })).toBeVisible()
})
