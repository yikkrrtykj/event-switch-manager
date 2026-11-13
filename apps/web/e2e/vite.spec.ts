import { expect, test } from '@playwright/test'

test('preserves same-origin writes through Vite and rejects a foreign origin', async ({ page, request }) => {
  const rejection = await request.post('/api/v1/events', {
    headers: { Origin: 'https://example.com' },
    data: { name: 'Foreign request' },
  })
  expect(rejection.status()).toBe(403)

  await page.goto('/')
  await page.getByLabel('Event name').fill('Vite rehearsal')
  await page.getByRole('button', { name: 'Create event' }).click()
  await expect(page.getByRole('option', { name: 'Vite rehearsal' })).toHaveCount(1)
})
