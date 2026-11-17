import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { defineConfig } from '@playwright/test'

const origin = 'http://127.0.0.1:8765'
const viteOrigin = 'http://127.0.0.1:5173'
const useVite = process.env.ESM_E2E_VITE === '1'
const chromium = process.env.ESM_E2E_CHROMIUM
const database = process.env.ESM_TEST_DATABASE ??= join(
  mkdtempSync(join(tmpdir(), 'esm-e2e-')),
  'plan.sqlite3',
)

export default defineConfig({
  testDir: 'e2e',
  testMatch: useVite ? 'vite.spec.ts' : ['dashboard.spec.ts', 'planner.spec.ts', 'capability.spec.ts'],
  outputDir: useVite ? 'test-results-vite' : 'test-results',
  use: {
    baseURL: useVite ? viteOrigin : origin, trace: 'retain-on-failure',
    ...(chromium ? { launchOptions: { executablePath: chromium } } : {}),
  },
  webServer: [
    {
      command: 'python -m event_switch_manager --web-dist dist --database "' + database + '"'
        + (useVite ? ' --dev' : ''),
      url: origin + '/api/v1/health',
      reuseExistingServer: false,
    },
    ...(useVite ? [{
      command: 'npm run dev',
      url: viteOrigin + '/api/v1/health',
      reuseExistingServer: false,
    }] : []),
  ],
})
