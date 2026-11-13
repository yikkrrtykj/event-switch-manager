import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { defineConfig } from '@playwright/test'

const origin = 'http://127.0.0.1:8765'
const database = process.env.ESM_TEST_DATABASE ??= join(
  mkdtempSync(join(tmpdir(), 'esm-e2e-')),
  'plan.sqlite3',
)

export default defineConfig({
  testDir: 'e2e',
  use: { baseURL: origin },
  webServer: {
    command: 'python -m event_switch_manager --web-dist dist --database "' + database + '"',
    url: origin + '/api/v1/health',
    reuseExistingServer: false,
  },
})
