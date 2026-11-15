import { spawn, spawnSync } from 'node:child_process'
import { cpSync, mkdirSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { setTimeout } from 'node:timers/promises'

const [lint, before, temp] = process.argv.slice(2)
if (!lint || !before || !temp) throw new Error('Supply the pinned linter, built baseline and temp directory.')
const cwd = process.cwd()
const evidence = resolve('test-results', 'hallmark')
mkdirSync(evidence, { recursive: true })
const url = 'http://127.0.0.1:8767/'
const database = join(temp, 'esm-hallmark-review.sqlite3')
const results = []

function capture(label, workdir, ...args) {
  const result = spawnSync(process.execPath, [lint, ...args], {
    cwd: workdir, encoding: 'utf8', timeout: 95_000, maxBuffer: 4_000_000,
  })
  const output = (result.stdout ?? '') + (result.stderr ?? '') + (result.error ? String(result.error) : '')
  writeFileSync(join(evidence, label + '.txt'), output)
  process.stdout.write(output)
  const skipped = /render (?:tier )?(?:skipped|not run)|no puppeteer-core|no Chrome or Chromium/i.test(output)
  results.push({ label, code: result.status, skipped })
}

async function serve(dist, work) {
  const server = spawn('python', ['-m', 'event_switch_manager', '--web-dist', dist,
    '--database', database, '--port', '8767'], { stdio: 'inherit' })
  const done = new Promise((resolve, reject) => {
    server.once('exit', resolve)
    server.once('error', reject)
  })
  try {
    for (let i = 0; i < 60; i++) {
      const ready = await fetch(url + 'api/v1/health').then((res) => res.ok, () => false)
      if (ready) {
        await work()
        return
      }
      if (server.exitCode !== null) break
      await setTimeout(250)
    }
    throw new Error('Hallmark review API did not start.')
  } finally {
    server.kill()
    await done
  }
}

async function fixture() {
  async function post(path, data) {
    const response = await fetch(url + 'api/v1/events' + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: new URL(url).origin },
      body: JSON.stringify(data),
    })
    if (!response.ok) throw new Error('Unable to create Hallmark fixture: ' + await response.text())
    return response.json()
  }
  const event = await post('', { name: 'Synthetic tournament — Hallmark review', management_vlan: 10 })
  await post('/' + event.id + '/plan-revisions', {
    event_id: event.id, schema_version: 1, management_vlan: 10,
    vlans: [{ id: 10, name: 'Management', purpose: 'management' }, { id: 20, name: 'Players' }],
    subnets: [{ id: '00000000-0000-0000-0000-000000000101', vlan: 20, network: '192.168.20.0/24' }],
  })
}

capture('static', cwd, 'src', '--scope', 'app')
await serve(join(before, 'dist'), async () => {
  await fixture()
  capture('before', before, 'src/Dashboard.tsx', 'src/style.css', '--scope', 'app', '--before', '--render', '--url', url)
})
cpSync(join(before, '.hallmark'), join(cwd, '.hallmark'), { recursive: true })
await serve(resolve('dist'), async () => {
  capture('render', cwd, 'src', '--scope', 'app', '--render',
    '--url', url + '#planner/addressing', '--url', url + '#ports', '--url', url + '#devices')
  capture('kept', cwd, 'src/Dashboard.tsx', 'src/style.css', '--scope', 'app', '--kept', '--render', '--url', url)
})
writeFileSync(join(evidence, 'result.json'), JSON.stringify(results, null, 2))
if (results.some((result) => result.skipped || result.code !== 0)) process.exitCode = 1
