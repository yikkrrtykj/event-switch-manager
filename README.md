# Event Switch Manager

An offline Windows workspace for planning and delivering esports event networks. The foundation provides a dashboard, event and planned Cisco inventory records, and SQLite migrations. The API and dashboard run on IPv4 loopback. Device writes are disabled.

## First setup (online)

Use Python 3.12 and Node.js 22.20+ (22.x) or 24.12+ (24.x). Run from the repository root. This step downloads the pinned Python dependencies and the npm packages from their registries, then builds the static UI.

Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -c apps/api/constraints-py312.txt -e "./apps/api[dev]"
.\.venv\Scripts\python.exe -m pip check
npm --prefix apps/web ci
npm --prefix apps/web run build
```

Linux

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -c apps/api/constraints-py312.txt -e './apps/api[dev]'
.venv/bin/python -m pip check
npm --prefix apps/web ci
npm --prefix apps/web run build
```

## Start the built application (offline)

From the repository root, run `.\.venv\Scripts\python.exe -m event_switch_manager` on Windows or `.venv/bin/python -m event_switch_manager` on Linux. Open [http://127.0.0.1:8765](http://127.0.0.1:8765). Keep the installed Python environment and `apps/web/dist` available. Startup serves the UI locally and applies Alembic migrations before accepting requests. The default Windows database is `%LOCALAPPDATA%\EventSwitchManager\esm.sqlite3`. Use `--database PATH` for an isolated workspace. Stop the service before copying the database for an offline backup.

For hot reload, add `--dev` to the backend command and run `npm --prefix apps/web run dev` in a second terminal. Use [http://127.0.0.1:5173](http://127.0.0.1:5173) and the default API port. The Vite proxy preserves the browser's Host and Origin.

## Planning API

| Method | Path under `/api/v1` |
| --- | --- |
| GET | `/health`, `/openapi.json` |
| GET, POST | `/events` |
| GET, PUT | `/events/{event_id}` |
| GET, POST | `/events/{event_id}/devices` |
| GET, PUT | `/events/{event_id}/devices/{device_id}` |

POST and PUT require `Origin: http://127.0.0.1:8765` when called directly on the default API port. PUT replaces the editable record. A device belongs to one event. Hostname, management IPv4 address and serial number are unique within that event when present. The dashboard creates events and reads inventory. Device creation and edits are available through the API.

```powershell
$localUrl = 'http://127.0.0.1:8765'
$api = "$localUrl/api/v1"
$headers = @{ Origin = $localUrl }
$event = Invoke-RestMethod "$api/events" -Method Post -Headers $headers -ContentType 'application/json' -Body '{"name":"Lab Finals","management_vlan":120}'
Invoke-RestMethod "$api/events/$($event.id)/devices" -Method Post -Headers $headers -ContentType 'application/json' -Body '{"hostname":"Lab-Core","family":"catalyst-9300","role":"core","management_ip":"192.0.2.10"}'
```

## Tests

From `apps/api`, use the project virtual environment's Python to run `python -m ruff check .`, `python -m mypy`, and `python -m pytest -q`. From `apps/web`, run `npm test` and `npm run build`. For browser tests, make the same Python environment active on PATH. On first setup, install Chromium with `npx playwright install chromium` (on Linux CI, add `--with-deps`). Run `npm run test:e2e` from `apps/web` with port 8765 available. Run the same command with `ESM_E2E_VITE=1` in the environment to test the Vite proxy on port 5173. Each run starts its own backend with an isolated temporary database.

[Architecture](docs/architecture.md) · [V1 requirements and roadmap](docs/v1-roadmap.md) · [Device support matrix](docs/support-matrix.md)
