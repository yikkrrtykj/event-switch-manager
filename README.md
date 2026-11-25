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

## Windows offline portable package (R75)

The onedir package does not require Python, Node.js or Docker on the target
Windows x64 computer. It listens only on `127.0.0.1:8765`, applies Alembic
migrations to the user database and opens the local browser after startup.

Build the package on a Windows workstation with Python 3.12 and Node.js:

```powershell
npm --prefix apps/web ci
npm --prefix apps/web run build
python -m venv .venv-packaging
.\.venv-packaging\Scripts\python.exe -m pip install -c apps/api/constraints-py312.txt ./apps/api
.\.venv-packaging\Scripts\python.exe -m pip install -r apps/api/packaging/requirements-packaging.txt
powershell -NoProfile -ExecutionPolicy Bypass -File apps/api/packaging/build_windows.ps1 `
  -Python ".venv-packaging/Scripts/python.exe" -WebDist "apps/web/dist"
```

The build writes these local artifacts (not a GitHub Release):

```text
apps/api/dist/EventSwitchManager-windows-x64.zip
apps/api/dist/EventSwitchManager-build-record.json
apps/api/dist/EventSwitchManager/EventSwitchManager.exe
```

The build record contains the version, Git SHA, SHA-256 of the ZIP and EXE,
static assets, Alembic migrations and Python package inventory.

Extract the ZIP and run `EventSwitchManager.exe`; the browser opens the local
dashboard. The portable directory can be moved or replaced without moving the
database. The normal Windows database is
`%LOCALAPPDATA%\EventSwitchManager\esm.sqlite3`; never put user data in the
portable directory. Use `--database PATH` for an isolated workspace. Use
`--no-browser` when running a smoke test or scripted startup.

Close the application with Ctrl+C or by closing its console; the listening
port is released. If port 8765 is occupied, startup fails with an explicit
message and does not stop the other process. For an offline backup, stop the
application first, then copy `esm.sqlite3` to a separate location. Migration
failure is reported without deleting or recreating an existing database.

The real EXE smoke test (health, dashboard, Event, saved Revision, Cisco Review
Bundle JSON, restart persistence, arbitrary working directories, port conflict
and port release) is run by the Windows Portable Runtime CI job; its ZIP and
smoke report are uploaded as CI artifacts, not published as a Release.

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
