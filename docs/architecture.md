# Architecture

## Foundation

| Layer | Location | Responsibility |
| --- | --- | --- |
| React + TypeScript + Vite + Tailwind | `apps/web` | Dashboard, event creation, inventory view and API client |
| FastAPI and Pydantic | `apps/api/src/event_switch_manager/api.py`, `schemas.py` | Versioned HTTP API, input validation and serialization |
| Domain vocabulary | `domain.py` in the backend package | Planned switch family and event role as independent types |
| Persistence | `models.py`, `database.py`, `migrations/` in the backend package | SQLite records, foreign keys, scoped uniqueness and Alembic schema revisions |
| Integrations | `integrations.py` in the backend package | Contracts for Cisco discovery, Console queries, Kea inspection, Hillstone inspection and hypervisor preflight |
| Local web security | `security.py`, `settings.py`, `__main__.py` in the backend package | Fixed IPv4 loopback bind, exact Host allowlist, same-origin mutation checks and browser response headers |

Event and Device records use stable UUIDs. The management VLAN is event-specific and defaults to 10. A planned device can exist before a serial number or exact SKU is known. Device identity and observed capabilities will be stored separately from editable planning data. A family identifier neither guarantees a software capability nor grants permission to deploy. PR #1 has no integration implementations, hardware operations, generic CLI endpoint or device write setting.

The built frontend and API share an origin and have no CDN dependencies. In Vite mode the API accepts the explicit Vite host for its local proxy. The API rejects requests using a foreign Host and requires exact Origin equality for mutations. There is no cross-origin allowlist. This trust boundary is for a single-user workstation and does not authenticate arbitrary software running on that workstation. Production-like static mode also sets a content security policy. English copy ships first. The planner milestone will introduce message catalogs before expanding UI coverage.

Alembic runs with a SQLite writer lock at startup. Foreign keys are enabled for every connection. Inventory records use case-insensitive uniqueness for hostnames and serials. Inventory POST and PUT edit only the planning database. The launcher defaults to the operating system's per-user data directory so source and web asset changes do not replace event data.

## V1 dependencies and ownership

- **Event / Network Planner** owns the desired state. Use stable entity IDs and versioned import/export. Network revisions must be captured as immutable inputs to previews and deployments. Editing a plan must invalidate approvals bound to a previous revision.
- **Cisco Configuration Engine** consumes a validated revision and observed capability profile. Keep rules and Jinja2 templates on the backend. Generate typed artifacts, validate before rendering and distinguish preview from an approved deployment plan.
- **Cisco Adapter** maps exact hardware, version, license, interfaces and boot/storage observations to capabilities. Use explicit unknown capability results. **Console Engine** owns pySerial I/O, exclusive COM leases, prompt handling and disconnect behavior. Only vetted typed operations can reach the transport.
- **Deployment Engine** owns persisted transitions, approval checks, per-platform reset strategies and checkpoints. Reconnect by rediscovering identity and state. Do not resume a destructive operation from the last attempted command alone.
- **Verification and Recovery** compare intended, observed running and persisted state, record evidence and recovery options, and distinguish configuration backup from proven restoration. Backups use encryption and authenticated integrity checks. Store Windows secrets in the system credential store and keep raw captures out of ordinary logs.
- **Kea/Stork** consume the same plan, own DHCP rendering and compare live changes before writes. **Hypervisor adapters** handle VM provisioning and certificate-verified platform preflight. Both platforms share one guest service and configuration workflow.
- **Hillstone** consumes the plan for routing and policy checks and compares version-qualified read-only observations over host-verified SSH. Its integration contract exposes no mutation path. Any commands offered for manual operation need matching StoneOS evidence.
- **Web UI** shows validation, configuration preview, explicit approvals, progress and reports from the backend. Add shadcn/ui components locally as shared primitives become necessary. No device syntax or capability rules live in the browser.

## Clean Deploy safety contract

A durable run transitions through DISCOVER → BACKUP → PRECHECK → APPROVAL → RESET → REBOOT → BOOTSTRAP → DEPLOY → VERIFY → SAVE → COMPLETE. FAIL, SKIP, STOP_FOR_MANUAL and RECOVERY_REQUIRED preserve evidence and explain how to continue. Checkpoints bind the approved plan hash, exact device and Stack identity, platform strategy, backup evidence and approved maintenance context. Stop on missing or failed backup, unknown software, unhealthy Stack, uncertain reboot outcome or Console disconnect. Recovery begins with read-only rediscovery. A lost connection cannot trigger automatic replay of reset or reload.

An approved strategy handles startup configuration and independent VLAN data without modifying boot variables, deleting images, formatting Flash, clearing licenses or invoking `factory-reset all`. Core approval additionally requires serial and role confirmation, a maintenance window and confirmation that the device is out of production, L3 and Stack checks, and a separate disruptive-operation confirmation. Verify authentication recovery via Console, running intent, save outcome and persistence. Only certified model/version combinations can become eligible.
