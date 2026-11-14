# Frontend design

Event Switch Manager is a local workstation for network engineers planning and delivering events. Each screen opens on the work it supports, such as the VLAN table, the Stack port map or the current deployment phase. Use real observations, saved plans and verification evidence for operational claims. Keep synthetic fixtures clearly identified in tests and screenshots.

## Hallmark and the Web stack

Use Hallmark v2.0.0 App Screens as the development and review process. The reference is upstream commit [`04977e15f3dfd6ee4b74c887dac3eb52665d6c92`](https://github.com/Nutlope/hallmark/commit/04977e15f3dfd6ee4b74c887dac3eb52665d6c92). Review changes to this reference as a repository change. Start with the [README](https://github.com/Nutlope/hallmark/blob/04977e15f3dfd6ee4b74c887dac3eb52665d6c92/README.md), [Skill](https://github.com/Nutlope/hallmark/blob/04977e15f3dfd6ee4b74c887dac3eb52665d6c92/skills/hallmark/SKILL.md), [App Screens](https://github.com/Nutlope/hallmark/blob/04977e15f3dfd6ee4b74c887dac3eb52665d6c92/skills/hallmark/references/flow.md#app-screens), [gates](https://github.com/Nutlope/hallmark/blob/04977e15f3dfd6ee4b74c887dac3eb52665d6c92/skills/hallmark/references/gates.md), [interaction states](https://github.com/Nutlope/hallmark/blob/04977e15f3dfd6ee4b74c887dac3eb52665d6c92/skills/hallmark/references/interaction-and-states.md) and [Redesign](https://github.com/Nutlope/hallmark/blob/04977e15f3dfd6ee4b74c887dac3eb52665d6c92/skills/hallmark/references/redesign.md).

Use React, TypeScript, Vite and Tailwind CSS. Use local shadcn/ui primitives as shared components are introduced. Hallmark, its lint scripts and its browser tooling belong to the developer environment. The built app serves its assets locally, including any fonts. The event workstation can run the built Web UI offline.

For an online Codex development environment:

```sh
npx skills add nutlope/hallmark -g --agent codex
```

Invoke `$hallmark` in a Codex CLI session that supports the skill. Check the installed version and revision against the project reference. For reproducible lint evidence, use scripts from the pinned checkout if the installer resolves a different revision.

## Shared design system

WEB-03 establishes the visual direction and records it in one root `design.md` or an equivalent shared specification. Keep the chosen values in shared CSS tokens linked to Tailwind and shadcn/ui. Subsequent screens inherit the system. Review new tokens and shared component variants with the screens that use them.

| System area | Project rule |
| --- | --- |
| Color, borders and surfaces | Use semantic tokens for backgrounds, panels, text, muted text, borders, focus, selection and status. Reserve accent color for primary actions, current selection and meaningful state. |
| Typography | Use a shared fixed type scale with readable labels and field values. Use tabular numerals for comparable values and a shared monospace face for interface IDs, CIDRs and logs where useful. |
| Spacing and radius | Share spacing, compact row and control heights, and radius values. Aim for 32–40px desktop controls with adequate hit areas. Give touch controls room in narrow layouts. |
| Focus and interaction | Provide instant visible keyboard focus, readable contrast and distinct hover, pressed, selected, disabled, pending and invalid states. Use reduced-motion CSS. Pair status color with text. |
| Responsive layout | Use shared navigation and workspace patterns. Keep page overflow under control. Give tables and port maps their own labeled scroll regions when necessary, with key identifiers and actions reachable by keyboard. |
| Tables and forms | Use labeled columns, stable row identity, accessible selection and compact spacing. Show validation at the affected row or field. Preserve keyboard behavior during inline edits and make bulk selection, effects and save results clear. |

Use App Screens scope for workspaces. Use tables and forms for dense records, inline editing or disclosure for routine edits, and dialogs where the workflow needs them. Keep labels readable and concise. Keep shareable filters, tabs and pagination in the URL where appropriate. Use app-sized headings, navigation and status indicators. Marketing hero sections, promotional copy, stock photos and landing-page section patterns are outside the workstation design.

## Screen patterns

| Screen | What the operator needs |
| --- | --- |
| Dashboard | Current event, planning status and deployment or verification status with evidence when available. Display observed counts only when the data source can substantiate them. |
| Network Planner | Dense VLAN, subnet, gateway, DHCP and ISP tables with inline edits and bulk actions. Identify conflicts by field, row and related record. |
| Port Editor | Actual Cisco interface IDs grouped by Stack member, multiselect and bulk edits, and distinct Access, Trunk, LACP and PoE states. Distinguish planned, unused, conflicting and unsupported ports. Preserve access to every port. |
| Console Deployment | Current state-machine phase and searchable logs. Retain approval and confirmation steps. Highlight `STOP_FOR_MANUAL` and `RECOVERY_REQUIRED` with the required operator action and evidence. |
| Kea DHCP | Scope, Reservation and Lease tables with conflicts located at the relevant address or pool. Show service, plan and acceptance status independently. |
| Hillstone Routing Planner | Per-VLAN ISP priority and separate destination routes, SBR and PBR. Surface Track, SNAT and VPN conflicts with affected routes. Label generated configuration for manual application. |

Every data region has loading, empty, error and populated states. Loading preserves the shape of the content, empty offers the relevant next action, and error identifies the failure and retry path when available. Keep these presentation states separate from operational verdicts:

| Verdict | Meaning |
| --- | --- |
| PASS | Verified success with applicable evidence. |
| FAIL | Attempted and failed its check. Show the reason and evidence. |
| SKIP | Deliberately omitted. Show why. |
| BLOCKED | Waiting on a prerequisite. Show what is missing and who or what can unblock it. |
| NOT VERIFIED | No applicable verification result is available. |
| STOP_FOR_MANUAL | Paused for explicit operator action. Show the current phase and next safe step. |
| RECOVERY_REQUIRED | An abnormal outcome requires recovery. Show the recovery state and available evidence. |

UI changes preserve API contracts, data validation, backend capability checks and deployment approval logic. A cosmetic change cannot authorize a device operation or add a Hillstone write action.

## Frontend review

For a redesign, inventory routes, fields, handlers, selectors, test hooks, validation and approval flows before editing. Capture the current screens and run Hallmark Redesign with `--before`, then compare with `--kept` using app scope. Pair that comparison with existing React and Playwright regression tests for framework event wiring and business behavior.

Run static lint on the changed Web sources. Include the shared global stylesheet if it supplies rules the files rely on.

```sh
node <hallmark-skill-dir>/scripts/sloplint.mjs <changed-web-files> --scope app
```

Run the browser tier with the local Vite app started and a tested Chrome or Chromium and `puppeteer-core` setup. Check that the chosen browser actually launches and can reach the route. Record browser and tool versions. Hallmark also supports `CHROME_PATH` and `HALLMARK_PUPPETEER` when explicit paths are needed.

```sh
node <hallmark-skill-dir>/scripts/sloplint.mjs <changed-web-files> --scope app --render --url http://127.0.0.1:5173/
```

For WEB-03, attach representative screenshots at 1280, 1440 and 1920 CSS pixels and check a narrower desktop window and 320px mobile. Verify keyboard navigation, focus, contrast, reduced motion and data states. Check that compact layouts keep high-priority actions visible and confine intentional table overflow to the table region.

Record the Hallmark revision, paths, routes, static findings, browser findings and screenshots in the PR. Resolve Floor failures, record the rationale for any Reflex waiver and review Finish findings. Report blocked installation or browser checks explicitly. Record static output separately from browser evidence. Build, type checks and functional tests remain independent acceptance checks.
