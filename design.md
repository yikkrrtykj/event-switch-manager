# Event Switch Manager design system

The local workbench uses Hallmark v2.0.0 App Screens at commit
04977e15f3dfd6ee4b74c887dac3eb52665d6c92. The application ships local React, TypeScript,
Tailwind CSS and local shadcn/ui Input and Table sources with semantic slots. Browser review tools
stay in CI. No fonts or data are fetched to render the production interface.

- Navigation uses one top bar with event context and five destinations. Network Planner
  sections use shareable hash routes. The main surface is a record table with field diagnostics.
- Semantic tokens in apps/web/src/style.css cover surfaces, text, selection, focus, success,
  warning and error. Headings use a fixed scale. Addresses, hashes and JSON use a monospaced font.
- Tables have labeled scroll regions. Controls are compact at desktop widths and touch-sized
  at narrow widths. Keyboard users can skip navigation, focus diagnostics and use modal dialogs.
  Reduced-motion preferences remove transitions.
- A saved revision has a server-supplied validity status. An unsaved draft loses its validation
  result when it changes. Hardware preflight has a separate state. A revision export is always
  obtained from the canonical backend endpoint.

## Current port editing scope

The editor uses the v1 model for access, trunk, routed, VLANs and Port-Channel/LACP. Unknown
hardware capability remains visible. The API persists additional port intent as described in
[WEB-02A port settings](docs/web-02a-port-settings.md). The extended editor and actual device
writes remain outside this scope.

## Network Planner Web backlog

- **WEB-01**. The English workbench and editable topology link table ship here. Complete
  the English message catalog, Simplified Chinese locale, language switch, and localized
  errors, warnings and confirmations in a separate UI change. Language changes must preserve
  plan data and revision hashes. Evaluate an optional topology view for tracing links across
  devices and Stack members. The editable link table already supports precise review.
- **WEB-02**. WEB-02A adds compatible PortSettings fields, validation and persistence tests.
  WEB-02B exposes them in the Port Editor. Add SKU, software version and license capability
  rules in the hardware phase, with explicit unverified states until evidence is available.
- **WEB-03**. The pinned Hallmark App Screens workflow and cross-platform browser
  acceptance cover the workbench. F18 media-slot size hints on compact badges and
  controls are advisory. Keep those elements compact when browser tests confirm
  readable labels, responsive layout, focus visibility and contrast.
