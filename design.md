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
hardware capability remains visible. Description, administrative shutdown, speed/duplex, PoE,
PortFast and BPDU Guard await their capability-aware persisted fields. Actual device writes
remain disabled.
