# Web development instructions

Follow [the frontend design standard](../../docs/frontend-design.md) for this directory. Use Hallmark v2 App Screens for workstation UI and the repository's shared tokens and components. Preserve the React, TypeScript, Vite and Tailwind stack and reuse local shadcn/ui primitives. The development tool and browser checks stay outside the shipped app.

Review the existing screen, data states and operator workflow before editing. Keep current fields, interactions, validation, permissions and test hooks when redesigning. Apply the upstream Redesign inventory and comparison together with functional regression tests.

Run app-scope sloplint on changed Web files and test the live route with browser rendering when available. Record static and render results separately. Include viewport and functional evidence in UI PRs. Keep the existing Foundation Dashboard scope for PR #1. Establish and apply the shared visual system in the Network Planner Web milestone.
