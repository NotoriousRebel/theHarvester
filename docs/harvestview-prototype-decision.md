# HarvestView release UI prototype detour

This is a throwaway decision prototype for issues #342–#344. It does not change API requests, persistence, scheduling, or worker behavior. The prototype appears only when an existing route includes `?variant=mineral`, `?variant=ledger`, or `?variant=signal`; ordinary `/` and `/schedules` remain untouched.

## Visual territory decision

- **Mineral Run Desk** should remain the default direction. Its low-radius trays, etched provenance rails, warm neutral work surface, and restrained teal/amber/red signals preserve HarvestView's existing control-room model while increasing evidence hierarchy.
- **Field Evidence Ledger** makes comparison provenance and review feel deliberate. Ruled surfaces, editorial headings, and a linear schedule layout are excellent for case-reading, but reduce operational density and feel slower during repeated triage.
- **Signal Bay** makes run state exceptionally scannable by turning history into a horizontal signal rack and evidence into compact instruments. It is the boldest territory, but risks monitor-wall fatigue and weakens the durable-history mental model.

The selector intentionally changes layout structure, not just palette. It retains the selected territory across Run Desk and Schedules links, supports left/right keyboard cycling outside editable controls, and exposes System, Light, and Dark color modes.

## Planner decision

The four-step sequence—target and limits, passive source cohort, optional P1/P2 activity, final authorization review—makes the authorization expansion explicit without inventing new form state. The prototype moves the existing controls between steps, so field names, defaults, validation, selections, and the original submit path remain intact. Back and revise preserve values.

For production, keep this sequence but implement it inside the owned form module instead of retaining this DOM-moving prototype shim. Keep one primary and at most one secondary action per step, maintain the existing zero-source action-only path, and add explicit readiness/credential summaries before release.

## Interaction inventory

| Decision point | Visible peer choices | Secondary or disclosed behavior | Preserved contract |
| --- | --- | --- | --- |
| Run Desk header | Schedules, Import result file, Export database, Start enumeration | System/Light/Dark lives in the visually separate prototype chooser | Import, export, navigation, theme, and submission remain available. |
| Run assessment | Open execution outcomes | Partial or failed evidence names the first affected producer and retained reason inline | Lifecycle and terminal evidence remain separate; the full producer table remains available. |
| Authorized activity | Selected and recorded request values | Off, Not recorded, and Not applicable values move into a native details disclosure | Every request field remains readable. |
| Planner step 1 | Continue to sources | Close dialog | Target, limits, deadline, and advanced execution controls retain their defaults and validation. |
| Planner step 2 | Continue to activity | Back | P0 source search, capability selection, readiness, credentials, and selected counts are unchanged. |
| Planner step 3 | Review authorization | Back | P1/P2 sources and optional actions remain off until selected. |
| Planner step 4 | Start enumeration | Back to activity | Existing final summary and submit handler remain the commitment point. |
| Schedule header | Run desk, Refresh | System/Light/Dark lives in the separate prototype chooser | Navigation, refresh, and theme remain available. |
| Schedule card | Edit, History, Run now, Pause/Resume | Delete schedule is behind an explicit danger disclosure | Run now and Delete keep their existing confirmations; no schedule operation is removed. |

Keyboard behavior is exercised with forward Tab traversal, Enter, and Space through the full zero-source P1 planning flow. Step headings receive focus after navigation, progress uses `aria-current="step"`, and the existing dialog, fieldset, legend, details, label, and native-control semantics remain intact. Screen-reader automation is intentionally out of scope; semantic and focus assertions are the prototype evidence.

The retained edge inventory covers a 96-character run ID, a sanitized provider failure, completed zero-result evidence, a paginated 1,000-result route, 390px overflow safety, and computed light/dark contrast for body, navigation, success/warning/danger status, focus, and disabled-control pairs in all three territories.

## Review commands

```sh
uv run pytest tests/e2e/test_harvestview_prototype.py
HARVESTVIEW_PROTOTYPE_SCREENSHOT_DIR=docs/images/harvestview-prototype uv run pytest tests/e2e/test_harvestview_prototype.py -k render_prototype_matrix
```
