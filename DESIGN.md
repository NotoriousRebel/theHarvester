# Wayfinder design system

## Direction

Use the approved “Run desk” direction: a dark mineral navigation rail, warm neutral work surface, teal operational accent, amber warnings, and restrained red failures. The interface should feel like a field notebook crossed with a reliable control room-not a generic SaaS card grid.

## Typography

Use the local system stack only. Display and headings use a compact humanist sans stack; evidence values, IDs, timestamps, and status metadata use the system monospace stack. Body text stays at 16px on small screens and line length stays below 72 characters where prose appears.

## Layout

Desktop uses a fixed app header, a history rail, and one flexible evidence workbench. Result routes use a single table surface rather than nested cards. Tablet collapses secondary metadata. Mobile stacks history above evidence, preserves all actions, and keeps touch targets at least 44px.

## Color tokens

Use OKLCH tokens for background, surface, ink, muted text, line, teal accent, amber warning, red danger, and blue information. Light and dark themes must both meet WCAG AA contrast. Status always includes text or an icon as well as color.

## Interaction

Use native dialogs, buttons, inputs, details, and file controls. Motion is limited to short opacity/transform transitions for dialogs, notices, and selection; reduced-motion removes transforms and durations. Focus rings are never suppressed. Dynamic status changes use a polite live region.

## Tables and evidence

Use the locally served standalone Tabulator build for sorting, filtering, selection, and pagination. DNS status uses resolved, no-answer, disputed, and not-captured labels. Long values wrap or truncate with a title; they never break the viewport.

## Voice

Use precise operator language: “Start enumeration,” “Request cancellation,” “Import result file,” and “No runs yet.” Errors state what failed and the next action. Avoid scan, session, job, and vague success/error labels where the glossary has a precise term.
