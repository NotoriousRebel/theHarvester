# Issue tracker: GitHub

This file provides GitHub mechanics. `AGENTS.md` defines the authority boundary and workflow.

## Primary tracker

Issues, PRDs, plans, and agent-generated tickets live in `NotoriousRebel/theHarvester`.

Always pass `--repo NotoriousRebel/theHarvester` for write operations because the checkout also has an upstream remote.

### Fork operations

- Create: `gh issue create --repo NotoriousRebel/theHarvester --title "..." --body "..."`
- Read: `gh issue view <number> --repo NotoriousRebel/theHarvester --comments`
- List: `gh issue list --repo NotoriousRebel/theHarvester --state open`
- Comment: `gh issue comment <number> --repo NotoriousRebel/theHarvester --body "..."`
- Add a label: `gh issue edit <number> --repo NotoriousRebel/theHarvester --add-label "..."`
- Remove a label: `gh issue edit <number> --repo NotoriousRebel/theHarvester --remove-label "..."`
- Close: `gh issue close <number> --repo NotoriousRebel/theHarvester --comment "..."`

Use structured JSON output when a skill needs issue bodies, labels, assignees, or comments.

## Upstream monitoring

Use explicit read commands against `laramies/theHarvester`:

- Issues: `gh issue list --repo laramies/theHarvester --state open`
- Issue detail: `gh issue view <number> --repo laramies/theHarvester --comments`
- Pull requests: `gh pr list --repo laramies/theHarvester --state open`
- Pull-request detail: `gh pr view <number> --repo laramies/theHarvester --comments`
- Pull-request diff: `gh pr diff <number> --repo laramies/theHarvester`

When adopting upstream work, place the upstream URL in the fork tracking issue.

## Pull requests as a triage surface

PRs as a request surface: **no**.

The triage skill processes issues on `NotoriousRebel/theHarvester`. It does not automatically treat pull requests opened against the fork as requests.

GitHub shares a number sequence between issues and pull requests. Resolve an ambiguous fork reference with `gh pr view <number> --repo NotoriousRebel/theHarvester`, then fall back to `gh issue view`.

## Skill terminology

- "Publish to the issue tracker" means create an issue on `NotoriousRebel/theHarvester`.
- "Fetch the relevant ticket" means read the corresponding fork issue.

## Wayfinding

A wayfinding map is one fork issue with linked fork issues as child tickets.

- Map label: `wayfinder:map`
- Child labels: `wayfinder:research`, `wayfinder:prototype`, `wayfinder:grilling`, or `wayfinder:task`
- Prefer native GitHub sub-issues and issue dependencies.
- When unavailable, use a task list and `Blocked by: #<number>` links.
- Claim work by assigning the fork issue.
- Resolve work by recording the result, closing the child, and updating the map.
