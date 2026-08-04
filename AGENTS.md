# Agent guidebook

## Mission

Use this guide to turn an issue or request into a focused, verified change on `NotoriousRebel/theHarvester`.

The working principle is **fork-first**:

- Mutable work belongs to `NotoriousRebel/theHarvester`.
- `laramies/theHarvester` is a read-only source of issues, pull requests, discussions, and code history.
- Work may become an upstream pull request only through a separate action explicitly authorized by the user.

## Authority boundary

`origin` is the only routine write target.

Permitted upstream activity is read-only: inspect issues, pull requests, comments, reviews, diffs, checks, commits, and repository state.

An upstream mutation requires explicit authorization naming the exact action. This includes pushing, creating a branch, opening or editing an issue or pull request, commenting, labeling, assigning, closing, merging, or reacting.

Refresh or merge upstream state only when the user requests synchronization.

See `docs/agents/issue-tracker.md` for fork and upstream GitHub commands.

## Runbook

### 1. Orient

Before planning a change:

1. Inspect the current branch and worktree with `git status --short --branch`.
2. Confirm `origin` is `NotoriousRebel/theHarvester`.
3. Identify whether the request came from the fork, an upstream item, or the user directly.
4. Read relevant `CONTEXT.md` and ADRs when present.
5. For upstream work, read the full issue or pull request discussion and check for competing fixes.

Completion criterion: the agent can name the working branch, write target, work item, existing worktree state, and relevant project guidance.

### 2. Define the outcome

Translate the request into one observable result:

- Bug fix: name the failing case and expected behavior.
- Feature: name what the user can newly observe.
- Refactor: name the behavior that must remain unchanged.
- Investigation: name the question and the evidence needed to answer it.

State assumptions that affect implementation. Surface meaningful tradeoffs when more than one path is reasonable. Ask a concise question only when guessing would create material risk.

Completion criterion: the expected result, scope boundary, and verification method are explicit.

### Architecture migration checkpoint

An architecture program is a parent issue that creates dependent implementation issues or uses a branch that is not intended to merge directly into the target branch. Do not turn an architecture proposal or audit directly into an open-ended implementation backlog.

The freeze record on [fork issue #152](https://github.com/NotoriousRebel/theHarvester/issues/152) documents the parallel-architecture and review-debt failure that requires this checkpoint.

`codex/truthful-provider-integration` is immutable reference material at `22eb2d1966b39196c8a04e2793f5fd3e45277fb4`. Do not merge or extend it. Any authorized restart must be a new independent proposal from current `dev`.

Before the first dependent pull request merges:

1. Record the parent issue, its proposal pull request when one exists, intended merge target, exact current `origin/dev`, exact current `upstream/dev`, and proposed base. A requested fixed point does not replace this check.
2. Reconcile the proposal with `origin/dev` and `upstream/dev`. If the concept already exists, consolidate it instead of creating a parallel model.
3. Prove one representative end-to-end slice with an observable consumer. Internal status types and passing tests alone do not establish product value.
4. Record explicit human acceptance of the representative slice and permission for any additional dependent work on the parent issue.

After every dependent pull request, update the parent issue with the cumulative diff, remaining tickets, upstream overlap, and milestone fit before requesting permission for another. Stop the program if the proposal pull request named by the parent issue closes without merging or receives an unresolved compatibility finding. Restart only through a new independent proposal after the finding is reproduced and resolved.

Triage audit findings individually. Close or rewrite findings already satisfied by merged work instead of adding a second semantic migration by default.

Completion criterion: the named target architecture is accepted, the representative slice is useful and compatible, and the parent issue records permission for the next bounded step.

### 3. Establish the branch

For implementation work:

1. Start from the fork's current `dev`.
2. Create a focused feature or fix branch.
3. Keep `dev` and `master` as clean fork baselines.
4. Push branches only to `origin`.

Preserve existing worktree changes. Treat unrelated modifications as user-owned.

Completion criterion: the task is isolated on the intended fork branch without disturbing unrelated work.

### 4. Trace the path

Read the execution path before editing:

1. Find callers and adjacent implementations.
2. Reuse existing helpers, types, and conventions.
3. Locate the nearest tests covering the behavior.
4. Identify network, credential, persistence, parser, and active-scan boundaries affected by the change.

For discovery adapters, trace the adapter through the central orchestrator and its result getters. For API changes, trace request validation, authentication, rate limiting, target validation, and response behavior.

Completion criterion: the root cause or extension seam is identified, and every directly affected caller is accounted for.

### 5. Make the smallest change

Apply four checks:

1. **Think before coding.** Work from the stated outcome and assumptions.
2. **Keep it simple.** Add only what the current request needs. Prefer existing code and dependencies.
3. **Make it surgical.** Touch necessary files, match local style, and avoid adjacent cleanup.
4. **Define and verify the goal.** Keep the observable result and its check in view.

Remove imports, variables, or helpers made unused by the change. Record unrelated findings separately.

Security-sensitive behavior stays fail-closed. Use mocked provider responses in tests; routine verification must not perform live reconnaissance against third-party targets.

Completion criterion: the diff contains only the requested behavior and supporting tests or documentation.

### 6. Verify in layers

Run the narrowest meaningful check first, then expand according to risk.

Common checks:

- Focused test: `uv run pytest <test-path>`
- Full tests: `uv run pytest`
- Lint: `uv run ruff check .`
- Formatting: `uv run ruff format --check .`
- Typing: `uv run mypy theHarvester`

New discovery modules require focused pytest coverage. Changes to credentials, target validation, API access, active scans, persistence, or parsing require their relevant security or regression tests.

Completion criterion: required checks pass, or the exact failure and reason a check could not run are reported.

### 7. Hand off deliberately

Report non-trivial work using:

- Assumption:
- Changed:
- Verified:
- Remaining risk:

When publication is requested, commit and push the focused branch to `origin`. Keep upstream pull-request creation as a separate explicit authorization gate.

Completion criterion: the user knows the branch, changed files, verification evidence, worktree state, and whether any publication occurred.

## Project map

- `theHarvester/__main__.py`: CLI orchestration and result processing.
- `theHarvester/discovery/`: source-specific asynchronous discovery adapters.
- `theHarvester/lib/`: shared fetching, configuration, API, output, and SQLite behavior.
- `theHarvester/parsers/`: result extraction and normalization.
- `theHarvester/screenshot/`: active screenshot behavior.
- `tests/`: pytest coverage for adapters, shared behavior, and security boundaries.
- `pyproject.toml`: Python, dependency, test, lint, format, and typing configuration.

The project supports Python 3.12 and newer and exposes the `theHarvester` and `restfulHarvest` console commands.

## Agent skills

### Issue tracker

Issues and agent-generated work items live in `NotoriousRebel/theHarvester` GitHub Issues. Pull requests against the fork are not a triage request surface. Upstream issues and pull requests may be monitored read-only. See `docs/agents/issue-tracker.md`.

### Triage labels

Use `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, and `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository. Read root `CONTEXT.md` and relevant records under `docs/adr/` when present. See `docs/agents/domain.md`.
