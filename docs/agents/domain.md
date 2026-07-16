# Domain docs

theHarvester uses a single-context domain layout.

## Consumer rule

Before exploring an area, read:

- Root `CONTEXT.md` for project terminology and domain boundaries.
- Relevant records under `docs/adr/` for architectural decisions.

When either location is absent, continue without treating it as a blocker. Domain-modeling workflows create these files when terminology or decisions need a durable record.

## Layout

```
/
├── CONTEXT.md
├── docs/
│   └── adr/
├── theHarvester/
│   ├── discovery/
│   ├── lib/
│   ├── parsers/
│   └── screenshot/
└── tests/
```

`CONTEXT.md` owns the shared vocabulary. `docs/adr/` owns repository-wide architectural decisions.

## Vocabulary

Use terms defined in `CONTEXT.md` in issue titles, plans, tests, and architectural proposals.

When a concept is absent, check whether existing language already covers it. Send genuine terminology gaps to domain modeling.

## Decision conflicts

Read ADRs affecting the area before structural work. When a proposal conflicts with an ADR, identify the conflict and explain why the decision should be reconsidered.
