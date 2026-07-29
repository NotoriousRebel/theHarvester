# Discovery quality benchmark

`theHarvester-benchmark` is an offline qualification tool. It scores one completed, normalized evidence JSONL run against supplied synthetic truth and supplied execution accounting. It does not load discovery adapters, contact providers, query DNS, or broaden target scope.

Run it with local inputs:

```console
theHarvester-benchmark \
  --run-jsonl completed-run.jsonl \
  --fixture tests/fixtures/benchmark/truth.fixture \
  --metadata benchmark-metadata.json \
  --output benchmark-report.json
```

The fixture declares a public identifier, expected in-scope names, DNS outcomes, wildcard ancestry, scope-extension evidence, external relationships, synthetic source payload findings, primary currently-addressable truth, bounded known inventory, and known-false names. Fixture names and payloads are inputs only and never appear in the report.

Execution metadata must declare:

- the benchmark arm's public identifier;
- selected sources and selected actions;
- provider availability;
- observed provider-request and DNS-query counts;
- declared cost in integer microunits;
- declared numeric settings and the settings actually applied; and
- request, DNS-query, runtime, and cost budgets.

Numeric settings are named evidence rather than benchmark constants. Arms may vary resolver, quorum, wildcard-probe, query, recursion, QPS, runtime, and futility settings. A run fails qualification if its declared and effective settings differ. A comparison is valid only when every arm passed and the arms used the same budget and provider availability.

## Metrics and gates

The sanitized report contains aggregate counts only. It reports unique currently-addressable yield, bounded known-inventory recovery, precision, wildcard false positives, resolver disagreement, out-of-scope promotion, incomplete source statuses, runtime, provider requests, DNS queries, declared cost, source-alone yield, exclusive source contribution, family overlap, combined yield, and distinct-family corroboration.

Qualification fails closed for a fixture DNS or source-payload mismatch, a currently-addressable claim without DNS evidence, a known-false primary result, wildcard false positive, out-of-scope promotion or recursive expansion, an unselected or missing execution, a failed/rate-limited/skipped or otherwise hidden partial run, mismatched declared/effective configuration, unavailable selected providers, accounting mismatch, or a budget overrun. Correlated observations in one source family retain source credit but count as one independent family.

The report deliberately omits the target, run identity, timestamps, entity and query names, resolver names, raw provider payloads, credentials, errors, and evidence excerpts. Input failures also return a generic error without echoing paths or input content.

## From evidence to a fork issue

A correctness fix qualifies for a sanitized fork implementation issue when a deterministic fixture demonstrates a specific invariant repair and the complete gate set shows no safety regression. A yield change qualifies only after repeated incremental currently-addressable-yield gains under equal declared budgets and equivalent provider availability; one showcase run is not enough. Publish only the behavior, aggregate checks, and implementation acceptance criteria to `NotoriousRebel/theHarvester`.

Any separately authorized run against a consented target is opt-in, is executed outside this benchmark command, and keeps its evidence local. Never attach target names, credentials, raw payloads, sensitive evidence, or private research to an implementation issue.

## Track live source yield

Every completed run now reports source yield in the terminal and writes one
`source_yield` record per selected provider to JSONL output. Each record
contains:

- `discovered_subdomains`: normalized in-scope names attributed to the source;
- `exclusive_subdomains`: names found by that source and no other selected
  provider;
- `currently_addressable_subdomains`: discovered names supported by the
  requested DNS validation; and
- `exclusive_currently_addressable_subdomains`: exclusive names supported by
  that validation.

Current-addressability values are `null` in JSONL and `n/a` in the terminal
when the run did not use exactly three resolver vantages. This prevents an
unvalidated observation count from being presented as a current DNS result.

Keep consented live runs in a private, ignored location:

```console
theHarvester \
  -d example.com \
  -b all \
  --dns-resolve 1.1.1.1,8.8.8.8,9.9.9.9 \
  -f /absolute/private/path/example-2026-07-29
```

Rank sources by exclusive contribution:

```console
jq -s '
  [.[] | select(.record_type == "source_yield") | .data]
  | sort_by(.exclusive_subdomains, .discovered_subdomains)
  | reverse
' example-2026-07-29.jsonl
```

List the exclusive names for private review:

```console
jq -r '
  select(.record_type == "merged_result")
  | .data
  | ([.provenance[]
      | select(.source | startswith("action:") | not)
      | .source] | unique) as $sources
  | select($sources | length == 1)
  | [$sources[0], .value]
  | @tsv
' example-2026-07-29.jsonl
```

Compare repeated runs only when selected sources, available credentials,
limits, DNS settings, and provider availability are equivalent. Keep target
names and entity-level evidence out of public issues and pull requests.
