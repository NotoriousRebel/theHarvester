# Discovery source workers

Discovery sources run through one fixed worker pool. CLI `-j` / `--source-workers`, REST `source_workers`, and
HarvestView's advanced run controls configure the same pool. The requested value must be positive; the effective count
is clamped to the number of selected sources. This setting changes admission concurrency only: every selected source
still runs, and it does not change provider pagination, result limits, DNS, RouteViews, virtual hosts, screenshots,
takeover checks, or API endpoint scanning.

## Selected default

The default is **six** source workers. It was selected from candidates five through eight with this rule:

1. retain the maximum result count and completed-source count;
2. reject candidates that increase provider HTTP 429, HTTP 503, or timeout outcomes over candidate five; and
3. reject candidates whose peak active tasks, measured memory, or measured sockets exceed candidate five by more than
   50%, or whose cancellation latency exceeds it by more than 100%; and
4. among the remaining candidates within 95% of the best results-per-minute rate, choose the smallest.

The committed offline cohort contains 20 sanitized, deterministic scripted source executions and 526 retained results.
It uses fixed seed `289`, nine repeats, and timing scale `0.05`. That scale keeps candidate runs around 2--3 seconds
so the scheduling signal dominates event-loop timing overhead. Each candidate executes through the production
`run_source_jobs` pool with standard-library scripted adapters. The profile declares a six-job pressure point and a
deterministic mix of HTTP 429, HTTP 503, timeout, and DNS failures above it. This makes completeness and failure outcomes
candidate-dependent instead of copying source-duration records into every result.

| Workers | Retained | Completed | 429 / 503 / timeout / DNS | Run p50 / p95 (ms) | Results/min | Cancel (ms) | Peak tasks | Peak memory |
| ---: | ---: | ---: | --- | --- | ---: | ---: | ---: | ---: |
| 5 | 526 | 20 | 0 / 0 / 0 / 0 | 2,456.682 / 3,054.999 | 12,846.596 | 0.966 | 5 | 254,261 |
| 6 | 526 | 20 | 0 / 0 / 0 / 0 | 2,228.340 / 2,806.666 | 14,163.009 | 0.831 | 6 | 236,218 |
| 7 | 81 | 6 | 5 / 5 / 4 / 5 | 2,067.289 / 2,535.166 | 4,496.748 | 0.657 | 7 | 169,104 |
| 8 | 81 | 6 | 5 / 5 / 4 / 5 | 2,016.899 / 2,426.230 | 4,698.647 | 1.098 | 8 | 180,443 |

Five and six retained the same maximum evidence with no additional provider failures and stayed within the explicit
resource thresholds. Five fell below 95% of six's throughput, so six is the smallest near-plateau candidate. Seven and
eight were rejected before throughput comparison because the deterministic pressure profile reduced completeness and
increased errors. A regression reruns the full cohort and requires the fresh selection, committed report, and shipping
default to agree.

Duration-only scheduling is reported separately as a pre-screen and cannot select the default. Reproduce both phases:

```bash
uv run python scripts/benchmark_source_workers.py \
  docs/benchmarks/source-workers-offline-cohort.jsonl \
  --output docs/benchmarks/source-workers-offline-report.json
```

## Limitations and optional live protocol

The offline profile opens no sockets, so peak sockets are not observable. Its durations, pressure point, and throughput
are synthetic; they require no API keys, provider cost, or target traffic and are not a provider guarantee. The harness
adds no benchmark dependency, and the scripted adapters use only the standard library around the production runner. The
benchmark adds no request, result, or runtime ceilings.

A supplementary Mozilla run compared three and six workers over the same five passive sources. Both retained 2,771 raw
results; three took 42.06 seconds and six took 44.92 seconds. CommonCrawl was partial in one run and failed in the other,
so the pair is inconclusive and is not selection evidence for the default.

An explicitly authorized live follow-up may use only `mozilla.org`, `tesla.com`, and `uber.com`, with no DNS or P2
actions. Run each candidate once per target, rotate candidate order between targets, save each JSONL summary, and compare
retained results and completed sources before throughput. Stop if a candidate increases HTTP 429, HTTP 503, or timeout
outcomes. Do not choose a faster candidate that retains fewer results or completes fewer sources.

Example command for one authorized cell (change only the target, worker count, and output name):

```bash
uv run theHarvester -d mozilla.org \
  -b crtsh,certspotter,commoncrawl,hackertarget,otx,rapiddns,urlscan,waybackarchive \
  --source-workers 5 -f /private/tmp/source-workers-mozilla-5
```

Use candidate orders `5,6,7,8` for Mozilla, `6,7,8,5` for Tesla, and `7,8,5,6` for Uber to reduce ordering bias.
