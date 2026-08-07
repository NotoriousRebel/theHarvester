# Keep Wayfinder orchestration separate with one isolated worker

Status: accepted

## Decision

Wayfinder owns a durable orchestration record separate from theHarvester's optional terminal `RunResult` evidence. A submission receives its stable ID while queued. One local worker claims one queued run at a time and executes the finite theHarvester core in an isolated child process.

Lifecycle transitions are `queued -> running -> completed|failed`, `queued -> cancelled`, and `running -> cancelling -> cancelled`. A fixed whole-run deadline applies to the child. Running cancellation first requests cooperative termination, waits a short grace period, and then forces termination if needed. Queued cancellation is an atomic transition that prevents the worker claim.

Evidence already persisted remains attached after failure or cancellation. Terminal evidence status (`complete`, `partial`, or `failed`) is reported independently from orchestration lifecycle status. On service restart, queued runs may resume; orphaned running or cancelling records become failed because their process ownership cannot be proven.

## Why

The existing core is a finite one-shot enumerator and its result object is created only when execution begins. Reusing it as queue state would conflate operator intent, process ownership, cancellation acknowledgement, and evidence quality. A single worker matches the local single-operator product, avoids concurrent output and credential contention, and can be widened later only if measured demand justifies it.

## Consequences

Wayfinder needs its own small SQLite table and lifecycle API. Child-process boundaries make deadline and forced cancellation reliable across blocking provider code. Work is serialized by design. Imported evidence enters as an already completed Wayfinder run and never enters the queue.
