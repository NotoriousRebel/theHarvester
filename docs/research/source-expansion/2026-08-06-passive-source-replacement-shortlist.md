# Passive source replacement shortlist

Date: 2026-08-06

## Question

Which maintained discovery providers can replace recently removed or dead
sources with useful domain-in results, without duplicating the current source
catalog, relying on undocumented scraping, launching unannounced active scans,
or retaining raw provider payloads?

## Outcome

The best next implementation is **Shodan CT**, salvaged from fork PR #144 onto
current upstream `dev`. Its first-party service documents a no-key hostname
endpoint, and a bounded `mozilla.org` pilot returned 208 distinct names.

**Arquivo.pt is no longer an implementation recommendation.** Its endpoint is
healthy, but a bounded `mozilla.org` pilot with `limit=10000` produced only one
distinct subdomain, `www.mozilla.org`, because repeated apex captures consume
the result window. Provider-side exclusion filters timed out in bounded probes.

**ThreatMiner is not currently viable.** Its documented domain endpoint returned
HTTP 500 with an empty body during the consented `mozilla.org` pilot.

The strongest newly discovered candidate is **sub.md**. Its API contract is
excellent and anonymous access is practical, but no public terms or explicit
redistribution policy was linked from the service or API documentation. It
should not ship until maintainers receive written confirmation that an
open-source client may make automated queries and emit normalized names.

Live P0 checks used only the user-approved `mozilla.org` target. No target was
contacted directly and no active scan was requested.

## Baseline and method

The current upstream catalog was checked first in
[`theHarvester/lib/source_catalog.py`](../../../theHarvester/lib/source_catalog.py).
It already includes DNSDB, OTX, SecurityScorecard, SecurityTrails, certificate
transparency, web archive, web search, code search, breach, and several passive
DNS families. DNSDB is no longer a new-source candidate.

This pass rechecked the current source catalog and recorded its own evidence
so the shortlist remains reviewable without unpublished notes.

Google, Reddit, and X were used only to discover leads. A Reddit discussion
surfaced mnemonic PassiveDNS, and a ProjectDiscovery X source announcement
pointed back to the current Subfinder registry. No factual recommendation below
depends on either social post: [Reddit lead](https://www.reddit.com/r/OSINT/comments/1j8xbyb/need_help_finding_out_when_a_certain_subdomain/),
[ProjectDiscovery X lead](https://x.com/pdiscoveryio/status/1924510890394530064).

Every candidate was then checked against first-party documentation, provider
terms, provider pages, or official repositories. Current source registries from
[Subfinder](https://github.com/projectdiscovery/subfinder/tree/dev/pkg/subscraping/sources)
and [BBOT](https://github.com/blacklanternsecurity/bbot/tree/stable/bbot/modules)
were used only as maintenance and interoperability evidence.

Activity classes follow the repository glossary:

- **P0** queries an existing third-party dataset.
- **P1** makes DNS requests about the target.
- **P2** contacts the target directly or asks a provider to collect against it.

## Ranked shortlist

| Rank | Candidate | Activity | Access | Domain-in output | Maintenance | Adapter size | Decision |
|---:|---|---:|---|---|---|---|---|
| 1 | Shodan CT | P0 | No key | Certificate-associated hostnames | Live first-party service and current Subfinder adapter | Very small, one JSON request | Salvage fork PR #144 first |
| 2 | Arquivo.pt CDX | P0 | No key | Historical hostnames | Current official API documentation | Small, one bounded NDJSON request | Park after low-yield pilot |
| 3 | sub.md | P0 | No key or optional Bearer key | Subdomains | Live health indicator, current docs, current Subfinder adapter | Very small, newline parser | Terms clarification first |
| 4 | WhoisFreaks Subdomains | P0 | Credit-based API key | Active and inactive nested subdomains | Current 2026 docs, SDKs, and status surfaces | Small, paginated JSON | Require a test key and usage-rights confirmation |
| 5 | Sourcegraph stream search | P0 | Public search works without a token | Subdomains and target-domain emails found in public code | Current API docs; AUP updated 2026-06-12 | Medium, bounded SSE parser | Pilot after simpler sources |
| 6 | Yandex Search API v2 | P0 | Yandex Cloud key, folder, and billing | Subdomains, target-domain emails, result URLs | Current v2 REST, quota, pricing, and release docs | Medium, Base64 XML pages | Terms review before a paid regional-index pilot |

There is no P1 recommendation in this list. DNS resolution and validation are a
separate activity boundary and should not be disguised as a replacement passive
provider. Candidates that can trigger remote collection are classified P2 and
parked below.

## Candidate evidence

### 1. Shodan CT

**Why it is interesting:** Shodan's public CT mirror has a direct hostname
endpoint and useful coverage within the same CT source family as `crtsh` and
`certspotter`. It must not be treated as independent corroboration. The
first-party landing page documents `GET /api/v1/domain/{domain}/hostnames`. A
bounded 2026-08-06 pilot returned HTTP 200 and 208 distinct `mozilla.org` names,
including nested hostnames:
[Shodan CT Logs API](https://ctl.shodan.io/).

**Use boundary:** Shodan's service terms govern website and API plans, require
Shodan attribution when its information is included in other materials, and say
no fixed transmission limit is currently promised. The adapter makes one serial
request per selected target, retains only normalized names, and identifies the
source as Shodan CT in code, help, and documentation. It does not copy or resell
the service or its raw response:
[Shodan terms](https://static.shodan.io/legal/terms.html).

**Existing work:** fork PR #144 already contains the adapter and offline
contracts. Its base predates the current source catalog and completed-result
seams, so salvage the focused provider behavior onto current upstream `dev`
instead of merging the stale branch wholesale.

### 2. Arquivo.pt CDX

**Why it is interesting:** its documented CDX service is a separately operated
web-archive interface that may expose historical names not returned by the
current Common Crawl and Internet Archive adapters. Exclusive yield remains a
hypothesis for a consented comparison, not an established corpus distinction.

**Contract:** query `GET https://arquivo.pt/wayback/cdx` with a domain match,
request newline-delimited JSON, select only archived URLs, and apply one
operator-bounded result limit. Do not download archived page bodies. The
official CDX documentation describes domain and wildcard matching:
[CDX API](https://github.com/arquivo/pwa-technologies/wiki/URL-search:-CDX-server-API).

**Limits:** the provider documents 250 CDX requests per 60 seconds per IP and
warns that addresses exceeding the limit can be permanently blocked. One serial
request per target stays far below that boundary:
[API limits](https://arquivo.pt/api).

**Rights:** archived pages retain their original rights. The adapter should emit
normalized exact-suffix hostnames only in its first slice. It should not mirror
page content, snippets, or raw CDX responses.

**Measured limitation:** `limit=10,000` yielded only `www.mozilla.org` after
normalization. `collapse=urlkey` did not collapse duplicate rows, and bounded
negative-filter probes timed out. Do not ship an adapter until a documented,
bounded query can reach descendant keys without downloading a huge capture set.

### ThreatMiner

**Why it is interesting:** ThreatMiner is a threat-intelligence corpus rather
than another general CT or web index. Its historical or incident-linked names
may be exclusive even when total yield is smaller.

**Contract:** `GET https://api.threatminer.org/v2/domain.php?q=<domain>&rt=5`
returns subdomains. The response documents `status_code`, `status_message`, and
`results`. The same domain API exposes passive DNS with `rt=2`, but that should
be a separate follow-up after its IP schema and provenance are fixture-tested.

**Limits and rights:** the provider states 10 queries per minute, requires no
key, and identifies the non-profit service as licensed under Creative Commons
Attribution 4.0: [ThreatMiner API](https://www.threatminer.org/api.php).

**Current failure:** the documented `rt=5` endpoint returned HTTP 500 with an
empty body on 2026-08-06. Do not implement while the public contract is failing.

### 3. sub.md

**Why it is interesting:** the provider says its index combines certificate
transparency, passive DNS, and X.509 data and contains more than five billion
subdomains. That breadth is likely to produce high raw yield, although it is an
aggregated source family rather than independent corroboration.

**Contract:** `GET https://api.sub.md/v1/search?apex=<domain>` returns
`text/plain` with one FQDN per line. Authentication is optional. A Bearer token
raises limits without changing the result shape. `404` means an understood
empty result, `429` and `503` provide `Retry-After`, and the endpoint documents
ETag-based anonymous caching: [API documentation](https://sub.md/docs/).

**Limits:** anonymous access is 1 request per second with a burst of 2 and 50
queries per day. Paid tiers are documented on the provider homepage:
[sub.md service and pricing](https://sub.md/).

**Rights gate:** neither the service page nor API documentation links terms of
service or states whether normalized results may be redistributed by an
open-source client. Ask the provider for written confirmation before
implementation. If approved, this is a one-request adapter with no new
dependency and should support both anonymous and optional-key use.

### 4. WhoisFreaks Subdomains API

**Why it is interesting:** this is a direct descendant inventory from a provider
not currently represented in the catalog. It returns nested names and can return
active, inactive, or both statuses, which is useful secondary subdomain evidence
without pretending that historical names are currently addressable.

**Contract and limits:** the API accepts `domain`, `page`, date filters, and an
optional status. Responses expose `current_page`, `total_pages`,
`total_records`, and `subdomains`. Plan-specific rate-limit behavior and credit
usage are linked from the same current documentation:
[Subdomains API](https://whoisfreaks.com/documentation/subdomains-api),
[rate limiting](https://whoisfreaks.com/documentation/api-rate-limiting),
[credit usage](https://whoisfreaks.com/documentation/credit-usage#subdomains-lookup-api).

**Rights gate:** a commercial key establishes access, not redistribution
rights. Before implementation, obtain applicable first-party terms or written
confirmation that an open-source client may make automated queries and emit
normalized names and status metadata. Never retain the bulk provider database
or raw pages.

### 5. Sourcegraph streaming code search

**Why it is interesting:** public code can contain environment-specific
hostnames and target-domain email addresses that DNS, CT, and web archives do
not observe. It is a useful independent discovery class even though it overlaps
the existing GitHub and GitLab source family.

**Contract:** public Sourcegraph.com searches work without authentication. The
stream endpoint emits `matches`, `progress`, `filters`, `alert`, and `done`
events. The terminal progress object exposes result counts, skipped shards, and
limit conditions: [streaming API](https://sourcegraph.com/docs/api/stream-api),
[query syntax](https://sourcegraph.com/docs/code-search/queries).

**Limits and rights:** the AUP, modified 2026-06-12, prohibits automatic or
excessive bulk activity. Use one serial query with a small `count:` cap. Do not
use `count:all`, query sharding, or parallel searches:
[Acceptable Use Policy](https://sourcegraph.com/terms/aup).

**Data minimization:** extract exact-suffix names and target-domain emails in
memory. Never serialize source lines, code snippets, or complete event bodies.

### 6. Yandex Search API v2

**Why it is interesting:** Yandex is an independent regional web index. It can
surface Russian-language and nearby regional results missed by the existing
Baidu, Brave, DuckDuckGo, Mojeek, and Yahoo adapters.

Use the current Cloud API, not legacy XML endpoints. It requires an API key,
folder ID, billing, serial pagination, and decoding Base64 XML. Stop at the
documented 250-result ceiling:
[quickstart](https://yandex.cloud/en/docs/search-api/quickstart),
[REST API](https://yandex.cloud/en/docs/search-api/api-ref/),
[quotas](https://yandex.cloud/en/docs/search-api/concepts/limits),
[pricing](https://yandex.cloud/en/docs/search-api/pricing).

Before a paid pilot, review the current Yandex Cloud service terms for
automated querying and normalized-result output. The technical and pricing
documents above do not establish those rights.

## Parked or rejected candidates

| Candidate | Activity | Decision | First-party evidence |
|---|---:|---|---|
| mnemonic PassiveDNS | P0 | Reject as domain-to-descendants adapter. The public API is no-key and well documented, but its own examples explicitly say an apex query does not contain subdomains of that apex. Keep it as a possible exact-name or IP pivot, not a source replacement. | [public API guide](https://docs.mnemonic.no/service-integration-guides/passivedns/docs/public/01-public_api.html) |
| Driftnet | P0 for existing-index queries | Park. It has rich CT, DNS, scan, and rDNS data, free non-commercial accounts, a current API, and a 10,000-result maximum. However, its current terms prohibit automated access and systematic retrieval without written permission. It was also acquired by SecurityScorecard, which already has a theHarvester source, so family overlap must be measured. | [service](https://driftnet.io/), [API docs](https://driftnet.io/api-docs), [terms](https://driftnet.io/policies/terms), [acquisition](https://securityscorecard.com/company/press/securityscorecard-acquires-driftnet-to-power-real-time-threat-informed-third-party-risk-management/) |
| Reconeer | P0 without a fill; P2 when a miss launches collection | Park. It advertises 53 million names and returns hostname, IP, country, and rDNS data, but its docs say a Premium `404` triggers an asynchronous scan. That silently crosses into P2. The linked terms route returned 404 during review. | [service](https://www.reconeer.com/), [API docs](https://www.reconeer.com/docs.html), [pricing](https://www.reconeer.com/pricing.html) |
| PugRecon | P0 | Reject for a general integration. The index claims 3.9 billion names, but the free plan caps results at 30 and its terms grant personal, non-commercial use only. | [service](https://pugrecon.com/), [terms](https://pugrecon.com/terms/) |
| DigitalYama | P0 | Park. It offers 25 trial credits and paid plans at 1 request per second, but no complete public endpoint documentation, pagination contract, terms, or redistribution rights were found on the public site. | [service](https://digitalyama.com/), [pricing](https://digitalyama.com/pricing) |
| Profundis | P0 | Park. The live service and current Subfinder adapter show a subdomain SSE endpoint, but no public source-specific limits or redistribution contract could be verified. | [service](https://profundis.io/), [Subfinder adapter](https://github.com/projectdiscovery/subfinder/tree/dev/pkg/subscraping/sources/profundis) |
| recon.cloud | P0 | Reject as dead. Both the service host and the endpoint used by Subfinder failed DNS resolution on 2026-08-06. | [Subfinder adapter](https://github.com/projectdiscovery/subfinder/tree/dev/pkg/subscraping/sources/reconcloud) |
| SubDomainRadar | P2 | Park as explicit active work only. Its managed task can run deeper enumeration and must never be included in `all` as a passive replacement. | [API docs](https://api.subdomainradar.io/docs) |
| BinaryEdge | P0 historically | Reject. Standalone BinaryEdge products and data access shut down on 2025-03-31. | [transition FAQ](https://help.coalitioninc.com/hc/en-us/articles/34383910057371-BinaryEdge-Transition-FAQ) |
| ThreatMiner | P0 | Reject for now. The documented domain endpoint returned HTTP 500 with an empty body during a bounded `mozilla.org` check on 2026-08-06. | [API documentation](https://www.threatminer.org/api.php) |
| ThreatCrowd | P0 historically | Reject as dead. The provider aliases end in AWS load-balancer DNS names that return `NXDOMAIN`, and the supported OTX API is already represented separately. | [local service-status research](../threatcrowd-service-status.md) |

The following prior decisions remain unchanged: park CIRCL PassiveDNS because
access is restricted to trusted partners; park MerkleMap because API docs and
automation terms conflict; reject AnubisDB because its current redirect ended
at a Cloudflare HTTP 403 and no usable first-party contract was available;
reject MySSL until first-party limits and redistribution contracts exist; do
not wrap Subfinder, Amass, or BBOT as a single source because that would erase
provenance and duplicate requests.

## Recommended first implementation slice

Salvage **Shodan CT hostname collection only** from fork PR #144 onto current
upstream `dev`:

1. Keep one bounded no-key request to the documented hostname endpoint.
2. Normalize exact-suffix hostnames through the existing shared hostname seam.
3. Preserve `www`, reduce wildcard certificate names to their concrete suffix,
   and exclude malformed or out-of-scope names.
4. Attribute transport, non-success, rate-limit, and malformed-body outcomes.
5. Register only the `subdomains` route and preserve existing CLI, REST, JSON,
   JSONL, XML, SQLite, and public getter contracts.
6. Add offline fixtures for success, malformed rows, non-success, and `429`.

Do not import the stale run-evidence abstractions from PR #144. Current upstream
already owns the collection and output seams.

Evaluate sub.md only after the rights question is answered. Independent
providers should be reviewed as a small parallel batch, not a dependency stack.
Use a true stacked PR only when a shared transport or output prerequisite
creates a real dependency.

## Later yield experiment

After implementation, compare candidates on approved targets using a frozen
P0-only baseline:

- distinct exact-suffix names from each source;
- names exclusive against the same unchanged baseline;
- completion, truncation, request, credit, and elapsed-time evidence;
- source family, so two aggregators are not treated as independent support;
- no DNS, HTTP, screenshots, or target interaction in the P0 experiment.

Promote a source only if it produces non-zero exclusive names on more than one
consented target and its activity, completion state, cost, and usage rights are
clear.
