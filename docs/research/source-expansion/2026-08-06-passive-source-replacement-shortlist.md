# Passive source replacement shortlist

Date: 2026-08-06

## Question

Which maintained discovery providers can replace recently removed or dead
sources with useful domain-in results, without duplicating the current source
catalog, relying on undocumented scraping, launching unannounced active scans,
or retaining raw provider payloads?

## Outcome

The best next implementation remains **Arquivo.pt**. It is a no-key P0 source,
has a documented domain-match API and explicit limits, and may add historical
hostnames not returned by the current Common Crawl and Internet Archive
adapters.

The smallest no-key follow-up candidate is **ThreatMiner**. Its contract is one
documented request with a clear 10-query-per-minute ceiling and a CC BY 4.0
service license, but current corpus freshness is not documented. Require current
official activity evidence or a consented yield pilot before implementation.

The strongest newly discovered candidate is **sub.md**. Its API contract is
excellent and anonymous access is practical, but no public terms or explicit
redistribution policy was linked from the service or API documentation. It
should not ship until maintainers receive written confirmation that an
open-source client may make automated queries and emit normalized names.

No live target enumeration was performed. Candidate yield is therefore a
hypothesis to test later against consented targets, not a measured ranking.

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
| 1 | Arquivo.pt CDX | P0 | No key | Subdomains; historical URLs are available but should be deferred | Current official API documentation | Small, one bounded JSON request | Implement first |
| 2 | ThreatMiner | P0 | No key | Subdomains first; passive-DNS IPs are a later contract | First-party API page is reachable; corpus freshness is unverified | Very small, one JSON request | Require freshness evidence or a consented pilot |
| 3 | sub.md | P0 | No key or optional Bearer key | Subdomains | Live health indicator, current docs, current Subfinder adapter | Very small, newline parser | Terms clarification first |
| 4 | WhoisFreaks Subdomains | P0 | Credit-based API key | Active and inactive nested subdomains | Current 2026 docs, SDKs, and status surfaces | Small, paginated JSON | Require a test key and usage-rights confirmation |
| 5 | Sourcegraph stream search | P0 | Public search works without a token | Subdomains and target-domain emails found in public code | Current API docs; AUP updated 2026-06-12 | Medium, bounded SSE parser | Pilot after simpler sources |
| 6 | Yandex Search API v2 | P0 | Yandex Cloud key, folder, and billing | Subdomains, target-domain emails, result URLs | Current v2 REST, quota, pricing, and release docs | Medium, Base64 XML pages | Terms review before a paid regional-index pilot |

There is no P1 recommendation in this list. DNS resolution and validation are a
separate activity boundary and should not be disguised as a replacement passive
provider. Candidates that can trigger remote collection are classified P2 and
parked below.

## Candidate evidence

### 1. Arquivo.pt CDX

**Why it is interesting:** its documented CDX service is a separately operated
web-archive interface that may expose historical names not returned by the
current Common Crawl and Internet Archive adapters. Exclusive yield remains a
hypothesis for a consented comparison, not an established corpus distinction.

**Contract:** query `GET https://arquivo.pt/wayback/cdx` with a domain match,
request JSON, select only the archived URL and capture timestamp, and apply one
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

### 2. ThreatMiner

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

**Caveat:** no pagination, result cap, dataset timestamp, or completeness signal
is documented. The adapter must report a bounded single-request completion and
must not imply exhaustive coverage.

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
| ThreatCrowd | P0 historically | Reject as dead. The provider aliases end in AWS load-balancer DNS names that return `NXDOMAIN`, and the supported OTX API is already represented separately. | [local service-status research](../threatcrowd-service-status.md) |

The following prior decisions remain unchanged: park CIRCL PassiveDNS because
access is restricted to trusted partners; park MerkleMap because API docs and
automation terms conflict; reject AnubisDB and MySSL until first-party limits
and redistribution contracts exist; do not wrap Subfinder, Amass, or BBOT as a
single source because that would erase provenance and duplicate requests.

## Recommended first implementation slice

Implement **Arquivo.pt hostname collection only** from the current upstream
`dev`:

1. Add one P0 source catalog entry with the `subdomains` route.
2. Make one bounded `GET https://arquivo.pt/wayback/cdx` domain-match request.
3. Request JSON and only the fields needed to extract the archived URL and
   capture timestamp.
4. Normalize exact-suffix hostnames through the existing shared hostname seam.
5. Treat `200` with no names as empty; attribute terminal HTTP, rate-limit, and
   malformed-body outcomes without retaining the raw response.
6. Add offline fixtures for repeated captures, nested names, unrelated suffixes,
   malformed rows, and a terminal `429`.
7. Preserve CLI, REST, JSON, JSONL, XML, SQLite, and public getter contracts.

Do not add archived page downloads or emit every historical URL in this slice.
Those outputs can multiply storage and may carry unrelated personal or
copyrighted content. Hostname yield answers the immediate replacement need.

ThreatMiner `rt=5` is the next candidate to evaluate after current activity or
consented yield evidence is available. Evaluate sub.md only after the rights
question is answered. These providers do not depend on one another, so any
eventual implementation PRs should be reviewed as a small parallel batch rather
than a dependency stack. Use a true stacked PR only when a shared transport or
output prerequisite creates a real dependency.

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
