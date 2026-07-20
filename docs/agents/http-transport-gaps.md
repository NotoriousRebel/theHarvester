# Direct HTTP migration gaps

No discovery source that creates `aiohttp.ClientSession` directly can preserve its current behavior through the public
`AsyncFetcher` contract yet. `fetch` has no controls for the existing sources' zero response delay or aiohttp's
system-default TLS trust roots. The POST candidates have additional gaps listed below.

| Source | Capability needed before migration |
| --- | --- |
| `bitbucket.py` | Response status and `Link` metadata together with text and JSON bodies. |
| `builtwith.py` | Response status and JSON decoding with content-type validation disabled. |
| `githubcode.py` | Response status and `Link` metadata together with text and JSON bodies. |
| `haveibeenpwned.py` | Response status so only a `200` JSON body is processed. |
| `intelxsearch.py` | One caller-owned session across a JSON POST and follow-up GET. |
| `leaklookup.py` | Response status, including its distinct `401` handling. |
| `search_dehashed.py` | Response status, configurable POST timeout, explicit proxy routing, and JSON-to-text fallback. |
| `securityscorecard.py` | Response status so only a `200` JSON body is processed. |
| `sherlockeye.py` | Response status, configurable POST timeout, explicit proxy URL, and error text. |
| `thc.py` | Response status and rate-limit headers for bounded retry behavior. |
| `venacussearch.py` | Zero-delay paginated requests and aiohttp's system-default TLS trust roots. |
