# Direct HTTP migration gaps

Venacus now uses the public `AsyncFetcher` contract with explicit zero-delay and system-default TLS controls. The
remaining discovery sources that create `aiohttp.ClientSession` directly still need the capabilities listed below.

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
