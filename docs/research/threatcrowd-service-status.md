# ThreatCrowd service status

Accessed: 2026-08-05

## Conclusion

ThreatCrowd is currently nonfunctional and should be treated as an abandoned provider integration. This is not an API-key failure and not a transient HTTP error: both public ThreatCrowd hostnames end in AWS Elastic Load Balancer DNS names that authoritative AWS DNS returns as `NXDOMAIN`.

No official retirement announcement was found. The evidence therefore does not support saying that ThreatCrowd was formally retired. It does support removing or explicitly disabling the bundled `threatcrowd` source until its owner publishes a working, supported endpoint.

AlienVault is operationally associated with ThreatCrowd through its infrastructure, official repository, and archived "powered by AlienVault" branding, but did not document OTX as a drop-in migration. OTX has a current passive-DNS endpoint with a different contract, and theHarvester already exposes it separately as `otx`.

## Confirmed facts

### Ownership and service history

- ThreatCrowd's official API repository is now owned by the [`AlienVault-OTX` GitHub organization](https://github.com/AlienVault-OTX/ApiV2). Its API code and documentation have not changed since the last code commit in 2018. The README still documents `www.threatcrowd.org/searchApi/v2/...`, no API key, and a limit of one request every ten seconds. It contains no retirement or migration notice. [Official API README](https://github.com/AlienVault-OTX/ApiV2/blob/7ba12f4c9c2b88bed1ba14cefaa660e122deef92/README.md)
- The latest archived working official homepage says "ThreatCrowd is now powered by AlienVault" and links users to AlienVault OTX. It does not say that OTX replaced the ThreatCrowd API or that the ThreatCrowd API was retired. [Archived official homepage, captured 2022-09-03](https://web.archive.org/web/20220903164001id_/https://www.threatcrowd.org/)
- `otxb.io` is a separate AlienVault-controlled infrastructure domain. Its registry RDAP record names `AlienVault` as the registrant organization and shows registration on 2016-11-10. [Identity Digital RDAP](https://rdap.identitydigital.services/rdap/domain/otxb.io)
- `threatcrowd.org` remains registered through 2027-03-07 and its registry record was last changed on 2026-05-05. Public registration data is privacy-redacted, so registration alone does not identify its current legal owner. [Public Interest Registry RDAP](https://rdap.publicinterestregistry.org/rdap/domain/threatcrowd.org)
- A 2019 answer in the official API repository explicitly says the ThreatCrowd and AlienVault APIs are different APIs. Later questions asking whether ThreatCrowd was decommissioned or moved remain unanswered. [Issue #5 and response](https://github.com/AlienVault-OTX/ApiV2/issues/5#issuecomment-491749626), [issue #8](https://github.com/AlienVault-OTX/ApiV2/issues/8), [issue #9](https://github.com/AlienVault-OTX/ApiV2/issues/9)

### Current failure state

Authoritative DNS queries on 2026-08-05 returned these chains:

```text
www.threatcrowd.org
  CNAME prod-otxb-threatcrowd.otxb.io
  CNAME prod-ecsel-o1gfruenxfub-825410333.us-west-2.elb.amazonaws.com
  NXDOMAIN

ci-www.threatcrowd.org
  CNAME ci-otxb-threatcrowd.otxb.io
  CNAME ci-ot-ecsel-d98bl3b3gzg6-1321736763.us-west-2.elb.amazonaws.com
  NXDOMAIN
```

The first aliases were confirmed against ThreatCrowd's authoritative Cloudflare servers, the `otxb.io` aliases against its authoritative Route 53 servers, and the terminal `NXDOMAIN` directly against the authoritative AWS server for `us-west-2.elb.amazonaws.com`. Independent recursive results expose the same broken chains. [Google DNS production result](https://dns.google/resolve?name=www.threatcrowd.org&type=A), [Google DNS CI result](https://dns.google/resolve?name=ci-www.threatcrowd.org&type=A)

No HTTP request reaches a ThreatCrowd server. Credentials, rate-limit sleeps, HTTP retries, user-agent changes, and longer timeouts cannot repair this failure.

Archived official responses also show this is longstanding rather than a short outage: the last captured `200` homepage was 2022-09-03, followed by a `503` on 2022-09-19 and repeated `503` captures through 2026-03-12. [Internet Archive capture index](https://web.archive.org/cdx/search/cdx?url=www.threatcrowd.org/&output=json&fl=timestamp,statuscode,mimetype,original,digest&from=2022&to=2026&collapse=digest), [latest captured 503 body](https://web.archive.org/web/20260312192635id_/https://www.threatcrowd.org/)

### Supported API options now

- Current LevelBlue OTX documentation lists `GET /api/v1/indicators/domain/{domain}/{section}`, with `passive_dns` as a supported section for records observed by LevelBlue Labs. It contains no ThreatCrowd endpoint or migration notice. [Official LevelBlue OTX API documentation](https://otx.alienvault.com/assets/static/external_api.html#api_v1_indicators_domain__domain___section__get)
- The supported OTX SDK takes an API key and sends it in the `X-OTX-API-KEY` header. [Official SDK README](https://github.com/AlienVault-OTX/OTX-Python-SDK), [official SDK authentication code](https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/OTXv2.py#L96-L116)
- OTX passive DNS overlaps with ThreatCrowd's domain-report use case, but it is not documented as the same service or response contract. Redirecting the ThreatCrowd adapter to OTX would silently duplicate theHarvester's existing `otx` source and would still require adapting to OTX behavior rather than changing a hostname.

### How the broken adapter returned to theHarvester

- Upstream PR [#1382](https://github.com/laramies/theHarvester/pull/1382) deleted `theHarvester/discovery/threatcrowd.py` on 2023-04-10.
- Issue [#2103](https://github.com/laramies/theHarvester/issues/2103) later listed modules found in ProjectDiscovery Subfinder but missing from theHarvester. It named `threatcrowd` but supplied no ThreatCrowd-specific service evidence.
- Bulk PR [#2131](https://github.com/laramies/theHarvester/pull/2131) re-added ThreatCrowd with nine other sources on 2025-09-23. Its ThreatCrowd adapter used the unofficial `ci-www.threatcrowd.org` hostname. The PR did not document a ThreatCrowd-specific live validation or provider migration.
- ProjectDiscovery had added the same CI hostname in [Subfinder PR #1508](https://github.com/projectdiscovery/subfinder/pull/1508), merged on 2025-02-25. On 2025-09-24 it excluded ThreatCrowd from no-auth source tests as randomly failing with JSON unmarshal errors. [Exclusion commit](https://github.com/projectdiscovery/subfinder/commit/c292a9c595506e9ae47543d2c501eeeb6f5d50ea)
- Current Subfinder still registers ThreatCrowd but marks it non-default and no-key. Its no-auth test exclusion remains in place. [Current adapter](https://github.com/projectdiscovery/subfinder/blob/3f5641b2b076fb18b0bd45012b6eb72af1c494c3/pkg/subscraping/sources/threatcrowd/threatcrowd.go), [current exclusion](https://github.com/projectdiscovery/subfinder/blob/3f5641b2b076fb18b0bd45012b6eb72af1c494c3/pkg/passive/sources_wo_auth_test.go)

## Inferences

These conclusions follow from the confirmed facts but are not official vendor statements:

1. ThreatCrowd appears effectively abandoned at the backend-routing layer. Registered domains and recently managed DNS or certificates do not demonstrate a functioning application.
2. The `otxb.io` aliases, AlienVault registration, transferred official repository, and archived AlienVault-branded homepage establish operational association with AlienVault. They do not prove a formal acquisition, product merger, or supported migration.
3. Repeated 503 captures since 2022, unanswered status issues, stale API documentation, and current authoritative `NXDOMAIN` make a temporary outage unlikely.
4. The dangling AWS aliases show stale infrastructure configuration. They do not by themselves prove a claimable subdomain-takeover vulnerability.

## Implication for theHarvester

The bundled adapter currently:

- appears in CLI help and the README provider matrix;
- appears in the runtime supported-engine list;
- is included by `-b all`;
- is selected by the `subdomains` and `ips` capability selectors; and
- can only return a DNS-resolution failure because its configured hostname has no reachable backend.

The next focused slice should remove or disable ThreatCrowd across the adapter, orchestration, catalogs, documentation, and contract tests. It should not:

- add an API key;
- add retries or sleeps;
- substitute the OTX endpoint behind the `threatcrowd` name; or
- modify the existing OTX adapter as part of the removal.

If LevelBlue later publishes a working ThreatCrowd endpoint and support contract, a new adapter can be evaluated from that documentation and tested independently.

