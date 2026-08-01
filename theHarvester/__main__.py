import argparse
import asyncio
import logging
import os
import re
import secrets
import string
import sys
import time
from collections.abc import Iterable
from contextlib import AsyncExitStack
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import anyio
import netaddr
import ujson
from aiomultiprocess import Pool

from theHarvester.discovery import (
    api_endpoints,
    baidusearch,
    bevigil,
    bitbucket,
    bravesearch,
    bufferoverun,
    builtwith,
    censysearch,
    certspottersearch,
    chaos,
    commoncrawl,
    criminalip,
    crtsh,
    dnsdb,
    dnssearch,
    duckduckgosearch,
    dymosearch,
    fofa,
    fullhuntsearch,
    githubcode,
    gitlabsearch,
    hackertarget,
    haveibeenpwned,
    hudsonrocksearch,
    huntersearch,
    intelxsearch,
    leakix,
    leaklookup,
    mojeek,
    netlas,
    onyphe,
    otxsearch,
    pentesttools,
    projectdiscovery,
    rapiddns,
    robtex,
    rocketreach,
    search_dehashed,
    search_dnsdumpster,
    searchhunterhow,
    securityscorecard,
    securitytrailssearch,
    sherlockeye,
    shodan_internetdb,
    shodanct,
    shodansearch,
    subdomaincenter,
    subdomainfinderc99,
    takeover,
    thc,
    threatcrowd,
    tombasearch,
    urlscan,
    venacussearch,
    virustotal,
    waybackarchive,
    whoisxml,
    windvane,
    yahoosearch,
    zoomeyesearch,
)
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib import hostchecker, stash
from theHarvester.lib.core import DATA_DIR, Core, show_default_error_message
from theHarvester.lib.dns_validation import AioDnsResolverVantage, DnsValidator
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.output import (
    configure_logging,
    format_run_terminal,
    legacy_json_result,
    legacy_report_hosts,
    output_logger,
    run_result_jsonl,
    run_result_xml,
    sorted_unique,
)
from theHarvester.lib.run import (
    ActivityClass,
    Derivation,
    DiscoveryObservation,
    ExecutionStatus,
    LegacyHostnameSource,
    ResultRecord,
    RunExecution,
    RunResult,
    ScopeClass,
    SourceStatus,
    add_run_evidence,
    complete_run,
    execute_run,
    legacy_dns_results,
    legacy_hostnames,
    start_run,
    validate_run,
)
from theHarvester.lib.source_catalog import ResultRoute, get_source_spec
from theHarvester.screenshot.screenshot import ScreenShotter

if TYPE_CHECKING:
    from collections.abc import Awaitable

logger = logging.getLogger(__name__)


def _normalize_hosts_for_storage(discovered_hosts: Iterable[object], target: str, *, include_target: bool = False) -> set[str]:
    normalized_target = target.strip().lower().rstrip('.')
    return {
        normalized
        for host in discovered_hosts
        if (normalized := normalize_scoped_hostname(host, normalized_target))
        and (include_target or normalized != normalized_target)
    }


def sanitize_for_xml(text: str) -> str:
    """Sanitize text for safe inclusion in XML documents."""
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&apos;')
    return text


def sanitize_filename(filename: str) -> str:
    filename = os.path.basename(filename)
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    # Remove consecutive underscores
    filename = re.sub(r'_+', '_', filename)
    filename = filename.strip('_.')
    if filename.startswith('.'):
        filename = '_' + filename
    # Ensure we have a valid filename
    if not filename:
        filename = 'sanitized_file'
    return filename


async def start(rest_args: argparse.Namespace | None = None):
    """Main program function"""
    parser = argparse.ArgumentParser(
        description='theHarvester is used to gather open source intelligence (OSINT) on a company or domain.'
    )
    parser.add_argument('-d', '--domain', help='Company name or domain to search.', required=True)
    parser.add_argument(
        '-l',
        '--limit',
        help='Limit the number of search results, default=500.',
        default=500,
        type=int,
    )
    parser.add_argument(
        '-S',
        '--start',
        help='Start with result number X, default=0.',
        default=0,
        type=int,
    )
    parser.add_argument(
        '-p',
        '--proxies',
        help='Use proxies for requests, enter proxies in proxies.yaml.',
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '-s',
        '--shodan',
        help='Use Shodan to query discovered hosts.',
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '--screenshot',
        help='Take screenshots of resolved domains specify output directory: --screenshot output_directory',
        default='',
        type=str,
    )

    parser.add_argument('-e', '--dns-server', help='DNS server to use for lookup.')
    parser.add_argument(
        '-t',
        '--take-over',
        help='Check for takeovers.',
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '-r',
        '--dns-resolve',
        help=(
            'Perform DNS resolution on subdomains with a resolver list or passed in resolvers. '
            'Exactly three distinct resolvers enable consensus and wildcard validation for migrated sources.'
        ),
        default='',
        type=str,
        nargs='?',
    )
    parser.add_argument(
        '-n',
        '--dns-lookup',
        help='Enable DNS server lookup, default False.',
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '-c',
        '--dns-brute',
        help='Perform a DNS brute force on the domain.',
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '-f',
        '--filename',
        help='Save the results to an XML and JSON file.',
        default='',
        type=str,
    )
    parser.add_argument('-w', '--wordlist', help='Specify a wordlist for API endpoint scanning.', default='')
    parser.add_argument('-a', '--api-scan', help='Scan for API endpoints.', action='store_true')
    parser.add_argument(
        '-q',
        '--quiet',
        help='Suppress missing API key warnings and reading the api-keys file.',
        default=False,
        action='store_true',
    )
    parser.add_argument('--verbose', help='Show informational diagnostic messages.', action='store_true')
    parser.add_argument(
        '-b',
        '--source',
        help="""Comma-separated sources or capability selectors: subdomains, emails, ips, asns, urls, people, or all.
                            Sources: baidu, bevigil, bitbucket, brave, bufferoverun,
                            builtwith, censys, certspotter, chaos, commoncrawl, criminalip, crtsh, dehashed, dnsdumpster, duckduckgo, dymo, fofa, fullhunt, github-code,
                            gitlab, hackertarget, haveibeenpwned, hudsonrock, hunter, hunterhow, intelx, leakix, leaklookup, mojeek, netlas, onyphe, otx, pentesttools,
                            projectdiscovery, rapiddns, robtex, rocketreach, securityscorecard, securityTrails, sherlockeye, shodan, shodanct, shodanInternetDB, subdomaincenter,
                            subdomainfinderc99, thc, threatcrowd, tomba, urlscan, venacus, virustotal, waybackarchive, whoisxml, windvane, yahoo, zoomeye""",
    )

    # determines if the filename is coming from rest api or user
    rest_filename = ''
    filename: str
    # indicates this from the rest API
    if rest_args:
        if rest_args.source and rest_args.source == 'getsources':
            return list(sorted(Core.get_supportedengines()))
        elif rest_args.dns_brute and getattr(rest_args, 'dns_brute_only', False):
            args = rest_args
            dnsbrute = (rest_args.dns_brute, True)
            filename = args.filename
        else:
            args = rest_args
            dnsbrute = (args.dns_brute, False)
            # We need to make sure the filename is random as to not overwrite other files
            filename = args.filename
            alphabet = string.ascii_letters + string.digits
            rest_filename += f'{"".join(secrets.choice(alphabet) for _ in range(32))}_{filename}' if len(filename) != 0 else ''
    else:
        args = parser.parse_args()
        filename = args.filename
        dnsbrute = (args.dns_brute, False)
        configure_logging(verbose=args.verbose)
        if args.verbose:
            logger.info('Verbose logging enabled')
    Core.quiet = getattr(args, 'quiet', False)
    try:
        db = stash.StashManager()
        await db.do_init()
    except (AttributeError, OSError, RuntimeError, ValueError) as init_error:
        if not args.quiet:
            output_logger.info(f'Error initializing StashManager: {init_error}')
        raise ValueError('Failed to initialize StashManager')

    if len(filename) > 0:
        if filename.startswith('~/'):
            # Allow home directory expansion but sanitize the rest
            base_path = await anyio.Path('~').expanduser()
            sanitized = sanitize_filename(filename[2:])
            filename = str(base_path.joinpath(sanitized))
        elif os.path.isabs(filename):
            # For absolute paths, sanitize just the filename component
            dirname = os.path.dirname(filename)
            basename = sanitize_filename(os.path.basename(filename))
            filename = os.path.join(dirname, basename)
        else:
            # For relative paths, sanitize the entire filename
            filename = sanitize_filename(filename)

    all_emails: list = []
    all_hosts: list = []
    all_ip: list = []
    all_people: list[dict[str, str]] = []
    dnslookup = args.dns_lookup
    dnsresolve: str | None = args.dns_resolve
    final_dns_resolver_list = []
    if dnsresolve is not None and len(dnsresolve) > 0:
        # Three scenarios:
        # 8.8.8.8
        # 1.1.1.1,8.8.8.8 or 1.1.1.1, 8.8.8.8
        # resolvers.txt
        if await anyio.Path(dnsresolve).exists():
            async with await anyio.open_file(dnsresolve, encoding='UTF-8') as fp:
                async for line in fp:
                    line = line.strip()
                    if len(line) == 0:
                        continue
                    try:
                        _ = netaddr.IPAddress(line)
                        final_dns_resolver_list.append(line)
                    except (netaddr.core.AddrFormatError, ValueError, TypeError) as e:
                        output_logger.info(f'An exception has occurred while reading from: {dnsresolve}, {e}')
                        output_logger.info(f'Current line: {line}')
        else:
            cleaned = dnsresolve.replace(' ', '')
            resolver_candidates = cleaned.split(',') if ',' in cleaned else [cleaned]
            for item in resolver_candidates:
                if len(item) == 0:
                    continue
                try:
                    # Verify user passed in an IP; this does not validate resolver behavior
                    _ = netaddr.IPAddress(item)
                    final_dns_resolver_list.append(item)
                except (netaddr.core.AddrFormatError, ValueError, TypeError) as e:
                    output_logger.info(f'Passed DNS resolver is invalid, skipping: {item} ({e})')

        # if for some reason, there are duplicates
        final_dns_resolver_list = list(dict.fromkeys(final_dns_resolver_list))
        if len(final_dns_resolver_list) == 0:
            output_logger.info('No valid DNS resolvers were parsed from --dns-resolve; continuing without custom resolvers.')

    engines: list = []
    # If the user specifies
    full: list = []
    host_ip: list = []
    limit: int = args.limit
    shodan = args.shodan
    screenshot_path = getattr(args, 'screenshot', '')
    api_scan_enabled = getattr(args, 'api_scan', False)
    start: int = args.start
    all_urls: list = []
    vhost: list = []
    word: str = args.domain.rstrip('\n')
    takeover_status = args.take_over
    use_proxy = args.proxies
    linkedin_people_list_tracker: list = []
    linkedin_links_tracker: list = []
    twitter_people_list_tracker: list = []
    interesting_urls: list = []
    total_asns: list = []

    linkedin_people_list_tracker = []
    linkedin_links_tracker = []
    twitter_people_list_tracker = []

    interesting_urls = []
    total_asns = []
    run_result = start_run(word)
    word = run_result.target
    source_executions: list[RunExecution] = []
    source_observations: list[DiscoveryObservation] = []
    selected_executions: list[RunExecution] = []
    selected_hostname_observations: list[DiscoveryObservation] = []
    result_sources: dict[tuple[str, str], set[str]] = {}
    pending_legacy_results: list[tuple[str, tuple[object, ...], str, str]] = []

    def _result_value(value: object) -> str:
        return value if isinstance(value, str) else ujson.dumps(value, sort_keys=True)

    def _remember_results(result_type: str, values: Iterable[object], source: str) -> None:
        for value in values:
            result_sources.setdefault((result_type, _result_value(value)), set()).add(source)

    def _defer_legacy_results(values: Iterable[object], result_type: str, source: str) -> None:
        pending_legacy_results.append((word, tuple(values), result_type, source))

    def _result_record(result_type: str, value: object, *fallback_sources: str) -> ResultRecord:
        normalized_value = _result_value(value)
        sources = result_sources.get((result_type, normalized_value), set(fallback_sources))
        return ResultRecord(result_type, normalized_value, tuple(sorted(sources)))

    def _completed_execution(
        name: str,
        activity: ActivityClass,
        started_at: datetime,
        started: float,
        result_count: int,
        error: Exception | None = None,
        *,
        partial: bool = False,
        observation_count: int = 0,
        entity_count: int = 0,
    ) -> RunExecution:
        status = (
            ExecutionStatus.PARTIAL
            if partial
            else ExecutionStatus.FAILED
            if error
            else ExecutionStatus.SUCCEEDED
            if result_count
            else ExecutionStatus.EMPTY
        )
        return RunExecution(
            name,
            activity,
            status,
            (time.perf_counter() - started) * 1000,
            result_count,
            observation_count=observation_count,
            entity_count=entity_count,
            error_type=type(error).__name__ if error else None,
            started_at=started_at,
            completed_at=datetime.now(UTC),
        )

    async def _store(
        search_engine: Any,
        source: str,
        run_result: RunResult | None = None,
    ) -> tuple[int, int, int]:
        """Process a source and persist its declared consolidated result routes.

        :param search_engine: search engine to fetch details from
        :param source: source against which the details (corresponding to the search engine) need to be persisted
        :param run_result: optional completed evidence run for a migrated source
        """
        if run_result is None:
            logger.info(f'Source {source} started')
            try:
                await search_engine.process(use_proxy)
            except Exception:
                logger.exception(f'Source {source} failed')
                raise
        source_spec = get_source_spec(source)
        routes = source_spec.routes
        result_count = 0
        observation_count = 0
        entity_count = 0

        if source:
            output_logger.info(f'[*] Searching {source[0].upper() + source[1:]}. ')

        if ResultRoute.HOSTS in routes:
            if run_result is not None and run_result.dns_validations:
                resolved_pair, host_names, temp_ips = legacy_dns_results(run_result, source_spec.name)
                all_ip.extend(temp_ips)
                full.extend(resolved_pair)
            elif run_result is not None:
                host_names = legacy_hostnames(run_result, source_spec.name)
            else:
                discovered_hosts = await search_engine.get_hostnames()
                host_names = list(_normalize_hosts_for_storage(discovered_hosts, word, include_target=source == 'intelx'))
            if run_result is None or not run_result.dns_validations:
                full.extend(host_names)
            all_hosts.extend(host_names)
            _remember_results('subdomain', host_names, source_spec.name)
            _defer_legacy_results(all_hosts, 'host', source)
            result_count += len(host_names)
            observation_count = len(host_names)
            entity_count = len(set(host_names))
            if run_result is None:
                collected_at = datetime.now(UTC)
                source_observations.extend(
                    DiscoveryObservation(
                        value=hostname,
                        source=source_spec.name,
                        derivation=Derivation.PROVIDER,
                        collected_at=collected_at,
                        scope_class=ScopeClass.IN_SCOPE,
                    )
                    for hostname in host_names
                )

        if ResultRoute.EMAILS in routes:
            email_list = await search_engine.get_emails()
            all_emails.extend(email_list)
            _remember_results('email', email_list, source_spec.name)
            _defer_legacy_results(email_list, 'email', source)
            result_count += len(email_list)

        if ResultRoute.IPS in routes:
            ips_list = await search_engine.get_ips()
            all_ip.extend(ips_list)
            _remember_results('ip', ips_list, source_spec.name)
            _defer_legacy_results(all_ip, 'ip', source)
            result_count += len(ips_list)

        if ResultRoute.PEOPLE in routes:
            people_list = await search_engine.get_people()
            all_people.extend(people_list)
            _remember_results('person', people_list, source_spec.name)
            _defer_legacy_results(people_list, 'people', source)
            result_count += len(people_list)

        if ResultRoute.LINKS in routes:
            links = await search_engine.get_links()
            linkedin_links_tracker.extend(links)
            _remember_results('url', links, source_spec.name)
            if len(links) > 0:
                _defer_legacy_results(links, 'linkedinlinks', source)
            result_count += len(links)

        if ResultRoute.INTERESTING_URLS in routes:
            iurls = await search_engine.get_interestingurls()
            interesting_urls.extend(iurls)
            _remember_results('url', iurls, source_spec.name)
            if len(iurls) > 0:
                _defer_legacy_results(iurls, 'interestingurls', source)
            result_count += len(iurls)

        if ResultRoute.ASNS in routes:
            fasns = await search_engine.get_asns()
            total_asns.extend(fasns)
            _remember_results('asn', fasns, source_spec.name)
            if len(fasns) > 0:
                _defer_legacy_results(fasns, 'asns', source)
            result_count += len(fasns)
        if run_result is None:
            logger.info(f'Source {source} completed')
        return result_count, observation_count, entity_count

    def store(search_engine: Any, source: str):
        async def run_source() -> None:
            started_at = datetime.now(UTC)
            started = time.perf_counter()
            result_count = 0
            observation_count = 0
            entity_count = 0
            error: Exception | None = None
            try:
                result_count, observation_count, entity_count = await _store(search_engine, source)
            except Exception as source_error:
                error = source_error
                raise
            finally:
                source_executions.append(
                    RunExecution(
                        name=get_source_spec(source).name,
                        activity=ActivityClass.PASSIVE,
                        status=(
                            ExecutionStatus.FAILED
                            if error is not None
                            else ExecutionStatus.SUCCEEDED
                            if result_count
                            else ExecutionStatus.EMPTY
                        ),
                        duration_ms=(time.perf_counter() - started) * 1000,
                        result_count=result_count,
                        observation_count=observation_count,
                        entity_count=entity_count,
                        error_type=type(error).__name__ if error else None,
                        started_at=started_at,
                        completed_at=datetime.now(UTC),
                    )
                )

        return run_source()

    stor_lst = []
    evidence_sources: list[LegacyHostnameSource] = []

    async def store_evidence_sources() -> None:
        nonlocal run_result
        run_result = await execute_run(word, tuple(evidence_sources), run=run_result)
        executions = {execution.source: execution for execution in run_result.source_executions}
        for evidence_source in evidence_sources:
            execution = executions[evidence_source.name]
            if execution.status in (SourceStatus.SUCCEEDED, SourceStatus.EMPTY) or execution.observation_count:
                await _store(evidence_source.search, evidence_source.legacy_name, run_result)

    if args.source is not None:
        engines = Core.expand_source_selection(args.source)
        # Iterate through search engines in order
        if set(engines).issubset(Core.get_supportedengines()):
            for engineitem in engines:
                if engineitem == 'baidu':
                    try:
                        baidu_search = baidusearch.SearchBaidu(word, limit)
                        stor_lst.append(
                            store(
                                baidu_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'bevigil':
                    try:
                        bevigil_search = bevigil.SearchBeVigil(word)
                        stor_lst.append(
                            store(
                                bevigil_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, error=e)

                elif engineitem == 'bitbucket':
                    try:
                        bitbucket_search = bitbucket.SearchBitBucket(word, limit)
                        stor_lst.append(
                            store(
                                bitbucket_search,
                                engineitem,
                            )
                        )
                    except Exception as ex:
                        if isinstance(ex, MissingKey):
                            output_logger.info(MissingKey('Bitbucket'))
                        else:
                            show_default_error_message(engineitem, word, ex)

                elif engineitem == 'brave':
                    try:
                        brave_search = bravesearch.SearchBrave(word, limit)
                        stor_lst.append(
                            store(
                                brave_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, error=e)

                elif engineitem == 'bufferoverun':
                    try:
                        bufferoverun_search = bufferoverun.SearchBufferover(word)
                        stor_lst.append(
                            store(
                                bufferoverun_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'builtwith':
                    try:
                        builtwith_search = builtwith.SearchBuiltWith(word)
                        stor_lst.append(store(builtwith_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            output_logger.info(f"Failed to perform BuiltWith search for word: '{word}'")
                            output_logger.info(f'A Missing Key Error occurred in builtwith: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'censys':
                    try:
                        censys_search = censysearch.SearchCensys(word, limit)
                        stor_lst.append(
                            store(
                                censys_search,
                                engineitem,
                            )
                        )
                    except MissingKey as mk:
                        if not args.quiet:
                            output_logger.info(f'Censys API key is missing or invalid: {mk}')
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network error while querying Censys: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Timeout occurred while contacting Censys: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'Censys returned unexpected data: {ve}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in Censys module: {e}')

                elif engineitem == 'certspotter':
                    try:
                        certspotter_search = certspottersearch.SearchCertspoter(word)
                        stor_lst.append(store(certspotter_search, engineitem))
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing Certspotter: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to Certspotter timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'Certspotter returned invalid data: {ve}')
                    except MissingKey as mk:
                        if not args.quiet:
                            output_logger.info(f'Unexpected response structure from Certspotter (missing key): {mk}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in Certspotter module: {e}')

                elif engineitem == 'chaos':
                    try:
                        chaos_search = chaos.SearchChaos(word)
                        stor_lst.append(
                            store(
                                chaos_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Chaos: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'commoncrawl':
                    try:
                        commoncrawl_search = commoncrawl.SearchCommoncrawl(word, limit)
                        stor_lst.append(
                            store(
                                commoncrawl_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'criminalip':
                    try:
                        criminalip_search = criminalip.SearchCriminalIP(word)
                        stor_lst.append(
                            store(
                                criminalip_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing key error occurred in criminalip: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'crtsh':
                    try:
                        crtsh_search = crtsh.SearchCrtsh(word)
                        source_spec = get_source_spec(engineitem)
                        evidence_sources.append(
                            LegacyHostnameSource(
                                name=source_spec.name,
                                legacy_name='CRTsh',
                                search=crtsh_search,
                                proxy=use_proxy,
                            )
                        )
                    except Exception as e:
                        output_logger.info(f'[!] A timeout occurred with crtsh, cannot find {args.domain}\n {e}')

                elif engineitem == 'dehashed':
                    try:
                        dehashed_search = search_dehashed.SearchDehashed(word)
                        stor_lst.append(
                            store(
                                dehashed_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in dehashed: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'dnsdb':
                    try:
                        dnsdb_search = dnsdb.SearchDNSDB(word)
                        source_spec = get_source_spec(engineitem)
                        evidence_sources.append(
                            LegacyHostnameSource(
                                name=source_spec.name,
                                legacy_name='dnsdb',
                                search=dnsdb_search,
                                proxy=use_proxy,
                            )
                        )
                    except MissingKey as e:
                        if not args.quiet:
                            output_logger.info(e)
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'dnsdumpster':
                    try:
                        dnsdumpster_search = search_dnsdumpster.SearchDNSDumpster(word)
                        stor_lst.append(
                            store(
                                dnsdumpster_search,
                                engineitem,
                            )
                        )
                    except MissingKey as e:
                        if not args.quiet:
                            output_logger.info(e)
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'duckduckgo':
                    duckduckgo_search = duckduckgosearch.SearchDuckDuckGo(word, limit)
                    stor_lst.append(
                        store(
                            duckduckgo_search,
                            engineitem,
                        )
                    )

                elif engineitem == 'dymo':
                    try:
                        dymo_search = dymosearch.SearchDymo(word)
                        stor_lst.append(store(dymo_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in dymo: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'fofa':
                    try:
                        fofa_search = fofa.SearchFofa(word)
                        stor_lst.append(
                            store(
                                fofa_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Fofa: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'fullhunt':
                    try:
                        fullhunt_search = fullhuntsearch.SearchFullHunt(word)
                        stor_lst.append(store(fullhunt_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in fullhunt: {e}')

                elif engineitem == 'github-code':
                    try:
                        github_search = githubcode.SearchGithubCode(word, limit)
                        stor_lst.append(
                            store(
                                github_search,
                                engineitem,
                            )
                        )
                    except MissingKey as ex:
                        if not args.quiet:
                            output_logger.info(f'A Missing Key error occurred in github-code: {ex}')

                elif engineitem == 'gitlab':
                    try:
                        gitlab_search = gitlabsearch.SearchGitlab(word)
                        stor_lst.append(
                            store(
                                gitlab_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'hackertarget':
                    try:
                        hackertarget_search = hackertarget.SearchHackerTarget(word)
                        stor_lst.append(store(hackertarget_search, engineitem))
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'haveibeenpwned':
                    try:
                        haveibeenpwned_search = haveibeenpwned.SearchHaveIBeenPwned(word)
                        stor_lst.append(
                            store(
                                haveibeenpwned_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(MissingKey('HaveIBeenPwned'))
                        else:
                            output_logger.info(f'An exception has occurred in HaveIBeenPwned search: {e}')

                elif engineitem == 'hudsonrock':
                    try:
                        hudsonrock_search = hudsonrocksearch.SearchHudsonRock(word)
                        stor_lst.append(
                            store(
                                hudsonrock_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        output_logger.info(f'An exception has occurred in Hudson Rock search: {e}')

                elif engineitem == 'hunter':
                    try:
                        hunter_search = huntersearch.SearchHunter(word, limit, start)
                        stor_lst.append(
                            store(
                                hunter_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Hunter: {e}')

                elif engineitem == 'hunterhow':
                    try:
                        hunterhow_search = searchhunterhow.SearchHunterHow(word)
                        stor_lst.append(store(hunterhow_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Hunter How: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in hunterhow search: {e}')

                elif engineitem == 'intelx':
                    try:
                        intelx_search = intelxsearch.SearchIntelx(word)
                        stor_lst.append(
                            store(
                                intelx_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in intelx: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in Intelx search: {e}')

                elif engineitem == 'leakix':
                    try:
                        leakix_search = leakix.SearchLeakix(word)
                        stor_lst.append(
                            store(
                                leakix_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'leaklookup':
                    try:
                        leaklookup_search = leaklookup.SearchLeakLookup(word)
                        stor_lst.append(
                            store(
                                leaklookup_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            output_logger.info(f'A Missing Key error occurred in LeakLookup: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in LeakLookup search: {e}')

                elif engineitem == 'mojeek':
                    try:
                        mojeek_search = mojeek.SearchMojeek(word, limit)
                        stor_lst.append(
                            store(
                                mojeek_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            output_logger.info(f'A Missing Key error occurred in Mojeek: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in Mojeek search: {e}')

                elif engineitem == 'netlas':
                    try:
                        netlas_search = netlas.SearchNetlas(word, limit)
                        stor_lst.append(
                            store(
                                netlas_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Netlas: {e}')

                elif engineitem == 'onyphe':
                    try:
                        onyphe_search = onyphe.SearchOnyphe(word)
                        stor_lst.append(
                            store(
                                onyphe_search,
                                engineitem,
                            )
                        )
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing Onyphe: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to Onyphe timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'Onyphe returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            output_logger.info(f'Unexpected response structure from Onyphe (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in Onyphe module: {e}')

                elif engineitem == 'otx':
                    try:
                        otxsearch_search = otxsearch.SearchOtx(word)
                        stor_lst.append(
                            store(
                                otxsearch_search,
                                engineitem,
                            )
                        )
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing OTX: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to OTX timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'OTX returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            output_logger.info(f'Unexpected response structure from OTX (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in OTX module: {e}')

                elif engineitem == 'pentesttools':
                    try:
                        pentesttools_search = pentesttools.SearchPentestTools(word)
                        stor_lst.append(store(pentesttools_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in PentestTools search: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in PentestTools search: {e}')

                elif engineitem == 'projectdiscovery':
                    try:
                        projectdiscovery_search = projectdiscovery.SearchDiscovery(word)
                        stor_lst.append(store(projectdiscovery_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in ProjectDiscovery: {e}')
                        else:
                            output_logger.info('An exception has occurred in ProjectDiscovery')

                elif engineitem == 'rapiddns':
                    try:
                        rapiddns_search = rapiddns.SearchRapidDns(word)
                        stor_lst.append(store(rapiddns_search, engineitem))
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing RapidDNS: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to RapidDNS timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'RapidDNS returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            output_logger.info(f'Unexpected response structure from RapidDNS (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in RapidDNS module: {e}')

                elif engineitem == 'robtex':
                    try:
                        robtex_search = robtex.SearchRobtex(word)
                        stor_lst.append(
                            store(
                                robtex_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'rocketreach':
                    try:
                        rocketreach_search = rocketreach.SearchRocketReach(word, limit)
                        stor_lst.append(store(rocketreach_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in RocketReach: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in RocketReach: {e}')

                elif engineitem == 'securityscorecard':
                    try:
                        securityscorecard_search = securityscorecard.SearchSecurityScorecard(word)
                        stor_lst.append(
                            store(
                                securityscorecard_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            output_logger.info(MissingKey('SecurityScorecard'))
                        else:
                            output_logger.info(f'An exception has occurred in SecurityScorecard search: {e}')

                elif engineitem == 'securityTrails':
                    try:
                        securitytrails_search = securitytrailssearch.SearchSecuritytrail(word)
                        stor_lst.append(
                            store(
                                securitytrails_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred Security Trails: {e}')

                elif engineitem == 'sherlockeye':
                    try:
                        sherlockeye_search = sherlockeye.SearchSherlockeye(word)
                        stor_lst.append(
                            store(
                                sherlockeye_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in sherlockeye: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'shodan':
                    try:
                        shodan_search = shodansearch.SearchShodan()

                        # For normal module usage, we need to create a wrapper that works with the store function
                        class ShodanWrapper:
                            def __init__(self, domain, shodan_client):
                                self.word = domain
                                self.hosts = set()
                                self.shodan = shodan_client

                            async def process(self, use_proxy: bool = False):
                                import socket

                                try:
                                    # Resolve domain to IP and search in Shodan
                                    ip = socket.gethostbyname(self.word)
                                    output_logger.info(f'\tSearching Shodan for {ip}')
                                    result = await self.shodan.search_ip(ip)
                                    if ip in result and isinstance(result[ip], dict):
                                        # Add the IP as a host for consistency with other modules
                                        self.hosts.add(ip)

                                        for host in result[ip].get('hostnames', []):
                                            self.hosts.add(host)

                                        output_logger.info(f'Found Shodan data for {ip}')
                                    elif ip in result and isinstance(result[ip], str):
                                        output_logger.info(f'{ip}: {result[ip]}')
                                except Exception as e:
                                    output_logger.info(f'Error in Shodan search: {e}')

                            async def get_hostnames(self):
                                return list(self.hosts)

                        shodan_wrapper = ShodanWrapper(word, shodan_search)
                        stor_lst.append(store(shodan_wrapper, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Shodan search: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in Shodan search: {e}')

                elif engineitem == 'shodanInternetDB':
                    try:
                        shodanidb_search = shodan_internetdb.SearchShodanInternetDB(word)
                        stor_lst.append(
                            store(
                                shodanidb_search,
                                engineitem,
                            )
                        )
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing Shodan InternetDB: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to Shodan InternetDB timed out: {te}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in Shodan InternetDB module: {e}')

                elif engineitem == 'shodanct':
                    shodanct_search = shodanct.SearchShodanCt(word)
                    source_spec = get_source_spec(engineitem)
                    evidence_sources.append(
                        LegacyHostnameSource(
                            name=source_spec.name,
                            legacy_name=source_spec.name,
                            search=shodanct_search,
                            proxy=use_proxy,
                        )
                    )

                elif engineitem == 'subdomaincenter':
                    try:
                        subdomaincenter_search = subdomaincenter.SubdomainCenter(word)
                        stor_lst.append(store(subdomaincenter_search, engineitem))
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing SubdomainCenter: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to SubdomainCenter timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'SubdomainCenter returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            output_logger.info(f'Unexpected response structure from SubdomainCenter (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in SubdomainCenter module: {e}')

                elif engineitem == 'subdomainfinderc99':
                    try:
                        subdomainfinderc99_search = subdomainfinderc99.SearchSubdomainfinderc99(word)
                        stor_lst.append(store(subdomainfinderc99_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Subdomainfinderc99 search: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in Subdomainfinderc99 search: {e}')

                elif engineitem == 'thc':
                    try:
                        thc_search = thc.SearchThc(word)
                        stor_lst.append(store(thc_search, engineitem))
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'threatcrowd':
                    try:
                        threatcrowd_search = threatcrowd.SearchThreatcrowd(word)
                        stor_lst.append(
                            store(
                                threatcrowd_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'tomba':
                    try:
                        tomba_search = tombasearch.SearchTomba(word, limit, start)
                        stor_lst.append(
                            store(
                                tomba_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Tomba: {e}')

                elif engineitem == 'urlscan':
                    try:
                        urlscan_search = urlscan.SearchUrlscan(word)
                        stor_lst.append(
                            store(
                                urlscan_search,
                                engineitem,
                            )
                        )
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing Urlscan: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to Urlscan timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'Urlscan returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            output_logger.info(f'Unexpected response structure from Urlscan (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in Urlscan module: {e}')

                elif engineitem == 'venacus':
                    try:
                        venacus_search = venacussearch.SearchVenacus(word=word, limit=limit, offset_doc=start)
                        stor_lst.append(
                            store(
                                venacus_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in venacus search: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in venacus search: {e}')

                elif engineitem == 'virustotal':
                    try:
                        virustotal_search = virustotal.SearchVirustotal(word)
                        stor_lst.append(store(virustotal_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in virustotal search: {e}')

                elif engineitem == 'waybackarchive':
                    try:
                        waybackarchive_search = waybackarchive.SearchWaybackarchive(word)
                        stor_lst.append(
                            store(
                                waybackarchive_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'whoisxml':
                    try:
                        whoisxml_search = whoisxml.SearchWhoisXML(word)
                        stor_lst.append(store(whoisxml_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in whoisxml search: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in WhoisXML search: {e}')

                elif engineitem == 'windvane':
                    try:
                        windvane_search = windvane.SearchWindvane(word)
                        stor_lst.append(
                            store(
                                windvane_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'yahoo':
                    try:
                        yahoo_search = yahoosearch.SearchYahoo(word, limit)
                        stor_lst.append(
                            store(
                                yahoo_search,
                                engineitem,
                            )
                        )
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing Yahoo: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to Yahoo timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'Yahoo returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            output_logger.info(f'Unexpected response structure from Yahoo (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in Yahoo module: {e}')

                elif engineitem == 'zoomeye':
                    try:
                        zoomeye_search = zoomeyesearch.SearchZoomEye(word, limit)
                        stor_lst.append(
                            store(
                                zoomeye_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in zoomeye: {e}')

            if evidence_sources:
                stor_lst.append(store_evidence_sources())

        elif rest_args is not None:
            try:
                rest_args.dns_brute
            except AttributeError:
                output_logger.info('\n[!] Invalid source.\n')
                sys.exit(1)
        else:
            # Print which engines aren't supported
            unsupported_engines = set(engines) - set(Core.get_supportedengines())
            if unsupported_engines:
                output_logger.info(f'The following engines are not supported: {unsupported_engines}')
            output_logger.info('\n[!] Invalid source.\n')
            sys.exit(1)

    async def worker(queue):
        while True:
            # Get a "work item" out of the queue.
            stor = await queue.get()
            try:
                await stor
                queue.task_done()
                # Notify the queue that the "work item" has been processed.
            except Exception as work_item_error:
                output_logger.info(
                    f'\n An error occurred while processing a "work item": {type(work_item_error).__name__}: {work_item_error}\n'
                )
                queue.task_done()

    async def handler(lst):
        queue: asyncio.Queue[Awaitable[Any]] = asyncio.Queue()
        for stor_method in lst:
            # enqueue the coroutines
            queue.put_nowait(stor_method)
        # Create three worker tasks to process the queue concurrently.
        tasks = []
        for _i in range(3):
            task = asyncio.create_task(worker(queue))
            tasks.append(task)

        # Wait until the queue is fully processed.
        await queue.join()

        # Cancel our worker tasks.
        for task in tasks:
            task.cancel()
        # Wait until all worker tasks are cancelled.
        await asyncio.gather(*tasks, return_exceptions=True)

    await handler(lst=stor_lst)
    represented_sources = {execution.name for execution in (*run_result.source_executions, *source_executions)}
    for selected_source in engines:
        try:
            source_name = get_source_spec(selected_source).name
        except KeyError:
            continue
        if source_name not in represented_sources:
            source_executions.append(
                RunExecution(
                    source_name,
                    ActivityClass.PASSIVE,
                    ExecutionStatus.FAILED,
                    0,
                    0,
                    error_type='SourceNotStarted',
                    started_at=run_result.started_at,
                    completed_at=datetime.now(UTC),
                )
            )
    run_result = add_run_evidence(
        run_result,
        executions=source_executions,
        observations=source_observations,
    )
    all_hosts = sorted_unique(all_hosts)
    all_emails = sorted_unique(all_emails)
    total_asns = sorted_unique(total_asns)
    interesting_urls = sorted_unique(interesting_urls)
    twitter_people_list_tracker = sorted_unique(twitter_people_list_tracker)
    linkedin_people_list_tracker = sorted_unique(linkedin_people_list_tracker)
    linkedin_links_tracker = sorted_unique(linkedin_links_tracker)
    all_urls = sorted_unique(all_urls)

    dns_requested = dnsresolve is None or bool(final_dns_resolver_list)
    if dns_requested:
        dns_started_at = datetime.now(UTC)
        dns_started = time.perf_counter()
        dns_error: Exception | None = None
        resolved_pair: list[str] = []
        dns_observation_count = 0
        dns_entity_count = 0
        try:
            if len(final_dns_resolver_list) == 3:
                async with AsyncExitStack() as resolver_stack:
                    vantages = []
                    for nameserver in final_dns_resolver_list:
                        vantage = AioDnsResolverVantage(nameserver)
                        vantages.append(vantage)
                        resolver_stack.push_async_callback(vantage.close)
                    run_result = await validate_run(run_result, DnsValidator(tuple(vantages)))
                dns_observation_count = len(run_result.dns_validations)
                dns_entity_count = sum(entity.addressability is not None for entity in run_result.entities)
                resolved_pair, _resolved_hosts, resolved_ips = legacy_dns_results(run_result)
            else:
                resolved_pair, _resolved_hosts, resolved_ips = await hostchecker.Checker(
                    all_hosts, final_dns_resolver_list
                ).check()
            full = sorted_unique(resolved_pair)
            all_ip.extend(resolved_ips)
            _remember_results('ip', resolved_ips, 'dns-resolution')
        except Exception as error:
            dns_error = error
            full = []
            logger.exception('DNS resolution failed')
        selected_executions.append(
            _completed_execution(
                'dns-resolution',
                ActivityClass.DNS,
                dns_started_at,
                dns_started,
                len(full),
                dns_error,
                observation_count=dns_observation_count,
                entity_count=dns_entity_count,
            )
        )
    else:
        full = list(all_hosts)

    # DNS brute force
    dns_bruteforce_results: list[str] = []
    if dnsbrute and dnsbrute[0] is True:
        output_logger.info('\n[*] Starting DNS brute force.')
        action_started_at = datetime.now(UTC)
        action_started = time.perf_counter()
        action_error: Exception | None = None
        normalized_brute_hosts: set[str] = set()
        try:
            dns_bruteforce_results, brute_hosts, brute_ips = await dnssearch.DnsForce(
                word, final_dns_resolver_list, verbose=True
            ).run()
            full.extend(dns_bruteforce_results)
            normalized_brute_hosts = _normalize_hosts_for_storage(brute_hosts, word)
            all_hosts.extend(normalized_brute_hosts)
            all_ip.extend(brute_ips)
            _remember_results('subdomain', normalized_brute_hosts, 'dns-brute')
            _remember_results('ip', brute_ips, 'dns-brute')
            _defer_legacy_results(sorted_unique(brute_hosts), 'host', 'dns_bruteforce')
            collected_at = datetime.now(UTC)
            selected_hostname_observations.extend(
                DiscoveryObservation(
                    hostname,
                    'dns-brute',
                    Derivation.DNS,
                    collected_at,
                    ScopeClass.IN_SCOPE,
                )
                for hostname in normalized_brute_hosts
            )
        except Exception as error:
            action_error = error
            logger.exception('DNS brute force failed')
        selected_executions.append(
            _completed_execution(
                'action:dns-brute',
                ActivityClass.DNS,
                action_started_at,
                action_started,
                len(dns_bruteforce_results),
                action_error,
                observation_count=len(normalized_brute_hosts),
                entity_count=len(normalized_brute_hosts),
            )
        )

    ip_list: list[str] = []
    for ip in set(all_ip):
        try:
            value = str(ip).strip()
            if value:
                ip_list.append(str(netaddr.IPNetwork(value) if '/' in value else netaddr.IPAddress(value)))
        except (netaddr.core.AddrFormatError, ValueError, TypeError):
            logger.info(f'Ignoring invalid IP result: {ip!r}')
    ip_list = sorted_unique(ip_list)
    host_ip = ip_list

    # DNS reverse lookup
    dnsrev: list = []
    if dnslookup is True:
        output_logger.info('\n[*] Starting active queries for DNSLookup.')
        action_started_at = datetime.now(UTC)
        action_started = time.perf_counter()
        action_error = None
        normalized_reverse_hosts: set[str] = set()
        try:
            reverse_tasks = {}
            for entry in host_ip:
                ip_range = dnssearch.serialize_ip_range(ip=entry, netmask='24')
                if ip_range and ip_range not in reverse_tasks:
                    reverse_tasks[ip_range] = asyncio.create_task(
                        dnssearch.reverse_all_ips_in_range(
                            iprange=ip_range,
                            callback=dnssearch.generate_postprocessing_callback(
                                target=word, local_results=dnsrev, overall_results=full
                            ),
                            nameservers=final_dns_resolver_list or None,
                        )
                    )
            await asyncio.gather(*reverse_tasks.values())
            normalized_reverse_hosts = _normalize_hosts_for_storage(dnsrev, word)
            all_hosts.extend(normalized_reverse_hosts)
            _remember_results('subdomain', normalized_reverse_hosts, 'dns-reverse')
            collected_at = datetime.now(UTC)
            selected_hostname_observations.extend(
                DiscoveryObservation(
                    hostname,
                    'dns-reverse',
                    Derivation.DNS,
                    collected_at,
                    ScopeClass.IN_SCOPE,
                )
                for hostname in normalized_reverse_hosts
            )
        except Exception as error:
            action_error = error
            logger.exception('Reverse DNS lookup failed')
        selected_executions.append(
            _completed_execution(
                'action:dns-reverse',
                ActivityClass.DNS,
                action_started_at,
                action_started,
                len(dnsrev),
                action_error,
                observation_count=len(normalized_reverse_hosts),
                entity_count=len(normalized_reverse_hosts),
            )
        )

    takeover_results: dict = {}
    if takeover_status:
        output_logger.info('\n[*] Performing subdomain takeover check (direct interaction)')
        action_started_at = datetime.now(UTC)
        action_started = time.perf_counter()
        action_error = None
        try:
            search_take = takeover.TakeOver(sorted_unique(all_hosts))
            await search_take.populate_fingerprints()
            await search_take.process(proxy=use_proxy)
            takeover_results = await search_take.get_takeover_results()
            _remember_results(
                'takeover',
                (f'{host}:{status}' for host, status in takeover_results.items()),
                'takeover',
            )
        except Exception as error:
            action_error = error
            logger.exception('Subdomain takeover check failed')
        selected_executions.append(
            _completed_execution(
                'action:takeover',
                ActivityClass.DIRECT,
                action_started_at,
                action_started,
                len(takeover_results),
                action_error,
            )
        )

    # Screenshots
    screenshot_tups = []
    if screenshot_path:
        action_started_at = datetime.now(UTC)
        action_started = time.perf_counter()
        action_error = None
        try:
            screen_shotter = ScreenShotter(screenshot_path)
            if screen_shotter.verify_path():
                await screen_shotter.verify_installation()
                output_logger.info(f'\nScreenshots can be found in: {screen_shotter.output}{screen_shotter.slash}')
                unique_resolved_domains = (
                    {url.split(':')[0] for url in full if ':' in url and 'www.' not in url} if dns_requested else set(all_hosts)
                )
                if unique_resolved_domains:
                    output_logger.info('Attempting to visit unique resolved domains, this is direct interaction')
                    async with Pool(10) as pool:
                        reachable = await pool.map(screen_shotter.visit, list(unique_resolved_domains))
                    reachable_domains = sorted({item[0] for item in reachable if item[1]})
                    async with Pool(3) as pool:
                        for chunk in screen_shotter.chunk_list(reachable_domains, 14):
                            screenshot_tups.extend(await pool.map(screen_shotter.take_screenshot, chunk))
            _remember_results('screenshot', screenshot_tups, 'screenshot')
        except Exception as error:
            action_error = error
            logger.exception('Screenshot capture failed')
        selected_executions.append(
            _completed_execution(
                'action:screenshot',
                ActivityClass.DIRECT,
                action_started_at,
                action_started,
                len(screenshot_tups),
                action_error,
            )
        )

    # Shodan
    shodanres = []
    if shodan is True:
        output_logger.info('[*] Searching Shodan. ')
        action_started_at = datetime.now(UTC)
        action_started = time.perf_counter()
        shodan_errors: list[Exception] = []
        try:
            for ip in host_ip:
                try:
                    output_logger.info('\tSearching for ' + ip)
                    shodan_search = shodansearch.SearchShodan()
                    shodandict = await shodan_search.search_ip(ip)
                    await asyncio.sleep(5)

                    # Check if the result is a string (error message)
                    if isinstance(shodandict[ip], str):
                        continue

                    # Process the results if it's a dictionary
                    if isinstance(shodandict[ip], dict):
                        rowdata = []
                        for _key, value in shodandict[ip].items():
                            if isinstance(value, int):
                                value = str(value)
                            if isinstance(value, list):
                                value = ', '.join(map(str, value))
                            rowdata.append(value)
                        shodanres.append(rowdata)
                        _remember_results('shodan', (rowdata,), 'shodan')
                except Exception as ip_error:
                    shodan_errors.append(ip_error)
                    output_logger.info(f'[SHODAN-error] Error searching {ip}: {ip_error}')
                    continue
        except Exception as e:
            shodan_errors.append(e)
            output_logger.info(f'[!] An error occurred with Shodan: {e} ')
        shodan_error = shodan_errors[0] if shodan_errors else None
        selected_executions.append(
            _completed_execution(
                'action:shodan',
                ActivityClass.DIRECT,
                action_started_at,
                action_started,
                len(shodanres),
                shodan_error,
                partial=bool(shodan_error and shodanres),
            )
        )

    # Enhanced code block for API Endpoint scanning feature
    endpoints_found: dict[str, Any] = {}
    interesting_endpoints: dict[str, Any] = {}
    auth_required: dict[str, Any] = {}
    api_versions: set[str] = set()
    rate_limits: dict[str, Any] = {}
    methods: set[str] = set()
    status_codes: set[int] = set()
    if api_scan_enabled or 'api_endpoints' in engines:
        action_started_at = datetime.now(UTC)
        action_started = time.perf_counter()
        action_error = None
        try:
            # Define a default wordlist if none is specified
            wordlist = args.wordlist or str(DATA_DIR / 'wordlists' / 'api_endpoints.txt')

            if not await anyio.Path(wordlist).exists():
                output_logger.info(f'\n[!] Wordlist not found: {wordlist}')
                output_logger.info('Creating a basic API wordlist for scanning...')
                # Create a default simple API endpoint list
                basic_endpoints = [
                    '/api',
                    '/api/v1',
                    '/api/v2',
                    '/api/v3',
                    '/graphql',
                    '/swagger',
                    '/docs',
                    '/redoc',
                    '/swagger-ui',
                    '/openapi.json',
                    '/api-docs',
                    '/rest',
                    '/ws',
                    '/swagger-ui.html',
                    '/health',
                    '/status',
                    '/metrics',
                    '/actuator',
                    '/debug',
                ]
                temp_wordlist = str(DATA_DIR / 'wordlists' / 'temp_api_endpoints.txt')
                async with await anyio.open_file(temp_wordlist, 'w') as f:
                    await f.write('\n'.join(basic_endpoints))
                wordlist = temp_wordlist
                output_logger.info(f'Basic API wordlist created with {len(basic_endpoints)} endpoints.')

            output_logger.info(f'\n[*] Starting API endpoint scanning with wordlist: {wordlist}')
            api_scanner = api_endpoints.SearchApiEndpoints(word=word, wordlist=wordlist)
            await api_scanner.do_search()

            endpoints_found = api_scanner.get_found_endpoints()
            interesting_endpoints = api_scanner.get_interesting_endpoints()
            auth_required = api_scanner.get_auth_required()
            api_versions = api_scanner.get_api_versions()
            rate_limits = api_scanner.get_rate_limits()
            methods = api_scanner.get_methods()
            status_codes = api_scanner.get_status_codes()
            _remember_results('api-endpoint', endpoints_found, 'api-scan')
            _remember_results('api-auth-required', auth_required, 'api-scan')
            _remember_results('api-version', api_versions, 'api-scan')
            _remember_results('api-rate-limited', rate_limits, 'api-scan')
            _remember_results('http-method', methods, 'api-scan')
            _remember_results('http-status', status_codes, 'api-scan')

            # Add results to storage
            db = stash.StashManager()
            _defer_legacy_results(endpoints_found, 'api_endpoint', 'api_scan')

            # Add to interesting URLs if any endpoints were found
            if interesting_endpoints:
                new_urls = list(interesting_endpoints)
                interesting_urls.extend(new_urls)

                # Also add complete domain paths to the interesting_urls list
                all_urls.extend(new_urls)

            output_logger.info('\n[+] API scanning completed successfully.')

        except MissingKey as error:
            action_error = error
            output_logger.info('\n[!] API endpoint scanning requires a wordlist. Use -w to specify a wordlist file.')
            output_logger.info('    Creating a basic wordlist and trying again...')
            # The wordlist creation code above could be used here
        except Exception as e:
            action_error = e
            output_logger.info(f'\n[!] An exception has occurred in API Endpoints scanning: {e}')
            output_logger.info('    Continuing with the rest of the scan...')
            logger.exception('API endpoint scan failed')
        selected_executions.append(
            _completed_execution(
                'action:api-scan',
                ActivityClass.DIRECT,
                action_started_at,
                action_started,
                len(endpoints_found),
                action_error,
            )
        )

    all_hosts = sorted_unique(all_hosts)
    all_ip = sorted_unique([*all_ip, *ip_list])
    interesting_urls = sorted_unique(interesting_urls)
    all_urls = sorted_unique(all_urls)
    if selected_hostname_observations:
        run_result = add_run_evidence(run_result, observations=selected_hostname_observations)
    report_hosts = sorted_unique(
        entity.value
        for entity in run_result.entities
        if ScopeClass.IN_SCOPE in entity.scope_classes and entity.value != run_result.target
    )
    result_records = [
        *(_result_record('subdomain', value) for value in report_hosts),
        *(
            _result_record(
                'scope-extension',
                entity.value,
                *(observation.source for observation in entity.observations),
            )
            for entity in run_result.entities
            if ScopeClass.SCOPE_EXTENSION in entity.scope_classes
        ),
        *(
            _result_record(
                'external-relationship',
                entity.value,
                *(observation.source for observation in entity.observations),
            )
            for entity in run_result.entities
            if ScopeClass.EXTERNAL_RELATIONSHIP in entity.scope_classes
        ),
        *(_result_record('ip', value) for value in all_ip),
        *(_result_record('asn', value) for value in total_asns),
        *(_result_record('email', value) for value in all_emails),
        *(_result_record('url', value) for value in sorted_unique([*interesting_urls, *all_urls, *linkedin_links_tracker])),
        *(_result_record('person', value) for value in twitter_people_list_tracker),
        *(_result_record('person', value) for value in linkedin_people_list_tracker),
        *(_result_record('person', value) for value in all_people),
        *(_result_record('vhost', value) for value in vhost),
        *(_result_record('takeover', f'{host}:{status}', 'takeover') for host, status in sorted(takeover_results.items())),
        *(_result_record('screenshot', value, 'screenshot') for value in screenshot_tups),
        *(_result_record('shodan', value, 'shodan') for value in shodanres),
        *(_result_record('api-endpoint', value, 'api-scan') for value in sorted(endpoints_found)),
        *(_result_record('api-auth-required', value, 'api-scan') for value in sorted(auth_required)),
        *(_result_record('api-version', value, 'api-scan') for value in sorted(api_versions)),
        *(_result_record('api-rate-limited', value, 'api-scan') for value in sorted(rate_limits)),
        *(_result_record('http-method', value, 'api-scan') for value in sorted(methods)),
        *(_result_record('http-status', value, 'api-scan') for value in sorted(status_codes)),
    ]
    completed_run = complete_run(run_result, results=result_records, executions=selected_executions)
    await db.store_run(completed_run, legacy_results=pending_legacy_results)

    command = 'REST /query' if rest_args is not None else ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in sys.argv)
    if not dns_requested:
        dns_configuration = 'DNS resolution: off'
    elif len(final_dns_resolver_list) == 3:
        dns_configuration = f'DNS resolution: consensus via {", ".join(final_dns_resolver_list)}'
    elif final_dns_resolver_list:
        dns_configuration = f'DNS resolution: {", ".join(final_dns_resolver_list)}'
    else:
        dns_configuration = 'DNS resolution: system resolvers'
    actions = [
        name
        for enabled, name in (
            (dnsbrute[0], 'dns-brute'),
            (dnslookup, 'dns-reverse'),
            (takeover_status, 'takeover'),
            (bool(screenshot_path), 'screenshot'),
            (shodan, 'shodan'),
            (api_scan_enabled or 'api_endpoints' in engines, 'api-scan'),
        )
        if enabled
    ]
    activity_summary = '; '.join(dict.fromkeys(str(execution.activity) for execution in completed_run.executions))
    if rest_args is None:
        output_logger.info(
            format_run_terminal(
                completed_run,
                configuration=(
                    f'Command: {command}',
                    f'Sources: {", ".join(engines) if engines else "none"}',
                    dns_configuration,
                    f'Actions: {", ".join(actions) if actions else "none"}',
                    f'Activity: {activity_summary or "none"}',
                ),
            )
        )

    if filename:
        output_logger.info('\n[*] Reporting started.')
        legacy_hosts = legacy_report_hosts(all_hosts, full if dns_requested else ())
        report_base = (
            os.path.join('theHarvester/app/static', os.path.splitext(rest_filename)[0])
            if rest_filename
            else os.path.splitext(filename)[0]
        )
        try:
            async with await anyio.open_file(report_base + '.xml', 'w+') as file:
                await file.write('<?xml version="1.0" encoding="UTF-8"?><theHarvester>')
                await file.write('<cmd>' + sanitize_for_xml(command) + '</cmd>')
                for email in all_emails:
                    await file.write('<email>' + sanitize_for_xml(email) + '</email>')
                for value in legacy_hosts:
                    host, ip = value.split(':', 1) if ':' in value else (value, '')
                    if ip and len(ip) > 3:
                        await file.write(
                            f'<host><ip>{sanitize_for_xml(ip)}</ip><hostname>{sanitize_for_xml(host)}</hostname></host>'
                        )
                    else:
                        await file.write(f'<host>{sanitize_for_xml(host)}</host>')
                for value in vhost:
                    host, ip = value.split(':', 1) if ':' in value else (value, '')
                    if ip and len(ip) > 3:
                        await file.write(
                            f'<vhost><ip>{sanitize_for_xml(ip)} </ip><hostname>{sanitize_for_xml(host)}</hostname></vhost>'
                        )
                    else:
                        await file.write(f'<vhost>{sanitize_for_xml(host)}</vhost>')
                await file.write(run_result_xml(completed_run))
                await file.write('</theHarvester>')
            output_logger.info('[*] XML File saved.')
        except (OSError, ValueError, TypeError, UnicodeEncodeError) as error:
            output_logger.info(f'[!] An error occurred while saving the XML file: {error}')

        try:
            json_dict: dict[str, object] = {
                'cmd': command,
                'hosts': legacy_hosts,
                'shodan': shodanres,
            }
            optional_results = {
                'ips': all_ip,
                'emails': all_emails,
                'vhosts': vhost,
                'interesting_urls': interesting_urls,
                'trello_urls': all_urls,
                'asns': total_asns,
                'twitter_people': twitter_people_list_tracker,
                'linkedin_people': linkedin_people_list_tracker,
                'linkedin_links': linkedin_links_tracker,
                'people': all_people,
                'takeover_results': takeover_results,
            }
            json_dict.update({key: value for key, value in optional_results.items() if value})
            async with await anyio.open_file(report_base + '.json', 'w+') as file:
                await file.write(ujson.dumps(legacy_json_result(completed_run, json_dict), sort_keys=True))
            output_logger.info('[*] JSON File saved.')
            async with await anyio.open_file(report_base + '.jsonl', 'w+') as file:
                await file.write(run_result_jsonl(completed_run) + '\n')
            output_logger.info('[*] JSONL File saved.')
        except (OSError, ValueError, TypeError, UnicodeEncodeError) as error:
            output_logger.info(f'[!] An error occurred while saving the JSON files: {error}')

    if rest_args is not None:
        if dnsbrute[1]:
            return (dns_bruteforce_results, completed_run) if getattr(rest_args, 'include_run', False) else dns_bruteforce_results
        all_hosts = sorted({host.replace('www.', '') for host in all_hosts})
        response = (
            total_asns,
            interesting_urls,
            twitter_people_list_tracker,
            linkedin_people_list_tracker,
            linkedin_links_tracker,
            all_urls,
            all_ip,
            all_emails,
            all_hosts,
        )
        return (*response, completed_run) if getattr(rest_args, 'include_run', False) else response
    sys.exit(0)


async def entry_point() -> None:
    try:
        configure_logging(verbose=False)
        Core.banner()
        await start()
    except KeyboardInterrupt:
        output_logger.info('\n\n[!] ctrl+c detected from user, quitting.\n\n ')
    except Exception as error_entry_point:
        output_logger.info(error_entry_point)
        sys.exit(1)
