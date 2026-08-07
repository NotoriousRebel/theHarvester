import ipaddress
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any, cast
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.staticfiles import StaticFiles

from theHarvester import __main__, __version__
from theHarvester.lib import stash
from theHarvester.lib.api.additional_endpoints import router as additional_router
from theHarvester.lib.api.auth import get_api_key
from theHarvester.lib.api.rate_limit import API_RATE_LIMIT, limiter
from theHarvester.lib.api.wayfinder import is_public_target, start_worker, stop_worker
from theHarvester.lib.api.wayfinder import router as wayfinder_router
from theHarvester.lib.api.wayfinder import ui_router as wayfinder_ui_router
from theHarvester.lib.completed_result import CompletedResult, ResultKind
from theHarvester.lib.enumeration import EnumerationOptions
from theHarvester.lib.recursive_dns import DEFAULT_RECURSIVE_DNS_QUERY_LIMIT
from theHarvester.lib.source_catalog import ActivityClass, get_source_spec

logger = logging.getLogger(__name__)


# Define Pydantic models for request and response validation
class QueryResultItem(BaseModel):
    type: ResultKind
    value: str
    sources: list[str] = Field(default_factory=list)


class QueryResponse(BaseModel):
    asns: list[str] = Field(default_factory=list, description='List of ASNs')
    interesting_urls: list[str] = Field(default_factory=list, description='List of interesting URLs')
    twitter_people: list[str] = Field(default_factory=list, description='List of Twitter people')
    linkedin_people: list[dict] = Field(default_factory=list, description='List of LinkedIn people')
    linkedin_links: list[str] = Field(default_factory=list, description='List of LinkedIn links')
    trello_urls: list[str] = Field(default_factory=list, description='List of discovered URLs (legacy field name)')
    ips: list[str] = Field(default_factory=list, description='List of IPs')
    emails: list[str] = Field(default_factory=list, description='List of emails')
    hosts: list[str] = Field(default_factory=list, description='List of hosts')
    breaches: list[str] = Field(default_factory=list, description='List of breach names')
    run_id: UUID | None = Field(None, description='Completed run identifier when terminal evidence was requested')
    status: str | None = Field(None, description='Completed evidence status when terminal evidence was requested')
    results: list[QueryResultItem] = Field(default_factory=list, description='Typed terminal evidence')
    source_executions: list[dict[str, object]] = Field(default_factory=list, description='Per-source execution outcomes')


class ErrorResponse(BaseModel):
    detail: str = Field(..., description='Error message')
    error_type: str | None = Field(None, description='Type of error')
    traceback: str | None = Field(None, description='Error traceback')


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    await start_worker()
    try:
        yield
    finally:
        await stop_worker()


app = FastAPI(
    title='Restful Harvest',
    description='Rest API for theHarvester powered by FastAPI',
    version=__version__,
    docs_url='/docs',
    redoc_url='/redoc',
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore

app.add_middleware(
    cast('Any', CORSMiddleware),
    allow_origins=[],
    allow_credentials=False,
    allow_methods=['GET', 'POST'],
    allow_headers=['Content-Type', 'X-API-Key'],
)

# Include additional endpoints
app.include_router(additional_router, prefix='/additional', tags=['Additional APIs'])
app.include_router(wayfinder_ui_router)
app.include_router(wayfinder_router)

# This is where we will host files that arise if the user specifies a filename
try:
    app.mount('/static', StaticFiles(directory='theHarvester/lib/api/static/'), name='static')
except RuntimeError:
    static_path = os.path.expanduser('~/.local/share/theHarvester/static/')
    if not os.path.isdir(static_path):
        os.makedirs(static_path)
        app.mount(
            '/static',
            StaticFiles(directory=static_path),
            name='static',
        )


# Define Pydantic model for bot response
class BotResponse(BaseModel):
    bot: str = Field(..., description='Bot message')


@app.get('/nicebot', response_model=BotResponse)
async def bot() -> Response:
    """Easter egg endpoint for bots.

    Returns a Star Wars reference when accessed.
    """
    return JSONResponse({'bot': 'These are not the droids you are looking for'})


# Define Pydantic model for sources response
class SourcesResponse(BaseModel):
    sources: list[str] = Field(..., description='List of supported data sources')


class CompletedRunSummary(BaseModel):
    run_id: UUID
    target: str
    started_at: datetime
    completed_at: datetime
    result_count: int


class CompletedResultItem(BaseModel):
    type: ResultKind
    value: str


class CompletedRunDetail(CompletedRunSummary):
    results: list[CompletedResultItem]


@app.get(
    '/sources',
    response_model=SourcesResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def getsources(request: Request) -> Response:
    """Endpoint to query for available sources theHarvester supports.

    Returns a list of all supported data sources that can be used with the query endpoint.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    try:
        sources = __main__.Core.get_supportedengines()
        return JSONResponse({'sources': sources})
    except Exception as e:
        logger.exception('Error in getsources endpoint')

        return JSONResponse(
            {
                'detail': 'An error occurred while retrieving sources',
                'error_type': type(e).__name__,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@app.get(
    '/runs',
    response_model=list[CompletedRunSummary],
    responses={status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse}},
)
@limiter.limit(API_RATE_LIMIT)
async def list_runs(
    request: Request,
    _api_key: Annotated[str, Depends(get_api_key)],
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> list[dict[str, object]]:
    """List recently completed enumeration runs."""
    manager = stash.StashManager()
    await manager.do_init()
    return await manager.list_completed_results(limit=limit)


@app.get(
    '/runs/{run_id}',
    response_model=CompletedRunDetail,
    responses={
        status.HTTP_404_NOT_FOUND: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def get_run(
    request: Request,
    run_id: UUID,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> dict[str, object]:
    """Retrieve one completed enumeration run with its normalized evidence."""
    manager = stash.StashManager()
    await manager.do_init()
    try:
        result = await manager.load_completed_result(run_id)
    except LookupError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Completed run not found') from error
    return {
        'run_id': str(result.run_id),
        'target': result.target,
        'started_at': result.started_at.isoformat(),
        'completed_at': result.completed_at.isoformat(),
        'result_count': len(result.results),
        'results': [{'type': kind, 'value': value} for kind, value in result.results],
    }


# Define Pydantic model for DNS brute force response
class DnsBruteResponse(BaseModel):
    dns_bruteforce: list[str] = Field(default_factory=list, description='List of DNS brute force results')


@app.get(
    '/dnsbrute',
    response_model=DnsBruteResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def dnsbrute(
    request: Request,
    domain: Annotated[str, Query(min_length=3, description='Domain to be brute forced')],
    user_agent: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header(alias='X-API-Key')] = None,
    dns_resolve: Annotated[
        str, Query(description='Perform DNS resolution on subdomains with a resolver list or passed in resolvers')
    ] = '',
) -> Response:
    """Endpoint for DNS brute forcing.

    This endpoint performs DNS brute force on the specified domain and returns the results.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        get_api_key(request, x_api_key)
        # Validate domain
        if not domain or len(domain) < 3:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Domain must be at least 3 characters long')

        # Call the main function with the provided parameters
        dns_bruteforce = await __main__.start(
            EnumerationOptions(
                dns_brute=True,
                domain=domain,
                source='',
                dns_resolve=dns_resolve,
            ),
            return_dns_brute_result=True,
        )

        return JSONResponse({'dns_bruteforce': dns_bruteforce})

    except HTTPException as e:
        # Re-raise HTTP exceptions
        raise e
    except Exception as e:
        logger.exception('Error in dnsbrute endpoint')

        return JSONResponse(
            {
                'detail': 'An error occurred while processing your request',
                'error_type': type(e).__name__,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@app.get(
    '/query',
    response_model=QueryResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def query(
    request: Request,
    source: Annotated[
        list[str],
        Query(description='Data sources or capability selectors to query; repeated values form a union'),
    ],
    domain: Annotated[str, Query(min_length=3, description='Domain to be harvested')],
    dns_server: Annotated[str, Query(description='DNS server to use for lookup')] = '',
    user_agent: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header(alias='X-API-Key')] = None,
    dns_brute: Annotated[bool, Query(description='Perform a DNS brute force on the domain')] = False,
    dns_lookup: Annotated[bool, Query(description='Enable DNS server lookup')] = False,
    dns_resolve: Annotated[
        str, Query(description='Perform DNS resolution on subdomains with a resolver list or passed in resolvers')
    ] = '',
    dns_recursive_depth: Annotated[
        int, Query(ge=0, description='Recursively discover DNS names beneath currently addressable parents')
    ] = 0,
    dns_recursive_query_limit: Annotated[
        int, Query(gt=0, description='Maximum DNS record queries across resolver vantages')
    ] = DEFAULT_RECURSIVE_DNS_QUERY_LIMIT,
    dns_recursive_runtime_seconds: Annotated[
        float, Query(gt=0, allow_inf_nan=False, description='Maximum runtime in seconds for recursive DNS discovery')
    ] = 60.0,
    filename: Annotated[str, Query(description='Save the results to an XML and JSON file')] = '',
    proxies: Annotated[bool, Query(description='Use proxies for requests')] = False,
    shodan: Annotated[bool, Query(description='Use Shodan to query discovered hosts')] = False,
    take_over: Annotated[bool, Query(description='Check for takeovers')] = False,
    wordlist: Annotated[str, Query(description='Specify a wordlist for API endpoint scanning')] = '',
    api_scan: Annotated[bool, Query(description='Scan for API endpoints')] = False,
    limit: Annotated[int, Query(description='Limit the number of search results')] = 500,
    start: Annotated[int, Query(description='Start with result number X')] = 0,
) -> Response:
    """Query function that allows user to query theHarvester rest API.

    This endpoint performs searches using the specified data sources and returns the results.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate sources
        selected_sources = __main__.Core.expand_source_selection(','.join(source))
        supported_engines = __main__.Core.get_supportedengines()
        for selected_source in selected_sources:
            if selected_source not in supported_engines:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Source '{selected_source}' is not supported. Supported sources: {', '.join(supported_engines)}",
                )

        source_activities = {get_source_spec(selected_source).activity for selected_source in selected_sources}
        credentialed_source = any(
            source_name in selected_sources and bool((key_getter() or '').strip())
            for source_name, key_getter in (
                ('dehashed', __main__.Core.dehashed_key),
                ('hibpverified', __main__.Core.hibpverified_key),
                ('leaklookup', __main__.Core.leaklookup_key),
            )
        )
        requires_operator_auth = credentialed_source or any(
            (
                dns_brute,
                dns_lookup,
                bool(dns_resolve),
                dns_recursive_depth > 0,
                take_over,
                api_scan,
                any(activity is not ActivityClass.PASSIVE for activity in source_activities),
            )
        )
        if requires_operator_auth:
            get_api_key(request, x_api_key)

        if dns_recursive_depth > 0:
            try:
                recursive_resolvers = {
                    str(ipaddress.ip_address(value.strip())) for value in dns_resolve.split(',') if value.strip()
                }
            except ValueError as error:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='recursive DNS requires exactly three distinct resolver IPs',
                ) from error
            if len(recursive_resolvers) != 3:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='recursive DNS requires exactly three distinct resolver IPs',
                )

        has_direct_activity = ActivityClass.DIRECT in source_activities or take_over or api_scan
        if has_direct_activity and not await is_public_target(domain.strip().rstrip('.')):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='P2 direct interaction requires a publicly routable target',
            )

        # Call the main function with the provided parameters
        full_execution = any((dns_brute, dns_lookup, dns_recursive_depth > 0, shodan, take_over, api_scan))
        options = EnumerationOptions(
            dns_brute=dns_brute,
            dns_lookup=dns_lookup,
            dns_server=dns_server,
            domain=domain,
            filename=filename,
            limit=limit,
            proxies=proxies,
            shodan=shodan,
            source=','.join(selected_sources),
            start=start,
            take_over=take_over,
            wordlist=wordlist,
            api_scan=api_scan,
            dns_resolve=dns_resolve,
            dns_recursive_depth=dns_recursive_depth,
            dns_recursive_query_limit=dns_recursive_query_limit,
            dns_recursive_runtime_seconds=dns_recursive_runtime_seconds,
        )
        if full_execution:
            *result, _completed_result = await __main__.start(
                options,
                persist_completed_result=True,
                include_breaches=True,
                return_completed_result=True,
            )
        else:
            result = await __main__.start(
                options,
                persist_completed_result=True,
                include_breaches=True,
            )
        (
            asns,
            iurls,
            twitter_people_list,
            linkedin_people_list,
            linkedin_links,
            aurls,
            aips,
            aemails,
            ahosts,
            abreaches,
        ) = result

        # Return the results using the Pydantic model
        response_payload = {
            'asns': asns,
            'interesting_urls': iurls,
            'twitter_people': twitter_people_list,
            'linkedin_people': linkedin_people_list,
            'linkedin_links': linkedin_links,
            'trello_urls': aurls,
            'ips': aips,
            'emails': aemails,
            'hosts': ahosts,
            'breaches': abreaches,
        }
        if full_execution and isinstance(_completed_result, CompletedResult):
            evidence = _completed_result.evidence_dict()
            response_payload.update(
                run_id=evidence['run_id'],
                status=evidence['status'],
                results=evidence['results'],
                source_executions=evidence['source_executions'],
            )
        return JSONResponse(response_payload)
    except HTTPException as e:
        # Re-raise HTTP exceptions
        raise e
    except Exception as e:
        logger.exception('Error in query endpoint')

        return JSONResponse(
            {
                'detail': 'An error occurred while processing your request',
                'error_type': type(e).__name__,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
