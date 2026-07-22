from __future__ import annotations

from theHarvester.lib.api.api import QueryResponse, app


def test_public_rest_routes_remain_available() -> None:
    routes = {(path, method.upper()) for path, operations in app.openapi()['paths'].items() for method in operations}
    expected = {
        ('/', 'GET'),
        ('/nicebot', 'GET'),
        ('/sources', 'GET'),
        ('/dnsbrute', 'GET'),
        ('/query', 'GET'),
        ('/additional/breaches', 'POST'),
        ('/additional/leaks', 'POST'),
        ('/additional/security-score', 'POST'),
        ('/additional/tech-stack', 'POST'),
        ('/additional/all', 'POST'),
    }

    assert expected <= routes


def test_query_response_fields_remain_compatible() -> None:
    required_fields = {
        'asns',
        'interesting_urls',
        'twitter_people',
        'linkedin_people',
        'linkedin_links',
        'trello_urls',
        'ips',
        'emails',
        'hosts',
    }

    assert required_fields <= set(QueryResponse.model_fields)
