from theHarvester.lib.core import AsyncFetcher, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.run import SourceIncompleteError, SourceRateLimitedError


class SearchShodanCt:
    """Read names from Shodan's public Certificate Transparency mirror.

    Certificate records can reveal historical or unused names. They do not
    prove that a hostname currently resolves, so this passive source never
    labels a result as addressable. Current DNS validation remains the
    operator's separate, explicit ``-r`` choice. Wildcard certificate names
    are reduced to their concrete suffix and are not treated as wildcard DNS
    evidence.
    """

    def __init__(self, word: str) -> None:
        self.word = word.strip().lower().rstrip('.')
        self.hostnames: set[str] = set()
        self.proxy = False

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        response = await AsyncFetcher.fetch(
            url=f'https://ctl.shodan.io/api/v1/domain/{self.word}/hostnames',
            json=True,
            proxy=self.proxy,
            include_metadata=True,
        )
        if not isinstance(response, FetcherResponse):
            raise SourceIncompleteError('Shodan CT request failed')
        if response.status == 429:
            raise SourceRateLimitedError('Shodan CT rate limit reached')
        if not 200 <= response.status < 300:
            raise SourceIncompleteError('Shodan CT request failed')
        payload = response.body
        if not isinstance(payload, list):
            raise SourceIncompleteError('Shodan CT returned an incomplete response')
        malformed = not all(isinstance(candidate, str) for candidate in payload)
        for candidate in payload:
            if not isinstance(candidate, str):
                continue
            normalized = normalize_scoped_hostname(candidate.strip().removeprefix('*.'), self.word)
            if normalized is None or len(normalized) > 253 or not normalized.isascii():
                continue
            labels = normalized.split('.')
            if any(
                not label
                or len(label) > 63
                or not label[0].isalnum()
                or not label[-1].isalnum()
                or not all(character.isalnum() or character == '-' for character in label)
                for label in labels
            ):
                continue
            self.hostnames.add(normalized)
        if malformed:
            raise SourceIncompleteError(
                'Shodan CT returned malformed hostname data',
                findings=tuple(sorted(self.hostnames)),
            )

    async def get_hostnames(self) -> set[str]:
        return self.hostnames
