import datetime
import json
import logging
import os
from collections.abc import Iterable
from sqlite3.dbapi2 import Row

import aiosqlite

from theHarvester.lib.dns_validation import Addressability, DnsValidationObservation
from theHarvester.lib.run import (
    ActivityClass,
    Derivation,
    DiscoveryObservation,
    ExecutionStatus,
    MergedEntity,
    ResultRecord,
    RunExecution,
    RunResult,
    ScopeClass,
)

logger = logging.getLogger(__name__)


db_path = os.path.expanduser('~/.local/share/theHarvester')

if not os.path.isdir(db_path):
    os.makedirs(db_path)


class StashManager:
    def __init__(self) -> None:
        self.db = os.path.join(db_path, 'stash.sqlite')
        self.results = ''
        self.totalresults = ''
        self.latestscandomain: dict = {}
        self.domainscanhistory: list = []
        self.scanboarddata: dict = {}
        self.scanstats: list = []
        self.latestscanresults: list = []
        self.previousscanresults: list = []

    @staticmethod
    def _col0_int(row: Row | None) -> int:
        try:
            val = row[0] if row is not None else None
            return int(val) if val is not None else 0
        except Exception:
            return 0

    @staticmethod
    def _col0_value(row: Row | None):
        return row[0] if row is not None else None

    async def do_init(self) -> None:
        async with aiosqlite.connect(self.db) as db:
            await db.executescript(
                """
                CREATE TABLE IF NOT EXISTS results (
                    domain TEXT, resource TEXT, type TEXT, find_date DATE, source TEXT
                );
                CREATE TABLE IF NOT EXISTS enumeration_runs (
                    run_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    status TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS run_executions (
                    run_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    activity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    duration_ms REAL NOT NULL,
                    result_count INTEGER NOT NULL,
                    observation_count INTEGER NOT NULL,
                    entity_count INTEGER NOT NULL,
                    error_type TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    PRIMARY KEY (run_id, position),
                    FOREIGN KEY (run_id) REFERENCES enumeration_runs(run_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS run_results (
                    run_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    sources TEXT NOT NULL,
                    PRIMARY KEY (run_id, position),
                    FOREIGN KEY (run_id) REFERENCES enumeration_runs(run_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS run_observations (
                    run_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT NOT NULL,
                    derivation TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    scope_class TEXT NOT NULL,
                    PRIMARY KEY (run_id, position),
                    FOREIGN KEY (run_id) REFERENCES enumeration_runs(run_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS run_entities (
                    run_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    value TEXT NOT NULL,
                    addressability TEXT,
                    PRIMARY KEY (run_id, position),
                    FOREIGN KEY (run_id) REFERENCES enumeration_runs(run_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS run_dns_validations (
                    run_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    candidate TEXT,
                    query_name TEXT NOT NULL,
                    resolver TEXT NOT NULL,
                    queried_at TEXT NOT NULL,
                    ipv4 TEXT NOT NULL,
                    ipv6 TEXT NOT NULL,
                    cnames TEXT NOT NULL,
                    rcode TEXT NOT NULL,
                    ttl INTEGER,
                    cname_chain TEXT NOT NULL,
                    latency_ms REAL NOT NULL,
                    error TEXT,
                    is_wildcard_control INTEGER NOT NULL,
                    wildcard_depth TEXT,
                    PRIMARY KEY (run_id, position),
                    FOREIGN KEY (run_id) REFERENCES enumeration_runs(run_id) ON DELETE CASCADE
                );
                """
            )
            await db.commit()

    async def store_run(
        self,
        run: RunResult,
        *,
        legacy_results: Iterable[tuple[str, Iterable[object], str, str]] = (),
    ) -> None:
        """Persist one completed run and its legacy rows in one transaction."""
        if run.completed_at is None:
            raise ValueError('cannot persist an incomplete run')
        async with aiosqlite.connect(self.db, timeout=30) as db:
            await db.execute('PRAGMA foreign_keys = ON')
            await db.execute(
                'INSERT INTO enumeration_runs VALUES (?, ?, ?, ?, ?)',
                (run.run_id, run.target, run.started_at.isoformat(), run.completed_at.isoformat(), run.status),
            )
            for domain, resources, result_type, source in legacy_results:
                if result_type == 'people':
                    continue
                await db.executemany(
                    'INSERT INTO results (domain, resource, type, find_date, source) VALUES (?, ?, ?, ?, ?)',
                    [(domain, resource, result_type, datetime.date.today(), source) for resource in resources],
                )
            await db.executemany(
                'INSERT INTO run_executions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    (
                        run.run_id,
                        position,
                        execution.name,
                        execution.activity,
                        execution.status,
                        execution.duration_ms,
                        execution.result_count,
                        execution.observation_count,
                        execution.entity_count,
                        execution.error_type,
                        execution.started_at.isoformat() if execution.started_at else None,
                        execution.completed_at.isoformat() if execution.completed_at else None,
                    )
                    for position, execution in enumerate(run.executions)
                ],
            )
            await db.executemany(
                'INSERT INTO run_results VALUES (?, ?, ?, ?, ?)',
                [
                    (run.run_id, position, result.type, result.value, json.dumps(result.sources))
                    for position, result in enumerate(run.results)
                ],
            )
            await db.executemany(
                'INSERT INTO run_observations VALUES (?, ?, ?, ?, ?, ?, ?)',
                [
                    (
                        run.run_id,
                        position,
                        observation.value,
                        observation.source,
                        observation.derivation,
                        observation.collected_at.isoformat(),
                        observation.scope_class,
                    )
                    for position, observation in enumerate(run.observations)
                ],
            )
            await db.executemany(
                'INSERT INTO run_entities VALUES (?, ?, ?, ?)',
                [(run.run_id, position, entity.value, entity.addressability) for position, entity in enumerate(run.entities)],
            )
            await db.executemany(
                'INSERT INTO run_dns_validations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    (
                        run.run_id,
                        position,
                        observation.candidate,
                        observation.query_name,
                        observation.resolver,
                        observation.queried_at.isoformat(),
                        json.dumps(observation.ipv4),
                        json.dumps(observation.ipv6),
                        json.dumps(observation.cnames),
                        observation.rcode,
                        observation.ttl,
                        json.dumps(observation.cname_chain),
                        observation.latency_ms,
                        observation.error,
                        observation.is_wildcard_control,
                        observation.wildcard_depth,
                    )
                    for position, observation in enumerate(run.dns_validations)
                ],
            )
            await db.commit()

    async def load_run(self, run_id: str) -> RunResult | None:
        """Load one completed run from the structured run tables."""
        async with aiosqlite.connect(self.db, timeout=30) as db:
            run_cursor = await db.execute(
                'SELECT target, started_at, completed_at FROM enumeration_runs WHERE run_id = ?',
                (run_id,),
            )
            run_row = await run_cursor.fetchone()
            if run_row is None:
                return None
            executions = await (
                await db.execute(
                    'SELECT name, activity, status, duration_ms, result_count, observation_count, entity_count, '
                    'error_type, started_at, completed_at FROM run_executions WHERE run_id = ? ORDER BY position',
                    (run_id,),
                )
            ).fetchall()
            results = await (
                await db.execute(
                    'SELECT type, value, sources FROM run_results WHERE run_id = ? ORDER BY position',
                    (run_id,),
                )
            ).fetchall()
            observations = await (
                await db.execute(
                    'SELECT value, source, derivation, collected_at, scope_class FROM run_observations '
                    'WHERE run_id = ? ORDER BY position',
                    (run_id,),
                )
            ).fetchall()
            entities = await (
                await db.execute(
                    'SELECT value, addressability FROM run_entities WHERE run_id = ? ORDER BY position',
                    (run_id,),
                )
            ).fetchall()
            validations = await (
                await db.execute(
                    'SELECT candidate, query_name, resolver, queried_at, ipv4, ipv6, cnames, rcode, ttl, '
                    'cname_chain, latency_ms, error, is_wildcard_control, wildcard_depth '
                    'FROM run_dns_validations WHERE run_id = ? ORDER BY position',
                    (run_id,),
                )
            ).fetchall()

        loaded_observations = tuple(
            DiscoveryObservation(
                value=row[0],
                source=row[1],
                derivation=Derivation(row[2]),
                collected_at=datetime.datetime.fromisoformat(row[3]),
                scope_class=ScopeClass(row[4]),
            )
            for row in observations
        )
        return RunResult(
            run_id=run_id,
            target=run_row[0],
            started_at=datetime.datetime.fromisoformat(run_row[1]),
            completed_at=datetime.datetime.fromisoformat(run_row[2]),
            executions=tuple(
                RunExecution(
                    name=row[0],
                    activity=ActivityClass(row[1]),
                    status=ExecutionStatus(row[2]),
                    duration_ms=row[3],
                    result_count=row[4],
                    observation_count=row[5],
                    entity_count=row[6],
                    error_type=row[7],
                    started_at=datetime.datetime.fromisoformat(row[8]) if row[8] else None,
                    completed_at=datetime.datetime.fromisoformat(row[9]) if row[9] else None,
                )
                for row in executions
            ),
            results=tuple(ResultRecord(row[0], row[1], tuple(json.loads(row[2]))) for row in results),
            observations=loaded_observations,
            entities=tuple(
                MergedEntity(
                    row[0],
                    tuple(observation for observation in loaded_observations if observation.value == row[0]),
                    Addressability(row[1]) if row[1] else None,
                )
                for row in entities
            ),
            dns_validations=tuple(
                DnsValidationObservation(
                    run_id=run_id,
                    candidate=row[0],
                    query_name=row[1],
                    resolver=row[2],
                    queried_at=datetime.datetime.fromisoformat(row[3]),
                    ipv4=tuple(json.loads(row[4])),
                    ipv6=tuple(json.loads(row[5])),
                    cnames=tuple(json.loads(row[6])),
                    rcode=row[7],
                    ttl=row[8],
                    cname_chain=tuple(json.loads(row[9])),
                    latency_ms=row[10],
                    error=row[11],
                    is_wildcard_control=bool(row[12]),
                    wildcard_depth=row[13],
                )
                for row in validations
            ),
        )

    async def store(self, domain, resource, res_type, source) -> None:
        self.domain = domain
        self.resource = resource
        self.type = res_type
        self.source = source
        self.date = datetime.date.today()
        try:
            async with aiosqlite.connect(self.db, timeout=30) as db:
                await db.execute(
                    'INSERT INTO results (domain,resource, type, find_date, source) VALUES (?,?,?,?,?)',
                    (self.domain, self.resource, self.type, self.date, self.source),
                )
                await db.commit()
        except Exception as e:
            logger.info(f'Unexpected error while storing result: {e}')

    async def store_all(self, domain, all, res_type, source) -> None:
        # people are not stored in the database
        if res_type == 'people':
            return

        self.domain = domain
        self.all = all
        self.type = res_type
        self.source = source
        self.date = datetime.date.today()
        master_list = [(self.domain, x, self.type, self.date, self.source) for x in self.all]
        async with aiosqlite.connect(self.db, timeout=30) as db:
            try:
                await db.executemany(
                    'INSERT INTO results (domain,resource, type, find_date, source) VALUES (?,?,?,?,?)',
                    master_list,
                )
                await db.commit()
            except Exception as e:
                logger.info(f'Unexpected error while storing result: {e}')

    async def generatedashboardcode(self, domain):
        try:
            # TODO refactor into generic method
            self.latestscandomain['domain'] = domain
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="host"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['host'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="email"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['email'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="ip"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['ip'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="vhost"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['vhost'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="shodan"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['shodan'] = self._col0_int(data)
                cursor = await conn.execute("""SELECT MAX(find_date) FROM results WHERE domain=?""", (domain,))
                data = await cursor.fetchone()
                self.latestscandomain['latestdate'] = self._col0_value(data)
                latestdate = self._col0_value(data)
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="host"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailshost = await cursor.fetchall()
                self.latestscandomain['scandetailshost'] = scandetailshost
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="email"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsemail = await cursor.fetchall()
                self.latestscandomain['scandetailsemail'] = scandetailsemail
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="ip"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsip = await cursor.fetchall()
                self.latestscandomain['scandetailsip'] = scandetailsip
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="vhost"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsvhost = await cursor.fetchall()
                self.latestscandomain['scandetailsvhost'] = scandetailsvhost
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="shodan"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsshodan = await cursor.fetchall()
                self.latestscandomain['scandetailsshodan'] = scandetailsshodan
            return self.latestscandomain
        except Exception as e:
            logger.info(f'Unexpected error while generating the dashboard code: {e}')

    async def getlatestscanresults(self, domain, previousday: bool = False) -> Iterable[Row | str] | None:
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                if previousday:
                    try:
                        cursor = await conn.execute(
                            """
                        SELECT DISTINCT(find_date)
                        FROM results
                        WHERE find_date=date('now', '-1 day') and domain=?""",
                            (domain,),
                        )
                        previousscandate = await cursor.fetchone()
                        prev_date = self._col0_value(previousscandate)
                        if not prev_date:  # When theHarvester runs first time/day, this query will return.
                            self.previousscanresults = [
                                'No results',
                                'No results',
                                'No results',
                                'No results',
                                'No results',
                            ]
                        else:
                            cursor = await conn.execute(
                                """
                            SELECT find_date, domain, source, type, resource
                            FROM results
                            WHERE find_date=? and domain=?
                            ORDER BY source,type
                            """,
                                (
                                    prev_date,
                                    domain,
                                ),
                            )
                            results = await cursor.fetchall()
                            self.previousscanresults = list(results)
                        return self.previousscanresults
                    except Exception as e:
                        logger.info(f'Error in getting the previous scan results from the database: {e}')
                else:
                    try:
                        cursor = await conn.execute(
                            """SELECT MAX(find_date) FROM results WHERE domain=?""",
                            (domain,),
                        )
                        latestscandate = await cursor.fetchone()
                        latest_date = self._col0_value(latestscandate)
                        cursor = await conn.execute(
                            """
                        SELECT find_date, domain, source, type, resource
                        FROM results
                        WHERE find_date=? and domain=?
                        ORDER BY source,type
                        """,
                            (
                                latest_date,
                                domain,
                            ),
                        )
                        results = await cursor.fetchall()
                        self.latestscanresults = list(results)
                        return self.latestscanresults
                    except Exception as e:
                        logger.info(f'Error in getting the latest scan results from the database: {e}')
        except Exception as e:
            logger.info(f'Error connecting to theHarvester database: {e}')
        return self.latestscanresults

    async def getscanboarddata(self):
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="host"''')
                data = await cursor.fetchone()
                self.scanboarddata['host'] = self._col0_int(data)
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="email"''')
                data = await cursor.fetchone()
                self.scanboarddata['email'] = self._col0_int(data)
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="ip"''')
                data = await cursor.fetchone()
                self.scanboarddata['ip'] = self._col0_int(data)
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="vhost"''')
                data = await cursor.fetchone()
                self.scanboarddata['vhost'] = self._col0_int(data)
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="shodan"''')
                data = await cursor.fetchone()
                self.scanboarddata['shodan'] = self._col0_int(data)
                cursor = await conn.execute("""SELECT COUNT(DISTINCT(domain)) FROM results """)
                data = await cursor.fetchone()
                self.scanboarddata['domains'] = self._col0_int(data)
            return self.scanboarddata
        except Exception as e:
            logger.info(f'Unexpected error while getting the scanboard data: {e}')

    async def getscanhistorydomain(self, domain):
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                cursor = await conn.execute(
                    """SELECT DISTINCT(find_date) FROM results WHERE domain=?""",
                    (domain,),
                )
                dates = await cursor.fetchall()
                for date in dates:
                    cursor = await conn.execute(
                        """SELECT COUNT(*) from results WHERE domain=? AND type="host" AND find_date=?""",
                        (domain, date[0]),
                    )
                    counthost = await cursor.fetchone()
                    cursor = await conn.execute(
                        """SELECT COUNT(*) from results WHERE domain=? AND type="email" AND find_date=?""",
                        (domain, date[0]),
                    )
                    countemail = await cursor.fetchone()
                    cursor = await conn.execute(
                        """SELECT COUNT(*) from results WHERE domain=? AND type="ip" AND find_date=?""",
                        (domain, date[0]),
                    )
                    countip = await cursor.fetchone()
                    cursor = await conn.execute(
                        """SELECT COUNT(*) from results WHERE domain=? AND type="vhost" AND find_date=?""",
                        (domain, date[0]),
                    )
                    countvhost = await cursor.fetchone()
                    cursor = await conn.execute(
                        """SELECT COUNT(*) from results WHERE domain=? AND type="shodan" AND find_date=?""",
                        (domain, date[0]),
                    )
                    countshodan = await cursor.fetchone()
                    results = {
                        'date': str(date[0]),
                        'hosts': str(self._col0_int(counthost)),
                        'email': str(self._col0_int(countemail)),
                        'ip': str(self._col0_int(countip)),
                        'vhost': str(self._col0_int(countvhost)),
                        'shodan': str(self._col0_int(countshodan)),
                    }
                    self.domainscanhistory.append(results)
            return self.domainscanhistory
        except Exception as e:
            logger.info(f'Unexpected error while getting the scanhistory of a domain: {e}')

    async def getpluginscanstatistics(self) -> Iterable[Row] | None:
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                cursor = await conn.execute(
                    """
                SELECT domain,find_date, type, source, count(*)
                FROM results
                GROUP BY domain, find_date, type, source
                """
                )
                results = await cursor.fetchall()
                self.scanstats = list(results)
        except Exception as e:
            logger.info(f'Unexpected error while getting a plugins scanstatistics: {e}')
        return self.scanstats

    async def latestscanchartdata(self, domain):
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                self.latestscandomain['domain'] = domain
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="host"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['host'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="email"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['email'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="ip"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['ip'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="vhost"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['vhost'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="shodan"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['shodan'] = self._col0_int(data)
                cursor = await conn.execute("""SELECT MAX(find_date) FROM results WHERE domain=?""", (domain,))
                data = await cursor.fetchone()
                self.latestscandomain['latestdate'] = self._col0_value(data)
                latestdate = self._col0_value(data)
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="host"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailshost = await cursor.fetchall()
                self.latestscandomain['scandetailshost'] = scandetailshost
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="email"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsemail = await cursor.fetchall()
                self.latestscandomain['scandetailsemail'] = scandetailsemail
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="ip"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsip = await cursor.fetchall()
                self.latestscandomain['scandetailsip'] = scandetailsip
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="vhost"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsvhost = await cursor.fetchall()
                self.latestscandomain['scandetailsvhost'] = scandetailsvhost
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="shodan"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsshodan = await cursor.fetchall()
                self.latestscandomain['scandetailsshodan'] = scandetailsshodan
            return self.latestscandomain
        except aiosqlite.Error as db_err:
            logger.info(f"Database error occurred for domain '{domain}': {db_err}")
        except Exception as e:
            logger.info(f"Unexpected error in latestscanchartdata for domain '{domain}': {e}")
