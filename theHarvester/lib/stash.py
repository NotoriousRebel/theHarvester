import aiosqlite
import datetime


class StashManager:

    def __init__(self):
        self.db = "stash.sqlite"
        self.results = ""
        self.totalresults = ""
        self.latestscandomain = {}
        self.domainscanhistory = []
        self.scanboarddata = {}
        self.scanstats = []
        self.latestscanresults = []
        self.previousscanresults = []

    async def do_init(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute(
                'CREATE TABLE IF NOT EXISTS results (domain text, resource text, type text, find_date date, source text)')
            await db.commit()

    async def store(self, domain, resource, res_type, source):
        self.domain = domain
        self.resource = resource
        self.type = res_type
        self.source = source
        self.date = datetime.date.today()
        try:
            async with aiosqlite.connect(self.db, timeout=30) as db:
                await db.execute('INSERT INTO results (domain,resource, type, find_date, source) VALUES (?,?,?,?,?)',
                                 (self.domain, self.resource, self.type, self.date, self.source))
                await db.commit()
        except Exception as e:
            print(e)

    async def store_all(self, domain, all, res_type, source):
        self.domain = domain
        self.all = all
        self.type = res_type
        self.source = source
        self.date = datetime.date.today()
        master_list = [(self.domain, x, self.type, self.date, self.source) for x in self.all]
        async with aiosqlite.connect(self.db, timeout=30) as db:
            try:
                await db.executemany('INSERT INTO results (domain,resource, type, find_date, source) VALUES (?,?,?,?,?)',
                                     master_list)
                await db.commit()
            except Exception as e:
                print(e)

    async def generatedashboardcode(self, domain):
        try:
            # TODO refactor into generic method
            self.latestscandomain["domain"] = domain
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="host"''',
                                            (domain,))
                data = await cursor.fetchone()
                self.latestscandomain["host"] = data[0]
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="email"''',
                                            (domain,))
                data = await cursor.fetchone()
                self.latestscandomain["email"] = data[0]
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="ip"''', (domain,))
                data = await cursor.fetchone()
                self.latestscandomain["ip"] = data[0]
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="vhost"''',
                                            (domain,))
                data = await cursor.fetchone()
                self.latestscandomain["vhost"] = data[0]
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="shodan"''',
                                            (domain,))
                data = await cursor.fetchone()
                self.latestscandomain["shodan"] = data[0]
                cursor = await conn.execute('''SELECT MAX(find_date) FROM results WHERE domain=?''', (domain,))
                data = await cursor.fetchone()
                self.latestscandomain["latestdate"] = data[0]
                latestdate = data[0]
                cursor = await conn.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="host"''',
                                            (domain, latestdate,))
                scandetailshost = await cursor.fetchall()
                self.latestscandomain["scandetailshost"] = scandetailshost
                cursor = await conn.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="email"''',
                                            (domain, latestdate,))
                scandetailsemail = await cursor.fetchall()
                self.latestscandomain["scandetailsemail"] = scandetailsemail
                cursor = await conn.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="ip"''',
                                            (domain, latestdate,))
                scandetailsip = await cursor.fetchall()
                self.latestscandomain["scandetailsip"] = scandetailsip
                cursor = await conn.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="vhost"''',
                                            (domain, latestdate,))
                scandetailsvhost = await cursor.fetchall()
                self.latestscandomain["scandetailsvhost"] = scandetailsvhost
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="shodan"''',
                    (domain, latestdate,))
                scandetailsshodan = await cursor.fetchall()
                self.latestscandomain["scandetailsshodan"] = scandetailsshodan
            return self.latestscandomain
        except Exception as e:
            print(e)

    async def getlatestscanresults(self, domain, previousday=False):
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                if previousday:
                    try:
                        cursor = await conn.execute('''
                        SELECT DISTINCT(find_date)
                        FROM results
                        WHERE find_date=date('now', '-1 day') and domain=?''', (domain,))
                        previousscandate = await cursor.fetchone()
                        if not previousscandate:  # When theHarvester runs first time/day this query will return.
                            self.previousscanresults = ["No results", "No results", "No results", "No results",
                                                        "No results"]
                        else:
                            cursor = await conn.execute('''
                            SELECT find_date, domain, source, type, resource
                            FROM results
                            WHERE find_date=? and domain=?
                            ORDER BY source,type
                            ''', (previousscandate[0], domain,))
                            results = await cursor.fetchall()
                            self.previousscanresults = results
                        return self.previousscanresults
                    except Exception as e:
                        print(f'Error in getting the previous scan results from the database: {e}')
                else:
                    try:
                        cursor = await conn.execute('''SELECT MAX(find_date) FROM results WHERE domain=?''', (domain,))
                        latestscandate = await cursor.fetchone()
                        cursor = await conn.execute('''
                        SELECT find_date, domain, source, type, resource
                        FROM results
                        WHERE find_date=? and domain=?
                        ORDER BY source,type
                        ''', (latestscandate[0], domain,))
                        results = await cursor.fetchall()
                        self.latestscanresults = results
                        return self.latestscanresults
                    except Exception as e:
                        print(f'Error in getting the latest scan results from the database: {e}')
        except Exception as e:
            print(f'Error connecting to theHarvester database: {e}')

    async def getscanboarddata(self, domain=""):
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                if len(domain) != 0:
                    cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="host" and domain=?''',
                                                (domain,))
                else:
                    cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="host"''')
                data = await cursor.fetchone()
                self.scanboarddata["host"] = data[0]
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="email"''')
                data = await cursor.fetchone()
                self.scanboarddata["email"] = data[0]
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="ip"''')
                data = await cursor.fetchone()
                self.scanboarddata["ip"] = data[0]
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="vhost"''')
                data = await cursor.fetchone()
                self.scanboarddata["vhost"] = data[0]
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="shodan"''')
                data = await cursor.fetchone()
                self.scanboarddata["shodan"] = data[0]
                cursor = await conn.execute('''SELECT COUNT(DISTINCT(domain)) FROM results ''')
                data = await cursor.fetchone()
                self.scanboarddata["domains"] = data[0]
            return self.scanboarddata
        except Exception as e:
            print(e)

    async def getscanhistorydomain(self, domain):
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                cursor = await conn.execute('''SELECT DISTINCT(find_date) FROM results WHERE domain=?''', (domain,))
                dates = await cursor.fetchall()
                for date in dates:
                    cursor = await conn.execute(
                        '''SELECT COUNT(*) from results WHERE domain=? AND type="host" AND find_date=?''',
                        (domain, date[0]))
                    counthost = await cursor.fetchone()
                    cursor = await conn.execute(
                        '''SELECT COUNT(*) from results WHERE domain=? AND type="email" AND find_date=?''',
                        (domain, date[0]))
                    countemail = await cursor.fetchone()
                    cursor = await conn.execute(
                        '''SELECT COUNT(*) from results WHERE domain=? AND type="ip" AND find_date=?''',
                        (domain, date[0]))
                    countip = await cursor.fetchone()
                    cursor = await conn.execute(
                        '''SELECT COUNT(*) from results WHERE domain=? AND type="vhost" AND find_date=?''',
                        (domain, date[0]))
                    countvhost = await cursor.fetchone()
                    cursor = await conn.execute(
                        '''SELECT COUNT(*) from results WHERE domain=? AND type="shodan" AND find_date=?''',
                        (domain, date[0]))
                    countshodan = await cursor.fetchone()
                    results = {
                        "date": str(date[0]),
                        "hosts": str(counthost[0]),
                        "email": str(countemail[0]),
                        "ip": str(countip[0]),
                        "vhost": str(countvhost[0]),
                        "shodan": str(countshodan[0])
                    }
                    self.domainscanhistory.append(results)
            return self.domainscanhistory
        except Exception as e:
            print(e)

    async def getpluginscanstatistics(self, domain=""):
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                if len(domain) == 0:
                    cursor = await conn.execute('''
                    SELECT domain,find_date, type, source, count(*)
                    FROM results
                    GROUP BY domain, find_date, type, source
                    ''')
                    results = await cursor.fetchall()
                    self.scanstats = results
                else:
                    cursor = await conn.execute('''
                                       SELECT domain,find_date, type, source, count(*)
                                       FROM results WHERE domain=?
                                       GROUP BY domain, find_date, type, source
                                       ''', (domain,))
                    results = await cursor.fetchall()
                    self.scanstats = results

            return self.scanstats
        except Exception as e:
            print(e)

    async def latestscanchartdata(self, domain):
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                self.latestscandomain["domain"] = domain
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="host"''', (domain,))
                data = await cursor.fetchone()
                self.latestscandomain["host"] = data[0]
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="email"''', (domain,))
                data = await cursor.fetchone()
                self.latestscandomain["email"] = data[0]
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="ip"''', (domain,))
                data = await cursor.fetchone()
                self.latestscandomain["ip"] = data[0]
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="vhost"''', (domain,))
                data = await cursor.fetchone()
                self.latestscandomain["vhost"] = data[0]
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="shodan"''', (domain,))
                data = await cursor.fetchone()
                self.latestscandomain["shodan"] = data[0]
                cursor = await conn.execute('''SELECT MAX(find_date) FROM results WHERE domain=?''', (domain,))
                data = await cursor.fetchone()
                self.latestscandomain["latestdate"] = data[0]
                latestdate = data[0]
                cursor = await conn.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="host"''', (domain, latestdate,))
                scandetailshost = await cursor.fetchall()
                self.latestscandomain["scandetailshost"] = scandetailshost
                cursor = await conn.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="email"''', (domain, latestdate,))
                scandetailsemail = await cursor.fetchall()
                self.latestscandomain["scandetailsemail"] = scandetailsemail
                cursor = await conn.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="ip"''', (domain, latestdate,))
                scandetailsip = await cursor.fetchall()
                self.latestscandomain["scandetailsip"] = scandetailsip
                cursor = await conn.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="vhost"''', (domain, latestdate,))
                scandetailsvhost = await cursor.fetchall()
                self.latestscandomain["scandetailsvhost"] = scandetailsvhost
                cursor = await conn.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="shodan"''', (domain, latestdate,))
                scandetailsshodan = await cursor.fetchall()
                self.latestscandomain["scandetailsshodan"] = scandetailsshodan
            return self.latestscandomain
        except Exception as e:
            print(e)
