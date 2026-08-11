import sqlite3, json, time
from contextlib import contextmanager
from pathlib import Path

SCHEMA = r'''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS customers(
 id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,name TEXT,consent INTEGER NOT NULL DEFAULT 0,
 stripe_customer_id TEXT UNIQUE,subscription_id TEXT UNIQUE,subscription_status TEXT,tier TEXT DEFAULT 'community',
 created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS leads(
 id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,name TEXT,source TEXT,campaign TEXT,consent INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS suppressions(email TEXT PRIMARY KEY,reason TEXT NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS webhook_events(provider TEXT NOT NULL,event_id TEXT NOT NULL,status TEXT NOT NULL,payload TEXT,created_at INTEGER NOT NULL,PRIMARY KEY(provider,event_id));
CREATE TABLE IF NOT EXISTS entitlements(customer_id INTEGER NOT NULL,feature TEXT NOT NULL,active INTEGER NOT NULL,updated_at INTEGER NOT NULL,PRIMARY KEY(customer_id,feature),FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS licenses(
 id INTEGER PRIMARY KEY AUTOINCREMENT,customer_id INTEGER NOT NULL,activation_key_hash TEXT UNIQUE NOT NULL,installation_id TEXT,
 tier TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,expires_at INTEGER,created_at INTEGER NOT NULL,
 FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS jobs(
 id INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'queued',attempts INTEGER NOT NULL DEFAULT 0,
 run_after INTEGER NOT NULL,last_error TEXT,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS marketing_events(
 id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT,event TEXT NOT NULL,source TEXT,campaign TEXT,metadata TEXT,created_at INTEGER NOT NULL
);
'''

class DB:
    def __init__(self,path:Path): self.path=Path(path)
    @contextmanager
    def conn(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        c=sqlite3.connect(self.path,timeout=15,isolation_level=None)
        c.row_factory=sqlite3.Row
        c.execute('PRAGMA journal_mode=WAL'); c.execute('PRAGMA foreign_keys=ON'); c.execute('PRAGMA busy_timeout=5000')
        try: yield c
        finally: c.close()
    def init(self):
        with self.conn() as c: c.executescript(SCHEMA)
    def now(self): return int(time.time())
    def add_lead(self,email,name=None,source=None,campaign=None,consent=False):
        n=self.now()
        with self.conn() as c:
            c.execute('''INSERT INTO leads(email,name,source,campaign,consent,created_at,updated_at) VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(email) DO UPDATE SET name=COALESCE(excluded.name,name),source=COALESCE(excluded.source,source),campaign=COALESCE(excluded.campaign,campaign),consent=MAX(consent,excluded.consent),updated_at=excluded.updated_at''',(email.lower(),name,source,campaign,int(consent),n,n))
            c.execute('INSERT INTO marketing_events(email,event,source,campaign,metadata,created_at) VALUES(?,?,?,?,?,?)',(email.lower(),'lead_captured',source,campaign,'{}',n))
    def suppress(self,email,reason):
        with self.conn() as c: c.execute('INSERT OR REPLACE INTO suppressions(email,reason,created_at) VALUES(?,?,?)',(email.lower(),reason,self.now()))
    def is_suppressed(self,email):
        with self.conn() as c: return bool(c.execute('SELECT 1 FROM suppressions WHERE email=?',(email.lower(),)).fetchone())
    def claim_event(self,provider,event_id,payload):
        with self.conn() as c:
            try: c.execute('INSERT INTO webhook_events(provider,event_id,status,payload,created_at) VALUES(?,?,?,?,?)',(provider,event_id,'processing',json.dumps(payload),self.now())); return True
            except sqlite3.IntegrityError: return False
    def finish_event(self,provider,event_id,status='done'):
        with self.conn() as c: c.execute('UPDATE webhook_events SET status=? WHERE provider=? AND event_id=?',(status,provider,event_id))
    def queue(self,kind,payload,delay=0):
        n=self.now()
        with self.conn() as c: c.execute('INSERT INTO jobs(kind,payload,status,attempts,run_after,created_at,updated_at) VALUES(?,?,\'queued\',0,?,?,?)',(kind,json.dumps(payload),n+delay,n,n))
    def metrics(self):
        with self.conn() as c:
            return {k:c.execute(q).fetchone()[0] for k,q in {
                'leads':'SELECT COUNT(*) FROM leads','customers':'SELECT COUNT(*) FROM customers','active_subscriptions':"SELECT COUNT(*) FROM customers WHERE subscription_status IN ('active','trialing')",'suppressed':'SELECT COUNT(*) FROM suppressions','queued_jobs':"SELECT COUNT(*) FROM jobs WHERE status='queued'"}.items()}
