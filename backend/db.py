import sqlite3
from fastapi import HTTPException
from contextlib import contextmanager
from pathlib import Path


def is_postgres(settings):
    db_uri = getattr(settings, 'database', '')
    return db_uri.startswith(('postgres://', 'postgresql://'))


def _prepare_sql(sql: str) -> str:
    stripped = sql.strip().upper()
    if stripped.startswith('PRAGMA FOREIGN_KEYS') or stripped.startswith('PRAGMA JOURNAL_MODE'):
        return 'SELECT 1'
    if stripped.startswith('PRAGMA TABLE_INFO('):
        table = sql.strip().split('(')[1].split(')')[0].strip("'\" ")
        return f"SELECT 0, column_name FROM information_schema.columns WHERE table_name = '{table}'"
    if stripped.startswith('BEGIN IMMEDIATE'):
        return 'SELECT 1'

    if 'INSERT OR IGNORE INTO' in sql:
        sql = sql.replace('INSERT OR IGNORE INTO', 'INSERT INTO')
        if 'ON CONFLICT' not in sql:
            sql = sql + ' ON CONFLICT DO NOTHING'

    if 'INSERT OR REPLACE INTO rate_limits' in sql:
        return 'INSERT INTO rate_limits (bucket, window_start, count) VALUES (%s, %s, 1) ON CONFLICT (bucket) DO UPDATE SET window_start=EXCLUDED.window_start, count=1'

    if 'INSERT OR REPLACE INTO reseller_profiles' in sql:
        return 'INSERT INTO reseller_profiles (user_id, max_days) VALUES (%s, %s) ON CONFLICT (user_id) DO UPDATE SET max_days=EXCLUDED.max_days'

    parts = []
    in_quote = False
    quote_char = None
    for char in sql:
        if char in ("'", '"'):
            if not in_quote:
                in_quote = True
                quote_char = char
            elif quote_char == char:
                in_quote = False
                quote_char = None
            parts.append(char)
        elif char == '?' and not in_quote:
            parts.append('%s')
        else:
            parts.append(char)
    return ''.join(parts)


class PgConnectionWrapper:
    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=None):
        from psycopg2.extras import DictCursor
        cur = self._conn.cursor(cursor_factory=DictCursor)
        pg_sql = _prepare_sql(sql)
        if params is not None:
            cur.execute(pg_sql, params)
        else:
            cur.execute(pg_sql)
        return cur

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


@contextmanager
def connect(settings):
    if is_postgres(settings):
        import psycopg2
        url = settings.database
        if url.startswith('postgres://'):
            url = 'postgresql://' + url[len('postgres://'):]
        conn = psycopg2.connect(url)
        db = PgConnectionWrapper(conn)
        try:
            yield db
            db.commit()
        except HTTPException:
            db.commit()
            raise
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
    else:
        db = sqlite3.connect(settings.database, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except HTTPException:
            db.commit()
            raise
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()


def migrate(settings):
    if is_postgres(settings):
        with connect(settings) as db:
            db.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS users(
                id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active', role TEXT NOT NULL DEFAULT 'user',
                subscription_until BIGINT NOT NULL DEFAULT 0, password_until BIGINT,
                created_at BIGINT NOT NULL, console_only INTEGER NOT NULL DEFAULT 0,
                web_approved INTEGER NOT NULL DEFAULT 0, frozen_at BIGINT,
                application_id TEXT DEFAULT '00000000-0000-4000-8000-000000000001', hardware_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS sessions(
                id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                audience TEXT NOT NULL, expires_at BIGINT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, hardware_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS access_tokens(
                hash TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, expires_at BIGINT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens(
                hash TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS permissions(
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, permission TEXT NOT NULL, PRIMARY KEY(user_id, permission)
            );
            CREATE TABLE IF NOT EXISTS applications(
                id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at BIGINT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reseller_profiles(
                user_id TEXT PRIMARY KEY, max_days INTEGER NOT NULL DEFAULT 30
            );
            CREATE TABLE IF NOT EXISTS licenses(
                id TEXT PRIMARY KEY, key_hash TEXT UNIQUE NOT NULL, expires_at BIGINT NOT NULL,
                permission TEXT NOT NULL, hardware_bound INTEGER NOT NULL DEFAULT 1, hardware_hash TEXT,
                user_id TEXT REFERENCES users(id) ON DELETE SET NULL, revoked INTEGER NOT NULL DEFAULT 0,
                key_ciphertext TEXT, frozen_at BIGINT,
                application_id TEXT DEFAULT '00000000-0000-4000-8000-000000000001', reseller_id TEXT
            );
            CREATE TABLE IF NOT EXISTS variables(
                id TEXT PRIMARY KEY, name TEXT NOT NULL, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
                value TEXT NOT NULL, permission TEXT NOT NULL,
                application_id TEXT DEFAULT '00000000-0000-4000-8000-000000000001'
            );
            CREATE TABLE IF NOT EXISTS files(
                id TEXT PRIMARY KEY, storage_name TEXT NOT NULL UNIQUE, permission TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1, max_bytes BIGINT NOT NULL,
                application_id TEXT DEFAULT '00000000-0000-4000-8000-000000000001', file_data BYTEA
            );
            CREATE TABLE IF NOT EXISTS audit_logs(
                id SERIAL PRIMARY KEY, timestamp BIGINT NOT NULL, actor_id TEXT, event TEXT NOT NULL, target TEXT, outcome TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rate_limits(
                bucket TEXT PRIMARY KEY, window_start BIGINT NOT NULL, count INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS active_heartbeats(
                user_id TEXT PRIMARY KEY, last_seen BIGINT NOT NULL, session_id TEXT, username TEXT
            );
            INSERT INTO applications(id, name, status, created_at)
            VALUES('00000000-0000-4000-8000-000000000001', 'Default application', 'active', 0)
            ON CONFLICT (id) DO NOTHING;
            """)
        return

    with sqlite3.connect(settings.database) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE IF NOT EXISTS active_heartbeats(user_id TEXT PRIMARY KEY, last_seen BIGINT NOT NULL, session_id TEXT, username TEXT)')
        db.execute('CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY)')
        if not db.execute('SELECT 1 FROM schema_migrations WHERE version=1').fetchone():
            sql = (Path(__file__).parent / 'migrations/001_initial.sql').read_text()
            db.executescript('BEGIN IMMEDIATE;\n' + sql + '\nCOMMIT;')
        if not db.execute('SELECT 1 FROM schema_migrations WHERE version=2').fetchone():
            sql = (Path(__file__).parent / 'migrations/002_console_accounts.sql').read_text()
            db.executescript('BEGIN IMMEDIATE;\n' + sql + '\nCOMMIT;')
        if not db.execute('SELECT 1 FROM schema_migrations WHERE version=3').fetchone():
            sql = (Path(__file__).parent / 'migrations/003_visible_license_keys.sql').read_text()
            db.executescript('BEGIN IMMEDIATE;\n' + sql + '\nCOMMIT;')
        if not db.execute('SELECT 1 FROM schema_migrations WHERE version=4').fetchone():
            sql = (Path(__file__).parent / 'migrations/004_website_approval.sql').read_text()
            db.executescript('BEGIN IMMEDIATE;\n' + sql + '\nCOMMIT;')
        if not db.execute('SELECT 1 FROM schema_migrations WHERE version=5').fetchone():
            sql = (Path(__file__).parent / 'migrations/005_license_freeze.sql').read_text()
            db.executescript('BEGIN IMMEDIATE;\n' + sql + '\nCOMMIT;')
        if not db.execute('SELECT 1 FROM schema_migrations WHERE version=6').fetchone():
            sql = (Path(__file__).parent / 'migrations/006_applications_resellers.sql').read_text()
            db.executescript('BEGIN IMMEDIATE;\n' + sql + '\nCOMMIT;')
        if not db.execute('SELECT 1 FROM schema_migrations WHERE version=7').fetchone():
            sql = (Path(__file__).parent / 'migrations/007_application_fields.sql').read_text()
            db.executescript('BEGIN IMMEDIATE;\n' + sql + '\nCOMMIT;')
