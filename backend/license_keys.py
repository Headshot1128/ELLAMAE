"""Recoverable administrator-only license display; lookup still uses token hashes."""
import os
import secrets
import string
from pathlib import Path
from cryptography.fernet import Fernet


def cipher(settings, create=False):
    env_key = os.getenv('AUTH_LICENSE_ENCRYPTION_KEY') or os.getenv('FERNET_KEY')
    if env_key:
        return Fernet(env_key.encode() if isinstance(env_key, str) else env_key)

    db_str = getattr(settings, 'database', '')
    if db_str.startswith(('postgres://', 'postgresql://')):
        try:
            import psycopg2
            url = db_str
            if url.startswith('postgres://'):
                url = 'postgresql://' + url[len('postgres://'):]
            with psycopg2.connect(url) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT value FROM variables WHERE name='__sys_license_encryption_key__' LIMIT 1")
                    row = cur.fetchone()
                    if row and row[0]:
                        return Fernet(row[0].encode())
                    new_key = Fernet.generate_key().decode()
                    cur.execute("INSERT INTO variables(id, name, user_id, value, permission, application_id) VALUES('__sys_key__', '__sys_license_encryption_key__', NULL, %s, 'admin', '00000000-0000-4000-8000-000000000001') ON CONFLICT (id) DO UPDATE SET value=EXCLUDED.value", (new_key,))
                    conn.commit()
                    return Fernet(new_key.encode())
        except Exception:
            pass

    path = Path(settings.license_key_file or (db_str + '.license-key'))
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(Fernet.generate_key())
        except (FileExistsError, OSError):
            pass

    if path.exists():
        return Fernet(path.read_bytes().strip())
    return Fernet(Fernet.generate_key())


def generate():
    alphabet = string.ascii_uppercase + string.digits
    return 'NOVYX-' + '-'.join(''.join(secrets.choice(alphabet) for _ in range(6)) for _ in range(2))
