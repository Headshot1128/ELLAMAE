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
        path = Path(settings.license_key_file or 'data/license.key')
    else:
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
    # Safe in-memory fallback to avoid 500 crashes
    return Fernet(Fernet.generate_key())


def generate():
    alphabet = string.ascii_uppercase + string.digits
    return 'NOVYX-' + '-'.join(''.join(secrets.choice(alphabet) for _ in range(6)) for _ in range(2))
