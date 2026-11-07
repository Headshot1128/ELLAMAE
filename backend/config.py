import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database: str = 'data/auth.db'
    storage: str = 'data/private'
    access_seconds: int = 300
    session_seconds: int = 86400
    require_https: bool = False
    registration: bool = False
    rate_limit: int = 30
    license_key_file: str | None = None
    owner_username: str = 'slights'

    @classmethod
    def environment(cls):
        db_url = os.getenv('DATABASE_URL') or os.getenv('AUTH_DATABASE', 'data/auth.db')
        return cls(database=db_url,
                   storage=os.getenv('AUTH_STORAGE', 'data/private'),
                   require_https=os.getenv('AUTH_REQUIRE_HTTPS', 'false').lower() == 'true',
                   registration=os.getenv('AUTH_REGISTRATION', 'false') == 'true',
                   license_key_file=os.getenv('AUTH_LICENSE_KEY_FILE'),
                   owner_username=os.getenv('AUTH_OWNER_USERNAME', 'slights').lower())


def prepare(settings):
    if not settings.database.startswith(('postgres://', 'postgresql://')):
        Path(settings.database).parent.mkdir(parents=True, exist_ok=True)
    Path(settings.storage).mkdir(parents=True, exist_ok=True)
