import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from app import create_app

# Modules qui appellent Redis : limiteur de débit, liste noire, sessions et cache.
REDIS_USERS = ("app.cache.get_redis", "app.ratelimit.get_redis", "app.auth.get_redis", "app.sessions.get_redis")


@pytest.fixture(autouse=True)
def no_real_redis(monkeypatch):
    """Les tests ne touchent jamais un vrai Redis (même présent dans le conteneur) : sans cela, le limiteur de
    débit (60 requêtes par minute) répond 429 au bout de quelques dizaines de tests. Le code gère déjà un Redis
    indisponible ; un test qui a besoin d'un Redis le remplace lui-même (voir FakeRedis dans fakes.py)."""
    def unavailable():
        raise RedisConnectionError("Redis désactivé pendant les tests")
    for target in REDIS_USERS:
        monkeypatch.setattr(target, unavailable)


@pytest.fixture
def make_client(monkeypatch):
    """Client de test connecté avec un rôle donné (None = visiteur anonyme), sans Redis."""
    def _make(role=None):
        session = {"username": "test", "role": role} if role else None
        monkeypatch.setattr("app.access.load_session", lambda: session)
        app = create_app()
        app.config["TESTING"] = True
        return app.test_client()
    return _make
