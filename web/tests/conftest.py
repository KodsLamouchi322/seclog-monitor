import pytest

from app import create_app


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
