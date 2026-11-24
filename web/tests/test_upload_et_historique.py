import io
import json
from datetime import datetime

import pytest

HEADER = "timestamp,source_ip,event_type,result,severity\n"


class FakeCursor(list):
    def sort(self, *_a, **_k):
        return FakeCursor(reversed(self))

    def limit(self, n):
        return FakeCursor(self[:n])


class FakeCollection:
    def __init__(self):
        self.docs = []

    def insert_one(self, doc):
        doc = dict(doc)
        doc["_id"] = len(self.docs) + 1
        self.docs.append(doc)
        return type("R", (), {"inserted_id": doc["_id"]})()

    @staticmethod
    def _match(doc, query):
        for key, value in query.items():
            if isinstance(value, dict) and "$gte" in value:
                if not doc.get(key) or doc[key] < value["$gte"]:
                    return False
            elif doc.get(key) != value:
                return False
        return True

    def find_one(self, query):
        return next((d for d in self.docs if self._match(d, query)), None)

    def find(self, query=None):
        # comme MongoDB : chaque lecture renvoie des copies (le code appelant peut modifier les documents)
        return FakeCursor(dict(d) for d in self.docs if self._match(d, query or {}))


class FakeDb(dict):
    def __getitem__(self, name):
        return self.setdefault(name, FakeCollection())

    @property
    def files(self):
        return self["files"]


class FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def setex(self, key, _ttl, value):
        self.store[key] = value


@pytest.fixture
def db(monkeypatch):
    fake = FakeDb()
    for target in ("app.api.get_db", "app.upload.get_db"):
        monkeypatch.setattr(target, lambda: fake)
    return fake


# ---------------------------------------------------------------- import
def post_file(client, name, content):
    return client.post("/upload", data={"file": (io.BytesIO(content), name)}, content_type="multipart/form-data")


def test_upload_csv_accepte(make_client, db, tmp_path):
    client = make_client("analyste")
    client.application.config["UPLOAD_FOLDER"] = str(tmp_path)
    r = post_file(client, "logs.csv", (HEADER + "t,1.1.1.1,authentication,failure,high\n").encode())
    assert r.status_code == 201
    body = r.get_json()
    assert body["status"] == "pending" and body["total_lines"] == 1
    assert len(list(tmp_path.iterdir())) == 1
    assert db.files.docs[0]["original_name"] == "logs.csv"


def test_upload_tableau_json_converti_en_ndjson(make_client, db, tmp_path):
    client = make_client("analyste")
    client.application.config["UPLOAD_FOLDER"] = str(tmp_path)
    r = post_file(client, "logs.json", json.dumps([{"a": 1}, {"b": 2}]).encode())
    assert r.status_code == 201
    saved = next(tmp_path.iterdir()).read_text().splitlines()
    assert [json.loads(line) for line in saved] == [{"a": 1}, {"b": 2}]


@pytest.mark.parametrize("name,content,message", [
    ("logs.pdf", b"x", "Format non autorisé"),
    ("logs.csv", b"timestamp,source_ip\n1,2\n", "Colonnes manquantes"),
])
def test_upload_refuse_les_fichiers_invalides(make_client, db, tmp_path, name, content, message):
    client = make_client("analyste")
    client.application.config["UPLOAD_FOLDER"] = str(tmp_path)
    r = post_file(client, name, content)
    assert r.status_code == 400
    assert message in r.get_json()["error"]
    assert list(tmp_path.iterdir()) == []


def test_upload_sans_fichier(make_client, db):
    assert make_client("analyste").post("/upload").status_code == 400


# ------------------------------------------------------------ historique
def run_search(monkeypatch, total=5):
    monkeypatch.setattr("app.api.run_search", lambda es, params: {"total": total, "took_ms": 3, "results": []})
    monkeypatch.setattr("app.api.get_es", lambda: None)
    monkeypatch.setattr("app.cache.get_redis", FakeRedis)


def test_historique_enregistre_une_fois_meme_avec_le_cache(make_client, db, monkeypatch):
    run_search(monkeypatch)
    fake_redis = FakeRedis()
    monkeypatch.setattr("app.cache.get_redis", lambda: fake_redis)
    client = make_client("lecteur")
    first = client.get("/api/v1/logs?severity=high")
    second = client.get("/api/v1/logs?severity=high")
    assert first.headers["X-Cache"] == "MISS" and second.headers["X-Cache"] == "HIT"
    entries = db["search_history"].docs
    assert len(entries) == 1
    assert entries[0]["user"] == "test" and entries[0]["criteria"] == {"severity": "high"}
    assert isinstance(entries[0]["at"], datetime)


def test_historique_ignore_la_pagination_et_les_recherches_vides(make_client, db, monkeypatch):
    run_search(monkeypatch)
    client = make_client("lecteur")
    client.get("/api/v1/logs?page=2&size=50")
    client.get("/api/v1/logs?severity=high&page=1")
    client.get("/api/v1/logs?severity=high&page=2")
    assert len(db["search_history"].docs) == 1


def test_historique_distingue_les_recherches(make_client, db, monkeypatch):
    run_search(monkeypatch)
    client = make_client("lecteur")
    client.get("/api/v1/logs?severity=high")
    client.get("/api/v1/logs?severity=low")
    assert len(db["search_history"].docs) == 2


def test_historique_visible_par_son_auteur_seulement(make_client, db, monkeypatch):
    run_search(monkeypatch)
    col = db["search_history"]
    col.insert_one({"user": "test", "criteria": {"q": "a"}, "total": 1, "took_ms": 1, "at": datetime(2026, 1, 1)})
    col.insert_one({"user": "autre", "criteria": {"q": "b"}, "total": 2, "took_ms": 1, "at": datetime(2026, 1, 2)})
    mine = make_client("lecteur").get("/api/v1/searches").get_json()["results"]
    assert [r["criteria"] for r in mine] == [{"q": "a"}]
    everyone = make_client("admin").get("/api/v1/searches").get_json()["results"]
    assert len(everyone) == 2


# ------------------------------------------------------ en-têtes de sécurité
def test_en_tetes_de_securite(make_client):
    r = make_client("lecteur").get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert r.headers["Referrer-Policy"] == "same-origin"
    assert r.headers["Cache-Control"] == "no-store"


def test_pas_de_no_store_sur_les_fichiers_statiques(make_client):
    r = make_client().get("/static/css/app.css")
    assert "no-store" not in r.headers.get("Cache-Control", "")
