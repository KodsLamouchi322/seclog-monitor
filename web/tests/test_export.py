import pytest
from elasticsearch import TransportError

HIT = {"_source": {
    "@timestamp": "2026-11-12T10:00:00.000Z", "event": {"type": "authentication", "action": "login"},
    "result": "failure", "severity": "high",
    "source": {"ip": "185.220.101.45", "port": 4444, "geo": {"country_name": "Russia", "city_name": "Moscow"}},
    "user": {"name": "admin", "role": "admin"}, "host": {"name": "web-01"},
    "message": "=HYPERLINK(\"http://evil.example\")", "tags": ["brute_force", "off_hours"]}}


class FakeEs:
    def __init__(self, total=1, error=None):
        self.total, self.error, self.calls = total, error, []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return {"hits": {"total": {"value": self.total}, "hits": [HIT]}}


@pytest.fixture
def export(make_client, monkeypatch):
    def _export(es, role="lecteur", query=""):
        monkeypatch.setattr("app.api.get_es", lambda: es)
        return make_client(role).get("/api/v1/logs/export" + query)
    return _export


def test_export_csv_contenu(export):
    es = FakeEs()
    r = export(es, query="?severity=high&ip=185.220.101.45")
    assert r.status_code == 200
    assert r.mimetype == "text/csv"
    assert "attachment" in r.headers["Content-Disposition"]
    text = r.get_data(as_text=True)
    assert text.startswith("\ufeff")
    lines = text.lstrip("\ufeff").splitlines()
    assert lines[0].startswith("timestamp,type,action,result,severity,ip")
    assert "185.220.101.45" in lines[1]
    assert "brute_force|off_hours" in lines[1]


def test_export_neutralise_les_formules(export):
    text = export(FakeEs()).get_data(as_text=True)
    assert "'=HYPERLINK" in text


def test_export_reprend_les_filtres(export):
    es = FakeEs()
    export(es, query="?severity=high&ip=185.220.101.45")
    filters = es.calls[0]["query"]["bool"]["filter"]
    assert {"term": {"severity": "high"}} in filters
    assert {"term": {"source.ip": "185.220.101.45"}} in filters
    assert es.calls[0]["size"] == 10000


def test_export_signale_la_troncature(export):
    assert export(FakeEs(total=25000)).headers.get("X-Export-Truncated") == "true"
    assert "X-Export-Truncated" not in export(FakeEs(total=5)).headers


def test_export_es_indisponible(export):
    r = export(FakeEs(error=TransportError("down")))
    assert r.status_code == 503


def test_export_exige_une_connexion(make_client):
    assert make_client().get("/api/v1/logs/export").status_code == 401
