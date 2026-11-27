import importlib.util
from pathlib import Path

import pytest
from fakes import FakeDb

RULE = {"name": "Brute force", "type": "failed_logins_by_ip", "severity": "high", "window_minutes": 15,
        "block_ip": True, "params": {"threshold": 5}}


class FakeEs:
    def __init__(self, error=None):
        self.error, self.calls = error, []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return {"hits": {"total": {"value": 6}},
                "aggregations": {"by_ip": {"buckets": [{"key": "1.2.3.4", "doc_count": 6}]}}}


@pytest.fixture
def env(make_client, monkeypatch):
    db, es = FakeDb(), FakeEs()
    monkeypatch.setattr("app.rules.get_db", lambda: db)
    monkeypatch.setattr("app.rules.get_es", lambda: es)

    def _client(role):
        return make_client(role)
    return _client, db, es


def test_types_et_liste_ouverts_a_tous_les_roles(env):
    client, db, _ = env
    reader = client("lecteur")
    types = reader.get("/api/v1/rules/types").get_json()
    assert {t["id"] for t in types["types"]} == {"failed_logins_by_ip", "sql_injection", "silent_host",
                                                 "unauthorized_country"}
    assert reader.get("/api/v1/rules").get_json() == {"results": []}


@pytest.mark.parametrize("role", ["lecteur", "analyste"])
def test_ecriture_reservee_aux_admins(env, role):
    client, db, es = env
    c = client(role)
    assert c.post("/api/v1/rules", json=RULE).status_code == 403
    assert c.put("/api/v1/rules/abc", json=RULE).status_code == 403
    assert c.patch("/api/v1/rules/abc", json={"enabled": False}).status_code == 403
    assert c.delete("/api/v1/rules/abc").status_code == 403
    assert c.post("/api/v1/rules/test", json=RULE).status_code == 403
    assert db["alert_rules"].docs == [] and es.calls == []


def test_visiteur_non_connecte(env):
    client, _, _ = env
    assert client(None).get("/api/v1/rules").status_code == 401


def test_creation_puis_lecture(env):
    client, db, _ = env
    admin = client("admin")
    r = admin.post("/api/v1/rules", json=RULE)
    assert r.status_code == 201
    created = r.get_json()
    assert created["name"] == "Brute force" and created["created_by"] == "test" and created["id"]
    listed = admin.get("/api/v1/rules").get_json()["results"]
    assert [x["id"] for x in listed] == [created["id"]]
    assert listed[0]["params"] == {"threshold": 5} and listed[0]["enabled"] is True


def test_creation_invalide(env):
    client, db, _ = env
    r = client("admin").post("/api/v1/rules", json={**RULE, "type": "inconnu"})
    assert r.status_code == 400 and "Type de règle" in r.get_json()["error"]
    assert db["alert_rules"].docs == []


def test_modification(env):
    client, _, _ = env
    admin = client("admin")
    rule_id = admin.post("/api/v1/rules", json=RULE).get_json()["id"]
    r = admin.put(f"/api/v1/rules/{rule_id}", json={**RULE, "name": "Renommée", "severity": "critical"})
    assert r.status_code == 200
    assert r.get_json()["name"] == "Renommée" and r.get_json()["severity"] == "critical"


def test_activation_et_desactivation(env):
    client, _, _ = env
    admin = client("admin")
    rule_id = admin.post("/api/v1/rules", json=RULE).get_json()["id"]
    assert admin.patch(f"/api/v1/rules/{rule_id}", json={"enabled": False}).get_json()["enabled"] is False
    assert admin.patch(f"/api/v1/rules/{rule_id}", json={"enabled": "non"}).status_code == 400


def test_suppression(env):
    client, db, _ = env
    admin = client("admin")
    rule_id = admin.post("/api/v1/rules", json=RULE).get_json()["id"]
    assert admin.delete(f"/api/v1/rules/{rule_id}").status_code == 200
    assert admin.delete(f"/api/v1/rules/{rule_id}").status_code == 404
    assert db["alert_rules"].docs == []


@pytest.mark.parametrize("method", ["put", "patch", "delete"])
def test_identifiant_inconnu_ou_invalide(env, method):
    client, _, _ = env
    admin = client("admin")
    for rule_id in ("pas-un-id", "64b64b64b64b64b64b64b64b"):
        kwargs = {} if method == "delete" else {"json": {**RULE, "enabled": True}}
        r = getattr(admin, method)(f"/api/v1/rules/{rule_id}", **kwargs)
        assert r.status_code == 404


def test_test_de_regle_sans_effet_de_bord(env):
    client, db, es = env
    r = client("admin").post("/api/v1/rules/test", json=RULE)
    assert r.status_code == 200
    body = r.get_json()
    assert body["matched"] is True and body["findings"] == [{"key": "1.2.3.4", "count": 6}]
    assert db["alert_rules"].docs == []  # rien n'est enregistré


def test_test_de_regle_es_indisponible(env):
    from elasticsearch import TransportError
    client, _, es = env
    es.error = TransportError("down")
    assert client("admin").post("/api/v1/rules/test", json=RULE).status_code == 503


def test_page_regles_selon_le_role(make_client):
    admin_html = make_client("admin").get("/rules").get_data(as_text=True)
    assert 'id="new-rule"' in admin_html and 'data-admin="true"' in admin_html
    reader_html = make_client("lecteur").get("/rules").get_data(as_text=True)
    assert 'id="new-rule"' not in reader_html and 'data-admin="false"' in reader_html
    assert "réservée aux administrateurs" in reader_html


def test_script_de_regles_de_demonstration():
    script = Path(__file__).parents[2] / "scripts" / "seed_rules.py"
    spec = importlib.util.spec_from_file_location("seed_rules", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    db = FakeDb()
    first = module.seed(db)
    assert [status for _, status in first] == ["créée"] * 4
    assert [status for _, status in module.seed(db)] == ["déjà présente"] * 4
    types = {r["type"] for r in db["alert_rules"].docs}
    assert types == {"failed_logins_by_ip", "sql_injection", "silent_host", "unauthorized_country"}
