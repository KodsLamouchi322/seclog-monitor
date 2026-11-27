from datetime import datetime, timezone

import pytest

from app.alerting import MAX_WINDOW_MINUTES, evaluate, validate_rule

NOW = datetime(2026, 11, 30, 12, 0, tzinfo=timezone.utc)


def rule(**overrides):
    base = {"name": "Brute force", "type": "failed_logins_by_ip", "severity": "high", "window_minutes": 15,
            "params": {"threshold": 5}}
    base.update(overrides)
    return base


# ------------------------------------------------------------ validation
def test_regle_valide_avec_valeurs_par_defaut():
    clean = validate_rule({"name": "  Règle  ", "type": "sql_injection"})
    assert clean["name"] == "Règle"
    assert clean["severity"] == "medium" and clean["window_minutes"] == 15
    assert clean["cooldown_minutes"] == 15 and clean["enabled"] is True and clean["block_ip"] is False
    assert clean["params"] == {"threshold": 1}


def test_champs_inconnus_ignores():
    assert "evil" not in validate_rule({**rule(), "evil": "x"})


@pytest.mark.parametrize("bad,message", [
    ({"name": ""}, "nom"),
    ({"type": "inconnu"}, "Type de règle"),
    ({"severity": "extreme"}, "Gravité"),
    ({"window_minutes": 0}, "fenêtre"),
    ({"window_minutes": MAX_WINDOW_MINUTES + 1}, "fenêtre"),
    ({"window_minutes": True}, "fenêtre"),
    ({"params": {"threshold": 0}}, "seuil"),
    ({"params": {"threshold": "abc"}}, "seuil"),
    ({"enabled": "oui"}, "enabled"),
    ({"cooldown_minutes": -1}, "délai"),
])
def test_regle_invalide(bad, message):
    with pytest.raises(ValueError, match=f"(?i){message}"):
        validate_rule(rule(**bad))


def test_corps_non_json():
    with pytest.raises(ValueError):
        validate_rule("pas un objet")


def test_seuil_texte_numerique_accepte():
    assert validate_rule(rule(params={"threshold": "7"}))["params"]["threshold"] == 7


def test_blocage_ip_seulement_pour_les_regles_par_ip():
    assert validate_rule(rule(block_ip=True))["block_ip"] is True
    with pytest.raises(ValueError, match="blocage"):
        validate_rule({"name": "x", "type": "silent_host", "block_ip": True, "params": {"host": "fw-01"}})


def test_equipement_invalide():
    with pytest.raises(ValueError, match="équipement"):
        validate_rule({"name": "x", "type": "silent_host", "params": {"host": "a b; drop"}})


def test_pays_normalises_et_sans_doublon():
    params = {"allowed_countries": ["tn", " FR", "TN"]}
    clean = validate_rule({"name": "x", "type": "unauthorized_country", "params": params})
    assert clean["params"]["allowed_countries"] == ["TN", "FR"]


@pytest.mark.parametrize("countries", [[], ["FRA"], ["1A"], "TN"])
def test_pays_invalides(countries):
    with pytest.raises(ValueError):
        validate_rule({"name": "x", "type": "unauthorized_country", "params": {"allowed_countries": countries}})


# ------------------------------------------------------------ évaluation
class FakeEs:
    def __init__(self, response):
        self.response, self.calls = response, []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


def ip_buckets(*pairs):
    return {"hits": {"total": {"value": sum(c for _, c in pairs)}},
            "aggregations": {"by_ip": {"buckets": [{"key": k, "doc_count": c} for k, c in pairs]}}}


def test_echecs_de_connexion_par_ip():
    es = FakeEs(ip_buckets(("185.220.101.45", 12), ("10.0.0.9", 6)))
    result = evaluate(validate_rule(rule()), es, now=NOW)
    assert result["matched"] is True and result["total"] == 18
    assert result["findings"][0] == {"key": "185.220.101.45", "count": 12}
    query = es.calls[0]
    filters = query["query"]["bool"]["filter"]
    assert {"term": {"event.type": "authentication"}} in filters and {"term": {"result": "failure"}} in filters
    assert query["aggs"]["by_ip"]["terms"]["min_doc_count"] == 5
    assert query["size"] == 0
    window = filters[0]["range"]["@timestamp"]
    assert window["lte"] == NOW.isoformat() and window["gte"].startswith("2026-11-30T11:45")


def test_aucune_correspondance():
    result = evaluate(validate_rule(rule()), FakeEs(ip_buckets()), now=NOW)
    assert result == {"matched": False, "findings": [], "total": 0, "window_minutes": 15,
                      "evaluated_at": NOW.isoformat()}


def test_injection_sql():
    es = FakeEs(ip_buckets(("1.2.3.4", 3)))
    result = evaluate(validate_rule({"name": "x", "type": "sql_injection", "params": {"threshold": 2}}), es, now=NOW)
    assert result["matched"] is True
    assert {"term": {"event.action": "sql_injection_attempt"}} in es.calls[0]["query"]["bool"]["filter"]
    assert es.calls[0]["aggs"]["by_ip"]["terms"]["min_doc_count"] == 2


@pytest.mark.parametrize("total,matched", [(0, True), (4, False)])
def test_equipement_silencieux(total, matched):
    es = FakeEs({"hits": {"total": {"value": total}}})
    r = validate_rule({"name": "x", "type": "silent_host", "params": {"host": "fw-edge-01"}})
    result = evaluate(r, es, now=NOW)
    assert result["matched"] is matched
    assert {"match_phrase": {"host.name": "fw-edge-01"}} in es.calls[0]["query"]["bool"]["filter"]
    assert "aggs" not in es.calls[0]
    if matched:
        assert result["findings"][0]["detail"] == "aucun log reçu"


def test_pays_non_autorise():
    response = {"hits": {"total": {"value": 5}}, "aggregations": {"by_country": {"buckets": [
        {"key": "RU", "doc_count": 5, "users": {"buckets": [{"key": "alice"}, {"key": "bob"}]}}]}}}
    es = FakeEs(response)
    r = validate_rule({"name": "x", "type": "unauthorized_country", "params": {"allowed_countries": ["TN", "FR"]}})
    result = evaluate(r, es, now=NOW)
    assert result["findings"] == [{"key": "RU", "count": 5, "detail": "utilisateurs : alice, bob"}]
    bool_query = es.calls[0]["query"]["bool"]
    assert {"term": {"result": "success"}} in bool_query["filter"]
    assert bool_query["must_not"] == [{"terms": {"source.geo.country_iso_code": ["TN", "FR"]}}]
