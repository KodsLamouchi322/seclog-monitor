from datetime import datetime, timedelta, timezone

import pytest
from elasticsearch import TransportError
from fakes import FakeDb, FakeRedis
from redis.exceptions import ConnectionError as RedisConnectionError

import app.alert_engine as engine
from app.alert_engine import ALERTS, RULES, is_blockable, parse_networks, run_cycle
from app.worker import touch_heartbeat

NOW = datetime(2026, 11, 30, 12, 0, tzinfo=timezone.utc)
PUBLIC_IP = "185.220.101.45"


class FakeEs:
    """Renvoie des correspondances par adresse IP ; peut échouer pour un type de règle donné."""
    def __init__(self, buckets=((PUBLIC_IP, 12),), fail_on=None):
        self.buckets, self.fail_on, self.calls = buckets, fail_on, []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail_on and any(self.fail_on in str(f) for f in kwargs["query"]["bool"]["filter"]):
            raise TransportError("down")
        return {"hits": {"total": {"value": sum(c for _, c in self.buckets)}},
                "aggregations": {"by_ip": {"buckets": [{"key": k, "doc_count": c} for k, c in self.buckets]}}}


class BrokenRedis:
    def setex(self, *_a, **_k):
        raise RedisConnectionError("down")


def add_rule(db, **overrides):
    rule = {"name": "Brute force", "type": "failed_logins_by_ip", "severity": "high", "window_minutes": 15,
            "cooldown_minutes": 15, "enabled": True, "block_ip": False, "params": {"threshold": 5}}
    rule.update(overrides)
    return db[RULES].insert_one(rule).inserted_id


def alerts(db):
    return db[ALERTS].docs


# ---------------------------------------------------------------- alertes
def test_une_alerte_par_correspondance():
    db, es = FakeDb(), FakeEs((("1.2.3.4", 8), ("5.6.7.8", 6)))
    rule_id = add_rule(db)
    summary = run_cycle(db, es, FakeRedis(), now=NOW)
    assert summary == {"rules": 1, "alerts": 2, "blocked": 0, "errors": 0}
    first = alerts(db)[0]
    assert first["rule_id"] == rule_id and first["rule_name"] == "Brute force"
    assert first["key"] == "1.2.3.4" and first["count"] == 8 and first["severity"] == "high"
    assert first["status"] == "open" and first["created_at"] == NOW and first["blocked"] is False


def test_regle_inactive_non_evaluee():
    db, es = FakeDb(), FakeEs()
    add_rule(db, enabled=False)
    assert run_cycle(db, es, FakeRedis(), now=NOW)["rules"] == 0
    assert es.calls == [] and alerts(db) == []


def test_pas_de_correspondance_pas_d_alerte():
    db = FakeDb()
    add_rule(db)
    assert run_cycle(db, FakeEs(buckets=()), FakeRedis(), now=NOW)["alerts"] == 0


def test_delai_entre_deux_alertes():
    db, es = FakeDb(), FakeEs()
    add_rule(db, cooldown_minutes=15)
    run_cycle(db, es, FakeRedis(), now=NOW)
    assert run_cycle(db, es, FakeRedis(), now=NOW + timedelta(minutes=5))["alerts"] == 0
    assert len(alerts(db)) == 1
    assert run_cycle(db, es, FakeRedis(), now=NOW + timedelta(minutes=16))["alerts"] == 1
    assert len(alerts(db)) == 2


def test_nouvelle_cle_pendant_le_delai_declenche_une_alerte():
    db = FakeDb()
    add_rule(db, cooldown_minutes=60)
    run_cycle(db, FakeEs((("1.2.3.4", 8),)), FakeRedis(), now=NOW)
    run_cycle(db, FakeEs((("1.2.3.4", 9), ("9.9.9.9", 7))), FakeRedis(), now=NOW + timedelta(minutes=1))
    assert [a["key"] for a in alerts(db)] == ["1.2.3.4", "9.9.9.9"]


def test_delai_nul_realerte_a_chaque_passe():
    db, es = FakeDb(), FakeEs()
    add_rule(db, cooldown_minutes=0)
    run_cycle(db, es, FakeRedis(), now=NOW)
    run_cycle(db, es, FakeRedis(), now=NOW + timedelta(seconds=60))
    assert len(alerts(db)) == 2


def test_regle_invalide_ignoree_les_autres_continuent():
    db, es = FakeDb(), FakeEs()
    add_rule(db, name="Cassée", severity="extreme")
    add_rule(db, name="Saine")
    summary = run_cycle(db, es, FakeRedis(), now=NOW)
    assert summary["errors"] == 1 and summary["alerts"] == 1
    assert alerts(db)[0]["rule_name"] == "Saine"


def test_erreur_elasticsearch_isolee_par_regle():
    db = FakeDb()
    add_rule(db, name="SQL", type="sql_injection", params={"threshold": 1})
    add_rule(db, name="Brute force")
    summary = run_cycle(db, FakeEs(fail_on="sql_injection_attempt"), FakeRedis(), now=NOW)
    assert summary["errors"] == 1 and summary["alerts"] == 1
    assert alerts(db)[0]["rule_name"] == "Brute force"


# ------------------------------------------------------- blocage d'adresses
def test_blocage_d_une_adresse_publique():
    db, redis = FakeDb(), FakeRedis()
    add_rule(db, block_ip=True)
    summary = run_cycle(db, FakeEs(), redis, now=NOW, block_ttl=900)
    assert summary["blocked"] == 1
    assert redis.store == {"seclog:blacklist:" + PUBLIC_IP: "1"}
    assert alerts(db)[0]["blocked"] is True


def test_regle_sans_blocage_ne_touche_pas_redis():
    db, redis = FakeDb(), FakeRedis()
    add_rule(db, block_ip=False)
    run_cycle(db, FakeEs(), redis, now=NOW)
    assert redis.store == {}


@pytest.mark.parametrize("ip", ["10.10.0.196", "192.168.1.5", "127.0.0.1", "172.18.0.1", "169.254.1.1"])
def test_adresses_internes_jamais_bloquees(ip):
    db, redis = FakeDb(), FakeRedis()
    add_rule(db, block_ip=True)
    summary = run_cycle(db, FakeEs(((ip, 10),)), redis, now=NOW)
    assert summary["alerts"] == 1 and summary["blocked"] == 0 and redis.store == {}
    assert alerts(db)[0]["block_note"] == "adresse interne ou réservée"


def test_liste_de_protection():
    db, redis = FakeDb(), FakeRedis()
    add_rule(db, block_ip=True)
    run_cycle(db, FakeEs(), redis, now=NOW, never_block=parse_networks("185.220.0.0/16"))
    assert redis.store == {} and "ALERT_NEVER_BLOCK" in alerts(db)[0]["block_note"]


def test_maximum_de_blocages_par_passe(monkeypatch):
    monkeypatch.setattr(engine, "MAX_BLOCKS_PER_CYCLE", 2)
    db, redis = FakeDb(), FakeRedis()
    add_rule(db, block_ip=True)
    ips = tuple((f"8.8.8.{n}", 9) for n in range(1, 5))
    summary = run_cycle(db, FakeEs(ips), redis, now=NOW)
    assert summary["alerts"] == 4 and summary["blocked"] == 2 and len(redis.store) == 2
    assert alerts(db)[3]["block_note"] == "maximum de blocages par cycle atteint"


def test_redis_indisponible_l_alerte_est_quand_meme_creee():
    db = FakeDb()
    add_rule(db, block_ip=True)
    summary = run_cycle(db, FakeEs(), BrokenRedis(), now=NOW)
    assert summary["alerts"] == 1 and summary["blocked"] == 0
    assert alerts(db)[0]["block_note"] == "Redis indisponible"


@pytest.mark.parametrize("ip,expected", [
    ("185.220.101.45", True), ("8.8.8.8", True), ("10.0.0.1", False), ("pas-une-ip", False), ("::1", False)])
def test_is_blockable(ip, expected):
    assert is_blockable(ip)[0] is expected


def test_parse_networks():
    assert [str(n) for n in parse_networks("1.2.3.4, 10.0.0.0/8 ,")] == ["1.2.3.4/32", "10.0.0.0/8"]
    assert parse_networks("") == []
    with pytest.raises(ValueError):
        parse_networks("n'importe quoi")


# ----------------------------------------------------------- API et worker
def test_api_alertes_lecture_et_filtre(make_client, monkeypatch):
    db = FakeDb()
    rule_id = add_rule(db)
    monkeypatch.setattr("app.rules.get_db", lambda: db)
    run_cycle(db, FakeEs((("1.2.3.4", 8), ("5.6.7.8", 6))), FakeRedis(), now=NOW)
    db[ALERTS].docs[0]["status"] = "resolved"
    client = make_client("lecteur")
    everything = client.get("/api/v1/alerts").get_json()["results"]
    assert [a["key"] for a in everything] == ["5.6.7.8", "1.2.3.4"]  # la plus récente d'abord
    assert everything[0]["rule_id"] == str(rule_id) and everything[0]["created_at"].startswith("2026-11-30")
    assert [a["key"] for a in client.get("/api/v1/alerts?status=open").get_json()["results"]] == ["5.6.7.8"]


def test_api_alertes_parametres_invalides(make_client, monkeypatch):
    monkeypatch.setattr("app.rules.get_db", lambda: FakeDb())
    client = make_client("lecteur")
    assert client.get("/api/v1/alerts?status=nimporte").status_code == 400
    assert client.get("/api/v1/alerts?size=abc").status_code == 400
    assert client.get("/api/v1/alerts?size=500").status_code == 200
    assert make_client().get("/api/v1/alerts").status_code == 401


def test_battement_de_coeur_du_worker(tmp_path):
    path = tmp_path / "hb"
    touch_heartbeat(path)
    assert int(path.read_text()) > 0


def test_worker_survit_a_une_erreur_et_s_arrete_proprement(monkeypatch, tmp_path):
    import signal

    import app.worker as worker

    handlers, calls = {}, []

    class FakeEvent:  # attente instantanée : le test n'attend pas l'intervalle de 60 s
        def __init__(self):
            self.flag = False

        def set(self):
            self.flag = True

        def is_set(self):
            return self.flag

        def wait(self, _timeout=None):
            return self.flag

    def fake_cycle(*_a, **_k):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("panne ponctuelle")
        handlers[signal.SIGTERM](None, None)  # arrêt demandé pendant la 2e passe
        return {"rules": 0, "alerts": 0, "blocked": 0, "errors": 0}

    monkeypatch.setattr(worker.signal, "signal", lambda sig, fn: handlers.__setitem__(sig, fn))
    monkeypatch.setattr(worker.threading, "Event", FakeEvent)
    monkeypatch.setattr(worker, "run_cycle", fake_cycle)
    for name in ("get_db", "get_es", "get_redis"):
        monkeypatch.setattr(worker, name, lambda: None)
    monkeypatch.setattr(worker, "HEARTBEAT", tmp_path / "hb")
    monkeypatch.setenv("ALERT_NEVER_BLOCK", "203.0.113.7")
    worker.main()
    assert len(calls) == 2  # l'erreur de la 1re passe n'a pas arrêté le worker
    assert int((tmp_path / "hb").read_text()) > 0


def test_worker_refuse_une_liste_de_protection_invalide(monkeypatch):
    import app.worker as worker
    monkeypatch.setenv("ALERT_NEVER_BLOCK", "pas-une-ip")
    with pytest.raises(SystemExit, match="ALERT_NEVER_BLOCK"):
        worker.main()
