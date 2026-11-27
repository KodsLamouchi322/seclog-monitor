"""Règles d'alerte (module G) : définition, validation et évaluation sur Elasticsearch.

Les mêmes fonctions servent à l'API (test d'une règle) et au worker (évaluation périodique).
Types de règles :
- failed_logins_by_ip     : une adresse IP dépasse un seuil d'échecs de connexion dans la fenêtre ;
- sql_injection           : une adresse IP dépasse un seuil de tentatives d'injection SQL ;
- silent_host             : un équipement n'a envoyé aucun log dans la fenêtre ;
- unauthorized_country    : une connexion réussie provient d'un pays hors de la liste autorisée.
"""
import re
from datetime import datetime, timedelta, timezone

from .es import INDEX

SEVERITIES = ("low", "medium", "high", "critical")
MAX_WINDOW_MINUTES = 43200  # 30 jours
RULE_TYPES = {
    "failed_logins_by_ip": {"label": "Échecs de connexion par adresse IP", "can_block": True,
                            "params": {"threshold": 5}},
    "sql_injection": {"label": "Tentatives d'injection SQL par adresse IP", "can_block": True,
                      "params": {"threshold": 1}},
    "silent_host": {"label": "Équipement silencieux (aucun log reçu)", "can_block": False,
                    "params": {"host": ""}},
    "unauthorized_country": {"label": "Connexion réussie depuis un pays non autorisé", "can_block": False,
                             "params": {"allowed_countries": ["TN"]}},
}
HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")


def _int(data: dict, key: str, default: int, low: int, high: int, label: str) -> int:
    value = data.get(key, default)
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{label} doit être un entier compris entre {low} et {high}.")
    return value


def _bool(data: dict, key: str, default: bool, label: str) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"{label} doit être vrai ou faux.")
    return value


def validate_rule(data) -> dict:
    """Retourne la règle nettoyée (seuls les champs connus) ou lève ValueError avec un message clair."""
    if not isinstance(data, dict):
        raise ValueError("Corps JSON attendu.")
    name = data.get("name")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
        raise ValueError("Le nom est obligatoire (100 caractères maximum).")
    rule_type = data.get("type")
    if rule_type not in RULE_TYPES:
        raise ValueError("Type de règle inconnu : " + ", ".join(RULE_TYPES) + ".")
    severity = data.get("severity", "medium")
    if severity not in SEVERITIES:
        raise ValueError("Gravité inconnue : " + ", ".join(SEVERITIES) + ".")
    block_ip = _bool(data, "block_ip", False, "block_ip")
    if block_ip and not RULE_TYPES[rule_type]["can_block"]:
        raise ValueError("Le blocage d'IP n'est possible que pour les règles par adresse IP.")

    raw = data.get("params") or {}
    if not isinstance(raw, dict):
        raise ValueError("params doit être un objet.")
    if rule_type in ("failed_logins_by_ip", "sql_injection"):
        params = {"threshold": _int(raw, "threshold", RULE_TYPES[rule_type]["params"]["threshold"], 1, 100000,
                                    "Le seuil")}
    elif rule_type == "silent_host":
        host = raw.get("host")
        if not isinstance(host, str) or not HOST_RE.match(host.strip()):
            raise ValueError("Nom d'équipement invalide (lettres, chiffres, point, tiret, souligné).")
        params = {"host": host.strip()}
    else:
        countries = raw.get("allowed_countries")
        if not isinstance(countries, list) or not 1 <= len(countries) <= 50:
            raise ValueError("Liste de pays autorisés requise (1 à 50 codes).")
        cleaned = []
        for code in countries:
            code = str(code).strip().upper()
            if not COUNTRY_RE.match(code):
                raise ValueError(f"Code pays invalide : {code!r} (2 lettres, ex. TN).")
            if code not in cleaned:
                cleaned.append(code)
        params = {"allowed_countries": cleaned}

    return {
        "name": name.strip(),
        "type": rule_type,
        "severity": severity,
        "window_minutes": _int(data, "window_minutes", 15, 1, MAX_WINDOW_MINUTES, "La fenêtre (minutes)"),
        "cooldown_minutes": _int(data, "cooldown_minutes", 15, 0, 1440, "Le délai entre deux alertes (minutes)"),
        "enabled": _bool(data, "enabled", True, "enabled"),
        "block_ip": block_ip,
        "params": params,
    }


def _buckets(res: dict, name: str) -> list:
    return res.get("aggregations", {}).get(name, {}).get("buckets", [])


def evaluate(rule: dict, es, now: datetime | None = None) -> dict:
    """Évalue une règle (valide) sur la fenêtre qui précède `now` ; ne crée aucune alerte."""
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(minutes=rule["window_minutes"])
    window = {"range": {"@timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}}
    params = rule["params"]
    kind = rule["type"]
    must_not = []
    aggs = None

    if kind == "failed_logins_by_ip":
        filters = [window, {"term": {"event.type": "authentication"}}, {"term": {"result": "failure"}}]
        aggs = {"by_ip": {"terms": {"field": "source.ip", "size": 50, "min_doc_count": params["threshold"]}}}
    elif kind == "sql_injection":
        filters = [window, {"term": {"event.action": "sql_injection_attempt"}}]
        aggs = {"by_ip": {"terms": {"field": "source.ip", "size": 50, "min_doc_count": params["threshold"]}}}
    elif kind == "silent_host":
        filters = [window, {"match_phrase": {"host.name": params["host"]}}]
    else:
        filters = [window, {"term": {"event.type": "authentication"}}, {"term": {"result": "success"}}]
        must_not = [{"terms": {"source.geo.country_iso_code": params["allowed_countries"]}}]
        aggs = {"by_country": {"terms": {"field": "source.geo.country_iso_code", "size": 50},
                               "aggs": {"users": {"terms": {"field": "user.name", "size": 3}}}}}

    query = {"bool": {"filter": filters, "must_not": must_not}}
    kwargs = {"index": INDEX, "size": 0, "query": query, "track_total_hits": True}
    if aggs:
        kwargs["aggs"] = aggs
    res = es.search(**kwargs)

    if kind == "silent_host":
        silent = res["hits"]["total"]["value"] == 0
        findings = [{"key": params["host"], "count": 0, "detail": "aucun log reçu"}] if silent else []
    elif kind == "unauthorized_country":
        findings = [{"key": b["key"], "count": b["doc_count"],
                     "detail": "utilisateurs : " + ", ".join(str(u["key"]) for u in b["users"]["buckets"])}
                    for b in _buckets(res, "by_country")]
    else:
        findings = [{"key": b["key"], "count": b["doc_count"]} for b in _buckets(res, "by_ip")]
    return {"matched": bool(findings), "findings": findings, "total": sum(f["count"] for f in findings),
            "window_minutes": rule["window_minutes"], "evaluated_at": now.isoformat()}
