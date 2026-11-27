"""Moteur d'alerting (module G) : évalue les règles actives et enregistre les alertes.

Appelé chaque minute par le worker (voir worker.py). Principes :
- une alerte par couple (règle, clé) : par adresse IP, par équipement ou par pays ;
- une même alerte n'est pas recréée avant la fin du délai de la règle (cooldown) ;
- une règle en erreur n'empêche pas les autres de s'exécuter ;
- le blocage d'IP (liste noire Redis, la même que celle de la page de connexion) est limité par trois protections :
  jamais d'adresse interne, jamais d'adresse de la liste ALERT_NEVER_BLOCK, et un maximum par cycle.
"""
import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from elasticsearch import ApiError, TransportError
from redis.exceptions import RedisError

from .alerting import evaluate, validate_rule
from .auth import BL_PREFIX

RULES = "alert_rules"
ALERTS = "alerts"
MAX_BLOCKS_PER_CYCLE = 20
log = logging.getLogger("seclog.alerts")


def parse_networks(text: str) -> list:
    """« 203.0.113.7, 198.51.100.0/24 » -> liste de réseaux ; ValueError si une entrée est invalide."""
    return [ipaddress.ip_network(part.strip(), strict=False) for part in (text or "").split(",") if part.strip()]


def is_blockable(ip: str, never_block=()) -> tuple[bool, str]:
    """(autorisé, raison du refus). Les adresses internes ne sont jamais bloquées : on risquerait de s'enfermer."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, "adresse IP invalide"
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified \
            or addr.is_reserved:
        return False, "adresse interne ou réservée"
    if any(addr in net for net in never_block):
        return False, "adresse protégée (ALERT_NEVER_BLOCK)"
    return True, ""


def _in_cooldown(db, rule_id, key, now: datetime, minutes: int) -> bool:
    if minutes <= 0:
        return False
    since = now - timedelta(minutes=minutes)
    return db[ALERTS].find_one({"rule_id": rule_id, "key": key, "created_at": {"$gte": since}}) is not None


def _block(redis, ip: str, ttl: int, never_block, budget: int) -> tuple[bool, str]:
    if budget <= 0:
        return False, "maximum de blocages par cycle atteint"
    allowed, reason = is_blockable(ip, never_block)
    if not allowed:
        return False, reason
    try:
        redis.setex(BL_PREFIX + ip, ttl, "1")
    except RedisError:
        return False, "Redis indisponible"
    return True, ""


def run_cycle(db, es, redis, now: datetime | None = None, block_ttl: int = 900, never_block=()) -> dict:
    """Une passe d'évaluation de toutes les règles actives. Retourne un résumé chiffré."""
    now = now or datetime.now(timezone.utc)
    summary = {"rules": 0, "alerts": 0, "blocked": 0, "errors": 0}
    blocks_left = MAX_BLOCKS_PER_CYCLE
    for stored in db[RULES].find({"enabled": True}):
        summary["rules"] += 1
        name = stored.get("name", stored.get("_id"))
        try:
            rule = validate_rule(stored)
            result = evaluate(rule, es, now)
        except ValueError as exc:
            log.warning("Règle %s ignorée (invalide) : %s", name, exc)
            summary["errors"] += 1
            continue
        except (ApiError, TransportError) as exc:
            log.error("Règle %s : Elasticsearch a échoué : %s", name, exc)
            summary["errors"] += 1
            continue

        for finding in result["findings"]:
            if _in_cooldown(db, stored["_id"], finding["key"], now, rule["cooldown_minutes"]):
                continue
            alert = {"rule_id": stored["_id"], "rule_name": rule["name"], "rule_type": rule["type"],
                     "severity": rule["severity"], "key": finding["key"], "count": finding["count"],
                     "detail": finding.get("detail", ""), "window_minutes": rule["window_minutes"],
                     "status": "open", "blocked": False, "block_note": "", "created_at": now}
            if rule["block_ip"]:
                blocked, note = _block(redis, finding["key"], block_ttl, never_block, blocks_left)
                alert["blocked"], alert["block_note"] = blocked, note
                if alert["blocked"]:
                    blocks_left -= 1
                    summary["blocked"] += 1
                    log.warning("IP %s bloquée %s s (règle %s)", finding["key"], block_ttl, rule["name"])
                else:
                    log.info("IP %s non bloquée : %s", finding["key"], alert["block_note"])
            db[ALERTS].insert_one(alert)
            summary["alerts"] += 1
            log.warning("ALERTE [%s] %s : %s (%s événement(s))", rule["severity"], rule["name"],
                        finding["key"], finding["count"])
    return summary
