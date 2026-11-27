"""API des règles d'alerte (module G) : lecture pour tous les rôles, écriture réservée aux admins (voir access.py)."""
import logging
from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId
from elasticsearch import ApiError, BadRequestError, TransportError
from flask import Blueprint, jsonify, request
from pymongo.errors import PyMongoError

from .access import get_session
from .alert_engine import ALERTS
from .alerting import MAX_WINDOW_MINUTES, RULE_TYPES, SEVERITIES, evaluate, validate_rule
from .api import _serialize
from .db import get_db
from .es import get_es

COLLECTION = "alert_rules"
log = logging.getLogger("seclog.rules")
bp = Blueprint("rules", __name__, url_prefix="/api/v1")


def _oid(rule_id: str):
    try:
        return ObjectId(rule_id)
    except (InvalidId, TypeError):
        return None


def _user() -> str:
    return (get_session() or {}).get("username", "inconnu")


def _body_rule():
    """Valide le corps JSON ; retourne (règle, None) ou (None, réponse d'erreur)."""
    try:
        return validate_rule(request.get_json(silent=True)), None
    except ValueError as exc:
        return None, (jsonify(error=str(exc)), 400)


@bp.errorhandler(PyMongoError)
def _db_down(_e):
    return jsonify(error="Base de données indisponible."), 503


@bp.get("/rules/types")
def rule_types():
    types = [{"id": k, "label": v["label"], "can_block": v["can_block"], "defaults": v["params"]}
             for k, v in RULE_TYPES.items()]
    return jsonify(types=types, severities=list(SEVERITIES), max_window_minutes=MAX_WINDOW_MINUTES)


@bp.get("/rules")
def list_rules():
    docs = get_db()[COLLECTION].find().sort("_id", 1)
    return jsonify(results=[_serialize(d) for d in docs])


@bp.post("/rules")
def create_rule():
    rule, err = _body_rule()
    if err:
        return err
    now = datetime.now(timezone.utc)
    rule.update(created_by=_user(), created_at=now, updated_at=now)
    inserted = get_db()[COLLECTION].insert_one(rule)
    log.info("Règle d'alerte créée par %s : %s", rule["created_by"], rule["name"])
    return jsonify(_serialize({**rule, "_id": inserted.inserted_id})), 201


@bp.put("/rules/<rule_id>")
def update_rule(rule_id):
    oid = _oid(rule_id)
    rule, err = _body_rule()
    if err:
        return err
    if oid is None:
        return jsonify(error="Règle introuvable."), 404
    rule["updated_at"] = datetime.now(timezone.utc)
    col = get_db()[COLLECTION]
    if col.find_one({"_id": oid}) is None:
        return jsonify(error="Règle introuvable."), 404
    col.update_one({"_id": oid}, {"$set": rule})
    log.info("Règle d'alerte modifiée par %s : %s", _user(), rule["name"])
    return jsonify(_serialize(col.find_one({"_id": oid})))


@bp.patch("/rules/<rule_id>")
def toggle_rule(rule_id):
    oid = _oid(rule_id)
    data = request.get_json(silent=True) or {}
    if not isinstance(data.get("enabled"), bool):
        return jsonify(error="enabled (vrai ou faux) requis."), 400
    col = get_db()[COLLECTION]
    if oid is None or col.find_one({"_id": oid}) is None:
        return jsonify(error="Règle introuvable."), 404
    col.update_one({"_id": oid}, {"$set": {"enabled": data["enabled"], "updated_at": datetime.now(timezone.utc)}})
    log.info("Règle %s %s par %s", rule_id, "activée" if data["enabled"] else "désactivée", _user())
    return jsonify(_serialize(col.find_one({"_id": oid})))


@bp.delete("/rules/<rule_id>")
def delete_rule(rule_id):
    oid = _oid(rule_id)
    result = get_db()[COLLECTION].delete_one({"_id": oid}) if oid else None
    if not result or not result.deleted_count:
        return jsonify(error="Règle introuvable."), 404
    log.info("Règle %s supprimée par %s", rule_id, _user())
    return jsonify(status="deleted", id=rule_id)


@bp.post("/rules/test")
def test_rule():
    """Évalue une règle (enregistrée ou non) sur la fenêtre choisie, sans créer d'alerte ni bloquer d'IP."""
    rule, err = _body_rule()
    if err:
        return err
    try:
        return jsonify(evaluate(rule, get_es()))
    except BadRequestError:
        return jsonify(error="Règle invalide pour Elasticsearch."), 400
    except (ApiError, TransportError):
        return jsonify(error="Elasticsearch indisponible."), 503


ALERT_STATUSES = ("open", "acknowledged", "resolved", "snoozed")


@bp.get("/alerts")
def list_alerts():
    """Alertes les plus récentes d'abord ; filtre facultatif ?status=open ; ?size= (1 à 100, 20 par défaut)."""
    status = request.args.get("status")
    if status and status not in ALERT_STATUSES:
        return jsonify(error="status doit valoir : " + ", ".join(ALERT_STATUSES) + "."), 400
    try:
        size = min(100, max(1, int(request.args.get("size", 20))))
    except ValueError:
        return jsonify(error="size doit être un entier."), 400
    docs = get_db()[ALERTS].find({"status": status} if status else {}).sort("_id", -1).limit(size)
    results = []
    for doc in docs:
        doc["rule_id"] = str(doc.get("rule_id"))
        results.append(_serialize(doc))
    return jsonify(results=results)
