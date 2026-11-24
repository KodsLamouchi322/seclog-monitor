import csv
import io
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from bson.errors import InvalidId
from elasticsearch import ApiError, BadRequestError, TransportError
from flask import Blueprint, Response, jsonify, request
from pymongo.errors import PyMongoError

from .access import get_session
from .cache import cached_json
from .db import get_db
from .es import INDEX, get_es
from .search import build_query, run_search

COLLECTION = "files"

bp = Blueprint("api", __name__, url_prefix="/api/v1")


@bp.get("/logs")
def list_logs():
    def compute():
        try:
            data = run_search(get_es(), request.args.to_dict())
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        except (ApiError, TransportError):
            return jsonify(error="Elasticsearch indisponible."), 503
        return data

    resp = cached_json(compute)
    # Enregistré sur chaque recherche réussie, y compris quand la réponse vient du cache
    if hasattr(resp, "get_json") and resp.status_code == 200:
        _save_search(request.args.to_dict(), resp.get_json())
    return resp


EXPORT_MAX = 10000
EXPORT_HEADER = ["timestamp", "type", "action", "result", "severity", "ip", "port", "country", "city",
                 "user", "role", "host", "message", "tags"]


def _dig(src: dict, path: str):
    for part in path.split("."):
        if not isinstance(src, dict):
            return ""
        src = src.get(part, "")
    return src


def _csv_safe(value) -> str:
    """Neutralise l'injection de formule (Excel) : une cellule ne doit pas commencer par = + - @."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _export_row(src: dict) -> list:
    tags = src.get("tags") or []
    values = [_dig(src, "@timestamp"), _dig(src, "event.type"), _dig(src, "event.action"), src.get("result"),
              src.get("severity"), _dig(src, "source.ip"), _dig(src, "source.port"),
              _dig(src, "source.geo.country_name"), _dig(src, "source.geo.city_name"),
              _dig(src, "user.name"), _dig(src, "user.role"), _dig(src, "host.name"), src.get("message"),
              "|".join(tags) if isinstance(tags, list) else tags]
    return [_csv_safe(v) for v in values]


@bp.get("/logs/export")
def export_logs():
    """Export CSV des résultats d'une recherche (mêmes filtres que /logs), 10 000 lignes maximum."""
    try:
        res = get_es().search(index=INDEX, query=build_query(request.args.to_dict()),
                              sort=[{"@timestamp": {"order": "desc"}}], size=EXPORT_MAX,
                              track_total_hits=True)
    except BadRequestError:
        return jsonify(error="Critères de recherche invalides."), 400
    except (ApiError, TransportError):
        return jsonify(error="Elasticsearch indisponible."), 503
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(EXPORT_HEADER)
    for hit in res["hits"]["hits"]:
        writer.writerow(_export_row(hit["_source"]))
    name = f"seclog-export-{datetime.now(timezone.utc):%Y%m%d-%H%M}.csv"
    headers = {"Content-Disposition": f'attachment; filename="{name}"'}
    if res["hits"]["total"]["value"] > EXPORT_MAX:
        headers["X-Export-Truncated"] = "true"
    # BOM UTF-8 : Excel affiche correctement les accents
    return Response("\ufeff" + out.getvalue(), mimetype="text/csv", headers=headers)


@bp.get("/logs/<doc_id>")
def get_log(doc_id):
    try:
        res = get_es().search(index=INDEX, query={"ids": {"values": [doc_id]}}, size=1)
    except (ApiError, TransportError):
        return jsonify(error="Elasticsearch indisponible."), 503
    hits = res["hits"]["hits"]
    if not hits:
        return jsonify(error="Log introuvable."), 404
    return jsonify(id=hits[0]["_id"], **hits[0]["_source"])


def _serialize(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    for k, v in doc.items():
        if isinstance(v, datetime):
            doc[k] = v.isoformat()
    return doc


def _sync_status(col, doc: dict) -> dict:
    """pending -> ingested quand ES contient toutes les lignes attendues."""
    if doc.get("status") != "pending":
        return doc
    expected = max(0, (doc.get("total_lines") or 0) - (doc.get("invalid_lines") or 0))
    name = doc.get("stored_name")
    if not expected or not name:
        return doc
    count = get_es().count(
        index=INDEX, query={"term": {"upload.file_name": name}}
    )["count"]
    doc["indexed_count"] = count
    if count >= expected:
        now = datetime.now(timezone.utc)
        col.update_one(
            {"_id": doc["_id"]},
            {"$set": {"status": "ingested", "ingested_at": now,
                      "indexed_count": count}},
        )
        doc["status"], doc["ingested_at"] = "ingested", now
    return doc


@bp.get("/files")
def list_files():
    try:
        page = max(1, int(request.args.get("page", 1)))
        size = min(100, max(1, int(request.args.get("size", 20))))
    except ValueError:
        return jsonify(error="page et size doivent être des entiers."), 400
    col = get_db()[COLLECTION]
    query = {}
    status = request.args.get("status")
    if status:
        query["status"] = status
    total = col.count_documents(query)
    docs = (col.find(query).sort("_id", -1)
            .skip((page - 1) * size).limit(size))
    return jsonify(total=total, page=page, size=size,
                   results=[_serialize(d) for d in docs])


@bp.get("/files/<file_id>")
def get_file(file_id):
    try:
        oid = ObjectId(file_id)
    except (InvalidId, TypeError):
        return jsonify(error="Identifiant invalide."), 400
    col = get_db()[COLLECTION]
    doc = col.find_one({"_id": oid})
    if not doc:
        return jsonify(error="Fichier introuvable."), 404
    try:
        doc = _sync_status(col, doc)
    except (ApiError, TransportError):
        pass  # ES indisponible : on renvoie le statut tel que stocké
    return jsonify(_serialize(doc))


HISTORY = "search_history"
NOT_CRITERIA = {"page", "size", "sort", "order"}


def _save_search(args: dict, data: dict) -> None:
    """Historique par utilisateur ; une recherche identique répétée en moins d'une minute n'est pas dupliquée
    (changer de page ou de tri relance la même recherche)."""
    criteria = {k: v for k, v in args.items() if v and k not in NOT_CRITERIA}
    if not criteria:
        return
    user = (get_session() or {}).get("username", "inconnu")
    now = datetime.now(timezone.utc)
    try:
        col = get_db()[HISTORY]
        if col.find_one({"user": user, "criteria": criteria, "at": {"$gte": now - timedelta(seconds=60)}}):
            return
        col.insert_one({"user": user, "criteria": criteria, "total": data["total"],
                        "took_ms": data["took_ms"], "at": now})
    except PyMongoError:
        pass  # l'historique ne doit jamais bloquer une recherche


@bp.get("/searches")
def list_searches():
    try:
        size = min(50, max(1, int(request.args.get("size", 10))))
    except ValueError:
        return jsonify(error="size doit être un entier."), 400
    session = get_session() or {}
    # chacun voit ses recherches ; l'admin voit celles de tous
    query = {} if session.get("role") == "admin" else {"user": session.get("username")}
    docs = get_db()[HISTORY].find(query).sort("_id", -1).limit(size)
    return jsonify(results=[_serialize(d) for d in docs])


def _buckets(res: dict, name: str) -> list:
    return [{"key": b["key_as_string"] if "key_as_string" in b else b["key"],
             "count": b["doc_count"]}
            for b in res["aggregations"][name]["buckets"]]


@bp.get("/stats")
def stats():
    aggs = {
        "by_severity": {"terms": {"field": "severity", "size": 10}},
        "by_event_type": {"terms": {"field": "event.type", "size": 20}},
        "by_result": {"terms": {"field": "result", "size": 10}},
        "top_countries": {"terms": {"field": "source.geo.country_iso_code", "size": 10}},
        "top_ips": {"terms": {"field": "source.ip", "size": 10}},
        "per_day": {"date_histogram": {"field": "@timestamp",
                                       "calendar_interval": "day",
                                       "format": "yyyy-MM-dd"}},
    }

    def compute():
        try:
            res = get_es().search(index=INDEX, size=0, track_total_hits=True,
                                  query=build_query(request.args.to_dict()),
                                  aggs=aggs)
        except (ApiError, TransportError):
            return jsonify(error="Elasticsearch indisponible."), 503
        out = {"total": res["hits"]["total"]["value"], "took_ms": res["took"]}
        for name in aggs:
            out[name] = _buckets(res, name)
        return out

    return cached_json(compute)
