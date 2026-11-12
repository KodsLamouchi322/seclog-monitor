from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId
from elasticsearch import ApiError, TransportError
from flask import Blueprint, jsonify, request
from pymongo.errors import PyMongoError

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
        _save_search(request.args.to_dict(), data)
        return data

    return cached_json(compute)


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
    criteria = {k: v for k, v in args.items() if v and k not in NOT_CRITERIA}
    if not criteria:
        return
    try:
        get_db()[HISTORY].insert_one({
            "criteria": criteria,
            "total": data["total"],
            "took_ms": data["took_ms"],
            "at": datetime.now(timezone.utc),
        })
    except PyMongoError:
        pass  # l'historique ne doit jamais bloquer une recherche


@bp.get("/searches")
def list_searches():
    try:
        size = min(50, max(1, int(request.args.get("size", 10))))
    except ValueError:
        return jsonify(error="size doit être un entier."), 400
    docs = get_db()[HISTORY].find().sort("_id", -1).limit(size)
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
