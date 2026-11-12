from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId
from elasticsearch import ApiError, TransportError
from flask import Blueprint, jsonify, request

from .db import get_db
from .es import INDEX, get_es
from .search import run_search

COLLECTION = "files"

bp = Blueprint("api", __name__, url_prefix="/api/v1")


@bp.get("/logs")
def list_logs():
    try:
        data = run_search(get_es(), request.args.to_dict())
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except (ApiError, TransportError):
        return jsonify(error="Elasticsearch indisponible."), 503
    return jsonify(data)


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
