"""Endpoint /health : vérifie Elasticsearch, MongoDB, Redis et Logstash."""
import requests
from elasticsearch import Elasticsearch
from flask import Blueprint, current_app, jsonify
from pymongo import MongoClient
from redis import Redis

bp = Blueprint("health", __name__)


def _check_es(cfg) -> bool:
    return bool(Elasticsearch(cfg["ES_HOST"], request_timeout=2).ping())


def _check_mongo(cfg) -> bool:
    client = MongoClient(cfg["MONGO_URI"], serverSelectionTimeoutMS=2000)
    try:
        return client.admin.command("ping").get("ok") == 1.0
    finally:
        client.close()


def _check_redis(cfg) -> bool:
    return bool(Redis.from_url(cfg["REDIS_URL"], socket_connect_timeout=2).ping())


def _check_logstash(cfg) -> bool:
    return requests.get(cfg["LOGSTASH_URL"], timeout=2).status_code == 200


CHECKS = {
    "elasticsearch": _check_es,
    "mongodb": _check_mongo,
    "redis": _check_redis,
    "logstash": _check_logstash,
}


@bp.get("/health")
def health():
    results = {}
    for name, fn in CHECKS.items():
        try:
            results[name] = "ok" if fn(current_app.config) else "down"
        except Exception:  # noqa: BLE001 - un service injoignable ne doit pas faire planter l'endpoint
            results[name] = "down"
    healthy = all(v == "ok" for v in results.values())
    body = {"status": "ok" if healthy else "degraded", "checks": results}
    return jsonify(body), (200 if healthy else 503)
