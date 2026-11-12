from elasticsearch import Elasticsearch
from flask import current_app

INDEX = "logs-security-*"
_client = None


def get_es():
    """Retourne le client Elasticsearch (créé une seule fois)."""
    global _client
    if _client is None:
        _client = Elasticsearch(current_app.config["ES_HOST"], request_timeout=10)
    return _client
