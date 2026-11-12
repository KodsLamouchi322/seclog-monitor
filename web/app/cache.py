import json
from urllib.parse import urlencode

from flask import current_app, jsonify, request
from redis import Redis
from redis.exceptions import RedisError

TTL = 30
_client = None


def get_redis() -> Redis:
    global _client
    if _client is None:
        _client = Redis.from_url(
            current_app.config["REDIS_URL"],
            socket_connect_timeout=1,
            socket_timeout=1,
            decode_responses=True,
        )
    return _client


def _key() -> str:
    args = sorted(request.args.items())
    return f"seclog:cache:{request.path}?{urlencode(args)}"


def cached_json(compute):
    """Renvoie la réponse en cache, sinon calcule et stocke.
    compute() retourne un dict, ou une réponse d'erreur (tuple) jamais mise en cache."""
    key = _key()
    try:
        hit = get_redis().get(key)
        if hit:
            resp = jsonify(json.loads(hit))
            resp.headers["X-Cache"] = "HIT"
            return resp
    except RedisError:
        pass
    result = compute()
    if isinstance(result, dict):
        try:
            get_redis().setex(key, TTL, json.dumps(result))
        except RedisError:
            pass
        resp = jsonify(result)
        resp.headers["X-Cache"] = "MISS"
        return resp
    return result  # erreur (400/503) : pas de cache
