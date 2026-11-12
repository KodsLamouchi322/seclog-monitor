"""Limitation de débit par IP (Redis, fenêtre fixe).

- INCR seclog:rl:<ip>, EXPIRE posé au premier appel de la fenêtre.
- Dépassement : 429 + Retry-After. Toutes les réponses portent X-RateLimit-*.
- /health et /static ne sont jamais limités.
- Redis en panne : les requêtes passent (même comportement que le cache).
"""
import logging
import os
import time

from flask import g, jsonify, request
from redis.exceptions import RedisError

from .cache import get_redis

log = logging.getLogger("seclog.ratelimit")

EXEMPT_PATHS = {"/health"}
EXEMPT_PREFIXES = ("/static/",)


def client_ip(trust_proxy: bool) -> str:
    if trust_proxy:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def init_rate_limit(app):
    app.config.setdefault("RATE_LIMIT_MAX", int(os.getenv("RATE_LIMIT_MAX", "60")))
    app.config.setdefault("RATE_LIMIT_WINDOW", int(os.getenv("RATE_LIMIT_WINDOW", "60")))
    app.config.setdefault(
        "RATE_LIMIT_TRUST_PROXY", os.getenv("RATE_LIMIT_TRUST_PROXY", "0") == "1"
    )

    @app.before_request
    def _rate_limit():
        g.rl = None
        if request.path in EXEMPT_PATHS or request.path.startswith(EXEMPT_PREFIXES):
            return None
        limit = app.config["RATE_LIMIT_MAX"]
        window = app.config["RATE_LIMIT_WINDOW"]
        ip = client_ip(app.config["RATE_LIMIT_TRUST_PROXY"])
        key = f"seclog:rl:{ip}"
        try:
            r = get_redis()
            pipe = r.pipeline()
            pipe.incr(key)
            pipe.ttl(key)
            count, ttl = pipe.execute()
            if ttl < 0:  # clé sans expiration (1er appel ou EXPIRE perdu)
                r.expire(key, window)
                ttl = window
        except RedisError:
            return None
        g.rl = {
            "limit": limit,
            "remaining": max(0, limit - count),
            "reset": int(time.time()) + ttl,
        }
        if count > limit:
            if count == limit + 1:
                log.warning("Limite de débit dépassée par %s sur %s (%s req/%s s)", ip, request.path, limit, window)
            resp = jsonify(
                error="rate_limited",
                message=f"Trop de requêtes. Réessayez dans {ttl} s.",
                retry_after=ttl,
            )
            resp.status_code = 429
            resp.headers["Retry-After"] = str(ttl)
            return resp
        return None

    @app.after_request
    def _rate_limit_headers(resp):
        rl = g.get("rl")
        if rl:
            resp.headers["X-RateLimit-Limit"] = str(rl["limit"])
            resp.headers["X-RateLimit-Remaining"] = str(rl["remaining"])
            resp.headers["X-RateLimit-Reset"] = str(rl["reset"])
        return resp
