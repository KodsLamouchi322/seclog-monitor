"""Authentification minimale + liste noire Redis (RM01).

- POST /auth/login : 5 échecs depuis une IP -> IP en liste noire (TTL).
- Une IP en liste noire reçoit 403 partout, sauf /health et /api/v1/blacklist*.
- GET/DELETE /api/v1/blacklist : protégés par l'en-tête X-Admin-Token.
- Redis en panne : on ne bloque personne (même logique que le cache).
"""
import hmac
import ipaddress
import logging
import os

from flask import Blueprint, current_app, jsonify, request
from pymongo.errors import PyMongoError
from redis.exceptions import RedisError
from werkzeug.security import check_password_hash, generate_password_hash

from .cache import get_redis
from .db import get_db
from .sessions import create_session, set_session_cookie
from .ratelimit import client_ip

bp = Blueprint("auth", __name__)
log = logging.getLogger("seclog.auth")

FAIL_PREFIX = "seclog:login:fail:"
BL_PREFIX = "seclog:blacklist:"
BL_EXEMPT_PATHS = {"/health"}
BL_EXEMPT_PREFIXES = ("/static/", "/api/v1/blacklist")
# Hash factice : évite de révéler si un utilisateur existe (temps de réponse)
_DUMMY_HASH = generate_password_hash("dummy-password")


def _ip() -> str:
    return client_ip(current_app.config["RATE_LIMIT_TRUST_PROXY"])


def init_blacklist(app):
    app.config.setdefault("LOGIN_MAX_FAILS", int(os.getenv("LOGIN_MAX_FAILS", "5")))
    app.config.setdefault("LOGIN_FAIL_WINDOW", int(os.getenv("LOGIN_FAIL_WINDOW", "900")))
    app.config.setdefault("BLACKLIST_TTL", int(os.getenv("BLACKLIST_TTL", "900")))
    app.config.setdefault("ADMIN_TOKEN", os.getenv("ADMIN_TOKEN", ""))

    @app.before_request
    def _check_blacklist():
        if request.path in BL_EXEMPT_PATHS or request.path.startswith(BL_EXEMPT_PREFIXES):
            return None
        try:
            ttl = get_redis().ttl(BL_PREFIX + _ip())
        except RedisError:
            return None
        if ttl == -2:  # clé absente
            return None
        resp = jsonify(error="ip_blacklisted", message="IP bloquée (trop d'échecs de connexion).")
        resp.status_code = 403
        if ttl > 0:
            resp.headers["Retry-After"] = str(ttl)
        return resp


@bp.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
        return jsonify(error="bad_request", message="username et password requis"), 400

    try:
        user = get_db()["users"].find_one({"username": username})
    except PyMongoError:
        return jsonify(error="unavailable", message="Base utilisateurs indisponible"), 503

    pwd_ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
    ip = _ip()
    fail_key = FAIL_PREFIX + ip

    if user and pwd_ok:
        try:
            get_redis().delete(fail_key)
        except RedisError:
            pass
        sid = create_session(username, user.get("role", "user"))
        if sid is None:
            return jsonify(error="unavailable", message="Service de sessions indisponible"), 503
        resp = jsonify(status="ok", username=username)
        set_session_cookie(resp, sid)
        return resp, 200

    cfg = current_app.config
    max_fails = cfg["LOGIN_MAX_FAILS"]
    count = None
    try:
        r = get_redis()
        pipe = r.pipeline()
        pipe.incr(fail_key)
        pipe.ttl(fail_key)
        count, ttl = pipe.execute()
        if ttl < 0:
            r.expire(fail_key, cfg["LOGIN_FAIL_WINDOW"])
        log.warning("Échec de connexion depuis %s (%s/%s)", ip, count, max_fails)
        if count >= max_fails:
            r.setex(BL_PREFIX + ip, cfg["BLACKLIST_TTL"], "1")
            r.delete(fail_key)
            log.error("IP %s mise en liste noire après %s échecs (TTL %s s)", ip, count, cfg["BLACKLIST_TTL"])
            resp = jsonify(error="ip_blacklisted", message="Trop d'échecs : IP bloquée.")
            resp.status_code = 403
            resp.headers["Retry-After"] = str(cfg["BLACKLIST_TTL"])
            return resp
    except RedisError:
        pass
    body = {"error": "invalid_credentials", "message": "Identifiants invalides"}
    if count is not None:
        body["attempts_left"] = max(0, max_fails - count)
    return jsonify(body), 401


def _admin_check():
    """None si autorisé, sinon une réponse d'erreur."""
    token = current_app.config["ADMIN_TOKEN"]
    if not token:
        return jsonify(error="admin_disabled", message="ADMIN_TOKEN non configuré"), 503
    given = request.headers.get("X-Admin-Token", "")
    if not hmac.compare_digest(token.encode(), given.encode()):
        return jsonify(error="forbidden", message="X-Admin-Token invalide"), 403
    return None


@bp.get("/api/v1/blacklist")
def list_blacklist():
    err = _admin_check()
    if err:
        return err
    try:
        r = get_redis()
        items = []
        for key in r.scan_iter(match=BL_PREFIX + "*"):
            items.append({"ip": key[len(BL_PREFIX):], "ttl": r.ttl(key)})
    except RedisError:
        return jsonify(error="unavailable", message="Redis indisponible"), 503
    items.sort(key=lambda i: i["ip"])
    return jsonify(count=len(items), items=items)


@bp.delete("/api/v1/blacklist/<ip>")
def unblock(ip):
    err = _admin_check()
    if err:
        return err
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify(error="bad_request", message="Adresse IP invalide"), 400
    try:
        r = get_redis()
        removed = r.delete(BL_PREFIX + ip)
        r.delete(FAIL_PREFIX + ip)
    except RedisError:
        return jsonify(error="unavailable", message="Redis indisponible"), 503
    if not removed:
        return jsonify(error="not_found", message="IP absente de la liste noire"), 404
    return jsonify(status="unblocked", ip=ip)
