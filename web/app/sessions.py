"""Sessions serveur dans Redis : cookie opaque HttpOnly, données côté Redis."""
import json
import logging
import os
import secrets
import time

from flask import Blueprint, current_app, jsonify, request
from redis.exceptions import RedisError

from .cache import get_redis

log = logging.getLogger("seclog.session")
bp = Blueprint("sessions", __name__)
PREFIX = "seclog:session:"
COOKIE = "seclog_sid"


def init_sessions(app):
    app.config.setdefault("SESSION_TTL", int(os.getenv("SESSION_TTL", "3600")))
    app.config.setdefault("SID_COOKIE_SECURE", os.getenv("SESSION_COOKIE_SECURE", "0") == "1")


def create_session(username, role):
    sid = secrets.token_urlsafe(32)
    data = json.dumps({"username": username, "role": role, "created": int(time.time())})
    try:
        get_redis().setex(PREFIX + sid, current_app.config["SESSION_TTL"], data)
    except RedisError:
        log.error("Création de session impossible : Redis indisponible")
        return None
    return sid


def set_session_cookie(resp, sid):
    cfg = current_app.config
    resp.set_cookie(COOKIE, sid, max_age=cfg["SESSION_TTL"], httponly=True,
                    samesite="Lax", secure=cfg["SID_COOKIE_SECURE"])


def load_session():
    sid = request.cookies.get(COOKIE)
    if not sid or len(sid) > 100:
        return None
    try:
        raw = get_redis().get(PREFIX + sid)
    except RedisError:
        return None
    return json.loads(raw) if raw else None


@bp.get("/auth/me")
def me():
    s = load_session()
    if not s:
        return jsonify(error="unauthenticated", message="Session absente ou expirée"), 401
    return jsonify(username=s["username"], role=s["role"])


@bp.post("/auth/logout")
def logout():
    sid = request.cookies.get(COOKIE)
    if sid and len(sid) <= 100:
        try:
            get_redis().delete(PREFIX + sid)
        except RedisError:
            pass
    resp = jsonify(status="logged_out")
    resp.delete_cookie(COOKIE)
    return resp
