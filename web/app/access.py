"""Contrôle d'accès : qui a le droit d'ouvrir quelle page (US01).

Une seule règle globale (before_request) protège toute l'application :
- pages publiques : /health, /login, /auth/*, /static/* ;
- tout le reste exige une session valide (cookie seclog_sid, stockée dans Redis) ;
- selon le rôle : lecteur < analyste < admin.
  - lecteur : consulter (recherche, statistiques, fichiers) ;
  - analyste : lecteur + importer des fichiers (/upload) ;
  - admin : tout, y compris la liste noire d'IP.
Un rôle inconnu n'a aucun droit.
"""
from urllib.parse import quote

from flask import Blueprint, g, jsonify, redirect, render_template, request, url_for

from .sessions import load_session

bp = Blueprint("access", __name__)

ROLE_LEVEL = {"lecteur": 1, "analyste": 2, "admin": 3}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

PUBLIC_PATHS = {"/health", "/login", "/auth/login", "/auth/logout", "/auth/me"}
# /api/v1/blacklist* a son propre contrôle (admin ou en-tête X-Admin-Token), voir auth.py
PUBLIC_PREFIXES = ("/static/", "/api/v1/blacklist")


def get_session():
    """Session de la requête en cours (une seule lecture Redis par requête)."""
    if "session" not in g:
        g.session = load_session()
    return g.session


def role_level(session) -> int:
    return ROLE_LEVEL.get((session or {}).get("role"), 0)


def required_level(path: str, method: str) -> int:
    if path.startswith("/upload") or method not in SAFE_METHODS:
        return ROLE_LEVEL["analyste"]
    return ROLE_LEVEL["lecteur"]


def safe_next(value: str) -> str:
    """Adresse de retour après connexion : uniquement un chemin local (pas de redirection externe)."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return "/"


def _wants_html() -> bool:
    return (request.method == "GET" and not request.path.startswith(("/api/", "/auth/"))
            and request.accept_mimetypes.accept_html)


def init_access(app):
    @app.before_request
    def _check_access():
        path = request.path
        if path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES):
            return None
        session = get_session()
        if session is None:
            if _wants_html():
                target = path + ("?" + request.query_string.decode() if request.query_string else "")
                return redirect(url_for("access.login_page") + "?next=" + quote(target, safe="/"))
            return jsonify(error="unauthenticated", message="Connexion requise."), 401
        if role_level(session) < required_level(path, request.method):
            if _wants_html():
                return render_template("errors/403.html"), 403
            return jsonify(error="forbidden", message="Droits insuffisants pour cette action."), 403
        return None

    app.register_blueprint(bp)


@bp.get("/login")
def login_page():
    if get_session():
        return redirect(safe_next(request.args.get("next", "/")))
    return render_template("login.html", next_url=safe_next(request.args.get("next", "/")))
