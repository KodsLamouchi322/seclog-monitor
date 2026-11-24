import os

from flask import Flask, jsonify, render_template, request

from .logging_conf import setup_logging


def create_app() -> Flask:
    setup_logging()
    app = Flask(__name__)
    max_mb = int(os.getenv("MAX_UPLOAD_MB", "50"))
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-change-me"),
        ES_HOST=os.getenv("ES_HOST", "http://localhost:9200"),
        MONGO_URI=os.getenv("MONGO_URI", "mongodb://localhost:27017/seclog"),
        MONGO_DB=os.getenv("MONGO_DB", "seclog"),
        REDIS_URL=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        LOGSTASH_URL=os.getenv("LOGSTASH_URL", "http://localhost:9600"),
        # Adresse de Kibana telle que le NAVIGATEUR la voit (pas celle du réseau Docker)
        KIBANA_PUBLIC_URL=os.getenv("KIBANA_PUBLIC_URL", "http://localhost:5601").rstrip("/"),
        UPLOAD_FOLDER=os.getenv("UPLOAD_FOLDER", "/app/uploads"),
        # Module Upload (RM11)
        MAX_UPLOAD_MB=max_mb,
        MAX_CONTENT_LENGTH=max_mb * 1024 * 1024,
        ALLOWED_EXTENSIONS={"csv", "json", "txt"},
        PREVIEW_LINES=10,
    )

    from .health import bp as health_bp

    app.register_blueprint(health_bp)

    from .upload import bp as upload_bp

    app.register_blueprint(upload_bp)

    from .api import bp as api_bp

    app.register_blueprint(api_bp)
    from .ratelimit import init_rate_limit
    init_rate_limit(app)
    from .auth import bp as auth_bp, init_blacklist
    app.register_blueprint(auth_bp)
    init_blacklist(app)
    from .sessions import bp as sessions_bp, init_sessions
    app.register_blueprint(sessions_bp)
    init_sessions(app)

    from .access import get_session, init_access
    init_access(app)

    @app.context_processor
    def inject_user():
        return {"current_user": get_session()}

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        if resp.mimetype == "text/html":  # pas de page en cache après déconnexion (bouton Retour)
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/search")
    def search_page():
        return render_template("search.html")

    @app.get("/kibana")
    def kibana_page():
        base = app.config["KIBANA_PUBLIC_URL"]
        dashboard = f"{base}/app/dashboards#/view/seclog-security"
        embed = (dashboard + "?embed=true&show-time-filter=true&show-query-input=true"
                 "&_g=(refreshInterval:(pause:!f,value:30000),time:(from:now-30d,to:now))")
        return render_template("kibana.html", embed_url=embed, dashboard_url=dashboard)

    @app.errorhandler(404)
    def not_found(_e):
        # L'API et l'authentification répondent en JSON, le reste en page HTML.
        if request.path.startswith(("/api/", "/auth/")):
            return jsonify(error="not_found", message="Ressource introuvable."), 404
        return render_template("errors/404.html"), 404

    return app
