import os

from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__)
    max_mb = int(os.getenv("MAX_UPLOAD_MB", "50"))
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-change-me"),
        ES_HOST=os.getenv("ES_HOST", "http://localhost:9200"),
        MONGO_URI=os.getenv("MONGO_URI", "mongodb://localhost:27017/seclog"),
        MONGO_DB=os.getenv("MONGO_DB", "seclog"),
        REDIS_URL=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        LOGSTASH_URL=os.getenv("LOGSTASH_URL", "http://localhost:9600"),
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

    @app.get("/")
    def index():
        return (
            "<h1>SecLog Monitor</h1>"
            "<p>Squelette Flask opérationnel (Sprint 2).</p>"
            '<p><a href="/health">État des services</a></p>'
        )

    return app
