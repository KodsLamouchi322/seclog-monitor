import os

from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-change-me"),
        ES_HOST=os.getenv("ES_HOST", "http://localhost:9200"),
        MONGO_URI=os.getenv("MONGO_URI", "mongodb://localhost:27017/seclog"),
        REDIS_URL=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        LOGSTASH_URL=os.getenv("LOGSTASH_URL", "http://localhost:9600"),
        UPLOAD_FOLDER=os.getenv("UPLOAD_FOLDER", "/app/uploads"),
    )

    from .health import bp as health_bp

    app.register_blueprint(health_bp)

    @app.get("/")
    def index():
        return (
            "<h1>SecLog Monitor</h1>"
            "<p>Squelette Flask opérationnel (Sprint 2).</p>"
            '<p><a href="/health">État des services</a></p>'
        )

    return app
