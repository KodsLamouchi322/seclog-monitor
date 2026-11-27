"""Worker d'alerting : évalue les règles toutes les ALERT_INTERVAL_SECONDS secondes (60 par défaut).

Lancé dans son propre conteneur, avec la même image que l'application :  python -m app.worker
Le fichier /tmp/worker_heartbeat est mis à jour à chaque passe : c'est ce que vérifie le healthcheck Docker.
"""
import logging
import os
import signal
import threading
import time
from pathlib import Path

from . import create_app
from .alert_engine import parse_networks, run_cycle
from .cache import get_redis
from .db import get_db
from .es import get_es

HEARTBEAT = Path(os.getenv("WORKER_HEARTBEAT", "/tmp/worker_heartbeat"))
log = logging.getLogger("seclog.worker")


def touch_heartbeat(path: Path = HEARTBEAT) -> None:
    path.write_text(str(int(time.time())))


def main() -> None:
    app = create_app()
    interval = max(5, int(os.getenv("ALERT_INTERVAL_SECONDS", "60")))
    try:
        never_block = parse_networks(os.getenv("ALERT_NEVER_BLOCK", ""))
    except ValueError as exc:
        raise SystemExit(f"ALERT_NEVER_BLOCK invalide : {exc}")
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    log.info("Worker d'alerting démarré (intervalle %s s, adresses protégées : %s)", interval,
             ", ".join(map(str, never_block)) or "aucune")
    while not stop.is_set():
        started = time.monotonic()
        try:
            with app.app_context():
                summary = run_cycle(get_db(), get_es(), get_redis(), block_ttl=app.config["BLACKLIST_TTL"],
                                    never_block=never_block)
            log.info("Passe terminée : %s", summary)
        except Exception:  # noqa: BLE001 - le worker ne doit jamais s'arrêter sur une erreur ponctuelle
            log.exception("Passe d'évaluation en échec ; nouvelle tentative au prochain cycle")
        touch_heartbeat(HEARTBEAT)
        stop.wait(max(1.0, interval - (time.monotonic() - started)))
    log.info("Worker arrêté")


if __name__ == "__main__":
    main()
