# Worker d'alerting

Le worker utilise le code de `web/app` (modules `worker.py`, `alert_engine.py`, `alerting.py`) et la même image que
l'application web. Ce dossier contient seulement `service.yml`, le bloc à ajouter à `docker-compose.yml`.

Ajout du service (une seule fois, depuis la racine du dépôt) :

    awk 'FNR==NR{snip=snip $0 "\n"; next} /^networks:/{printf "%s", snip} {print}' \
        alert-worker/service.yml docker-compose.yml > docker-compose.new && mv docker-compose.new docker-compose.yml

Variables facultatives du `.env` : `ALERT_INTERVAL_SECONDS` (60) et `ALERT_NEVER_BLOCK` (adresses ou réseaux à ne jamais
bloquer, séparés par des virgules). Les adresses internes (10.x, 192.168.x, 127.x...) ne sont jamais bloquées.
