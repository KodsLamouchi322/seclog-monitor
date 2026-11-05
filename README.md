# SecLog Monitor

Plateforme de monitoring et d'analyse de logs de sécurité (scénario C : sécurité et authentification, DevSecOps).

Mini-projet ELK, projet individuel, 6 semaines (02/11/2026 - 11/12/2026).
Modules avancés : **G** (alerting), **K** (CI/CD et tests), **L** (observabilité).

## Fonctionnalités prévues

- Upload de logs de sécurité (CSV, JSON) avec validation et prévisualisation
- Pipelines Logstash (parsing, GeoIP, gravité) et indexation Elasticsearch
- Recherche avancée, API REST, historique des recherches
- Authentification avec rôles (admin, analyste SOC, lecteur)
- Dashboards Kibana intégrés
- Alerting : règles, notifications (SMTP, Slack/Discord/Teams), blocage automatique d'IP
- CI/CD et DevSecOps (GitHub Actions, SonarCloud, Bandit, Trivy, gitleaks)
- Observabilité (Prometheus, Grafana, Jaeger)

## Stack technique

Elasticsearch, Logstash, Kibana 8.x · Flask/Django · MongoDB 7.x · Redis 7.x · Docker Compose

## Structure du projet

| Dossier | Contenu |
| --- | --- |
| `web/` | Application web et API REST |
| `alert-worker/` | Worker d'alerting (module G) |
| `logstash/` | Pipelines Logstash |
| `elasticsearch/` | Index template |
| `kibana/` | Exports de dashboards |
| `monitoring/` | Prometheus et Grafana (module L) |
| `scripts/` | Génération de données de test |
| `docs/` | Analyse, architecture, maquettes |

## Démarrage rapide

```bash
cp .env.example .env      # puis adapter les valeurs
docker compose up -d      # disponible à partir du Sprint 2
```

Application : http://localhost:8000 · Kibana : http://localhost:5601

## Avancement

- [x] Sprint 1 : analyse et initialisation Git
- [ ] Sprint 2 : conception et environnement Docker
- [ ] Sprint 3 : backend core et ELK
- [ ] Sprint 4 : frontend, authentification, Kibana
- [ ] Sprint 5 : modules G et K
- [ ] Sprint 6 : module L, finalisation, soutenance

## Auteur

Ton Nom
