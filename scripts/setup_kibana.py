#!/usr/bin/env python3
"""Crée dans Kibana les visualisations et le tableau de bord SecLog (US06).

Usage (dans le conteneur web, qui connaît KIBANA_URL) :
    docker compose exec web python /scripts/setup_kibana.py                  # crée / met à jour
    docker compose exec web python /scripts/setup_kibana.py --export > kibana/exports/seclog-dashboard.ndjson

Crée : la vue de données « logs-security » (si absente), 3 visualisations Lens
(échecs de connexion par jour, top 10 des IP, top 10 des pays) et le tableau de bord
« seclog-security » (période 30 jours, rafraîchissement 30 s).
La carte de géolocalisation se crée dans l'application Maps de Kibana (voir README) puis s'ajoute au tableau de bord.
Chaque objet est créé séparément : si l'un échoue, les autres restent créés et l'erreur est affichée.
"""
import argparse
import json
import os
import sys
import time

import requests

DATA_VIEW_ID = "logs-security"
DASHBOARD_ID = "seclog-security"
HEADERS = {"kbn-xsrf": "true"}
FAILED_LOGIN = 'event.type : "authentication" and result : "failure"'


def log(message):
    print(message, file=sys.stderr)


def lens_xy(title, description, query, x_column, series_type):
    """Visualisation Lens en barres ou en courbe : une dimension (axe X) et un comptage d'événements."""
    layer_id = "layer1"
    count = {"label": "Événements", "dataType": "number", "operationType": "count", "isBucketed": False,
             "scale": "ratio", "sourceField": "___records___", "params": {"emptyAsNull": True}}
    return {
        "attributes": {
            "title": title,
            "description": description,
            "visualizationType": "lnsXY",
            "state": {
                "visualization": {
                    "legend": {"isVisible": False, "position": "right"},
                    "valueLabels": "hide",
                    "fittingFunction": "None",
                    "axisTitlesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                    "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                    "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
                    "gridlinesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                    "preferredSeriesType": series_type,
                    "layers": [{"layerId": layer_id, "accessors": ["col2"], "position": "top",
                                "seriesType": series_type, "showGridlines": False, "layerType": "data",
                                "xAccessor": "col1"}],
                },
                "query": {"query": query, "language": "kuery"},
                "filters": [],
                "datasourceStates": {"formBased": {"layers": {layer_id: {
                    "columns": {"col1": x_column, "col2": count},
                    "columnOrder": ["col1", "col2"],
                    "incompleteColumns": {},
                }}}},
                "internalReferences": [],
                "adHocDataViews": {},
            },
        },
        "references": [{"type": "index-pattern", "id": DATA_VIEW_ID,
                        "name": f"indexpattern-datasource-layer-{layer_id}"}],
    }


def top_terms(field, label, data_type, size=10):
    return {"label": label, "dataType": data_type, "operationType": "terms", "scale": "ordinal",
            "sourceField": field, "isBucketed": True,
            "params": {"size": size, "orderBy": {"type": "column", "columnId": "col2"},
                       "orderDirection": "desc", "otherBucket": False, "missingBucket": False,
                       "parentFormat": {"id": "terms"}}}


def build_objects():
    """Liste ordonnée (type, id, corps) : visualisations d'abord, tableau de bord ensuite."""
    timeline = lens_xy(
        "SecLog - Échecs de connexion par jour", "Timeline des authentifications échouées", FAILED_LOGIN,
        {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram", "sourceField": "@timestamp",
         "isBucketed": True, "scale": "interval", "params": {"interval": "auto", "includeEmptyColumns": True}},
        "line")
    top_ips = lens_xy(
        "SecLog - Top 10 des adresses IP (échecs de connexion)", "IP source avec le plus d'échecs", FAILED_LOGIN,
        top_terms("source.ip", "Adresse IP source", "ip"), "bar_horizontal")
    top_countries = lens_xy(
        "SecLog - Top 10 des pays (échecs de connexion)", "Pays d'origine des échecs de connexion", FAILED_LOGIN,
        top_terms("source.geo.country_name", "Pays", "string"), "bar_horizontal")
    visuals = [("seclog-failed-logins-timeline", timeline), ("seclog-top-ips", top_ips),
               ("seclog-top-countries", top_countries)]

    layout = [(0, 0, 48, 14), (0, 14, 24, 15), (24, 14, 24, 15)]
    panels, refs = [], []
    for index, ((vid, _), (x, y, w, h)) in enumerate(zip(visuals, layout), start=1):
        panels.append({"version": "8.15.3", "type": "lens", "panelIndex": f"p{index}",
                       "gridData": {"x": x, "y": y, "w": w, "h": h, "i": f"p{index}"},
                       "embeddableConfig": {"enhancements": {}}, "panelRefName": f"panel_p{index}"})
        refs.append({"type": "lens", "id": vid, "name": f"panel_p{index}"})
    dashboard = {
        "attributes": {
            "title": "SecLog Monitor - Sécurité",
            "description": "Échecs de connexion, adresses IP et pays les plus actifs",
            "hits": 0,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": "", "language": "kuery"}, "filter": []})},
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "syncCursor": True,
                                       "syncTooltips": False, "hidePanelTitles": False}),
            "panelsJSON": json.dumps(panels),
            "timeRestore": True, "timeFrom": "now-30d", "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 30000},
        },
        "references": refs,
    }
    return [("lens", vid, body) for vid, body in visuals] + [("dashboard", DASHBOARD_ID, dashboard)]


def wait_for_kibana(url, timeout=240):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{url}/api/status", timeout=5)
            if r.ok and r.json().get("status", {}).get("overall", {}).get("level") == "available":
                return True
        except (requests.RequestException, ValueError):
            pass
        time.sleep(3)
    return False


def ensure_data_view(url):
    if requests.get(f"{url}/api/data_views/data_view/{DATA_VIEW_ID}", headers=HEADERS, timeout=30).ok:
        log("Vue de données « logs-security » : déjà présente")
        return True
    body = {"data_view": {"id": DATA_VIEW_ID, "title": "logs-security-*", "name": "logs-security",
                          "timeFieldName": "@timestamp"}}
    r = requests.post(f"{url}/api/data_views/data_view", json=body, headers=HEADERS, timeout=30)
    log("Vue de données « logs-security » : " + ("créée" if r.ok else f"ÉCHEC HTTP {r.status_code} {r.text[:200]}"))
    return r.ok


def create_objects(url):
    failures = 0
    for obj_type, obj_id, body in build_objects():
        r = requests.post(f"{url}/api/saved_objects/{obj_type}/{obj_id}", params={"overwrite": "true"},
                          json=body, headers=HEADERS, timeout=30)
        if r.ok:
            log(f"  OK    {obj_type:<9} {obj_id}")
        else:
            failures += 1
            log(f"  ÉCHEC {obj_type:<9} {obj_id} : HTTP {r.status_code} {r.text[:300]}")
    return failures


def export_dashboard(url):
    r = requests.post(f"{url}/api/saved_objects/_export", headers=HEADERS, timeout=60,
                      json={"objects": [{"type": "dashboard", "id": DASHBOARD_ID}],
                            "includeReferencesDeep": True, "excludeExportDetails": True})
    if not r.ok:
        log(f"Export impossible : HTTP {r.status_code} {r.text[:300]}")
        return 1
    sys.stdout.write(r.text)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kibana-url", default=os.getenv("KIBANA_URL", "http://localhost:5601"))
    parser.add_argument("--export", action="store_true", help="écrit le tableau de bord au format .ndjson sur la sortie")
    args = parser.parse_args()
    url = args.kibana_url.rstrip("/")
    if not wait_for_kibana(url):
        log("Kibana ne répond pas : vérifie « docker compose ps ».")
        return 1
    if args.export:
        return export_dashboard(url)
    ok = ensure_data_view(url)
    failures = create_objects(url) if ok else 1
    if failures:
        log(f"{failures} objet(s) en échec : suis la création manuelle du README.")
        return 1
    log("Tableau de bord prêt : http://localhost:5601/app/dashboards#/view/" + DASHBOARD_ID)
    return 0


if __name__ == "__main__":
    sys.exit(main())
