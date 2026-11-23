def test_accueil_utilise_le_gabarit(make_client):
    r = make_client("lecteur").get("/")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "navbar" in html
    assert "SecLog Monitor" in html
    assert "Tableau de bord" in html


def test_tableau_de_bord_contenu(make_client):
    html = make_client("lecteur").get("/").get_data(as_text=True)
    for ident in ("kpi-events", "kpi-failures", "kpi-critical", "kpi-files",
                  "chart-per-day", "chart-severity", "chart-top-ips", "chart-event-type", 'id="period"'):
        assert ident in html
    assert "js/dashboard.js" in html


def test_page_upload_etend_le_gabarit(make_client):
    r = make_client("analyste").get("/upload")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "navbar" in html
    assert 'id="file"' in html
    assert "breadcrumb" in html


def test_404_html_pour_les_pages(make_client):
    r = make_client("lecteur").get("/page-inexistante")
    assert r.status_code == 404
    assert "Page introuvable" in r.get_data(as_text=True)


def test_404_json_pour_l_api(make_client):
    r = make_client("lecteur").get("/api/v1/inexistant")
    assert r.status_code == 404
    assert r.get_json()["error"] == "not_found"


def test_messages_flash_affiches(make_client):
    client = make_client("lecteur")
    with client.session_transaction() as sess:
        sess["_flashes"] = [("success", "Opération réussie")]
    html = client.get("/").get_data(as_text=True)
    assert "alert-success" in html
    assert "Opération réussie" in html
