import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_accueil_utilise_le_gabarit(client):
    r = client.get("/")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "navbar" in html
    assert "SecLog Monitor" in html
    assert "/upload" in html


def test_page_upload_etend_le_gabarit(client):
    r = client.get("/upload")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "navbar" in html
    assert 'id="file"' in html
    assert "breadcrumb" in html


def test_404_html_pour_les_pages(client):
    r = client.get("/page-inexistante")
    assert r.status_code == 404
    assert "Page introuvable" in r.get_data(as_text=True)


def test_404_json_pour_l_api(client):
    r = client.get("/api/v1/inexistant")
    assert r.status_code == 404
    assert r.get_json()["error"] == "not_found"


def test_messages_flash_affiches(client):
    with client.session_transaction() as sess:
        sess["_flashes"] = [("success", "Opération réussie")]
    html = client.get("/").get_data(as_text=True)
    assert "alert-success" in html
    assert "Opération réussie" in html
