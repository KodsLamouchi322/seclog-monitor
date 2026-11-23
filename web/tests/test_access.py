import pytest

from app.access import required_level, role_level, safe_next


HTML = {"Accept": "text/html"}  # ce qu'envoie un navigateur


def test_visiteur_redirige_vers_la_connexion(make_client):
    r = make_client().get("/", headers=HTML)
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/login")


def test_visiteur_garde_la_page_demandee(make_client):
    r = make_client().get("/upload", headers=HTML)
    assert r.status_code == 302
    assert r.headers["Location"] == "/login?next=/upload"


def test_visiteur_api_recoit_401_json(make_client):
    r = make_client().get("/api/v1/stats")
    assert r.status_code == 401
    assert r.get_json()["error"] == "unauthenticated"


def test_pages_publiques(make_client):
    client = make_client()
    assert client.get("/login").status_code == 200
    assert client.get("/static/css/app.css").status_code == 200


def test_lecteur_consulte_mais_ne_peut_pas_importer(make_client):
    client = make_client("lecteur")
    assert client.get("/").status_code == 200
    assert client.get("/upload").status_code == 403
    r = client.post("/upload")
    assert r.status_code == 403
    assert r.get_json()["error"] == "forbidden"


@pytest.mark.parametrize("role", ["analyste", "admin"])
def test_analyste_et_admin_ouvrent_l_import(make_client, role):
    assert make_client(role).get("/upload").status_code == 200


def test_role_inconnu_sans_droits(make_client):
    r = make_client("invite").get("/")
    assert r.status_code == 403


def test_deja_connecte_quitte_la_page_de_connexion(make_client):
    r = make_client("lecteur").get("/login?next=/upload")
    assert r.status_code == 302
    assert r.headers["Location"] == "/upload"


def test_next_externe_ignore(make_client):
    html = make_client().get("/login?next=//evil.example").get_data(as_text=True)
    assert "evil.example" not in html


def test_navbar_selon_le_role(make_client):
    lecteur = make_client("lecteur").get("/").get_data(as_text=True)
    assert "Se déconnecter" in lecteur
    assert "Import de logs" not in lecteur
    analyste = make_client("analyste").get("/").get_data(as_text=True)
    assert "Import de logs" in analyste


@pytest.mark.parametrize("value,expected", [
    ("/upload", "/upload"),
    ("/api/v1/logs?q=x", "/api/v1/logs?q=x"),
    ("//evil.example", "/"),
    ("https://evil.example", "/"),
    ("/\\evil.example", "/"),
    ("", "/"),
])
def test_safe_next(value, expected):
    assert safe_next(value) == expected


def test_niveaux_de_role():
    assert role_level({"role": "admin"}) > role_level({"role": "analyste"}) > role_level({"role": "lecteur"})
    assert role_level({"role": "x"}) == 0
    assert role_level(None) == 0
    assert required_level("/upload", "GET") == required_level("/x", "POST") > required_level("/x", "GET")


def test_liste_noire_reservee_aux_admins(make_client):
    r = make_client("analyste").get("/api/v1/blacklist")
    assert r.status_code == 403
    assert r.get_json()["error"] == "forbidden"
