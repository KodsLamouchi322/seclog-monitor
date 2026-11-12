from flask import Flask

from app.ratelimit import client_ip


def _ctx(headers=None, addr="10.0.0.1"):
    app = Flask("t")
    return app.test_request_context(
        "/", headers=headers or {}, environ_base={"REMOTE_ADDR": addr}
    )


def test_client_ip_sans_proxy_ignore_x_forwarded_for():
    with _ctx({"X-Forwarded-For": "1.2.3.4"}):
        assert client_ip(False) == "10.0.0.1"


def test_client_ip_proxy_de_confiance_prend_la_premiere_adresse():
    with _ctx({"X-Forwarded-For": "1.2.3.4, 10.0.0.9"}):
        assert client_ip(True) == "1.2.3.4"


def test_client_ip_proxy_sans_en_tete_retombe_sur_remote_addr():
    with _ctx():
        assert client_ip(True) == "10.0.0.1"
