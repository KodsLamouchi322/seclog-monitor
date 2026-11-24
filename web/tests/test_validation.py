import json

import pytest

from app.validation import ValidationError, validate_file

ALLOWED = {"csv", "json", "txt"}
HEADER = "timestamp,source_ip,event_type,result,severity\n"


def run(name, content, **kw):
    raw = content.encode() if isinstance(content, str) else content
    return validate_file(name, raw, ALLOWED, **kw)


def test_csv_valide():
    info = run("a.csv", HEADER + "2026-11-12T10:00:00Z,1.2.3.4,authentication,failure,high\n")
    assert info["format"] == "csv"
    assert info["total_lines"] == 1 and info["invalid_lines"] == 0
    assert info["preview"][0]["source_ip"] == "1.2.3.4"


def test_csv_ligne_invalide_comptee():
    info = run("a.csv", HEADER + "ok,1.2.3.4,authentication,failure,high\nligne,trop,courte\n")
    assert info["total_lines"] == 2 and info["invalid_lines"] == 1


def test_csv_colonnes_manquantes():
    with pytest.raises(ValidationError, match="Colonnes manquantes"):
        run("a.csv", "timestamp,source_ip\n1,2\n")


def test_apercu_limite():
    rows = "".join(f"{i},1.1.1.1,authentication,failure,low\n" for i in range(30))
    assert len(run("a.csv", HEADER + rows, preview_lines=10)["preview"]) == 10


def test_extension_refusee():
    with pytest.raises(ValidationError, match="Format non autorisé"):
        run("a.pdf", "x")


def test_fichier_vide():
    with pytest.raises(ValidationError, match="vide"):
        run("a.txt", "   \n")


def test_encodage_non_utf8():
    with pytest.raises(ValidationError, match="Encodage"):
        run("a.txt", b"\xff\xfe\x00caf\xe9")


def test_json_ndjson_avec_ligne_invalide():
    info = run("a.json", '{"a": 1}\nnot json\n{"b": 2}\n')
    assert info["total_lines"] == 3 and info["invalid_lines"] == 1 and info["was_array"] is False


def test_json_premiere_ligne_invalide_refusee():
    with pytest.raises(ValidationError, match="ligne 1"):
        run("a.json", "not json\n{\"a\": 1}\n")


def test_json_tableau():
    info = run("a.json", json.dumps([{"a": 1}, {"b": 2}, 3]))
    assert info["was_array"] is True
    assert info["total_lines"] == 3 and info["invalid_lines"] == 1 and len(info["events"]) == 2


def test_json_tableau_invalide():
    with pytest.raises(ValidationError, match="JSON invalide"):
        run("a.json", "[{")


def test_txt_valide():
    info = run("a.txt", "ligne 1\n\nligne 2\n")
    assert info["total_lines"] == 2 and info["preview"] == ["ligne 1", "ligne 2"]
