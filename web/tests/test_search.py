import pytest

from app.search import MAX_SIZE, build_query, parse_paging, run_search


def test_build_query_vide():
    assert build_query({}) == {"match_all": {}}
    assert build_query({"q": "  ", "ip": ""}) == {"match_all": {}}


def test_build_query_texte():
    q = build_query({"q": " failed login "})
    assert q["bool"]["must"] == [
        {"match": {"message": {"query": "failed login", "operator": "and"}}}
    ]
    assert q["bool"]["filter"] == []


def test_build_query_filtres_normalises():
    q = build_query({"severity": " HIGH ", "country": "tn", "ip": "10.0.0.1"})
    f = q["bool"]["filter"]
    assert {"term": {"severity": "high"}} in f
    assert {"term": {"source.geo.country_iso_code": "TN"}} in f
    assert {"term": {"source.ip": "10.0.0.1"}} in f
    assert q["bool"]["must"] == []


def test_build_query_event_type_et_result():
    f = build_query({"event_type": "Login", "result": "FAILURE"})["bool"]["filter"]
    assert {"term": {"event.type": "login"}} in f
    assert {"term": {"result": "failure"}} in f


def test_build_query_plage_dates():
    f = build_query({"date_from": "2026-11-01", "date_to": "2026-11-12"})["bool"]["filter"]
    assert f == [{"range": {"@timestamp": {"gte": "2026-11-01", "lte": "2026-11-12"}}}]
    f = build_query({"date_from": "2026-11-01"})["bool"]["filter"]
    assert f == [{"range": {"@timestamp": {"gte": "2026-11-01"}}}]


def test_parse_paging_defauts():
    assert parse_paging({}) == (1, 20)


def test_parse_paging_bornes():
    assert parse_paging({"page": "0", "size": "0"}) == (1, 1)
    assert parse_paging({"size": "5000"}) == (1, MAX_SIZE)
    assert parse_paging({"page": "-3"}) == (1, 20)


@pytest.mark.parametrize("params", [{"page": "abc"}, {"size": "x"}, {"page": None}])
def test_parse_paging_invalide(params):
    with pytest.raises(ValueError):
        parse_paging(params)


def test_parse_paging_fenetre():
    assert parse_paging({"page": "100", "size": "100"}) == (100, 100)
    with pytest.raises(ValueError):
        parse_paging({"page": "101", "size": "100"})


class FakeES:
    def __init__(self, total=45):
        self.calls = []
        self.total = total

    def search(self, **kw):
        self.calls.append(kw)
        hit = {"_id": "a1", "_source": {"severity": "high"}}
        return {"took": 3, "hits": {"total": {"value": self.total}, "hits": [hit]}}


def test_run_search_pagination_et_tri():
    es = FakeES()
    out = run_search(es, {"page": "2", "size": "10", "sort": "severity", "order": "asc"})
    kw = es.calls[0]
    assert kw["from_"] == 10 and kw["size"] == 10
    assert kw["sort"] == [{"severity_score": {"order": "asc"}}]
    assert out["total"] == 45 and out["pages"] == 5 and out["took_ms"] == 3
    assert out["results"] == [{"id": "a1", "severity": "high"}]


def test_run_search_tri_par_defaut():
    es = FakeES()
    run_search(es, {})
    assert es.calls[0]["sort"] == [{"@timestamp": {"order": "desc"}}]


def test_run_search_sort_invalide():
    es = FakeES()
    with pytest.raises(ValueError):
        run_search(es, {"sort": "nimporte"})
    assert es.calls == []
