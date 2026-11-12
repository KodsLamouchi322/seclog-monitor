from .es import INDEX

MAX_SIZE = 100
MAX_WINDOW = 10000
SORT_FIELDS = {"date": "@timestamp", "severity": "severity_score"}
TERM_FILTERS = {
    "event_type": "event.type",
    "result": "result",
    "severity": "severity",
}


def build_query(params: dict) -> dict:
    must, filters = [], []
    q = (params.get("q") or "").strip()
    if q:
        must.append({"match": {"message": {"query": q, "operator": "and"}}})
    for key, field in TERM_FILTERS.items():
        value = (params.get(key) or "").strip().lower()
        if value:
            filters.append({"term": {field: value}})
    ip = (params.get("ip") or "").strip()
    if ip:
        filters.append({"term": {"source.ip": ip}})
    country = (params.get("country") or "").strip().upper()
    if country:
        filters.append({"term": {"source.geo.country_iso_code": country}})
    rng = {}
    if params.get("date_from"):
        rng["gte"] = params["date_from"]
    if params.get("date_to"):
        rng["lte"] = params["date_to"]
    if rng:
        filters.append({"range": {"@timestamp": rng}})
    if not must and not filters:
        return {"match_all": {}}
    return {"bool": {"must": must, "filter": filters}}


def parse_paging(params: dict):
    try:
        page = max(1, int(params.get("page", 1)))
        size = min(MAX_SIZE, max(1, int(params.get("size", 20))))
    except (TypeError, ValueError):
        raise ValueError("page et size doivent être des entiers.")
    if page * size > MAX_WINDOW:
        raise ValueError(f"Pagination limitée à {MAX_WINDOW} résultats.")
    return page, size


def run_search(es, params: dict) -> dict:
    page, size = parse_paging(params)
    sort_key = params.get("sort", "date")
    if sort_key not in SORT_FIELDS:
        raise ValueError("sort doit valoir : " + ", ".join(SORT_FIELDS))
    order = "asc" if params.get("order") == "asc" else "desc"
    res = es.search(
        index=INDEX,
        query=build_query(params),
        sort=[{SORT_FIELDS[sort_key]: {"order": order}}],
        from_=(page - 1) * size,
        size=size,
        track_total_hits=True,
    )
    hits = [{"id": h["_id"], **h["_source"]} for h in res["hits"]["hits"]]
    total = res["hits"]["total"]["value"]
    return {
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size,
        "took_ms": res["took"],
        "results": hits,
    }
