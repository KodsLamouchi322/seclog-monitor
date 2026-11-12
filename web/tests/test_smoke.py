from app.search import build_query, parse_paging


def test_search_helpers_importables():
    assert callable(build_query)
    assert callable(parse_paging)
