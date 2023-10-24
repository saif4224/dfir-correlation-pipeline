from dfir_pipeline.correlate.ioc_matcher import IOCWatchlist


def test_matches_known_ip():
    watchlist = IOCWatchlist()
    match = watchlist.match("ip", "203.0.113.42")
    assert match is not None
    assert match.severity == 8


def test_matches_known_domain_by_substring():
    watchlist = IOCWatchlist()
    match = watchlist.match("domain", "update-check.example-c2.test")
    assert match is not None


def test_no_match_for_unknown_value():
    watchlist = IOCWatchlist()
    assert watchlist.match("ip", "10.0.0.1") is None


def test_match_any_field_returns_all_hits():
    watchlist = IOCWatchlist()
    matches = watchlist.match_any_field("readme.txt", "invoice.pdf.exe", ioc_type="filename")
    assert len(matches) == 1
    assert matches[0].value == "invoice.pdf.exe"


def test_empty_value_never_matches():
    watchlist = IOCWatchlist()
    assert watchlist.match("ip", "") is None
