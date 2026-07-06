"""Unit tests for the defang layer."""

from threatintel_mcp.sanitize import defang, defang_deep


def test_defang_url_scheme():
    assert defang("http://evil.test/path") == "hxxp://evil[.]test/path"
    assert defang("https://a.b.example.com") == "hxxps://a[.]b[.]example[.]com"


def test_defang_ipv4():
    assert defang("connect to 8.8.8.8 now") == "connect to 8[.]8[.]8[.]8 now"


def test_defang_bare_domain():
    assert defang("evil-domain.com") == "evil-domain[.]com"


def test_defang_leaves_prose_ellipsis_alone():
    # No alphanumeric on both sides of these dots, so they stay.
    assert defang("wait... ok") == "wait... ok"


def test_defang_deep_nested():
    payload = {
        "url": "http://bad.test",
        "ips": ["1.2.3.4", "5.6.7.8"],
        "meta": {"domain": "phish.example"},
        "count": 3,
    }
    out = defang_deep(payload)
    assert out["url"] == "hxxp://bad[.]test"
    assert out["ips"] == ["1[.]2[.]3[.]4", "5[.]6[.]7[.]8"]
    assert out["meta"]["domain"] == "phish[.]example"
    assert out["count"] == 3  # non-strings untouched
