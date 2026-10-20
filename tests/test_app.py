import json
import app as webshield


def test_homepage(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"WebShield" in response.data
    assert b"viewport" in response.data.lower()


def test_about_page(client):
    response = client.get("/about")
    assert response.status_code == 200
    assert b"Methodology" in response.data


def test_custom_404(client):
    response = client.get("/this-page-does-not-exist")
    assert response.status_code == 404
    assert b"404" in response.data


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "ok"


def test_scan_requires_authorization(client):
    response = client.post(
        "/api/scan", json={"url": "https://example.com", "authorized": False}
    )
    assert response.status_code == 400
    assert "permission" in response.json["error"].lower()


def test_url_normalization_blocks_non_http():
    try:
        webshield.normalize_url("file:///etc/passwd")
        assert False, "Expected URL validation to fail"
    except ValueError:
        pass


def test_url_normalization_blocks_embedded_credentials():
    try:
        webshield.normalize_url("https://user:password@example.com")
        assert False, "Expected URL validation to fail"
    except ValueError:
        pass


def test_report_not_found(client):
    response = client.get("/api/report/999999")
    assert response.status_code == 404


def test_url_normalization_blocks_ftp():
    try:
        webshield.normalize_url("ftp://example.com")
        assert False, "Expected unsupported scheme to be rejected"
    except ValueError:
        pass


def test_url_normalization_blocks_file_scheme():
    try:
        webshield.normalize_url("file:///etc/passwd")
        assert False, "Expected file scheme to be rejected"
    except ValueError:
        pass


def test_url_normalization_blocks_invalid_port():
    try:
        webshield.normalize_url("https://example.com:99999")
        assert False, "Expected invalid port to be rejected"
    except ValueError:
        pass


def test_url_normalization_accepts_https():
    result = webshield.normalize_url("https://example.com")
    assert result == "https://example.com"


def test_assert_public_target_blocks_loopback():
    try:
        webshield.assert_public_target("http://127.0.0.1")
        assert False, "Expected loopback target to be blocked"
    except ValueError:
        pass


def test_assert_public_target_blocks_private_ip():
    try:
        webshield.assert_public_target("http://192.168.1.1")
        assert False, "Expected private IP to be blocked"
    except ValueError:
        pass


def test_assert_public_target_blocks_localhost():
    try:
        webshield.assert_public_target("http://localhost")
        assert False, "Expected localhost to be blocked"
    except ValueError:
        pass
