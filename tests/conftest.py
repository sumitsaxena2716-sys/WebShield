import os
import tempfile
import pytest
import app as webshield


@pytest.fixture()
def client(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    monkeypatch.setattr(webshield, "DATABASE_PATH", path)
    webshield.init_db()
    webshield.app.config.update(TESTING=True, RATELIMIT_ENABLED=False)
    with webshield.app.test_client() as client:
        yield client
    try:
        os.remove(path)
    except OSError:
        pass
