from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_index_and_headers():
    r = client.get("/")
    assert r.status_code == 200 and "Scrubber" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_scrub_endpoint():
    r = client.post("/api/scrub", json={"text": "Server=10.1.2.3;Password=x1", "categories": ["ip"]})
    body = r.json()
    assert body["text"] == "Server=*REDACTED*;Password=x1"
    assert body["counts"] == {"ip": 1}


def test_save_settings(tmp_path, monkeypatch):
    import app.main as m
    monkeypatch.setattr(m, "CONFIG_DIR", tmp_path)
    (tmp_path / "sensitive_keys.txt").write_text("# header\nOldKey\n", encoding="utf-8")
    r = client.put("/api/settings", json={
        "custom_keys": ["NoReplyDisplayName", "ShellTitle", "shelltitle", " "],
        "custom_terms": ["Kommunen AB"],
        "allowlist": ["login.microsoftonline.com", "*.sokigo.com"],
    })
    assert r.status_code == 200
    assert (tmp_path / "sensitive_keys.txt").read_text(encoding="utf-8") == "# header\nNoReplyDisplayName\nShellTitle\n"
    assert (tmp_path / "allowlist.txt").read_text(encoding="utf-8") == "*.sokigo.com\n"
    d = client.get("/api/defaults").json()
    assert d["custom_keys"] == ["NoReplyDisplayName", "ShellTitle"]
    assert d["custom_terms"] == ["Kommunen AB"]
    assert "*.sokigo.com" in d["allowlist"]


def test_defaults():
    d = client.get("/api/defaults").json()
    assert any(c["id"] == "tenant_id" for c in d["categories"])
    assert "login.microsoftonline.com" in d["allowlist"]
