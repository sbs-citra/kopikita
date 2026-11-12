"""Test negatif remediasi Lab L2.3: py/sql-injection (CWE-89) di api/app.py fungsi login."""
import pytest


@pytest.mark.parametrize(
    "username",
    [
        "alice' OR '1'='1' --",
        "alice' --",
        "' OR 1=1 --",
        "x' UNION SELECT 1, 'alice' --",
    ],
)
def test_login_sql_injection_ditolak(client, username):
    resp = client.post("/login", json={"username": username, "password": "apa-saja"})
    assert resp.status_code == 401
    assert "auth" not in (resp.get_json() or {})


def test_login_username_dengan_kutip_tidak_error(client):
    resp = client.post("/login", json={"username": "o'brien", "password": "x"})
    assert resp.status_code == 401


def test_login_sah_tetap_berhasil(client):
    resp = client.post("/login", json={"username": "budi", "password": "budi123"})
    assert resp.status_code == 200
    assert resp.get_json()["user"]["username"] == "budi"
