"""Test negatif remediasi: py/clear-text-logging-sensitive-data (CWE-312) di api/app.py fungsi login."""
import logging

import pytest

PENANDA = "rahasia-unik-L2-3-xyz"  # pragma: allowlist secret (penanda uji, bukan rahasia)


@pytest.mark.parametrize("username", ["alice", "tidak-ada"])
def test_password_salah_tidak_masuk_log(client, caplog, username):
    with caplog.at_level(logging.DEBUG):
        resp = client.post("/login", json={"username": username, "password": PENANDA})
    assert resp.status_code == 401
    assert PENANDA not in caplog.text


def test_password_benar_tidak_masuk_log(client, caplog):
    with caplog.at_level(logging.DEBUG):
        resp = client.post("/login", json={"username": "alice", "password": "alice123"})  # pragma: allowlist secret
    assert resp.status_code == 200
    assert "alice123" not in caplog.text


def test_upaya_login_tetap_tercatat(client, caplog):
    """Log audit tetap ada (berguna untuk deteksi brute force), hanya tanpa password."""
    with caplog.at_level(logging.INFO, logger="kopikita"):
        client.post("/login", json={"username": "alice", "password": PENANDA})
    assert "login attempt" in caplog.text
