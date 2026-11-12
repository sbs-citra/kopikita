"""Test negatif remediasi: py/weak-sensitive-data-hashing (CWE-916) di api/kopikita/__init__.py."""
import pathlib
import re
import sqlite3

import pytest

import kopikita

KOPIKITA_SRC = pathlib.Path(kopikita.__file__).read_text(encoding="utf-8")


def test_hash_memakai_pbkdf2_600rb_iterasi():
    assert kopikita.hash_password("rahasia").startswith("pbkdf2:sha256:600000$")


def test_hash_bukan_md5_hex():
    assert not re.fullmatch(r"[0-9a-f]{32}", kopikita.hash_password("rahasia"))


def test_hash_bersalt_berbeda_untuk_password_sama():
    assert kopikita.hash_password("rahasia") != kopikita.hash_password("rahasia")


def test_verify_password_benar_dan_salah():
    stored = kopikita.hash_password("rahasia")
    assert kopikita.verify_password("rahasia", stored) is True
    assert kopikita.verify_password("salah", stored) is False


def test_md5_tidak_dipakai_lagi():
    assert "md5" not in KOPIKITA_SRC.lower()


def test_hash_di_database_kuat(client):
    from app import app as flask_app

    conn = sqlite3.connect(flask_app.config["DATABASE"])
    hashes = [r[0] for r in conn.execute("SELECT password_hash FROM users")]
    conn.close()
    assert hashes
    for h in hashes:
        assert h.startswith("pbkdf2:sha256:600000$")


@pytest.mark.parametrize(
    "payload",
    [
        {"username": "alice", "password": "salah"},  # pragma: allowlist secret (akun uji)
        {"username": "tidak-ada", "password": "alice123"},  # pragma: allowlist secret (akun uji)
        {"username": "alice", "password": ""},
        {"username": "alice", "password": 12345},
        {"username": ["alice"], "password": "alice123"},  # pragma: allowlist secret (akun uji)
    ],
)
def test_login_gagal_tetap_401(client, payload):
    resp = client.post("/login", json=payload)
    assert resp.status_code == 401
