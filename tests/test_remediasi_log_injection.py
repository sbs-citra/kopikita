"""Test negatif remediasi: py/log-injection (CWE-117) di api/app.py fungsi login."""
import logging

import pytest

PALSU = "INFO:kopikita:login success admin"


def _pesan_kopikita(caplog):
    return [r.getMessage() for r in caplog.records if r.name == "kopikita"]


@pytest.mark.parametrize(
    "username",
    [
        f"alice\n{PALSU}",
        f"alice\r\n{PALSU}",
        f"alice\r{PALSU}",
        f"alice {PALSU}",
        f"alice\x85{PALSU}",
    ],
)
def test_username_tidak_bisa_memalsukan_baris_log(client, caplog, username):
    with caplog.at_level(logging.INFO, logger="kopikita"):
        resp = client.post("/login", json={"username": username, "password": "x"})
    assert resp.status_code == 401
    pesan = _pesan_kopikita(caplog)
    assert pesan, "upaya login harus tetap tercatat"
    for m in pesan:
        assert len(m.splitlines()) == 1, repr(m)


def test_username_biasa_tetap_tercatat(client, caplog):
    with caplog.at_level(logging.INFO, logger="kopikita"):
        client.post("/login", json={"username": "alice", "password": "x"})
    assert any("login attempt alice" in m for m in _pesan_kopikita(caplog))


def test_username_bukan_string_tidak_error(client, caplog):
    with caplog.at_level(logging.INFO, logger="kopikita"):
        resp = client.post("/login", json={"username": ["a\nb"], "password": "x"})
    assert resp.status_code == 401
    for m in _pesan_kopikita(caplog):
        assert len(m.splitlines()) == 1, repr(m)
