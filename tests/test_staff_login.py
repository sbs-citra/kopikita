"""Test login staf: fungsional dan negatif (SQLi, rate limit, log, enumerasi)."""
import logging

import pytest

from app import app as flask_app
from db import connect
from staff import GENERIC_ERROR, create_staff, init_staff_db

USERNAME = "barista1"
PASSWORD = "KopiPanas!2026"  # akun uji khusus test  # pragma: allowlist secret


@pytest.fixture
def staff_client(client):
    db_path = flask_app.config["DATABASE"]
    init_staff_db(db_path)
    conn = connect(db_path)
    create_staff(conn, USERNAME, PASSWORD, "Sari Barista")
    conn.close()
    return client


def staff_login(client, username, password):
    return client.post("/staff/login", json={"username": username, "password": password})


def test_login_staf_berhasil(staff_client):
    resp = staff_login(staff_client, USERNAME, PASSWORD)
    assert resp.status_code == 200
    assert len(resp.get_json()["auth"]["token"]) > 20
    conn = connect(flask_app.config["DATABASE"])
    stored = conn.execute("SELECT password_hash FROM staff WHERE username = ?", (USERNAME,)).fetchone()
    conn.close()
    assert stored["password_hash"].startswith("pbkdf2:sha256:600000$")


def test_password_salah_401(staff_client):
    resp = staff_login(staff_client, USERNAME, "salah")
    assert resp.status_code == 401
    assert resp.get_json() == {"error": GENERIC_ERROR}


def test_username_tidak_ada_pesan_sama(staff_client):
    salah_pw = staff_login(staff_client, USERNAME, "salah")
    tidak_ada = staff_login(staff_client, "tidakada", "salah")
    assert tidak_ada.status_code == salah_pw.status_code == 401
    assert tidak_ada.get_json() == salah_pw.get_json()


def test_injeksi_sql_401(staff_client):
    injeksi = "' OR '1'='1' --"
    assert staff_login(staff_client, injeksi, "apa saja").status_code == 401
    assert staff_login(staff_client, USERNAME, injeksi).status_code == 401


def test_percobaan_keenam_429(staff_client):
    for _ in range(5):
        assert staff_login(staff_client, USERNAME, "salah").status_code == 401
    # Percobaan ke-6 ditolak walaupun password benar.
    resp = staff_login(staff_client, USERNAME, PASSWORD)
    assert resp.status_code == 429
    assert resp.headers["Retry-After"] == "900"


def test_password_tidak_di_log(staff_client, caplog):
    caplog.set_level(logging.DEBUG)
    salah = "TebakanRahasia#99"
    staff_login(staff_client, USERNAME, salah)
    staff_login(staff_client, USERNAME, PASSWORD)
    assert USERNAME in caplog.text  # log memang tertangkap
    assert salah not in caplog.text
    assert PASSWORD not in caplog.text
