"""Test negatif remediasi Lab L2.3."""
import pytest

from conftest import auth, login


# --- Alert 1: py/path-injection (CWE-22), api/app.py fungsi invoice ---

@pytest.mark.parametrize(
    "name",
    [
        "../config.py",
        "..%2fconfig.py",
        "/etc/passwd",
        "..\\config.py",
        "invoice-101.txt/../../config.py",
        "",
    ],
)
def test_invoice_path_traversal_ditolak(client, name):
    token = login(client, "alice", "alice123")
    resp = client.get(f"/invoices?file={name}", headers=auth(token))
    assert resp.status_code in (400, 404)
    assert "API_KEY" not in resp.get_data(as_text=True)


def test_invoice_milik_pelanggan_lain_ditolak(client):
    token = login(client, "alice", "alice123")
    resp = client.get("/invoices?file=invoice-102.txt", headers=auth(token))
    assert resp.status_code == 404


def test_invoice_tidak_ada_404(client):
    token = login(client, "alice", "alice123")
    resp = client.get("/invoices?file=invoice-999.txt", headers=auth(token))
    assert resp.status_code == 404


def test_invoice_milik_sendiri_tetap_bisa(client):
    token = login(client, "budi", "budi123")
    resp = client.get("/invoices?file=invoice-102.txt", headers=auth(token))
    assert resp.status_code == 200
    assert "INVOICE KOPIKITA #102" in resp.get_data(as_text=True)
