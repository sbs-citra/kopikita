"""API toko kopi KopiKita.

PERINGATAN: aplikasi ini SENGAJA rentan untuk pelatihan Secure Code AI Development.
Hanya jalankan di laptop atau runner CI milik sendiri.
"""
import functools
import logging
import os
import re
import secrets

from flask import Flask, abort, g, jsonify, request

import config
import kopikita
from db import connect, init_db

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("kopikita")

INVOICE_NAME = re.compile(r"invoice-(\d{1,9})\.txt")
DUMMY_PASSWORD_HASH = kopikita.hash_password(secrets.token_urlsafe(16))


def untuk_log(value):
    """Netralkan input pengguna sebelum masuk log agar tidak bisa memalsukan baris (CWE-117).

    Karakter tak tercetak (termasuk \\r, \\n, \\u2028, \\x85) diganti "?". replace() di akhir
    redundan secara fungsi, tetapi itulah pola sanitizer yang dikenali CodeQL py/log-injection.
    """
    if not isinstance(value, str):
        value = repr(value)
    value = "".join(ch if ch.isprintable() else "?" for ch in value[:200])
    return value.replace("\r", "").replace("\n", "")

app = Flask(__name__)
app.config.from_object(config)

import staff
staff.register(app)


def get_db():
    if "db" not in g:
        g.db = connect(app.config["DATABASE"])
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def current_user():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[len("Bearer "):]
    return get_db().execute(
        "SELECT users.id, users.username, users.full_name FROM sessions "
        "JOIN users ON users.id = sessions.user_id WHERE sessions.token = ?",
        (token,),
    ).fetchone()


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return jsonify(error="perlu login"), 401
        g.user = user
        return view(*args, **kwargs)

    return wrapper


@app.errorhandler(ValueError)
def bad_value(exc):
    return jsonify(error=str(exc)), 400


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    # Password tidak pernah dicatat (aturan 3 CLAUDE.md); cukup username untuk jejak audit.
    log.info("login attempt %s", untuk_log(username))
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="username atau password salah"), 401
    # Query berparameter: input pengguna dikirim sebagai data, bukan bagian dari SQL.
    # Hash bersalt tidak bisa dicocokkan di SQL, jadi ambil hash lalu verifikasi di Python.
    row = get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    # Username tak dikenal tetap menjalankan verifikasi (hash dummy) agar waktu respons setara.
    stored = row["password_hash"] if row is not None else DUMMY_PASSWORD_HASH
    if not kopikita.verify_password(password, stored) or row is None:
        return jsonify(error="username atau password salah"), 401
    token = secrets.token_urlsafe(24)
    get_db().execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, row["id"]))
    get_db().commit()
    return jsonify(auth={"token": token}, user={"username": row["username"]})


@app.get("/products")
def products():
    sort = kopikita.safe_sql(request.args.get("sort", "name"))
    cur = get_db().cursor()
    cur.execute(f"SELECT id, name, price, category FROM products ORDER BY {sort}")
    return jsonify(products=[dict(r) for r in cur.fetchall()])


@app.get("/orders")
@login_required
def my_orders():
    rows = get_db().execute(
        "SELECT id, items, total, status FROM orders WHERE user_id = ? ORDER BY id",
        (g.user["id"],),
    ).fetchall()
    return jsonify(orders=[dict(r) for r in rows])


@app.get("/orders/<int:order_id>")
@login_required
def order_detail(order_id):
    # RENTAN: sudah login, tetapi tidak memeriksa pemilik pesanan (BOLA, API1:2023)
    row = get_db().execute(
        "SELECT id, user_id, items, total, status FROM orders WHERE id = ?", (order_id,)
    ).fetchone()
    if row is None:
        abort(404)
    return jsonify(order=dict(row))


@app.get("/invoices")
@login_required
def invoice():
    name = request.args.get("file", "")
    # Hanya nama berkas polos invoice-<angka>.txt; tolak separator, "..", path absolut.
    match = INVOICE_NAME.fullmatch(name)
    if match is None:
        return jsonify(error="nama berkas invoice tidak valid"), 400
    order_id = int(match.group(1))
    # Hanya pemilik pesanan yang boleh membaca invoice-nya (cegah BOLA).
    owner = get_db().execute(
        "SELECT 1 FROM orders WHERE id = ? AND user_id = ?",
        (order_id, g.user["id"]),
    ).fetchone()
    if owner is None:
        abort(404)
    # Nama berkas disusun ulang dari order_id (int), bukan dari input mentah.
    filename = f"invoice-{order_id}.txt"
    # Lapisan kedua: path hasil normalisasi wajib tetap di dalam INVOICE_DIR.
    base = os.path.realpath(app.config["INVOICE_DIR"])
    path = os.path.realpath(os.path.join(base, filename))
    if not path.startswith(base + os.sep) or not os.path.isfile(path):
        return jsonify(error="invoice tidak ditemukan"), 404
    with open(path, encoding="utf-8") as fh:
        return fh.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}


if __name__ == "__main__":
    init_db(app.config["DATABASE"])
    # Debugger Werkzeug selalu mati (debug=False juga menimpa FLASK_DEBUG=1).
    # Default hanya localhost; container mengatur KOPIKITA_HOST=0.0.0.0 secara eksplisit.
    app.run(host=os.environ.get("KOPIKITA_HOST", "127.0.0.1"), port=5000, debug=False)
