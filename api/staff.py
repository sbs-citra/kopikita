"""Login staf (barista) KopiKita.

Keputusan keamanan:
- Semua query berparameter (placeholder ``?``); input tidak pernah disusun ke dalam SQL.
- Password disimpan sebagai PBKDF2-SHA256 600.000 iterasi (werkzeug.security, salt acak).
- Rate limit: maksimal 5 percobaan gagal per username per 15 menit, lalu 429.
- Password tidak pernah dicatat ke log; pesan error sama untuk username dan password yang salah.
"""
import functools
import hashlib
import logging
import secrets
import time

from flask import Blueprint, current_app, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from db import connect

log = logging.getLogger("kopikita.staff")

bp = Blueprint("staff", __name__, url_prefix="/staff")

PASSWORD_METHOD = "pbkdf2:sha256:600000"  # nama algoritma, bukan rahasia  # pragma: allowlist secret
MAX_FAILURES = 5
WINDOW_SECONDS = 15 * 60
MAX_USERNAME_LEN = 64
MAX_PASSWORD_LEN = 1024
GENERIC_ERROR = "username atau password salah"

STAFF_SCHEMA = """
CREATE TABLE IF NOT EXISTS staff (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS staff_login_failures (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_staff_login_failures_username_ts
    ON staff_login_failures (username, ts);
CREATE TABLE IF NOT EXISTS staff_sessions (
    token_hash TEXT PRIMARY KEY,
    staff_id INTEGER NOT NULL REFERENCES staff(id),
    created_at REAL NOT NULL
);
"""


def init_staff_db(path):
    """Membuat tabel staf bila belum ada."""
    conn = connect(path)
    conn.executescript(STAFF_SCHEMA)
    conn.close()


def normalize_username(username):
    return username.strip().lower()


def create_staff(conn, username, password, full_name):
    """Menambah akun staf dengan hash PBKDF2-SHA256 600.000 iterasi."""
    conn.execute(
        "INSERT INTO staff (username, password_hash, full_name) VALUES (?, ?, ?)",
        (
            normalize_username(username),
            generate_password_hash(password, method=PASSWORD_METHOD),
            full_name,
        ),
    )
    conn.commit()


@functools.lru_cache(maxsize=1)
def _dummy_hash():
    # Dipakai saat username tidak ada agar waktu respons setara (anti-enumerasi).
    return generate_password_hash(secrets.token_urlsafe(16), method=PASSWORD_METHOD)


def _now():
    return time.time()


def _db():
    # Memakai kunci g.db yang sama dengan app.get_db, sehingga ditutup oleh teardown app.
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def _recent_failures(db, username):
    return db.execute(
        "SELECT COUNT(*) FROM staff_login_failures WHERE username = ? AND ts > ?",
        (username, _now() - WINDOW_SECONDS),
    ).fetchone()[0]


@bp.post("/login")
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="permintaan tidak valid"), 400
    username = data.get("username")
    password = data.get("password")
    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or not username.strip()
        or not password
        or len(username) > MAX_USERNAME_LEN
        or len(password) > MAX_PASSWORD_LEN
    ):
        return jsonify(error="permintaan tidak valid"), 400

    key = normalize_username(username)
    db = _db()

    # Cek rate limit SEBELUM menghitung hash: percobaan ke-6 ditolak walau password benar.
    if _recent_failures(db, key) >= MAX_FAILURES:
        log.warning("staff login diblokir rate limit username=%r", key)
        resp = jsonify(error="terlalu banyak percobaan, coba lagi nanti")
        return resp, 429, {"Retry-After": str(WINDOW_SECONDS)}

    row = db.execute(
        "SELECT id, username, password_hash, full_name FROM staff WHERE username = ?",
        (key,),
    ).fetchone()

    if row is None:
        check_password_hash(_dummy_hash(), password)  # samakan waktu respons
        ok = False
    else:
        ok = check_password_hash(row["password_hash"], password)

    if not ok:
        db.execute(
            "INSERT INTO staff_login_failures (username, ts) VALUES (?, ?)", (key, _now())
        )
        db.commit()
        log.info("staff login gagal username=%r", key)
        return jsonify(error=GENERIC_ERROR), 401

    db.execute("DELETE FROM staff_login_failures WHERE username = ?", (key,))
    token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO staff_sessions (token_hash, staff_id, created_at) VALUES (?, ?, ?)",
        (hashlib.sha256(token.encode("utf-8")).hexdigest(), row["id"], _now()),
    )
    db.commit()
    log.info("staff login berhasil username=%r", key)
    return jsonify(
        auth={"token": token},
        staff={"username": row["username"], "full_name": row["full_name"]},
    )
