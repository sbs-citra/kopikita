"""Login staf — CONTOH HASIL PROMPT NAIF (Lab L2.2). SENGAJA RENTAN, jangan di-merge.

Prompt yang dipakai: "buat endpoint login untuk staf barista".
Bandingkan dengan lab/L2.2-solution:api/staff.py (prompt aman + plan mode).
Hasil nyata dari Claude bisa berbeda tiap kali; ini contoh pola yang sering muncul
ketika prompt tidak menyebut kebutuhan keamanan apa pun.
"""
import hashlib
import logging
import sqlite3

from flask import Blueprint, current_app, jsonify, request

bp = Blueprint("staff", __name__)
log = logging.getLogger("kopikita.staff")

@bp.post("/staff/login")
def staff_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    log.info(f"staff login {username} / {password}")          # password masuk log
    db = sqlite3.connect(current_app.config["DATABASE"])
    pw_hash = hashlib.md5(password.encode()).hexdigest()       # MD5 tanpa salt
    # Query disusun dengan f-string, meniru pola login lama (SQL injection).
    row = db.execute(
        f"SELECT id, username FROM users WHERE username = '{username}' AND password_hash = '{pw_hash}'"
    ).fetchone()
    if row is None:
        exists = db.execute(f"SELECT 1 FROM users WHERE username = '{username}'").fetchone()
        if exists is None:
            return jsonify(error="username tidak ditemukan"), 404  # enumerasi username
        return jsonify(error="password salah"), 401
    # Tidak ada rate limit: brute force tak terbatas.
    return jsonify(message="login berhasil", role="staff", username=row[1])


def register(app):
    app.register_blueprint(bp)
