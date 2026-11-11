# Berkas test untuk rules/kopikita-sql-taint.yaml (jalankan: semgrep --test rules/).
# Anotasi di baris SEBELUM sink:
#   ruleid: kopikita-sql-taint  -> baris berikut HARUS ditandai
#   ok: kopikita-sql-taint      -> baris berikut TIDAK BOLEH ditandai
# Kode ini SENGAJA rentan; jangan diimpor atau dijalankan.
import sqlite3

import kopikita
from flask import Flask, request

app = Flask(__name__)


def get_cursor():
    return sqlite3.connect(":memory:").cursor()


# --- Harus ditandai -------------------------------------------------------


@app.get("/cari")
def args_digabung_string():
    name = request.args.get("name")
    cur = get_cursor()
    # ruleid: kopikita-sql-taint
    cur.execute("SELECT * FROM users WHERE username = '" + name + "'")


@app.get("/kategori")
def args_fstring():
    kategori = request.args.get("category", "")
    cur = get_cursor()
    # ruleid: kopikita-sql-taint
    cur.execute(f"SELECT * FROM products WHERE category = '{kategori}'")


@app.post("/login")
def get_json_lewat_variabel():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    query = "SELECT id FROM users WHERE username = '" + username + "'"
    cur = get_cursor()
    # ruleid: kopikita-sql-taint
    cur.execute(query)


# --- Tidak boleh ditandai -------------------------------------------------


@app.get("/user")
def query_berparameter():
    name = request.args.get("name")
    cur = get_cursor()
    # ok: kopikita-sql-taint
    cur.execute("SELECT * FROM users WHERE username = ?", (name,))


@app.post("/user-json")
def get_json_berparameter():
    data = request.get_json(silent=True) or {}
    cur = get_cursor()
    # ok: kopikita-sql-taint
    cur.execute("SELECT * FROM users WHERE username = ?", (data.get("username"),))


@app.get("/products")
def tersanitasi_safe_sql():
    sort = kopikita.safe_sql(request.args.get("sort", "name"))
    cur = get_cursor()
    # ok: kopikita-sql-taint
    cur.execute(f"SELECT * FROM products ORDER BY {sort}")


@app.get("/konstan")
def query_konstan():
    cur = get_cursor()
    # ok: kopikita-sql-taint
    cur.execute("SELECT COUNT(*) FROM users")
