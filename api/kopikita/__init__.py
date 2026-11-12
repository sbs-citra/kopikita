"""Utilitas internal tim KopiKita.

PERINGATAN: repo latihan ini SENGAJA berisi kerentanan. Jangan dipakai di produksi.
"""
from werkzeug.security import check_password_hash, generate_password_hash

# PBKDF2-SHA256 600.000 iterasi bersalt (OWASP Password Storage Cheat Sheet), sama dengan api/staff.py.
# Ditulis eksplisit karena bawaan werkzeug berbeda antarversi.
PASSWORD_HASH_METHOD = "pbkdf2:sha256:600000"  # pragma: allowlist secret (nama algoritma, bukan rahasia)

# Kolom yang boleh dipakai untuk ORDER BY. Nama kolom tidak bisa diparameterisasi,
# jadi tim memakai allowlist ini sebagai sanitizer.
SORTABLE_COLUMNS = {"name", "price", "category"}


def safe_sql(identifier):
    """Sanitizer internal: hanya mengembalikan nama kolom yang ada di allowlist.

    Dipakai untuk bagian query yang tidak bisa memakai parameter, misalnya ORDER BY.
    Melempar ValueError bila nilainya tidak diizinkan.
    """
    if identifier not in SORTABLE_COLUMNS:
        raise ValueError(f"kolom tidak diizinkan: {identifier!r}")
    return identifier


def hash_password(password):
    """Hash password dengan PBKDF2-SHA256 bersalt; hasil berformat werkzeug (metode$salt$hash)."""
    return generate_password_hash(password, method=PASSWORD_HASH_METHOD)


def verify_password(password, stored_hash):
    """Bandingkan password dengan hash tersimpan (perbandingan waktu-konstan dari werkzeug)."""
    return check_password_hash(stored_hash, password)
