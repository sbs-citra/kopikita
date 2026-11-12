"""Test negatif remediasi Lab L2.3: py/flask-debug (CWE-215/489) di api/app.py blok __main__."""
import ast
import pathlib
import runpy

import pytest

APP_PY = pathlib.Path(__file__).resolve().parent.parent / "api" / "app.py"


def _app_run_calls():
    tree = ast.parse(APP_PY.read_text(encoding="utf-8"))
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "app"
    ]


def test_app_run_ada():
    assert len(_app_run_calls()) == 1


def test_app_run_tanpa_debug_true():
    for call in _app_run_calls():
        for kw in call.keywords:
            if kw.arg == "debug":
                assert isinstance(kw.value, ast.Constant) and kw.value.value is False


def test_app_run_tidak_hardcode_semua_interface():
    for call in _app_run_calls():
        for kw in call.keywords:
            if kw.arg == "host":
                assert not (isinstance(kw.value, ast.Constant) and kw.value.value == "0.0.0.0")


@pytest.mark.parametrize("env", [{}, {"FLASK_DEBUG": "1"}])
def test_main_menjalankan_tanpa_debugger(monkeypatch, env):
    """Jalankan blok __main__ dengan app.run disadap; debugger harus mati walau FLASK_DEBUG=1."""
    import flask

    import db

    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("KOPIKITA_HOST", raising=False)
    # Jangan menyentuh database asli saat blok __main__ dijalankan.
    monkeypatch.setattr(db, "init_db", lambda path: None)
    captured = {}

    def fake_run(self, host=None, port=None, debug=None, **options):
        captured.update(host=host, port=port, debug=debug)

    monkeypatch.setattr(flask.Flask, "run", fake_run)
    runpy.run_path(str(APP_PY), run_name="__main__")
    assert captured["debug"] is False
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 5000
