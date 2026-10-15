"""The page renders every case, and the dangerous cases stay inert."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app  # noqa: E402


def test_every_case_renders_both_columns():
    for case_id, case in app.CASES.items():
        for value in (case["normal"], case["attack"]):
            body = app.page(case_id, value)
            assert "Ordinary Python" in body and "es-python, network source on" in body
            assert case["sink"] in body
            assert "" not in body and "" not in body


def test_sql_injection_returns_every_user():
    _, outcome, rows = app.run_sqli("x' OR '1'='1")
    assert len(rows) == 3 and "3 rows" in outcome


def test_sql_is_limited_to_the_demo_table():
    for payload in ("x' UNION SELECT name, sql, 1, 2 FROM sqlite_master --",
                    "x' OR load_extension('x') --",
                    "x'; ATTACH DATABASE '/tmp/x' AS x --"):
        _, outcome, rows = app.run_sqli(payload)
        assert rows is None, payload


def test_command_and_path_cases_never_execute(monkeypatch):
    import builtins
    import subprocess

    def boom(*a, **k):
        raise AssertionError("must not run")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(os, "system", boom)
    monkeypatch.setattr(builtins, "open", boom)
    app.run_cmd("127.0.0.1; id")
    _, outcome, _ = app.run_path("../../../../etc/passwd")
    assert "outside" in outcome


def test_input_is_escaped():
    body = app.page("cmd", "<script>alert(1)</script>")
    assert "<script>alert(1)</script>" not in body
