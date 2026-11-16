"""Paso 7.2: los scripts de demo recorren el flujo REAL y no mienten (P-08, P-11)."""
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from api.main import app
from core import db
from scripts import bootstrap_demo
from scripts.demo_flow import DemoFlowError, InProcessTransport, enroll, merchant_verifies, sign_mandate


def run_demo(extra_env=None) -> subprocess.CompletedProcess:
    env = {key: value for key, value in os.environ.items() if key not in ("DATABASE_URL", "JWT_SECRET")}
    env.update({"PYTHONIOENCODING": "utf-8", **(extra_env or {})})
    return subprocess.run([sys.executable, "run_demo.py"], cwd=str(db.ROOT), env=env, capture_output=True,
                          text=True, encoding="utf-8", timeout=180)


def test_run_demo_walks_the_real_flow_and_ends_green():
    result = run_demo()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULTADO: OK (7 de 7" in result.stdout
    assert "FAIL" not in result.stdout


def test_run_demo_ends_red_when_a_guarantee_breaks(tmp_path):
    """Sin "✅" fijos: si la revocación no cortara las compras, el script lo dice y sale 1.
    El bug simulado (con un sitecustomize que solo carga este subproceso): la revocación
    RESPONDE "revoked" pero no se guarda. Debe fallar el paso que lo comprueba de verdad."""
    (tmp_path / "sitecustomize.py").write_text(
        f"import sys\nsys.path.insert(0, {str(db.ROOT)!r})\n"
        "import core.mandate_store as m\n"
        "def fake_revoke(mandate_id):\n"
        "    record = m.get_mandate(mandate_id)\n"
        "    record['live_state']['status'] = 'revoked'\n"
        "    return record\n"
        "m.revoke_mandate = fake_revoke\n",
        encoding="utf-8")
    result = run_demo({"PYTHONPATH": str(tmp_path)})
    assert result.returncode == 1, result.stdout + result.stderr
    assert "OK    La persona revoca el mandato" in result.stdout  # la respuesta "miente"…
    assert "FAIL  Compra después de revocar" in result.stdout     # …y el paso real lo detecta
    assert "RESULTADO: FALLÓ" in result.stdout


def test_bootstrap_demo_refuses_outside_dev_mode(monkeypatch, capsys):
    monkeypatch.delenv("AUTH_DEV_MODE", raising=False)
    assert bootstrap_demo.main(["--api", "http://127.0.0.1:9"]) == 2
    assert "AUTH_DEV_MODE=true" in capsys.readouterr().out


def test_the_flow_needs_a_dev_mode_api(monkeypatch):
    """Contra una API que NO está en desarrollo, el flujo se detiene: no hay código que leer."""
    monkeypatch.delenv("AUTH_DEV_MODE", raising=False)
    import api.auth as auth_api
    monkeypatch.setattr(auth_api, "send_verification_email", lambda *args: True)
    with TestClient(app) as client:
        with pytest.raises(DemoFlowError, match="AUTH_DEV_MODE"):
            enroll(InProcessTransport(client), "someone@example.com")


def test_the_shared_flow_signs_a_mandate_the_api_accepts(monkeypatch, service_key):
    monkeypatch.setenv("AUTH_DEV_MODE", "true")
    with TestClient(app) as client:
        api = InProcessTransport(client)
        person = enroll(api, "flow.user@example.com")
        record = sign_mandate(api, person, mandate_id="mnd_flow")
        assert record["live_state"]["status"] == "active"
        from tests.conftest import TEST_SERVICE_KEY
        assert merchant_verifies(api, TEST_SERVICE_KEY, "mnd_flow", 12000)["verdict"] == "APPROVE"
