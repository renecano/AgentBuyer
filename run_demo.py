#!/usr/bin/env python3
"""Recorrido de punta a punta del flujo REAL de AgentBuyer (P-08).

Uso:  python run_demo.py        (requiere requirements-dev.txt)

Levanta la API en este mismo proceso, sobre una base temporal en modo desarrollo
(sin red, sin OpenAI, sin SMTP), y recorre lo que hace una persona y un comercio:

  1. la persona inicia sesión y registra la llave de su dispositivo (prueba de posesión)
  2. firma un mandato con esa llave (tope $150, solo vuelos, solo VuelaYa, 3 usos)
  3. el comercio verifica una compra de $120 dentro del mandato   → se espera APPROVE
  4. el comercio intenta $400, sobre el tope                       → se espera ESCALATE
  5. la persona revoca el mandato
  6. el comercio intenta otra compra de $120                       → se espera REJECT
  7. la cadena del ledger de auditoría verifica completa            → se espera válida

Cada paso imprime lo que REALMENTE respondió la API y si coincide con lo esperado.
Sale con código 0 solo si todo coincidió; con 1 si algo no. Antes este script imprimía
"✅" fijos e importaba la línea estricta y el emisor "en lenguaje natural", que ya no
existen (P-08).
"""
from __future__ import annotations

import os
import secrets
import sys
import tempfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    workdir = tempfile.mkdtemp(prefix="agentbuyer-demo-")
    service_key = secrets.token_urlsafe(32)
    os.environ.update({
        "AUTH_DEV_MODE": "true",
        "DATABASE_URL": f"sqlite:///{Path(workdir, 'demo.db').as_posix()}",
        "SERVICE_API_KEY": service_key,
    })
    for variable in ("OPENAI_API_KEY", "SMTP_USER", "SMTP_PASS", "JWT_SECRET"):
        os.environ.pop(variable, None)

    from fastapi.testclient import TestClient

    from api.main import app
    from core import db
    from scripts.demo_flow import DemoFlowError, InProcessTransport, enroll, merchant_verifies, sign_mandate

    results: list[tuple[str, bool, str]] = []

    def step(name: str, ok: bool, detail: str) -> None:
        results.append((name, ok, detail))
        print(f"  {'OK  ' if ok else 'FAIL'}  {name}: {detail}")

    print("AgentBuyer — recorrido de punta a punta (API real, base temporal, modo desarrollo)\n")
    try:
        with TestClient(app) as client:
            api = InProcessTransport(client)
            person = enroll(api, "demo.user@example.com")
            step("Llave del dispositivo registrada", bool(person.key_id), person.key_id)

            record = sign_mandate(api, person, mandate_id="mnd_demo_run")
            mandate_id = record["mandate"]["mandate_id"]
            limit = record["mandate"]["constraints"]["max_amount_per_purchase_cents"] / 100
            step("Mandato firmado por su titular", record["live_state"]["status"] == "active",
                 f"{mandate_id}, tope ${limit:.2f}, estado {record['live_state']['status']}")

            for name, cents, expected in (("Compra de $120 dentro del mandato", 12000, "APPROVE"),
                                          ("Compra de $400 sobre el tope", 40000, "ESCALATE")):
                result = merchant_verifies(api, service_key, mandate_id, cents)
                failed = [check["rule"] for check in result["checks"] if not check["pass"]]
                step(name, result["verdict"] == expected,
                     f"veredicto {result['verdict']} (esperado {expected})" + (f"; checks que no pasaron: {failed}" if failed else ""))

            status, revoked = api.request("POST", f"/mandates/{mandate_id}/revoke", None, person.headers)
            step("La persona revoca el mandato", status == 200 and revoked["live_state"]["status"] == "revoked",
                 f"HTTP {status}, estado {revoked['live_state']['status'] if status == 200 else revoked}")

            result = merchant_verifies(api, service_key, mandate_id, 12000)
            step("Compra después de revocar", result["verdict"] == "REJECT", f"veredicto {result['verdict']} (esperado REJECT)")

            status, chain = api.request("GET", "/audit/verify")
            step("Cadena del ledger de auditoría", status == 200 and chain["valid"] is True,
                 f"{chain['message']} ({chain['total_blocks']} bloques)" if status == 200 else f"HTTP {status}")
    except DemoFlowError as error:
        step("Flujo", False, str(error))
    finally:
        db.dispose()

    failures = [name for name, ok, _ in results if not ok]
    print()
    if failures:
        print(f"RESULTADO: FALLÓ ({len(failures)} de {len(results)} pasos no dieron lo esperado: {', '.join(failures)})")
        return 1
    print(f"RESULTADO: OK ({len(results)} de {len(results)} pasos dieron lo esperado)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
