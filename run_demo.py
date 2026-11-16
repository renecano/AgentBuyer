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

    print("AgentBuyer — end-to-end walkthrough (real API, temporary database, development mode)\n")
    try:
        with TestClient(app) as client:
            api = InProcessTransport(client)
            person = enroll(api, "demo.user@example.com")
            step("Device key registered", bool(person.key_id), person.key_id)

            record = sign_mandate(api, person, mandate_id="mnd_demo_run")
            mandate_id = record["mandate"]["mandate_id"]
            limit = record["mandate"]["constraints"]["max_amount_per_purchase_cents"] / 100
            step("Mandate signed by its cardholder", record["live_state"]["status"] == "active",
                 f"{mandate_id}, limit ${limit:.2f}, status {record['live_state']['status']}")

            for name, cents, expected in (("A $120 purchase within the mandate", 12000, "APPROVE"),
                                          ("A $400 purchase over the limit", 40000, "ESCALATE")):
                result = merchant_verifies(api, service_key, mandate_id, cents)
                failed = [check["rule"] for check in result["checks"] if not check["pass"]]
                step(name, result["verdict"] == expected,
                     f"verdict {result['verdict']} (expected {expected})" + (f"; checks that did not pass: {failed}" if failed else ""))

            status, revoked = api.request("POST", f"/mandates/{mandate_id}/revoke", None, person.headers)
            step("The person revokes the mandate", status == 200 and revoked["live_state"]["status"] == "revoked",
                 f"HTTP {status}, status {revoked['live_state']['status'] if status == 200 else revoked}")

            result = merchant_verifies(api, service_key, mandate_id, 12000)
            step("A purchase after revoking", result["verdict"] == "REJECT", f"verdict {result['verdict']} (expected REJECT)")

            status, chain = api.request("GET", "/ledger/verify", None, person.headers)
            step("Audit ledger chain", status == 200 and chain["valid"] is True,
                 f"{chain['message']} ({chain['total_blocks']} blocks)" if status == 200 else f"HTTP {status}")
    except DemoFlowError as error:
        step("Flow", False, str(error))
    finally:
        db.dispose()

    failures = [name for name, ok, _ in results if not ok]
    print()
    if failures:
        print(f"RESULT: FAILED ({len(failures)} of {len(results)} steps did not give the expected result: {', '.join(failures)})")
        return 1
    print(f"RESULT: OK ({len(results)} of {len(results)} steps gave the expected result)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
