"""Prepara datos para una demo LOCAL (P-11): reemplaza al antiguo seed.

Uso, con la API corriendo en modo desarrollo (AUTH_DEV_MODE=true):
    AUTH_DEV_MODE=true python -m scripts.bootstrap_demo --email demo.user@example.com
    (opciones: --api http://127.0.0.1:8000)

Hace lo mismo que una persona en el navegador, por la API real: inicia sesión,
registra una llave de dispositivo con prueba de posesión y firma un mandato con ella.
Imprime el mandate_id y el access token para usarlos en la UI o con curl.

Se niega a correr si AUTH_DEV_MODE no es "true" en este proceso, y falla si la API no
está en modo desarrollo (los códigos OTP solo vienen en la respuesta en ese modo).
La llave privada vive solo en este proceso: el mandato se puede usar, pero no firmar
otro con la misma llave (eso es lo correcto para una llave no exportable).
"""
from __future__ import annotations

import argparse
import os
import sys

from scripts.demo_flow import DemoFlowError, HttpTransport, enroll, sign_mandate


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Creates a demo user with a signed mandate (development only).")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--email", default="demo.user@example.com")
    args = parser.parse_args(argv)

    if os.getenv("AUTH_DEV_MODE", "").strip().lower() != "true":
        print("ERROR: bootstrap_demo only runs with AUTH_DEV_MODE=true (it is a development utility).")
        return 2
    api = HttpTransport(args.api)
    try:
        person = enroll(api, args.email)
        record = sign_mandate(api, person)
    except (DemoFlowError, OSError) as error:
        print(f"ERROR: {error}")
        return 1
    print(f"Signed mandate: {record['mandate']['mandate_id']} (cardholder {person.email}, key {person.key_id})")
    print(f"Access token (Authorization: Bearer ...): {person.token}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
