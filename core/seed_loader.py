"""Carga mandatos semilla sin persistir ni importar estado vivo."""

import json
from pathlib import Path

from core.mandate_store import create_mandate, get_mandate


SEED_FILE = Path(__file__).resolve().parent.parent / "shared" / "seed_mandates.json"


def load_seed_mandates() -> list[str]:
    """Crea los mandatos semilla con la misma lógica del endpoint POST /mandates."""
    with SEED_FILE.open(encoding="utf-8") as seed_file:
        mandates = json.load(seed_file)

    if not isinstance(mandates, list):
        raise ValueError("shared/seed_mandates.json debe contener una lista de mandatos.")

    loaded_ids: list[str] = []
    for mandate in mandates:
        if not isinstance(mandate, dict):
            raise ValueError("Cada mandato semilla debe ser un objeto JSON.")

        mandate_id = mandate.get("mandate_id")
        if not isinstance(mandate_id, str) or not mandate_id.strip():
            raise ValueError("Cada mandato semilla requiere un mandate_id válido.")

        # Un startup normal inicia con memoria vacía. Evita duplicados si el
        # ciclo de vida de una app de pruebas se inicia más de una vez.
        if get_mandate(mandate_id) is None:
            create_mandate(mandate)
            loaded_ids.append(mandate_id)

    return loaded_ids
