"""Fixtures compartidos de la suite."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import api.main as api_main
from core.auth_tokens import ROLE_ADMIN, create_access_token

# Holgura de la expiración relativa del seed. Solo tiene que cubrir la duración de
# un test; un año evita cualquier borde de reloj.
SEED_VALIDITY = timedelta(days=365)

# Clave SOLO para la suite (>= 32 bytes). No es la clave de desarrollo del código.
TEST_JWT_SECRET = "pytest-only-jwt-secret-not-used-anywhere-else-0123456789"


@pytest.fixture(autouse=True)
def auth_config(monkeypatch):
    """Configuración de auth que la app EXIGE para arrancar (core/auth_tokens.
    validate_token_config): JWT_SECRET válido y modo desarrollo apagado, como en
    producción. Aísla la suite del .env y del entorno de quien la corre; los tests
    que prueban otras combinaciones las sobrescriben con monkeypatch."""
    monkeypatch.setenv("JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.delenv("AUTH_DEV_MODE", raising=False)
    monkeypatch.delenv("JWT_TTL_SECONDS", raising=False)
    # Sin admins ni keys de servicio salvo que el test las configure (fail-closed).
    monkeypatch.delenv("ADMIN_EMAILS", raising=False)
    monkeypatch.delenv("SERVICE_API_KEY", raising=False)


# Identidad del usuario de la suite en los tokens de auth_headers.
TEST_USER_EMAIL = "pytest.user@example.com"


@pytest.fixture()
def auth_headers(auth_config) -> dict[str, str]:
    """Header `Authorization: Bearer <JWT>` de un usuario válido, para llamar a
    endpoints protegidos con require_principal (api/security.py).

    El token es real: lo firma create_access_token con el mismo JWT_SECRET con el
    que arranca la app (auth_config), y la dependencia lo valida por el camino
    normal (firma, emisor, expiración, rol). No se desactiva ni se simula la auth.
    Es el mismo token que /auth/email/check emite tras verificar el OTP (ver
    test_token_from_real_email_login_opens_protected_endpoint).
    """
    return {"Authorization": f"Bearer {create_access_token(TEST_USER_EMAIL)}"}


@pytest.fixture()
def active_seed(monkeypatch, tmp_path) -> dict:
    """Carga el mandato semilla con una expiración RELATIVA al momento del test.

    shared/seed_mandates.json trae un expires_at absoluto que en algún momento
    queda en el pasado. Los tests que necesitan el seed ACTIVO no deben depender
    de la fecha del sistema, así que se usa una copia idéntica del seed real con
    expires_at = ahora + 1 año, y el lifespan de la app la carga por el camino
    normal (load_seed_mandates leyendo SEED_PATH).

    No toca la regla de expiración: un mandato realmente vencido se sigue
    rechazando (ver test_expired_seed_is_still_rejected). Si SEED_PATH deja de
    existir, monkeypatch falla con AttributeError en vez de ignorarse en silencio.
    Devuelve el seed tal como se cargó.
    """
    seeds = json.loads(Path(api_main.SEED_PATH).read_text(encoding="utf-8"))
    expires_at = (datetime.now(timezone.utc) + SEED_VALIDITY).strftime("%Y-%m-%dT%H:%M:%SZ")
    for seed in seeds:
        seed["expires_at"] = expires_at

    relative_seed = tmp_path / "seed_mandates.json"
    relative_seed.write_text(json.dumps(seeds, ensure_ascii=False), encoding="utf-8")
    monkeypatch.setattr(api_main, "SEED_PATH", str(relative_seed))
    return seeds[0]


@pytest.fixture()
def seed_owner_headers(active_seed) -> dict[str, str]:
    """Bearer del DUEÑO del mandato semilla, para los endpoints que exigen
    propiedad (api/security.py: require_mandate_access).

    El email NO se escribe a mano: sale del propio seed (human.email), que es de
    donde el arranque saca el dueño. Si el seed cambia de dueño, el token lo sigue
    y los tests no empiezan a mentir en silencio."""
    return {"Authorization": f"Bearer {create_access_token(active_seed['human']['email'])}"}


# Identidad admin y key de servicio de la suite.
TEST_ADMIN_EMAIL = "pytest.admin@example.com"
TEST_SERVICE_KEY = "pytest-only-service-key-0123456789-abcdefghijklmnop"


@pytest.fixture()
def admin_headers(auth_config, monkeypatch) -> dict[str, str]:
    """Bearer de un ADMIN real: el email está en ADMIN_EMAILS (como exige
    require_admin) y el token lleva role="admin", igual que el que emite
    /auth/email/check para ese email."""
    monkeypatch.setenv("ADMIN_EMAILS", TEST_ADMIN_EMAIL)
    return {"Authorization": f"Bearer {create_access_token(TEST_ADMIN_EMAIL, role=ROLE_ADMIN)}"}


@pytest.fixture()
def service_headers(auth_config, monkeypatch) -> dict[str, str]:
    """Header X-Service-Key con una key configurada en SERVICE_API_KEY, validada
    por require_service por el camino normal (comparación en tiempo constante)."""
    monkeypatch.setenv("SERVICE_API_KEY", TEST_SERVICE_KEY)
    return {"X-Service-Key": TEST_SERVICE_KEY}
