"""Configuración compartida de autenticación."""
import os


def auth_dev_mode_enabled() -> bool:
    """Modo desarrollo local. Solo el valor explícito "true" (sin distinguir
    mayúsculas) lo activa; cualquier otro valor o su ausencia = producción.

    Habilita: el código OTP en la respuesta (code_demo) y, si falta JWT_SECRET,
    la clave de firma de desarrollo. NUNCA debe estar activo en producción.
    """
    return os.getenv("AUTH_DEV_MODE", "").strip().lower() == "true"


def _csv_env(name: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


def admin_emails() -> frozenset[str]:
    """Emails con rol admin (ADMIN_EMAILS, separados por comas). Se normalizan a
    minúsculas igual que el email verificado en /auth/email/check. Se leen en cada
    llamada: quitar un email de la lista le retira el rol de inmediato."""
    return frozenset(email.lower() for email in _csv_env("ADMIN_EMAILS"))


# SERVICE_API_KEY solo se compara (no firma nada, a diferencia de JWT_SECRET):
# basta un mínimo que impida keys triviales o adivinables.
MIN_SERVICE_KEY_BYTES = 16
_GENERATE_KEY_HINT = 'python -c "import secrets; print(secrets.token_urlsafe(32))"'


class ServiceKeyConfigError(ValueError):
    """SERVICE_API_KEY está configurada pero es inválida."""


def service_api_keys() -> list[bytes]:
    """API keys de servicio válidas (SERVICE_API_KEY, separadas por comas; varias
    permiten rotar sin cortar el servicio).

    - Ausente o vacía → lista vacía: ninguna key es válida y los endpoints de
      servicio quedan cerrados (fail-closed). NO es un error de configuración.
    - Configurada con alguna key de menos de MIN_SERVICE_KEY_BYTES → ServiceKeyConfigError.
    """
    keys = [key.encode("utf-8") for key in _csv_env("SERVICE_API_KEY")]
    short = [index for index, key in enumerate(keys, start=1) if len(key) < MIN_SERVICE_KEY_BYTES]
    if short:
        positions = ", ".join(f"#{index}" for index in short)
        raise ServiceKeyConfigError(
            f"SERVICE_API_KEY inválida: la(s) key(s) {positions} tienen menos de "
            f"{MIN_SERVICE_KEY_BYTES} bytes. Genera una segura con: {_GENERATE_KEY_HINT}"
        )
    return keys


def validate_service_key_config() -> None:
    """Valida SERVICE_API_KEY si está configurada (lanza ServiceKeyConfigError).
    Sin configurar no hace nada: la app arranca con los endpoints de servicio cerrados."""
    service_api_keys()
