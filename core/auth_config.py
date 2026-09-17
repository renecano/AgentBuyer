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


def service_api_keys() -> list[bytes]:
    """API keys de servicio válidas (SERVICE_API_KEY, separadas por comas; varias
    permiten rotar sin cortar el servicio). Lista vacía = ninguna key válida."""
    return [key.encode("utf-8") for key in _csv_env("SERVICE_API_KEY")]
