"""Configuración compartida de autenticación."""
import os


def auth_dev_mode_enabled() -> bool:
    """Modo desarrollo local. Solo el valor explícito "true" (sin distinguir
    mayúsculas) lo activa; cualquier otro valor o su ausencia = producción.

    Habilita: el código OTP en la respuesta (code_demo) y, si falta JWT_SECRET,
    la clave de firma de desarrollo. NUNCA debe estar activo en producción.
    """
    return os.getenv("AUTH_DEV_MODE", "").strip().lower() == "true"
