import sys
import os

# Compatibilidad de codificación para terminales Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from mandate.issue import emitir_mandato
from core.verify import evaluar_intento_compra

# Configuración del entorno de prueba
SECRET_KEY = b"aegis_zero_trust_enterprise_2026"
DB_REVOCACION = {}

if __name__ == "__main__":
    print("🛡️ INICIANDO DEMOSTRACIÓN: AEGIS ZERO-TRUST AGENTIC COMMERCE\n")

    # 1. El usuario autoriza con Passkey y se emite el mandato
    print("--- 1. USUARIO AUTORIZA Y EMITE MANDATO ---")
    token, mandate_id = emitir_mandato("user_123", "offer_999", 150.00, "USD", SECRET_KEY)
    DB_REVOCACION[mandate_id] = "ACTIVE"
    print(f"Mandato firmado y entregado al agente (ID: {mandate_id})\n")

    # 2. Caso de Éxito
    print("--- 2. AGENTE INTENTA COMPRA VÁLIDA ---")
    resultado_1 = evaluar_intento_compra(token, SECRET_KEY, DB_REVOCACION, {
        "monto": 130.00, 
        "descripcion": "Vuelo redondo CDMX a Monterrey"
    })
    print(f"Resultado: {resultado_1['mensaje']}\n")

    # 3. Intento Adversario (Detectado por LLM Auditor usando tus créditos)
    print("--- 3. AGENTE INTENTA EVASIÓN / CONTRABANDO DE CATEGORÍA ---")
    resultado_2 = evaluar_intento_compra(token, SECRET_KEY, DB_REVOCACION, {
        "monto": 145.00, 
        "descripcion": "Tarjeta de regalo de Amazon de $145"
    })
    print(f"Resultado: {resultado_2['mensaje']}\n")

    # 4. Prueba de Fuego: Kill Switch en Vivo
    print("--- 4. PRUEBA DE FUEGO: KILL SWITCH ---")
    print("El usuario presiona el botón de revocación de emergencia...")
    DB_REVOCACION[mandate_id] = "REVOKED"
    
    resultado_3 = evaluar_intento_compra(token, SECRET_KEY, DB_REVOCACION, {
        "monto": 120.00, 
        "descripcion": "Vuelo válido a Monterrey"
    })
    print(f"Resultado: {resultado_3['mensaje']}\n")
