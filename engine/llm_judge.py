import json
import os
import urllib.error
import urllib.request
from typing import Tuple, Dict, Any

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")


def verificar_semantica_con_llm(
    intento_desc: str,
    categoria_permitida: str,
    precio: float,
    allow_offline_heuristic: bool = True,
) -> Tuple[bool, str]:
    """
    Valida semánticamente si una compra respeta una categoría autorizada y no intenta evadir el mandato.
    
    Devuelve:
        (es_riesgosa_o_no_permitida: bool, motivo: str)
        - True: Rechazada / Riesgosa
        - False: Aprobada / Cumple la categoría
    """
    api_key = os.getenv("OPENAI_API_KEY", "")

    if not api_key:
        if not allow_offline_heuristic:
            return True, "No hay una API key configurada; compra rechazada por seguridad."
        
        # Heurística conservadora offline
        desc_lower = intento_desc.lower()
        cat_lower = categoria_permitida.lower()
        
        activos_prohibidos = ["gift card", "tarjeta regalo", "crypto", "bitcoin", "saldo", "vale", "cash", "voucher", "rolex", "joya"]
        if any(w in desc_lower for w in activos_prohibidos):
            return True, f"Detección de evasión o activo líquido prohibido en '{intento_desc}'."
            
        keywords = {
            "flight": ["vuelo", "flight", "aerolíneas", "airline", "pasaje", "aéreo", "boarding"],
            "travel": ["vuelo", "flight", "hotel", "hospedaje", "travel", "viaje", "traslado"],
            "hotel": ["hotel", "hospedaje", "room", "habitación", "resort"],
        }
        
        rel_keywords = keywords.get(cat_lower, [cat_lower])
        if any(k in desc_lower for k in rel_keywords) or cat_lower in desc_lower:
            return False, f"Validación heurística aprobada: '{intento_desc}' pertenece a '{categoria_permitida}'."
            
        return True, f"El artículo '{intento_desc}' no pertenece claramente a la categoría autorizada '{categoria_permitida}'."

    schema = {
        "name": "veredicto_compra",
        "schema": {
            "type": "object",
            "properties": {
                "es_fraude_o_evasion": {
                    "type": "boolean",
                    "description": "True si la compra viola o intenta evadir el mandato."
                },
                "motivo": {
                    "type": "string",
                    "description": "Explicación breve, concreta y verificable."
                },
                "nivel_riesgo": {
                    "type": "string",
                    "enum": ["bajo", "medio", "alto"]
                }
            },
            "required": ["es_fraude_o_evasion", "motivo", "nivel_riesgo"],
            "additionalProperties": False
        },
        "strict": True
    }

    instrucciones = f"""
Evalúa una solicitud de compra conforme al mandato autorizado.

Categoría permitida: {categoria_permitida!r}
Artículo solicitado: {intento_desc!r}
Precio declarado: {precio:.2f}

Rechaza la compra si:
- No pertenece claramente a la categoría autorizada.
- Es dinero, tarjeta regalo, criptomoneda, saldo, vale, activo transferible
  o cualquier mecanismo equivalente.
- Permite revenderse fácilmente para convertirlo en dinero.
- Parece diseñada para evadir la intención del mandato.
- La descripción es ambigua o insuficiente para autorizarla con seguridad.

No inventes datos. Ante ambigüedad, aplica un criterio conservador.
"""

    data = {
        "model": "gpt-4.1-mini",
        "input": [
            {
                "role": "system",
                "content": [{
                    "type": "input_text",
                    "text": (
                        "Eres un auditor de cumplimiento para compras automatizadas. "
                        "Devuelves únicamente una evaluación estructurada, breve y objetiva."
                    )
                }]
            },
            {
                "role": "user",
                "content": [{"type": "input_text", "text": instrucciones}]
            }
        ],
        "text": {
            "format": {
                "type": "json_schema",
                **schema
            }
        },
        "temperature": 0
    }

    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(data).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.loads(response.read().decode("utf-8"))

        contenido = result["output"][0]["content"][0]["text"]
        analisis = json.loads(contenido)

        es_riesgosa = analisis["es_fraude_o_evasion"]
        motivo = analisis["motivo"]
        riesgo = analisis["nivel_riesgo"]

        print(f"\n[VALIDACIÓN SEMÁNTICA CON LLM] Riesgo: {riesgo} | Veredicto: {motivo}\n")
        return es_riesgosa, motivo

    except urllib.error.HTTPError as e:
        detalle = e.read().decode("utf-8", errors="replace")
        return True, f"Error HTTP del validador ({e.code}): {detalle}"

    except (KeyError, IndexError, json.JSONDecodeError) as e:
        return True, f"Respuesta inválida del validador: {e}"

    except Exception as e:
        return True, f"Error al validar la compra: {e}"


# Alias retrocompatible
judge_ambiguous_intent = verificar_semantica_con_llm
