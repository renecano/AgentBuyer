import json
  import os
  import urllib.error
  import urllib.request

  OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

  def verificar_semantica_con_llm(
      intento_desc: str,
      categoria_permitida: str,
      precio: float,
  ) -> tuple[bool, str]:
      """Valida si una compra respeta una categoría autorizada.

      Devuelve:
          (es_riesgosa_o_no_permitida, motivo)
      """
      if not OPENAI_API_KEY:
          # Fail closed: sin validación, la compra no se autoriza.
          return True, "No hay una API key configurada; compra rechazada por seguridad."

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
          "https://

• Exploring
  └ Read SKILL.md (openai-docs skill)

• import json
  import os
  import urllib.error
  import urllib.request

  OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

  def verificar_semantica_con_llm(
      intento_desc: str,
      categoria_permitida: str,
      precio: float,
  ) -> tuple[bool, str]:
      """Valida si una compra respeta una categoría autorizada.

      Devuelve:
          (es_riesgosa_o_no_permitida, motivo)
      """
      if not OPENAI_API_KEY:
          # Fail closed: sin validación, la compra no se autoriza.
          return True, "No hay una API key configurada; compra rechazada por seguridad."

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
              "Authorization": f"Bearer {OPENAI_API_KEY}",
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

          print("\n[VALIDACIÓN SEMÁNTICA]")
          print(f"Riesgo: {riesgo}")
          print(f"Veredicto: {motivo}\n")

          return es_riesgosa, motivo

      except urllib.error.HTTPError as e:
          detalle = e.read().decode("utf-8", errors="replace")
          return True, f"Error HTTP del validador ({e.code}): {detalle}"

      except (KeyError, IndexError, json.JSONDecodeError) as e:
          return True, f"Respuesta inválida del validador: {e}"

      except Exception as e:
          return True, f"Error al validar la compra: {e}"

  Cambios clave:

  - Usa OPENAI_API_KEY desde variables de entorno, no una clave escrita en el código.
  - Migra a /v1/responses.
  - Usa JSON Schema estricto, en vez de confiar en campos opcionales.
  - Elimina la petición de “pensamiento paso a paso”; basta con un motivo breve y auditable.
  - Usa temperature=0 para decisiones más consistentes.
  - Aplica fail closed: ante error, ambigüedad o ausencia de clave, rechaza la compra.
