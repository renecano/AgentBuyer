import uuid
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List

from shared.schemas import (
    Mandate,
    CatalogItem,
    PurchaseAttempt,
    VerificationResult,
)
from mandate.sign import sign_payload
from core.merchant import vuelaya_merchant, VuelaYaMerchant
from core.mandate_store import get_mandate, get_mandate_signer
from core.money import format_money, is_cents
from audit.log import append_entry
from core.merchant_search import _merchant_slug, search_merchant_offers


class PurchasingAgent:
    """
    Autonomous purchasing agent that discovers deals, evaluates them against active mandates,
    signs purchase attempts cryptographically, and submits them to merchants.
    """

    def __init__(self, agent_id: str, agent_privkey: str, agent_pubkey: str):
        self.agent_id = agent_id
        self.agent_privkey = agent_privkey
        self.agent_pubkey = agent_pubkey
        self.purchase_history: List[Dict[str, Any]] = []

    def create_signed_attempt(
        self,
        mandate: Mandate,
        item: CatalogItem,
        merchant_id: str,
        override_amount: Optional[float] = None,
        tampered_nonce: Optional[str] = None,
        tampered_agent_id: Optional[str] = None,
        forge_signature: bool = False,
    ) -> PurchaseAttempt:
        attempt_id = f"att_{uuid.uuid4().hex[:10]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        nonce = tampered_nonce if tampered_nonce else secrets.token_hex(16)
        active_agent_id = tampered_agent_id if tampered_agent_id else self.agent_id
        amount = override_amount if override_amount is not None else item.price

        unsigned_dict: Dict[str, Any] = {
            "attempt_id": attempt_id,
            "mandate_id": mandate.mandate_id,
            "agent_id": active_agent_id,
            "merchant_id": merchant_id,
            "category": item.category,
            "amount": amount,
            "currency": item.currency,
            "timestamp": timestamp,
            "nonce": nonce,
            "item_description": getattr(item, "description", getattr(item, "title", "Vuelo")),
            "metadata": item.metadata,
        }

        if forge_signature:
            signature = "forged_signature_000000000000000000000000000000000000000000000000"
        else:
            signature = sign_payload(self.agent_privkey, unsigned_dict)

        return PurchaseAttempt(
            **unsigned_dict,
            signature=signature,
            agent_signature=signature,
        )


    def attempt_purchase(
        self,
        mandate: Mandate,
        item: CatalogItem,
        merchant: Optional[VuelaYaMerchant] = None,
        override_amount: Optional[float] = None,
        tampered_nonce: Optional[str] = None,
        tampered_agent_id: Optional[str] = None,
        forge_signature: bool = False,
    ) -> Tuple[PurchaseAttempt, VerificationResult]:
        actual_merchant = merchant if merchant is not None else vuelaya_merchant
        attempt = self.create_signed_attempt(
            mandate=mandate,
            item=item,
            merchant_id=actual_merchant.merchant_id,
            override_amount=override_amount,
            tampered_nonce=tampered_nonce,
            tampered_agent_id=tampered_agent_id,
            forge_signature=forge_signature,
        )

        from core.verify import gateway
        result = gateway.verify_and_authorize(attempt, mandate, merchant_pubkey=actual_merchant.pubkey)

        if result.authorized:
            actual_merchant.record_settlement(
                attempt_id=attempt.attempt_id,
                settlement_token=result.settlement_token,
                amount=attempt.amount,
            )

        self.purchase_history.append({
            "attempt": attempt.model_dump(),
            "result": result.model_dump(),
        })

        return attempt, result


def _category_key(mandate: dict) -> str:
    """Clave de búsqueda ('flights' | 'hotels') según la categoría del mandato."""
    constraints = mandate.get("constraints", {}) or {}
    allowed = constraints.get("allowed_categories") or []
    taxon = allowed[0] if allowed else "travel.flights"
    return "hotels" if taxon == "travel.hotels" else "flights"


def _discover_offers(category_key: str, search_fields: dict | None) -> tuple[list[dict], str]:
    """Descubre ofertas (vuelos u hoteles) SOLO con búsqueda web real.

    Si no hay campos de búsqueda o la búsqueda no devuelve ofertas, regresa
    una lista vacía: el llamador informa "no encontré ofertas" en vez de
    inventar datos de un catálogo falso.
    """
    if isinstance(search_fields, dict) and search_fields:
        offers = search_merchant_offers(category_key, search_fields)
        if offers:
            if category_key == "hotels":
                nights = search_fields.get("nights")
                label = f"{search_fields.get('destination', '?')}" + (f" · {nights} nights" if nights else "")
                taxon = "travel.hotels"
            else:
                label = f"{search_fields.get('origin', '?')}->{search_fields.get('destination', '?')}"
                taxon = "travel.flights"
            found = [
                {
                    "id": f"web_{index}",
                    # "route" es la etiqueta visible (ruta de vuelo o destino de hotel);
                    # el nombre se conserva por contrato con el frontend.
                    "route": label,
                    # Borde (5.1): el precio de la oferta web pasa a centavos exactos.
                    "price_cents": offer["price_cents"],
                    "category": taxon,
                    "merchant_id": _merchant_slug(offer["merchant"]),
                    "merchant": offer["merchant"],
                    "details": offer["details"],
                    "url": offer["url"],
                    "source": "web",
                }
                for index, offer in enumerate(offers)
            ]
            return found, "web"
    return [], "web"


def _limits(mandate: dict) -> tuple[int | None, int | None]:
    """(tope por compra, price_below) del mandato, en centavos (5.1)."""
    constraints = mandate.get("constraints") or {}
    cap = constraints.get("max_amount_per_purchase_cents")
    below = next((condition.get("value_cents") for condition in constraints.get("conditions", [])
                  if isinstance(condition, dict) and condition.get("type") == "price_below"), None)
    return (cap if is_cents(cap) else None), (below if is_cents(below) else None)


def _fits(offer: dict, cap: int | None, below: int | None) -> bool:
    """La MISMA regla que el engine (5.1: antes el agente usaba <= y el engine <):
    precio <= tope por compra Y precio < price_below. Sin tope conocido no cabe."""
    price = offer.get("price_cents")
    if not is_cents(price) or price <= 0 or cap is None:
        return False
    return price <= cap and (below is None or price < below)


class SignedSearchFieldsMismatch(ValueError):
    """El llamador pidió buscar otra cosa que lo que el titular firmó."""


# ── Escenarios de demostración (4.2) ────────────────────────────────────────
#
# La demo de React ya no llama /verify directo (P-03): pide a /agent/run un escenario
# EXPLÍCITO y visible. El servidor construye una oferta sintética, rotulada como tal,
# y la verifica por el mismo camino que una compra real, pero un escenario NUNCA
# compra (sin usos, sin gasto, sin recibo) y queda registrado como escenario.
SCENARIO_TRAP_OFFER = "trap_offer"
SCENARIO_AFTER_REVOCATION = "after_revocation"
SCENARIOS = (SCENARIO_TRAP_OFFER, SCENARIO_AFTER_REVOCATION)


class ScenarioNotApplicable(ValueError):
    """El escenario no aplica al estado del mandato (p. ej. "after_revocation" sin revocar)."""


def _scenario_offer(scenario: str, mandate: dict, live_status: str, category_key: str) -> dict:
    constraints = mandate.get("constraints", {}) or {}
    merchant_id = (constraints.get("allowed_merchants") or ["mch_vuelaya"])[0]
    category = (constraints.get("allowed_categories") or ["travel.flights"])[0]
    cap, below = _limits(mandate)
    # Un precio que CABE en el mandato: así lo único que decide es lo que el escenario muestra.
    ceiling = min(value for value in (cap, (below - 1) if below else None, 10_000) if value is not None)
    price_cents = max(100, ceiling - 3_000)
    fields = mandate.get("search_fields") or {}
    route = (f"{fields.get('origin', '?')}->{fields.get('destination', '?')}" if category_key != "hotels"
             else str(fields.get("destination", "?")))
    if scenario == SCENARIO_TRAP_OFFER:
        # Activo líquido empaquetado con el pasaje: una de las trampas que el firewall
        # semántico debe atrapar (gift cards, vouchers, crypto).
        details = "Demo scenario — fare bundled with a $20 travel gift card charged separately within 48h (fine print)"
    else:
        if live_status != "revoked":
            raise ScenarioNotApplicable("The 'after_revocation' scenario needs a revoked mandate. Revoke it first.")
        details = "Demo scenario — a clean, in-limit offer presented after the mandate was revoked"
    return {
        "id": f"scenario_{scenario}",
        "route": route,
        "price_cents": price_cents,
        "category": category,
        "merchant_id": merchant_id,
        "merchant": merchant_id.removeprefix("mch_").replace("_", " ").title(),
        "details": details,
        "url": "",
        "source": "scenario",
    }


def bind_search_fields(mandate_id: str, mandate: dict, search_fields: dict | None) -> dict | None:
    """search_fields con los que puede buscar el agente.

    En un mandato FIRMADO por el titular (kind=human) el agente queda atado a lo
    firmado: si el llamador manda otros, es un error (no se ignoran en silencio);
    si manda los mismos (tras la normalización de la spec) o ninguno, se usan los
    guardados. En los demás mandatos, el comportamiento de siempre."""
    signer = get_mandate_signer(mandate_id)
    if signer is None or signer.get("kind") != "human":
        return search_fields
    stored = mandate.get("search_fields") or {}
    if search_fields is not None:
        from mandate.mandate_message import MandateMessageError, normalize_search_fields
        try:
            requested = normalize_search_fields(search_fields)
        except MandateMessageError as error:
            raise SignedSearchFieldsMismatch(f"search_fields: {error}") from None
        if requested != stored:
            raise SignedSearchFieldsMismatch(
                "This mandate was signed by the cardholder: the agent can only search what was signed."
            )
    return stored


def run_agent(mandate_id: str, search_fields: dict | None = None, scenario: str | None = None) -> dict:
    """Descubre, decide, intenta y registra el resultado de una compra.

    Descubre ofertas REALES vía web search con search_fields ({origin,
    destination, departure_date, ...}); si el llamador no los pasa, usa los
    guardados en el mandato. Sin resultados reales NO hay compra: se informa
    "no encontré vuelos" (no existe ya un catálogo demo de respaldo).
    """
    record = get_mandate(mandate_id)
    mandate = record["mandate"] if record is not None else {}
    if scenario is not None and scenario not in SCENARIOS:
        raise ScenarioNotApplicable(f"Unknown scenario. Allowed: {', '.join(SCENARIOS)}.")
    search_fields = bind_search_fields(mandate_id, mandate, search_fields)
    if not search_fields:
        stored_fields = mandate.get("search_fields")
        if isinstance(stored_fields, dict) and stored_fields:
            search_fields = stored_fields

    category_key = _category_key(mandate)
    cap, below = _limits(mandate)
    if scenario:
        # Sin búsqueda web (no gasta OpenAI): la oferta del escenario es sintética.
        live_status = record["live_state"]["status"] if record is not None else "missing"
        flights_seen, discovery_source = [_scenario_offer(scenario, mandate, live_status, category_key)], "scenario"
    else:
        flights_seen, discovery_source = _discover_offers(category_key, search_fields)

    if not flights_seen:
        message = (
            "Saturday no encontró ofertas en este momento. "
            "No se realizó ningún intento de compra; intenta de nuevo."
        )
        append_entry(
            {
                "type": "agent_run",
                "mandate_id": mandate_id,
                "summary": "La búsqueda web no devolvió ofertas; el agente no intentó ninguna compra.",
            }
        )
        return {
            "mandate_id": mandate_id,
            "attempt_id": None,
            "discovery_source": discovery_source,
            "flights_seen": [],
            "selected_flight": None,
            "no_offers": True,
            "purchase_completed": False,
            "human_readable": message,
        }

    eligible = [flight for flight in flights_seen if _fits(flight, cap, below)]
    if not eligible:
        # 5.1: si ninguna oferta cabe en el mandato, NO se intenta la más barata (antes
        # se intentaba igual y el guardián tenía que pararla). No hay compra que proponer.
        message = (
            f"Saturday encontró {len(flights_seen)} ofertas, pero ninguna cabe en el mandato "
            f"(tope {format_money(cap) if cap is not None else '—'} USD"
            + (f", price_below {format_money(below)} USD" if below is not None else "")
            + "). No se intentó ninguna compra."
        )
        append_entry({"type": "agent_run", "mandate_id": mandate_id, "summary": message})
        return {
            "mandate_id": mandate_id,
            "attempt_id": None,
            "discovery_source": discovery_source,
            "flights_seen": flights_seen,
            "selected_flight": None,
            "no_offers": False,
            "no_fit": True,
            "purchase_completed": False,
            "human_readable": message,
        }
    selected_flight = min(eligible, key=lambda flight: flight["price_cents"])
    attempt_id = f"att_agent_{uuid.uuid4().hex[:12]}"
    agent_id = mandate.get("agent", {}).get("id", "agent_marta")
    
    attempt = {
        "attempt_id": attempt_id,
        "mandate_id": mandate_id,
        "presented_by_agent": agent_id,
        # 4.2: nonce único (anti-replay) y firma del agente sobre el intento.
        "nonce": secrets.token_hex(16),
        "purchase": {
            "merchant_id": selected_flight["merchant_id"],
            "category": selected_flight["category"],
            "amount_cents": selected_flight["price_cents"],
            "currency": (mandate.get("constraints") or {}).get("currency", "USD"),
            "description": (f"Hotel stay: {selected_flight['route']}" if category_key == "hotels" else f"Flight {selected_flight['route']}") + (f" — {selected_flight['details']}" if selected_flight.get("details") else ""),
            "metadata": {
                "flight_id": selected_flight["id"],
                "price_cents": selected_flight["price_cents"],
                "source": selected_flight["source"],
                **({"url": selected_flight["url"]} if selected_flight.get("url") else {}),
            },
        },
    }

    from core.agent_keys import AGENT_SIGNATURE_FIELD, sign_attempt
    attempt[AGENT_SIGNATURE_FIELD] = sign_attempt(agent_id, attempt)

    from api.verify import verify_attempt
    verification = verify_attempt(attempt, scenario=scenario)
    verdict = verification.get("verdict", "REJECT")
    # Un escenario de demostración nunca es una compra, aunque el veredicto fuera APPROVE.
    completed = verdict == "APPROVE" and not scenario

    story = (
        # R12: un escenario no es una búsqueda real ni una compra; se dice tal cual.
        f"Escenario de demostración '{scenario}': oferta sintética (no salió de una búsqueda real) "
        f"de {selected_flight.get('merchant', selected_flight['merchant_id'])} por {format_money(selected_flight['price_cents'])} USD. "
        f"Verify devolvió {verdict}; en un escenario nunca se compra. {verification.get('human_readable', '')}"
    ) if scenario else (
        f"Encontró {len(flights_seen)} {'hoteles' if category_key == 'hotels' else 'vuelos'} en la web (búsqueda real). "
        + (f"Aplicó el límite price_below de {format_money(below)} USD y " if below is not None else f"Aplicó el tope de {format_money(cap)} USD y ")
        + f"eligió {selected_flight['route']} de {selected_flight.get('merchant', selected_flight['merchant_id'])} por {format_money(selected_flight['price_cents'])} USD. "
        + ("La compra fue completada tras recibir APPROVE." if completed else f"La compra no procedió: verify devolvió {verdict}. {verification.get('human_readable', '')}")
    )
    
    append_entry(
        {
            "type": "agent_run",
            "mandate_id": mandate_id,
            "attempt_id": attempt_id,
            "verdict": verdict,
            "summary": story,
        }
    )
    if completed:
        append_entry(
            {
                "type": "purchase_completed",
                "mandate_id": mandate_id,
                "attempt_id": attempt_id,
                "verdict": "APPROVE",
                "summary": f"Compra completada por Saturday: {selected_flight['route']} por {format_money(selected_flight['price_cents'])} USD.",
            }
        )
        try:
            from core.notifications import enviar_ticket_confirmacion
            # Solo el correo del titular; sin él, notifications omite el envío
            # (jamás caer a SMTP_USER: eso mandaba el recibo al propio emisor).
            user_email = mandate.get("human", {}).get("email") or ""
            enviar_ticket_confirmacion(
                correo_destino=user_email,
                detalles_reserva={
                    "destino": selected_flight.get("route", "Buenos Aires ➔ Córdoba"),
                    "proveedor": selected_flight.get("merchant", "VuelaYa Travel"),
                    "pnr": f"PNR-VYA-{attempt_id[-6:].upper()}",
                    # Borde con el correo: el recibo muestra unidades.
                    "precio_total": selected_flight["price_cents"] / 100,
                    "moneda": "USD",
                    "pasajero": mandate.get("human", {}).get("display_name", "Marta"),
                    "candidate_id": mandate_id,
                }
            )
        except Exception as notify_err:
            print("Aviso al enviar ticket de confirmación:", notify_err)
    return {
        "mandate_id": mandate_id,
        "attempt_id": attempt_id,
        "discovery_source": discovery_source,
        "flights_seen": flights_seen,
        "selected_flight": selected_flight,
        "selection_reason": "La oferta más barata que cabe en el mandato.",
        "attempt": attempt,
        "verification": verification,
        "purchase_completed": completed,
        "human_readable": story,
    }
