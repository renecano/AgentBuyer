from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from copy import deepcopy

from shared.schemas import CatalogItem, PurchaseAttempt, VerificationResult
from core.verify import verify_purchase

# Catálogo funcional mock VuelaYa
FLIGHTS: list[dict] = [
    {"id": "FLIGHT_COR_130", "route": "BUE->COR", "price": 130.0, "category": "travel.flights", "merchant_id": "mch_vuelaya"},
    {"id": "FLIGHT_COR_145_TRAP", "route": "BUE->COR", "price": 145.0, "category": "travel.flights", "merchant_id": "mch_vuelaya"},
    {"id": "FLIGHT_COR_300", "route": "BUE->COR", "price": 300.0, "category": "travel.flights", "merchant_id": "mch_vuelaya"},
    {"id": "FLIGHT_MDZ_180", "route": "BUE->MDZ", "price": 180.0, "category": "travel.flights", "merchant_id": "mch_vuelaya"},
    {"id": "HOTEL_COR_90", "route": "HOTEL-COR", "price": 90.0, "category": "hospitality", "merchant_id": "mch_vuelaya"},
]


def get_flights() -> list[dict]:
    """Entrega una copia para que ningún cliente cambie el catálogo interno."""
    return deepcopy(FLIGHTS)


class VuelaYaMerchant:
    """
    Mock Online Travel Agency (VuelaYa) that accepts purchases from AI agents
    via cryptographic mandate verification.
    """

    MERCHANT_ID = "mch_vuelaya"
    MERCHANT_NAME = "VuelaYa Travel Agency"

    def __init__(self):
        self.merchant_id = self.MERCHANT_ID
        self.pubkey = "vuelaya_pubkey_ed25519"
        self.catalog: Dict[str, CatalogItem] = {

            "FLIGHT_COR_130": CatalogItem(
                item_id="FLIGHT_COR_130",
                title="Vuelo Buenos Aires (AEP) -> Córdoba (COR) [Promo]",
                category="travel.flights",
                price=130.0,
                currency="USD",
                merchant_id=self.MERCHANT_ID,
                metadata={
                    "origin": "AEP",
                    "destination": "COR",
                    "airline": "Aerolíneas Argentinas",
                    "cabin": "Economy",
                    "flight_number": "AR1504",
                },
                available=True,
            ),
            "FLIGHT_COR_300": CatalogItem(
                item_id="FLIGHT_COR_300",
                title="Vuelo Buenos Aires (AEP) -> Córdoba (COR) [Premium Last Minute]",
                category="travel.flights",
                price=300.0,
                currency="USD",
                merchant_id=self.MERCHANT_ID,
                metadata={
                    "origin": "AEP",
                    "destination": "COR",
                    "airline": "FlyBondi Priority",
                    "cabin": "Premium",
                    "flight_number": "FB5201",
                },
                available=True,
            ),
            "FLIGHT_MDZ_180": CatalogItem(
                item_id="FLIGHT_MDZ_180",
                title="Vuelo Buenos Aires (AEP) -> Mendoza (MDZ)",
                category="travel.flights",
                price=180.0,
                currency="USD",
                merchant_id=self.MERCHANT_ID,
                metadata={
                    "origin": "AEP",
                    "destination": "MDZ",
                    "airline": "JetSmart",
                    "cabin": "Economy",
                },
                available=True,
            ),
            "HOTEL_COR_90": CatalogItem(
                item_id="HOTEL_COR_90",
                title="Hotel Boutique Córdoba Centro (1 noche)",
                category="hospitality",
                price=90.0,
                currency="USD",
                merchant_id=self.MERCHANT_ID,
                metadata={"destination": "COR", "city": "Cordoba"},
                available=True,
            ),
            "LUXURY_WATCH_999": CatalogItem(
                item_id="LUXURY_WATCH_999",
                title="Reloj Suizo de Lujo (Intento Fraudulento)",
                category="electronics",
                price=999.0,
                currency="USD",
                merchant_id=self.MERCHANT_ID,
                metadata={"brand": "SwissWatch"},
                available=True,
            ),
        }
        self.settled_orders: List[Dict[str, Any]] = []

    def get_catalog(self) -> List[CatalogItem]:
        return list(self.catalog.values())

    def get_item(self, item_id: str) -> Optional[CatalogItem]:
        return self.catalog.get(item_id)

    def record_settlement(self, attempt_id: str, settlement_token: Optional[str] = None, amount: float = 0.0):
        self.settled_orders.append({
            "attempt_id": attempt_id,
            "settlement_id": settlement_token,
            "settlement_token": settlement_token,
            "amount": amount,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def process_purchase(self, attempt: PurchaseAttempt) -> VerificationResult:
        """
        Receives an agent's purchase attempt and executes the independent verification protocol.
        """
        result = verify_purchase(attempt)
        if result.authorized:
            self.settled_orders.append({
                "attempt_id": attempt.attempt_id,
                "item_id": attempt.item_id,
                "item_title": attempt.item_title,
                "amount": attempt.amount,
                "currency": attempt.currency,
                "settlement_id": result.settlement_id,
                "dispute_token": result.dispute_token,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        return result



# Global merchant singleton
vuelaya_merchant = VuelaYaMerchant()
