import pytest
from engine.llm_judge import verificar_semantica_con_llm


def test_verificar_semantica_allowed_flight():
    # Vuelo legítimo dentro de la categoría flight
    es_riesgosa, motivo = verificar_semantica_con_llm(
        intento_desc="Vuelo Buenos Aires - Córdoba AR1504",
        categoria_permitida="flight",
        precio=130.00,
        allow_offline_heuristic=True,
    )
    assert es_riesgosa is False
    assert isinstance(motivo, str) and len(motivo) > 5


def test_verificar_semantica_evasion_gift_card():
    # Intento de evasión comprando tarjeta de regalo o crypto
    es_riesgosa, motivo = verificar_semantica_con_llm(
        intento_desc="Amazon Gift Card $100 Saldo",
        categoria_permitida="flight",
        precio=100.00,
        allow_offline_heuristic=True,
    )
    assert es_riesgosa is True
    assert isinstance(motivo, str) and len(motivo) > 5


def test_verificar_semantica_wrong_category():
    # Intento de comprar comida cuando solo se permite flight
    es_riesgosa, motivo = verificar_semantica_con_llm(
        intento_desc="Cena de Lujo en Restaurante Gourmet",
        categoria_permitida="flight",
        precio=120.00,
        allow_offline_heuristic=True,
    )
    assert es_riesgosa is True
