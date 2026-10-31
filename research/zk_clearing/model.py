"""Offline, non-consensus reference model for a proposed P2Poolv2 share clearing batch.

This module does NOT authenticate sharechain state, authorizations, Bitcoin
funding, or enforce Bitcoin escrow. All such inputs are caller assertions.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Mapping

MAX_SATS = 21_000_000 * 100_000_000
DOMAIN = "p2poolv2/proposed-share-clearing/v0"


class InvalidBatch(ValueError):
    """The proposed batch violates a reference accounting invariant."""


@dataclass(frozen=True)
class Sale:
    share_outpoint: str
    seller_share_address: str
    seller_bitcoin_address: str
    buyer_share_address: str
    buyer_id: str
    price_sats: int


@dataclass(frozen=True)
class Escrow:
    buyer_id: str
    bitcoin_outpoint: str
    bitcoin_refund_address: str
    funding_sats: int
    fee_budget_sats: int


@dataclass(frozen=True)
class Context:
    network: str
    sharechain_tip: str
    bitcoin_tip: str
    expiry_bitcoin_height: int


@dataclass(frozen=True)
class InputState:
    """Assertions supplied by an external verifier, NOT proven by this model."""

    context: Context
    owners_by_outpoint: Mapping[str, str]
    authorized_sales_by_outpoint: Mapping[str, Sale]
    previously_cleared_outpoints: frozenset[str]
    previously_used_escrows: frozenset[str]


@dataclass(frozen=True)
class BatchPlan:
    commitment: str
    payouts: tuple[tuple[str, int], ...]
    refunds: tuple[tuple[str, int], ...]
    fee_budget_sats: int
    funding_sats: int


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidBatch(message)


def _amount(value: int, field: str, allow_zero: bool = False) -> None:
    _require(type(value) is int, f"{field} must be an integer")
    lower = 0 if allow_zero else 1
    _require(lower <= value <= MAX_SATS, f"{field} out of range")


def _text(value: str, field: str) -> None:
    _require(isinstance(value, str) and bool(value.strip()), f"empty {field}")


def plan_batch(
    sales: tuple[Sale, ...],
    escrows: tuple[Escrow, ...],
    state: InputState,
    expected_context: Context,
    observed_bitcoin_height: int,
) -> BatchPlan:
    """Check an offline settlement plan against *asserted* input state.

    No transaction construction, signature checking, ZK proof, or BitVM bridge.
    Callers must independently authenticate inputs and persist spent nullifiers.
    """
    _require(state.context == expected_context, "snapshot context mismatch")
    _require(type(observed_bitcoin_height) is int and observed_bitcoin_height >= 0, "invalid observed height")
    _require(type(state.context.expiry_bitcoin_height) is int and state.context.expiry_bitcoin_height >= 0, "invalid expiry height")
    _require(observed_bitcoin_height <= state.context.expiry_bitcoin_height, "expired snapshot")
    _text(state.context.network, "network")
    _text(state.context.bitcoin_tip, "bitcoin tip")
    _text(state.context.sharechain_tip, "sharechain tip")
    _require(bool(sales), "empty batch")
    _require(bool(escrows), "no escrow funding")

    escrow_by_buyer: dict[str, Escrow] = {}
    escrow_outpoints: set[str] = set()
    for escrow in escrows:
        _text(escrow.buyer_id, "buyer id")
        _text(escrow.bitcoin_outpoint, "escrow outpoint")
        _text(escrow.bitcoin_refund_address, "refund address")
        _amount(escrow.funding_sats, "funding")
        _amount(escrow.fee_budget_sats, "fee budget", allow_zero=True)
        _require(escrow.buyer_id not in escrow_by_buyer, "duplicate buyer escrow")
        _require(escrow.bitcoin_outpoint not in escrow_outpoints, "duplicate escrow outpoint")
        _require(escrow.bitcoin_outpoint not in state.previously_used_escrows, "escrow reused")
        escrow_by_buyer[escrow.buyer_id] = escrow
        escrow_outpoints.add(escrow.bitcoin_outpoint)

    input_outpoints: set[str] = set()
    costs_by_buyer: dict[str, int] = {}
    payouts_by_address: dict[str, int] = {}
    for sale in sales:
        _text(sale.share_outpoint, "share outpoint")
        _text(sale.seller_share_address, "seller share address")
        _text(sale.seller_bitcoin_address, "seller bitcoin address")
        _text(sale.buyer_share_address, "buyer share address")
        _text(sale.buyer_id, "buyer id")
        _amount(sale.price_sats, "sale price")
        _require(sale.share_outpoint not in input_outpoints, "duplicate share outpoint")
        _require(sale.share_outpoint not in state.previously_cleared_outpoints, "share already cleared")
        _require(state.owners_by_outpoint.get(sale.share_outpoint) == sale.seller_share_address,
                 "unmatched asserted share owner")
        _require(state.authorized_sales_by_outpoint.get(sale.share_outpoint) == sale,
                 "unmatched asserted authorization")
        _require(sale.buyer_id in escrow_by_buyer, "missing buyer escrow")
        input_outpoints.add(sale.share_outpoint)
        costs_by_buyer[sale.buyer_id] = costs_by_buyer.get(sale.buyer_id, 0) + sale.price_sats
        payouts_by_address[sale.seller_bitcoin_address] = (
            payouts_by_address.get(sale.seller_bitcoin_address, 0) + sale.price_sats
        )

    _require(set(costs_by_buyer) == set(escrow_by_buyer), "unused buyer escrow")
    refunds_by_address: dict[str, int] = {}
    for escrow in escrows:
        amount_owed = costs_by_buyer[escrow.buyer_id] + escrow.fee_budget_sats
        _require(amount_owed <= escrow.funding_sats, "undercollateralized buyer")
        change = escrow.funding_sats - amount_owed
        refunds_by_address[escrow.bitcoin_refund_address] = (
            refunds_by_address.get(escrow.bitcoin_refund_address, 0) + change
        )

    funding = sum(escrow.funding_sats for escrow in escrows)
    fee_budget = sum(escrow.fee_budget_sats for escrow in escrows)
    payouts = tuple(sorted(payouts_by_address.items()))
    refunds = tuple(sorted((address, amount) for address, amount in refunds_by_address.items() if amount))
    _require(sum(amount for _, amount in payouts) + sum(amount for _, amount in refunds) + fee_budget == funding,
             "settlement conservation failure")

    # The commitment binds all data this model uses, including fee allocations,
    # asserted snapshots and spend/replay guards. It is NOT a ZK proof or escrow.
    statement = {
        "domain": DOMAIN,
        "context": asdict(state.context),
        "sales": [asdict(sale) for sale in sorted(sales, key=lambda item: item.share_outpoint)],
        "escrows": [asdict(escrow) for escrow in sorted(escrows, key=lambda item: item.buyer_id)],
        "owners": sorted((outpoint, state.owners_by_outpoint[outpoint]) for outpoint in input_outpoints),
        "authorizations": sorted((outpoint, asdict(state.authorized_sales_by_outpoint[outpoint]))
                                 for outpoint in input_outpoints),
        "previously_cleared": sorted(state.previously_cleared_outpoints),
        "previously_used_escrows": sorted(state.previously_used_escrows),
        "payouts": payouts,
        "refunds": refunds,
        "fee_budget_sats": fee_budget,
        "funding_sats": funding,
    }
    encoded = json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    commitment = hashlib.sha256(encoded).hexdigest()
    return BatchPlan(commitment, payouts, refunds, fee_budget, funding)
