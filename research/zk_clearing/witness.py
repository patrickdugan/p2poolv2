"""Bounded Circom witness adapter for the offline clearing reference model.

This adapter only converts caller-asserted, locally consistent bookkeeping
into public/private circuit inputs. It does not prove any external facts.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json

from model import (
    DOMAIN,
    MAX_SATS,
    BatchPlan,
    Context,
    Escrow,
    InputState,
    InvalidBatch,
    Sale,
    plan_batch,
)

SALE_SLOTS = 16
BUYER_SLOTS = 4
# Order of the BN254 scalar field, the prime Circom's default `bn128` curve
# computes in. (21888...208583 is the base field q, not this.)
BN254_FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def build_circuit_inputs(
    sales: tuple[Sale, ...],
    escrows: tuple[Escrow, ...],
    state: InputState,
    expected_context: Context,
    observed_bitcoin_height: int,
) -> tuple[dict, BatchPlan]:
    """Create inputs for the accounting-only 16x4 circuit.

    The returned plan commitment is NOT a public input in this circuit.
    The circuit thus cannot bind payouts to sale IDs, seller addresses,
    signatures, sharechain membership or actual Bitcoin transaction outputs.
    """
    if len(sales) > SALE_SLOTS:
        raise InvalidBatch("sale count exceeds bounded circuit")
    if len(escrows) > BUYER_SLOTS:
        raise InvalidBatch("buyer count exceeds bounded circuit")
    plan = plan_batch(sales, escrows, state, expected_context, observed_bitcoin_height)
    ordered_sales = sorted(sales, key=lambda sale: sale.share_outpoint)
    ordered_escrows = sorted(escrows, key=lambda escrow: escrow.buyer_id)
    buyer_indices = {escrow.buyer_id: index for index, escrow in enumerate(ordered_escrows)}
    costs = Counter()
    assignment_counts = Counter()
    prices = [0] * SALE_SLOTS
    active = [0] * SALE_SLOTS
    inverses = [0] * SALE_SLOTS
    selectors = [[0] * BUYER_SLOTS for _ in range(SALE_SLOTS)]
    for sale_index, sale in enumerate(ordered_sales):
        buyer_index = buyer_indices[sale.buyer_id]
        prices[sale_index] = sale.price_sats
        active[sale_index] = 1
        inverses[sale_index] = pow(sale.price_sats, -1, BN254_FR)
        selectors[sale_index][buyer_index] = 1
        costs[buyer_index] += sale.price_sats
        assignment_counts[buyer_index] += 1

    funding = [0] * BUYER_SLOTS
    fee_budget = [0] * BUYER_SLOTS
    refund = [0] * BUYER_SLOTS
    active_buyer = [0] * BUYER_SLOTS
    buyer_count_inverses = [0] * BUYER_SLOTS
    for buyer_index, escrow in enumerate(ordered_escrows):
        funding[buyer_index] = escrow.funding_sats
        fee_budget[buyer_index] = escrow.fee_budget_sats
        refund[buyer_index] = escrow.funding_sats - escrow.fee_budget_sats - costs[buyer_index]
        active_buyer[buyer_index] = 1
        buyer_count_inverses[buyer_index] = pow(assignment_counts[buyer_index], -1, BN254_FR)

    inputs = {
        "funding": funding,
        "feeBudget": fee_budget,
        "refund": refund,
        "totalPayout": sum(prices),
        "price": prices,
        "activeSale": active,
        "priceInverse": inverses,
        "selector": selectors,
        "activeBuyer": active_buyer,
        "buyerCountInverse": buyer_count_inverses,
        "activeCountInverse": pow(len(ordered_sales), -1, BN254_FR),
    }
    check_relation(inputs)
    return inputs, plan


def check_relation(inputs: dict) -> None:
    """Plain-Python semantic oracle for the circuit equations.

    This checks integer and inverse arithmetic; it is NOT a Circom compiler,
    R1CS evaluator, SNARK prover, or independent cryptographic verifier.
    """
    funding = inputs["funding"]
    fees = inputs["feeBudget"]
    refunds = inputs["refund"]
    prices = inputs["price"]
    active_sale = inputs["activeSale"]
    inverses = inputs["priceInverse"]
    assignment = inputs["selector"]
    active_buyer = inputs["activeBuyer"]
    buyer_count_inverse = inputs["buyerCountInverse"]
    payout = inputs["totalPayout"]
    active_count_inverse = inputs["activeCountInverse"]
    if not (len(funding) == len(fees) == len(refunds) == len(active_buyer)
            == len(buyer_count_inverse) == BUYER_SLOTS):
        raise InvalidBatch("incorrect buyer slots")
    if not (len(prices) == len(active_sale) == len(inverses) == len(assignment) == SALE_SLOTS):
        raise InvalidBatch("incorrect sale slots")
    for value in (*funding, *fees, *refunds, *prices, payout):
        if type(value) is not int or not 0 <= value <= MAX_SATS:
            raise InvalidBatch("amount out of 0..MAX_SATS range")
    for value in (*active_sale, *active_buyer):
        if type(value) is not int or value not in (0, 1):
            raise InvalidBatch("active flags must be bits")
    for inverse in (*inverses, *buyer_count_inverse, active_count_inverse):
        if type(inverse) is not int or not 0 <= inverse < BN254_FR:
            raise InvalidBatch("invalid field inverse")
    if sum(active_sale) == 0 or sum(active_sale) * active_count_inverse % BN254_FR != 1:
        raise InvalidBatch("invalid total active count inverse")
    for sale_index in range(SALE_SLOTS):
        if len(assignment[sale_index]) != BUYER_SLOTS:
            raise InvalidBatch("incorrect selector slots")
        if any(type(choice) is not int or choice not in (0, 1) for choice in assignment[sale_index]):
            raise InvalidBatch("nonbinary selector")
        if sum(assignment[sale_index]) != active_sale[sale_index]:
            raise InvalidBatch("not one-hot for active sale")
        if not active_sale[sale_index] and prices[sale_index] != 0:
            raise InvalidBatch("inactive sale has a price")
        if prices[sale_index] * inverses[sale_index] % BN254_FR != active_sale[sale_index]:
            raise InvalidBatch("incorrect price inverse")
    if sum(prices) != payout:
        raise InvalidBatch("total payout mismatch")
    for buyer in range(BUYER_SLOTS):
        buyer_count = sum(assignment[sale][buyer] for sale in range(SALE_SLOTS))
        if buyer_count * buyer_count_inverse[buyer] % BN254_FR != active_buyer[buyer]:
            raise InvalidBatch("incorrect buyer count inverse")
        if not active_buyer[buyer] and (buyer_count or funding[buyer] or fees[buyer] or refunds[buyer]):
            raise InvalidBatch("inactive buyer contains value")
        cost = sum(prices[sale] * assignment[sale][buyer] for sale in range(SALE_SLOTS))
        if funding[buyer] != cost + fees[buyer] + refunds[buyer]:
            raise InvalidBatch("buyer funding mismatch")


def field_id(kind: str, value: str) -> int:
    """Map an identity string to a nonzero field element below BN254_FR.

    SHA-256 of a domain-separated label, truncated to 253 bits so it is
    always smaller than the 254-bit prime. Zero is reserved for padding.
    """
    digest = hashlib.sha256(f"{DOMAIN}/{kind}/{value}".encode()).digest()
    element = int.from_bytes(digest, "big") >> 3
    if element == 0:
        raise InvalidBatch(f"{kind} {value!r} hashes to zero")
    return element


def build_committed_inputs(
    sales: tuple[Sale, ...],
    escrows: tuple[Escrow, ...],
    state: InputState,
    expected_context: Context,
    observed_bitcoin_height: int,
) -> tuple[dict, BatchPlan]:
    """Inputs for accounting16x4_committed.circom.

    Adds saleId (share outpoint), sellerId (seller's sharechain address, which
    owns the share output) and buyerId (escrow buyer) to the v0 inputs, in the
    same slot order. The circuit hashes them with prices and the selected
    buyer into the public saleCommitment.
    """
    inputs, plan = build_circuit_inputs(sales, escrows, state, expected_context, observed_bitcoin_height)
    ordered_sales = sorted(sales, key=lambda sale: sale.share_outpoint)
    ordered_escrows = sorted(escrows, key=lambda escrow: escrow.buyer_id)
    inputs["saleId"] = [0] * SALE_SLOTS
    inputs["sellerId"] = [0] * SALE_SLOTS
    inputs["buyerId"] = [0] * BUYER_SLOTS
    for index, sale in enumerate(ordered_sales):
        inputs["saleId"][index] = field_id("share_outpoint", sale.share_outpoint)
        inputs["sellerId"][index] = field_id("seller_share_address", sale.seller_share_address)
    for index, escrow in enumerate(ordered_escrows):
        inputs["buyerId"][index] = field_id("buyer", escrow.buyer_id)
    check_committed_relation(inputs)
    return inputs, plan


def check_committed_relation(inputs: dict) -> None:
    """The v0 oracle plus the identity rules of the committed circuit.

    The Poseidon commitment itself is computed by the circuit and checked
    against circomlibjs in groth16/commit.js, not here.
    """
    check_relation(inputs)
    for value in (*inputs["saleId"], *inputs["sellerId"], *inputs["buyerId"]):
        if type(value) is not int or not 0 <= value < BN254_FR:
            raise InvalidBatch("identity out of field range")
    for sale in range(SALE_SLOTS):
        if not inputs["activeSale"][sale] and (inputs["saleId"][sale] or inputs["sellerId"][sale]):
            raise InvalidBatch("padding sale slot carries an identity")
    for buyer in range(BUYER_SLOTS):
        if not inputs["activeBuyer"][buyer] and inputs["buyerId"][buyer]:
            raise InvalidBatch("unused escrow slot carries an identity")


def encode_snarkjs_input(inputs: dict) -> str:
    """Serialize all field elements as strings to avoid JS Number rounding."""
    check_relation(inputs)

    def stringify(value):
        if type(value) is int:
            return str(value)
        if isinstance(value, list):
            return [stringify(item) for item in value]
        if isinstance(value, dict):
            return {key: stringify(item) for key, item in value.items()}
        raise InvalidBatch("unsupported Circom input type")

    return json.dumps(stringify(inputs), sort_keys=True, separators=(",", ":"))
