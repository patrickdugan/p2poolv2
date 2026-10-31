"""Emit an illustrative Circom witness JSON. All identities are placeholders.

Usage: python3 example_inputs.py [--committed]
"""

import sys

from model import Context, Escrow, InputState, Sale
from witness import build_circuit_inputs, build_committed_inputs, encode_snarkjs_input


def example_batch(sales: tuple[Sale, ...] | None = None):
    context = Context("signet", "example-share-tip", "example-bitcoin-tip", 500)
    if sales is None:
        sales = (
            Sale("example-share:0", "exampleShareAlice", "exampleBtcAlice", "exampleBuyerShare1", "buyer1", 1200),
            Sale("example-share:1", "exampleShareBob", "exampleBtcBob", "exampleBuyerShare2", "buyer2", 1800),
        )
    escrows = (
        Escrow("buyer1", "example-btc:0", "exampleRefund1", 1600, 100),
        Escrow("buyer2", "example-btc:1", "exampleRefund2", 2300, 200),
    )
    state = InputState(
        context=context,
        owners_by_outpoint={sale.share_outpoint: sale.seller_share_address for sale in sales},
        authorized_sales_by_outpoint={sale.share_outpoint: sale for sale in sales},
        previously_cleared_outpoints=frozenset(),
        previously_used_escrows=frozenset(),
    )
    return sales, escrows, state, context


def resplit_sales() -> tuple[Sale, ...]:
    """A different sale list with the same per-buyer totals as the example."""
    return (
        Sale("example-share:2", "exampleShareCarol", "exampleBtcCarol", "exampleBuyerShare1", "buyer1", 600),
        Sale("example-share:3", "exampleShareCarol", "exampleBtcCarol", "exampleBuyerShare1", "buyer1", 600),
        Sale("example-share:4", "exampleShareDave", "exampleBtcDave", "exampleBuyerShare2", "buyer2", 1000),
        Sale("example-share:5", "exampleShareDave", "exampleBtcDave", "exampleBuyerShare2", "buyer2", 800),
    )


def example_circuit_inputs(committed: bool = False, sales: tuple[Sale, ...] | None = None) -> dict:
    sales, escrows, state, context = example_batch(sales)
    build = build_committed_inputs if committed else build_circuit_inputs
    inputs, _ = build(sales, escrows, state, context, 499)
    return inputs


def main() -> None:
    print(encode_snarkjs_input(example_circuit_inputs(committed="--committed" in sys.argv[1:])))


if __name__ == "__main__":
    main()
