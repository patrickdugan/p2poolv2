"""Emit an illustrative Circom witness JSON. All identities are placeholders."""

from model import Context, Escrow, InputState, Sale
from witness import build_circuit_inputs, encode_snarkjs_input


def main() -> None:
    context = Context("signet", "example-share-tip", "example-bitcoin-tip", 500)
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
    inputs, _ = build_circuit_inputs(sales, escrows, state, context, 499)
    print(encode_snarkjs_input(inputs))


if __name__ == "__main__":
    main()
