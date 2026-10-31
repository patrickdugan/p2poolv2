pragma circom 2.1.8;

// One sale slot at the depth chosen in OWNERSHIP.md (40 levels, leaves up to depth 39).
// The one that is proved and verified end to end by ownership/run.sh.

include "owned_sale.circom";

component main {public [utxoRoot, activeSale, saleId, sellerId]} = OwnedSales(1, 40);
