pragma circom 2.1.8;

// Sixteen sale slots, the width of accounting16x4_committed.circom, at 40 levels.
// Compiled to count constraints; not proved (the proving key needs a 2^18 powers-of-tau file).

include "owned_sale.circom";

component main {public [utxoRoot, activeSale, saleId, sellerId]} = OwnedSales(16, 40);
