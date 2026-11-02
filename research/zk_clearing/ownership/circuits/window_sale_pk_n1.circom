pragma circom 2.1.8;

// One sale slot against the packed dense window tree: bottom nodes of four (key, owner) records
// and five eight-way levels above (131,072 positions).

include "window_sale.circom";

component main {public [windowRoot, activeSale, saleId, sellerId]} = PackedWindowSales(1, 2, 3, 5);
