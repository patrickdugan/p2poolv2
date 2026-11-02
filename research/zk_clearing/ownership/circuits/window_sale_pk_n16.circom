pragma circom 2.1.8;

// Sixteen sale slots against the packed dense window tree (four records per bottom node, five
// eight-way levels above).

include "window_sale.circom";

component main {public [windowRoot, activeSale, saleId, sellerId]} = PackedWindowSales(16, 2, 3, 5);
