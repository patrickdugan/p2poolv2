pragma circom 2.1.8;

// Sixteen sale slots against the binary dense window tree at 17 levels, the width of
// owned_sale_n16.circom. Compiled to count constraints.

include "window_sale.circom";

component main {public [windowRoot, activeSale, saleId, sellerId]} = WindowSales(16, 1, 17);
