pragma circom 2.1.8;

// Sixteen sale slots against the eight-way dense window tree at 6 levels.

include "window_sale.circom";

component main {public [windowRoot, activeSale, saleId, sellerId]} = WindowSales(16, 3, 6);
