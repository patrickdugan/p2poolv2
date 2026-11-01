pragma circom 2.1.8;

// One sale slot against the eight-way dense window tree at 6 levels (262,144 positions).

include "window_sale.circom";

component main {public [windowRoot, activeSale, saleId, sellerId]} = WindowSales(1, 3, 6);
