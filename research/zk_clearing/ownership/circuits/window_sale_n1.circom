pragma circom 2.1.8;

// One sale slot against the binary dense window tree at 17 levels (131,072 positions, M5's
// live set is 119,953). Compiled to count constraints and to run the circuit on a
// production-size tree (ownership/bench_window.py).

include "window_sale.circom";

component main {public [windowRoot, activeSale, saleId, sellerId]} = WindowSales(1, 1, 17);
