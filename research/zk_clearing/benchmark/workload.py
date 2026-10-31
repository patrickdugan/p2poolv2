"""The M7 workload: 100 miners, 5 market makers, 10,000 share-sale offers.

Fixed seed. Miners' hashrate shares follow a Pareto law (a few large miners,
a long tail), each offer's seller is drawn by hashrate, its buyer uniformly
among market makers, its price from a log-normal around 50,000 sats, and
arrivals are uniform over one week.
"""

from __future__ import annotations

from dataclasses import dataclass
import random

SEED = 20261101
MINERS = 100
MARKET_MAKERS = 5
OFFERS = 10_000
WEEK_SECONDS = 7 * 24 * 3600


@dataclass(frozen=True)
class Offer:
    arrival: float  # seconds from the start of the week
    miner: int
    market_maker: int
    price_sats: int


def hashrate_shares(rng: random.Random) -> list[float]:
    raw = [rng.paretovariate(1.2) for _ in range(MINERS)]
    total = sum(raw)
    return [value / total for value in raw]


def offers(seed: int = SEED) -> list[Offer]:
    rng = random.Random(seed)
    weights = hashrate_shares(rng)
    result = []
    for _ in range(OFFERS):
        price = int(min(5_000_000, max(1_000, rng.lognormvariate(10.82, 1.0))))  # median e^10.82 ~ 50,000
        result.append(
            Offer(
                arrival=rng.uniform(0, WEEK_SECONDS),
                miner=rng.choices(range(MINERS), weights=weights)[0],
                market_maker=rng.randrange(MARKET_MAKERS),
                price_sats=price,
            )
        )
    return sorted(result, key=lambda offer: offer.arrival)
