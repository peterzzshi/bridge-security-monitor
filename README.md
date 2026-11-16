# Bridge Security Monitor

Real-time exploit detection for cross-chain bridges. Ingests lock/unlock and mint/burn events from
Wormhole and LayerZero on Ethereum and from Wormhole Portal on Solana, aggregates them in Flink, and
pushes severity-ranked alerts to a WebSocket.

Bridges are the highest-value target in DeFi, and the damage is done in the first minutes — so the
interesting question is not "what happened last week" but "is this bridge behaving outside its
normal
envelope right now". This pipeline answers that with windows over finalized events.

## What It Detects

Seven pipelines, each emitting an Avro alert to its own Kafka topic:

| Signal                  | Window       | Fires on                                                                   |
|-------------------------|--------------|----------------------------------------------------------------------------|
| Transfer volume         | 5 min        | Lock/unlock totals per `(bridge, chain)` cross size thresholds             |
| Supply tracking         | 5 min        | Net minted/burned; **burn-only with no mints is critical** (drain pattern) |
| Cross-chain flow        | 5 min        | Inflow/outflow imbalance for one bridge across chains                      |
| Exploit patterns        | 60 s session | Rapid transfers, large single transfer, lock/mint supply mismatch          |
| Reentrancy              | 5 s          | More than one lock or unlock in a single transaction hash                  |
| Unusual size            | 5 min        | Per-token Welford mean/variance over transfer amounts                      |
| Cross-chain correlation | session      | A lock and its matching unlock, joined on `message_hash`                   |

## Pipeline

| Component           | Language        | Role                                                       |
|---------------------|-----------------|------------------------------------------------------------|
| `evm-ingester/`     | Rust            | `eth_subscribe` logs; 12-block depth finality              |
| `solana-ingester/`  | Rust            | `logsSubscribe` + finalized-slot polling                   |
| `aggregator/`       | Java 21 / Flink | Seven windowed pipelines, Avro sinks                       |
| `alerting-service/` | Kotlin / Ktor   | Dapr consumer, Redis recent-alert cache, WebSocket fan-out |
| `dapr/`             | YAML            | Kafka pub/sub component and alert subscriptions            |

`common/` is the shared Rust crate: config, Avro encoding, CloudEvents envelope, retry, finality
buffer, amount normalization, publisher. Event and alert schemas live once in root `schemas/` and
are
codegen'd by both the Maven and Gradle builds. See [ARCHITECTURE.md](ARCHITECTURE.md) for the flow
between them and the reasoning behind each decision.

## Quick Start

```bash
cp .env.example .env          # add ETH_RPC_URL and/or SOLANA_RPC_URL
docker compose up -d --build
```

Without RPC URLs the two ingesters fail validation and restart continuously; that is the intended
fail-fast behavior, and the rest of the stack still runs.

| Endpoint | URL |
|---|---|
| Health (also reports Redis and live WS connections) | `http://localhost:8080/health` |
| WebSocket alerts | `ws://localhost:8080/ws/alerts` |
| Recent alerts for a bridge | `http://localhost:8080/alerts/{bridgeAddress}/{chain}` |
| Flink UI | `http://localhost:8081` |

WebSocket clients can filter server-side with `?bridgeAddress=`, `?chain=`, `?severity=` (minimum)
and `?alertTypes=`.

## Latency, Honestly

This is a post-finality detector, not a pre-execution shield. An EVM event is published only after 12
confirmations (~2.4 min) and then has to clear a 5 s watermark and a window boundary. Solana finality
polling lands around 13 s. Nobody is front-run — the goal is to fire before an exploit has finished
draining, and before a human watching dashboards would notice.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — data flow, design decisions, alert semantics
- [GAPS.md](GAPS.md) — accepted limitations and open defects
- [AGENT.md](AGENT.md) — conventions and commands

Each component directory has its own `README.md`.
