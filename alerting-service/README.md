# Alerting Service

Kotlin/Ktor service that consumes bridge security alerts from Flink via Dapr, caches recent alerts in
Redis, and broadcasts them to WebSocket clients.

## Build & Test

```bash
./gradlew test
./gradlew build
```

Avro alert classes are generated from `../schemas` at build time, so no schema path is configured at
runtime.

## Run

```bash
REDIS_HOST=localhost ./gradlew run
```

Full stack: `docker compose up -d --build` from the repo root. Settings live in
[`AppConfig`](src/main/kotlin/io/github/peterzzshi/bridge/alerting/config/AppConfig.kt) — Redis host
and port, alert retention, WebSocket keepalive. If Redis is unreachable the process fails at startup,
not on first request.

## API

### WebSocket

- `GET /ws/alerts` — live alert stream, one JSON object per text frame
  - `bridgeAddress` — exact match
  - `chain` — CAIP-2 chain id; Cross-Chain Flow alerts never match (they carry no chain)
  - `severity` — minimum severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
  - `alertTypes` — comma-separated, e.g. `EXPLOIT_DETECTION,REENTRANCY`

### REST

- `GET /health` — pings Redis, reports WebSocket connection count
- `GET /alerts/{bridgeAddress}/{chain}?limit=100` — recent alerts for one bridge+chain, newest first

### Dapr

- `POST /dapr/subscribe` — returns the five subscriptions (Dapr also loads the declarative
  subscriptions from `../dapr/subscriptions/alerting-subscriptions.yaml`)
- `POST /events/{transfer-volume,supply-tracking,cross-chain-flow,exploit-detection,reentrancy}` —
  CloudEvent handler per topic

## Message Format

Dapr delivers a CloudEvent whose `data_base64` holds the Avro-binary alert. A missing or undecodable
payload is logged and dropped; the handler still returns 200 so the sidecar does not redeliver a
poison message indefinitely.

See [ARCHITECTURE.md](../ARCHITECTURE.md) for the full data flow and
[DATA_MODEL.md](../DATA_MODEL.md#storage) for the Redis key layout.
