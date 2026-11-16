# evm-ingester

Subscribes to bridge contract events on an EVM chain over a WebSocket RPC, waits for block-depth
finality, and publishes `BridgeTransferEvent` records to Kafka via Dapr.

The EVM decoder handles Wormhole lock/unlock and LayerZero packet send/verify. It emits no
`BridgeSupplyEvent`: the Wormhole token bridge on Ethereum operates in lock/unlock mode, so value
movement appears as a transfer rather than a supply change.

One process serves every bridge in its config file, each with its own listener task. The design is
one instance per EVM chain — same binary, different config — publishing to the same topics as the
Solana ingester.

## Run

```bash
docker compose up -d evm-ingester evm-ingester-dapr
```

Set `ETH_RPC_URL` (a `wss://` URL) in `.env` at the repo root. It carries an API key, so it is never
written to a file in the repo or the image. Without it the process exits at startup.

`src/config.rs` owns the configuration: env vars (all required, no fallback defaults) and the
`evm-bridges.toml` table. Bridge entries are validated at load — unknown keys, an empty list, a
malformed or duplicate address, and an unknown protocol all fail at startup with the offending field
in the message.

## Design Notes

- **Reorg handling**: logs flagged `removed: true` by the subscription are dropped, not forwarded.
- **Finality gate**: an event becomes final only once the chain has advanced 12 blocks past it
  (`confirmations` is a constant in `config.rs`, not a TOML key). Depth-based, so no separate poller
  is needed — unlike the Solana ingester's external-slot model.
- **Gas data**: populated from the transaction receipt (`gas_used`, `effective_gas_price`), fetched
  when the event is emitted, not when it is first seen.
- **Failure visibility**: events evicted from the finality buffer on overflow, and publishes that
  exhaust their retries, go to `TOPIC_DLQ`. An unreachable Dapr sidecar logs and exits rather than
  degrading silently. Decode failures are logged and the log is skipped. No health endpoint, no
  metrics exporter.

## Test & Lint

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt -- --check
```
