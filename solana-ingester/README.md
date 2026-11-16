# solana-ingester

Subscribes to bridge program logs on Solana over a WebSocket RPC, waits for finalized-slot
confirmation, and publishes `BridgeTransferEvent` / `BridgeSupplyEvent` records to Kafka via Dapr.

One process serves every bridge in its config file. The design is one instance per RPC endpoint —
same binary, different config — publishing to the same topics as the EVM ingester.

## Run

```bash
docker compose up -d solana-ingester solana-ingester-dapr
```

Set `SOLANA_RPC_URL` (a `wss://` URL) in `.env` at the repo root. It carries an API key, so it is
never written to a file in the repo or the image. Without it the process exits at startup.

`src/config.rs` owns the configuration: env vars (all required, no fallback defaults) and the
`solana-bridges.toml` table. Bridge entries are validated at load — unknown keys, an empty list, an
unparseable or duplicate `program_id`, and an unknown protocol all fail at startup.

Health check: `GET http://localhost:<APP_PORT>/health`.

## Design Notes

- **Pipeline layering**: `bridge_handler` owns every I/O call for a bridge — fetch the transaction,
  walk instructions, hand off. `bridge_decoder` and `bridge_normalizer` are pure: neither awaits
  anything, so a record's contents are fixed by the transaction, not by state read later.
- **Instruction decoding**: bridge programs are reached through CPI from routers, so instructions
  appear as `PartiallyDecoded` and must be matched by program id rather than position.
- **Finality gate**: events buffer until their slot is at or below the finalized slot, which a
  separate poller refreshes every `FINALITY_POLL_INTERVAL_SECS`. `finalized` costs roughly 13 s of
  latency and carries no reorg risk.
- **Gas data**: the transaction fee goes in `gasUsed` and `gasPrice` is the string `"0"` — Solana has
  no gas price.
- **Event coverage**: all four Portal instructions are decoded — `TransferNative` (lock),
  `TransferWrapped` (burn), `CompleteNative` (unlock) and `CompleteWrapped` (mint). Amounts come
  from
  instruction bytes for the outgoing legs and from the VAA for the incoming legs.
- **Failure visibility**: publishes retry with backoff, then fall back to `TOPIC_DLQ`. An unreachable
  Dapr sidecar logs and exits. Decode failures are logged and the transaction is skipped. No metrics
  exporter.

## Test & Lint

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt -- --check
```
