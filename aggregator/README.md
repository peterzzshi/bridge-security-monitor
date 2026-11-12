# Aggregator

Apache Flink 2 job (Java 21) consuming bridge events from Kafka and producing five alert streams.

`io.github.peterzzshi.bridge.BridgeStreamProcessor` builds five pipelines over the two ingest topics
and sinks each one to its own Kafka topic. See root
[ARCHITECTURE.md](../ARCHITECTURE.md#event-to-alert-mapping) for the event-to-alert contract.

Every value the job reads is a required env var with no fallback — a missing or malformed one fails
the job at launch with the variable name in the message.
[`BridgeStreamProcessorConfig.fromEnv`](src/main/java/io/github/peterzzshi/bridge/config/BridgeStreamProcessorConfig.java)
is the full list; `docker-compose.yml` holds the values for the default stack. Alert topic names are
constants in `AlertTopics`, not env vars.

## Build & Test

```bash
mvn test
mvn -DskipTests package
```

## Run

The compose stack runs the job in standalone application mode:

```bash
docker compose up -d flink-jobmanager flink-taskmanager
```

The shaded jar declares `BridgeStreamProcessor` as its main class, so
`java -jar target/aggregator-1.0-SNAPSHOT.jar` starts the job directly, as does
`flink run -c io.github.peterzzshi.bridge.BridgeStreamProcessor`.

Flink UI: <http://localhost:8081>. One job, five sink vertices.
