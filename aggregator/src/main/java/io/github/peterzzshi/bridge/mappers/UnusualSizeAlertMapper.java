package io.github.peterzzshi.bridge.mappers;

import io.github.peterzzshi.bridge.model.UnusualSizeAccumulator;
import io.github.peterzzshi.bridge.schema.alert.UnusualSizeAlert;
import java.io.Serial;
import java.time.Duration;
import java.time.Instant;
import org.apache.flink.api.common.functions.MapFunction;

public class UnusualSizeAlertMapper implements MapFunction<UnusualSizeAccumulator, UnusualSizeAlert> {

  @Serial
  private static final long serialVersionUID = 1L;

  private final long windowDurationMillis;

  public UnusualSizeAlertMapper(final Duration windowDuration) {
    this.windowDurationMillis = windowDuration.toMillis();
  }

  @Override
  public UnusualSizeAlert map(final UnusualSizeAccumulator acc) {
    final Instant windowStart = Instant.ofEpochMilli(acc.windowEnd - this.windowDurationMillis);
    final Instant windowEnd = Instant.ofEpochMilli(acc.windowEnd);

    final double stddev = acc.count > 1 ? Math.sqrt(acc.m2 / acc.count) : 0.0;

    return UnusualSizeAlert.newBuilder()
        .setBridgeAddress(acc.bridgeAddress)
        .setChain(acc.chain)
        .setTokenSymbol(acc.token)
        .setWindowStart(windowStart)
        .setWindowEnd(windowEnd)
        .setSeverity(AlertSeverity.compute(acc))
        .setAlertType("UNUSUAL_SIZE")
        .setCount(acc.count)
        .setMean(acc.mean)
        .setStddev(stddev)
        .build();
  }
}
