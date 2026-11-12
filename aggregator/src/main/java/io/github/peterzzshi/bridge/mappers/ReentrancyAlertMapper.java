package io.github.peterzzshi.bridge.mappers;

import io.github.peterzzshi.bridge.model.ReentrancyAccumulator;
import io.github.peterzzshi.bridge.schema.alert.ReentrancyAlert;
import java.io.Serial;
import java.time.Duration;
import java.time.Instant;
import org.apache.flink.api.common.functions.MapFunction;

public class ReentrancyAlertMapper implements MapFunction<ReentrancyAccumulator, ReentrancyAlert> {

  @Serial
  private static final long serialVersionUID = 1L;

  private final long windowDurationMillis;

  public ReentrancyAlertMapper(final Duration windowDuration) {
    this.windowDurationMillis = windowDuration.toMillis();
  }

  @Override
  public ReentrancyAlert map(final ReentrancyAccumulator acc) {
    final Instant windowStart = Instant.ofEpochMilli(acc.windowEnd - this.windowDurationMillis);
    final Instant windowEnd = Instant.ofEpochMilli(acc.windowEnd);

    return ReentrancyAlert.newBuilder()
        .setTransactionHash(acc.transactionHash)
        .setBridgeAddress(acc.bridgeAddress)
        .setChain(acc.chain)
        .setWindowStart(windowStart)
        .setWindowEnd(windowEnd)
        .setSeverity(AlertSeverity.compute(acc))
        .setAlertType("REENTRANCY")
        .setLockCount(acc.lockCount)
        .setUnlockCount(acc.unlockCount)
        .build();
  }
}
