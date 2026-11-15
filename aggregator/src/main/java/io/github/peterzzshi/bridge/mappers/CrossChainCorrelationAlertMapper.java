package io.github.peterzzshi.bridge.mappers;

import io.github.peterzzshi.bridge.model.CrossChainCorrelationAccumulator;
import io.github.peterzzshi.bridge.schema.alert.BridgeProtocol;
import io.github.peterzzshi.bridge.schema.alert.CrossChainCorrelationAlert;
import io.github.peterzzshi.bridge.schema.alert.CrossChainPattern;
import java.io.Serial;
import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import org.apache.flink.api.common.functions.MapFunction;

public class CrossChainCorrelationAlertMapper
    implements MapFunction<CrossChainCorrelationAccumulator, CrossChainCorrelationAlert> {

  @Serial
  private static final long serialVersionUID = 1L;

  private final long windowDurationMillis;

  public CrossChainCorrelationAlertMapper(final Duration windowDuration) {
    this.windowDurationMillis = windowDuration.toMillis();
  }

  @Override
  public CrossChainCorrelationAlert map(final CrossChainCorrelationAccumulator acc) {
    final Instant windowEnd = Instant.ofEpochMilli(acc.windowEnd);
    final Instant windowStart = Instant.ofEpochMilli(acc.windowEnd - this.windowDurationMillis);

    final Long timeDelta = acc.hasLock && acc.hasUnlock
        ? acc.unlockTimestamp - acc.lockTimestamp
        : null;

    return CrossChainCorrelationAlert.newBuilder()
        .setMessageHash(acc.messageHash)
        .setBridgeAddress(acc.bridgeAddress)
        .setProtocol(BridgeProtocol.valueOf(acc.protocol))
        .setWindowStart(windowStart)
        .setWindowEnd(windowEnd)
        .setSeverity(AlertSeverity.compute(acc))
        .setAlertType("CROSS_CHAIN_CORRELATION")
        .setPatterns(acc.patterns.stream().map(p -> CrossChainPattern.valueOf(p.name())).toList())
        .setLockChain(acc.lockChain)
        .setUnlockChain(acc.unlockChain)
        .setLockAmount(acc.lockAmount == null ? null : new BigDecimal(acc.lockAmount))
        .setUnlockAmount(acc.unlockAmount == null ? null : new BigDecimal(acc.unlockAmount))
        .setTimeDelta(timeDelta)
        .build();
  }
}
