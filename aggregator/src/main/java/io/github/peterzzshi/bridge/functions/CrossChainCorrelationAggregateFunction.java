package io.github.peterzzshi.bridge.functions;

import io.github.peterzzshi.bridge.model.CrossChainCorrelationAccumulator;
import io.github.peterzzshi.bridge.model.CrossChainPattern;
import io.github.peterzzshi.bridge.schema.event.BridgeTransferEvent;
import io.github.peterzzshi.bridge.schema.event.TransferDirection;
import java.io.Serial;
import java.math.BigInteger;
import org.apache.flink.api.common.functions.AggregateFunction;

/**
 * Correlates the lock and unlock legs of one Wormhole message by its {@code message_hash}. Each
 * side lands at most once per accumulator, so an at-least-once replay of the same event cannot
 * double-count, and arrival order does not matter: an unlock that precedes its lock only fills the
 * unlock slot and the lock fills the other when it arrives.
 */
public class CrossChainCorrelationAggregateFunction implements
    AggregateFunction<BridgeTransferEvent, CrossChainCorrelationAccumulator,
        CrossChainCorrelationAccumulator> {

  @Serial
  private static final long serialVersionUID = 1L;

  /**
   * A 10% fee gap between locked and released value is normal; more than that is a signal.
   */
  private static final BigInteger AMOUNT_TOLERANCE_PERCENT = BigInteger.TEN;

  private static boolean amountsDiverge(final BigInteger locked, final BigInteger unlocked) {
    if (locked.signum() == 0) {
      return !unlocked.equals(BigInteger.ZERO);
    }
    final BigInteger difference = unlocked.subtract(locked).abs();
    return difference.multiply(BigInteger.valueOf(100))
        .compareTo(locked.abs().multiply(AMOUNT_TOLERANCE_PERCENT)) > 0;
  }

  @Override
  public CrossChainCorrelationAccumulator createAccumulator() {
    return new CrossChainCorrelationAccumulator();
  }

  @Override
  public CrossChainCorrelationAccumulator add(
      final BridgeTransferEvent event,
      final CrossChainCorrelationAccumulator acc) {

    if (acc.messageHash == null) {
      acc.messageHash = event.getMessageHash();
      acc.bridgeAddress = event.getBridgeAddress();
      acc.protocol = event.getProtocol().toString();
    }

    if (event.getDirection() == TransferDirection.lock) {
      if (!acc.hasLock) {
        acc.hasLock = true;
        acc.lockChain = event.getChain();
        acc.lockAmount = new BigInteger(event.getAmount().unscaledValue().toString());
        acc.lockTimestamp = event.getBlockTimestamp();
      }
    } else if (!acc.hasUnlock) {
      acc.hasUnlock = true;
      acc.unlockChain = event.getChain();
      acc.unlockAmount = new BigInteger(event.getAmount().unscaledValue().toString());
      acc.unlockTimestamp = event.getBlockTimestamp();
    }

    return acc;
  }

  @Override
  public CrossChainCorrelationAccumulator getResult(final CrossChainCorrelationAccumulator acc) {
    final CrossChainCorrelationAccumulator result = acc.copy();

    if (result.hasUnlock && !result.hasLock) {
      result.patterns.add(CrossChainPattern.CROSS_CHAIN_UNLOCK_WITHOUT_LOCK);
    }
    if (result.hasLock && !result.hasUnlock) {
      result.patterns.add(CrossChainPattern.CROSS_CHAIN_LOCK_WITHOUT_UNLOCK);
    }
    if (result.hasLock && result.hasUnlock) {
      if (result.lockChain.equals(result.unlockChain)) {
        result.patterns.add(CrossChainPattern.CROSS_CHAIN_SAME_CHAIN);
      }
      if (amountsDiverge(result.lockAmount, result.unlockAmount)) {
        result.patterns.add(CrossChainPattern.CROSS_CHAIN_AMOUNT_MISMATCH);
      }
    }

    return result;
  }

  @Override
  public CrossChainCorrelationAccumulator merge(
      final CrossChainCorrelationAccumulator a,
      final CrossChainCorrelationAccumulator b) {

    final CrossChainCorrelationAccumulator merged = a.copy();

    if (!merged.hasLock && b.hasLock) {
      merged.hasLock = true;
      merged.lockChain = b.lockChain;
      merged.lockAmount = b.lockAmount;
      merged.lockTimestamp = b.lockTimestamp;
    }
    if (!merged.hasUnlock && b.hasUnlock) {
      merged.hasUnlock = true;
      merged.unlockChain = b.unlockChain;
      merged.unlockAmount = b.unlockAmount;
      merged.unlockTimestamp = b.unlockTimestamp;
    }

    return merged;
  }
}
