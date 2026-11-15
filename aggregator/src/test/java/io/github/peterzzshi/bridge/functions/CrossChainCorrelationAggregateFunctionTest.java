package io.github.peterzzshi.bridge.functions;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.peterzzshi.bridge.model.CrossChainCorrelationAccumulator;
import io.github.peterzzshi.bridge.model.CrossChainPattern;
import io.github.peterzzshi.bridge.schema.event.BridgeProtocol;
import io.github.peterzzshi.bridge.schema.event.BridgeTransferEvent;
import io.github.peterzzshi.bridge.schema.event.TransferDirection;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.Test;

class CrossChainCorrelationAggregateFunctionTest {

  private static final String MESSAGE_HASH = "2:000000000000000000000000b6f6d86a8f9879a9c87f643768d499977f6b6c58:42";

  private final CrossChainCorrelationAggregateFunction function =
      new CrossChainCorrelationAggregateFunction();

  static BridgeTransferEvent event(
      final TransferDirection direction,
      final String chain,
      final String amount,
      final long blockTimestamp) {
    return BridgeTransferEvent.newBuilder()
        .setEventId("event-" + direction)
        .setBlockNumber(1L)
        .setBlockTimestamp(blockTimestamp)
        .setTransactionHash("0xab")
        .setLogIndex(0)
        .setChain(chain)
        .setChainName(chain)
        .setBridgeAddress("0x3ee18b2214aff97000d974cf647e7c347e8fa585")
        .setProtocol(BridgeProtocol.wormhole)
        .setDirection(direction)
        .setGasUsed(21000L)
        .setGasPrice("1")
        .setEventTimestamp(blockTimestamp)
        .setSender("")
        .setRecipient("")
        .setToken("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
        .setAmount(new BigDecimal(amount))
        .setMessageHash(MESSAGE_HASH)
        .build();
  }

  private CrossChainCorrelationAccumulator aggregate(final BridgeTransferEvent... events) {
    final CrossChainCorrelationAccumulator acc = this.function.createAccumulator();
    for (final BridgeTransferEvent event : events) {
      this.function.add(event, acc);
    }
    return this.function.getResult(acc);
  }

  @Test
  void matchedLegsWithEqualAmountsAndDistinctChainsProduceNoPatterns() {
    final CrossChainCorrelationAccumulator result = this.aggregate(
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.lock, "solana:5eykt", "1000", 100),
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.unlock, "eip155:1", "1000", 160));

    assertThat(result.patterns).isEmpty();
    assertThat(result.lockChain).isEqualTo("solana:5eykt");
    assertThat(result.unlockChain).isEqualTo("eip155:1");
  }

  @Test
  void unlockBeforeLockStillCorrelatesBothLegs() {
    final CrossChainCorrelationAccumulator result = this.aggregate(
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.unlock, "eip155:1", "500", 200),
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.lock, "solana:5eykt", "500", 100));

    assertThat(result.hasLock).isTrue();
    assertThat(result.hasUnlock).isTrue();
    assertThat(result.patterns).isEmpty();
  }

  @Test
  void unlockWithoutLockIsFlagged() {
    final CrossChainCorrelationAccumulator result = this.aggregate(
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.unlock, "eip155:1", "500", 200));

    assertThat(result.patterns).containsExactly(CrossChainPattern.CROSS_CHAIN_UNLOCK_WITHOUT_LOCK);
  }

  @Test
  void lockWithoutUnlockIsFlagged() {
    final CrossChainCorrelationAccumulator result = this.aggregate(
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.lock, "solana:5eykt", "500", 200));

    assertThat(result.patterns).containsExactly(CrossChainPattern.CROSS_CHAIN_LOCK_WITHOUT_UNLOCK);
  }

  @Test
  void sameChainUnlockIsFlagged() {
    final CrossChainCorrelationAccumulator result = this.aggregate(
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.lock, "eip155:1", "500", 100),
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.unlock, "eip155:1", "500", 200));

    assertThat(result.patterns).containsExactly(CrossChainPattern.CROSS_CHAIN_SAME_CHAIN);
  }

  @Test
  void tenPercentDivergenceIsWithinTolerance() {
    final CrossChainCorrelationAccumulator result = this.aggregate(
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.lock, "solana:5eykt", "1000", 100),
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.unlock, "eip155:1", "900", 200));

    assertThat(result.patterns).isEmpty();
  }

  @Test
  void divergenceBeyondTenPercentIsFlagged() {
    final CrossChainCorrelationAccumulator result = this.aggregate(
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.lock, "solana:5eykt", "1000", 100),
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.unlock, "eip155:1", "1101", 200));

    assertThat(result.patterns).containsExactly(CrossChainPattern.CROSS_CHAIN_AMOUNT_MISMATCH);
  }

  @Test
  void zeroLockWithNonZeroUnlockIsFlagged() {
    final CrossChainCorrelationAccumulator result = this.aggregate(
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.lock, "solana:5eykt", "0", 100),
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.unlock, "eip155:1", "1", 200));

    assertThat(result.patterns).containsExactly(CrossChainPattern.CROSS_CHAIN_AMOUNT_MISMATCH);
  }

  @Test
  void replayedEventDoesNotOverwriteTheFirstLeg() {
    final CrossChainCorrelationAccumulator result = this.aggregate(
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.lock, "solana:5eykt", "1000", 100),
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.lock, "solana:5eykt", "999999", 300));

    assertThat(result.lockAmount).isEqualByComparingTo(new BigInteger("1000"));
  }

  @Test
  void mergeCombinesSidesFromDifferentAccumulators() {
    final CrossChainCorrelationAccumulator a = this.function.createAccumulator();
    final CrossChainCorrelationAccumulator b = this.function.createAccumulator();

    this.function.add(
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.lock, "solana:5eykt", "1000", 100), a);
    this.function.add(
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.unlock, "eip155:1", "1000", 200), b);

    final CrossChainCorrelationAccumulator merged = this.function.getResult(
        this.function.merge(a, b));

    assertThat(merged.hasLock).isTrue();
    assertThat(merged.hasUnlock).isTrue();
    assertThat(merged.patterns).isEmpty();
  }

  @Test
  void getResultDoesNotMutateTheAccumulator() {
    final CrossChainCorrelationAccumulator acc = this.function.createAccumulator();
    this.function.add(
        CrossChainCorrelationAggregateFunctionTest.event(
            TransferDirection.unlock, "eip155:1", "500", 200), acc);

    final List<CrossChainPattern> patternsBefore = List.copyOf(acc.patterns);
    final CrossChainCorrelationAccumulator result = this.function.getResult(acc);

    assertThat(acc.patterns).containsExactlyElementsOf(patternsBefore);
    assertThat(result.patterns).containsExactly(CrossChainPattern.CROSS_CHAIN_UNLOCK_WITHOUT_LOCK);
  }
}
