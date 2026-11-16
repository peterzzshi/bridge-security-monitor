package io.github.peterzzshi.bridge.functions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import io.github.peterzzshi.bridge.model.UnusualSizeAccumulator;
import io.github.peterzzshi.bridge.schema.event.BridgeProtocol;
import io.github.peterzzshi.bridge.schema.event.BridgeTransferEvent;
import io.github.peterzzshi.bridge.schema.event.TransferDirection;
import java.math.BigDecimal;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class UnusualSizeAggregateFunctionTest {

  private final UnusualSizeAggregateFunction function = new UnusualSizeAggregateFunction();

  private static BridgeTransferEvent event(final String bridge, final String chain,
      final String amount, final String symbol) {
    return BridgeTransferEvent.newBuilder()
        .setEventId("evt-" + amount)
        .setTransactionHash("0xabc")
        .setBridgeAddress(bridge)
        .setChain(chain)
        .setChainName("ethereum")
        .setDirection(TransferDirection.lock)
        .setProtocol(BridgeProtocol.wormhole)
        .setAmount(new BigDecimal(new BigInteger(amount)))
        .setTokenSymbol(symbol)
        .setBlockNumber(1000L)
        .setBlockTimestamp(1234567890L)
        .setLogIndex(0)
        .setGasUsed(50000L)
        .setGasPrice("100000000")
        .setEventTimestamp(1234567890L)
        .setSender("0xsender")
        .setRecipient("0xrecipient")
        .setToken("0xtoken")
        .build();
  }

  @Test
  void addAccumulatesWelfordMeanAndM2() {
    final UnusualSizeAccumulator acc = this.function.createAccumulator();

    this.function.add(event("0x123", "ethereum", "100", "WETH"), acc);
    this.function.add(event("0x123", "ethereum", "200", "WETH"), acc);
    this.function.add(event("0x123", "ethereum", "300", "WETH"), acc);

    // For [100, 200, 300]: step-by-step Welford gives mean=200, m2=20000
    assertThat(acc.count).isEqualTo(3);
    assertThat(acc.mean).isCloseTo(200.0, within(0.0001));
    assertThat(acc.m2).isCloseTo(20000.0, within(0.0001));
  }

  @Test
  void mergeProducesIdenticalStatisticsToSequentialAdd() {
    final UnusualSizeAccumulator a = this.function.createAccumulator();
    final UnusualSizeAccumulator b = this.function.createAccumulator();

    this.function.add(event("0x123", "ethereum", "100", "WETH"), a);
    this.function.add(event("0x123", "ethereum", "200", "WETH"), a);
    this.function.add(event("0x123", "ethereum", "300", "WETH"), b);

    final UnusualSizeAccumulator merged = this.function.merge(a, b);

    assertThat(merged.count).isEqualTo(3);
    assertThat(merged.mean).isCloseTo(200.0, within(0.0001));
    assertThat(merged.m2).isCloseTo(20000.0, within(0.0001));
  }

  @Test
  void mergeIsOrderIndependent() {
    final UnusualSizeAccumulator a = this.function.createAccumulator();
    final UnusualSizeAccumulator b = this.function.createAccumulator();

    this.function.add(event("0x123", "ethereum", "100", "WETH"), a);
    this.function.add(event("0x123", "ethereum", "200", "WETH"), a);
    this.function.add(event("0x123", "ethereum", "300", "WETH"), b);

    final UnusualSizeAccumulator ab = this.function.merge(a, b);
    final UnusualSizeAccumulator ba = this.function.merge(b, a);

    assertThat(ab.count).isEqualTo(ba.count);
    assertThat(ab.mean).isCloseTo(ba.mean, within(0.0001));
    assertThat(ab.m2).isCloseTo(ba.m2, within(0.0001));
  }

  @Test
  void mergeWithEmptyAccumulatorReturnsOther() {
    final UnusualSizeAccumulator empty = this.function.createAccumulator();
    final UnusualSizeAccumulator populated = this.function.createAccumulator();

    this.function.add(event("0x123", "ethereum", "500", "WETH"), populated);

    final UnusualSizeAccumulator merged = this.function.merge(empty, populated);

    assertThat(merged.count).isEqualTo(1);
    assertThat(merged.mean).isCloseTo(500.0, within(0.0001));
    assertThat(merged.m2).isCloseTo(0.0, within(0.0001));
  }

  @Test
  void firstEventPopulatesMetadata() {
    final UnusualSizeAccumulator acc = this.function.createAccumulator();

    this.function.add(event("0x123", "ethereum", "100", "WETH"), acc);

    assertThat(acc.bridgeAddress).isEqualTo("0x123");
    assertThat(acc.chain).isEqualTo("ethereum");
    assertThat(acc.token).isEqualTo("WETH");
  }

  @Test
  void countReachesColdStartBoundary() {
    final UnusualSizeAccumulator acc = this.function.createAccumulator();

    for (int i = 0; i < 99; i++) {
      this.function.add(event("0x123", "ethereum", "100", "WETH"), acc);
    }
    assertThat(acc.count).isEqualTo(99);

    this.function.add(event("0x123", "ethereum", "100", "WETH"), acc);
    assertThat(acc.count).isEqualTo(100);
  }
}
