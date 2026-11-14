package io.github.peterzzshi.bridge.functions;

import io.github.peterzzshi.bridge.model.UnusualSizeAccumulator;
import io.github.peterzzshi.bridge.schema.event.BridgeTransferEvent;
import java.io.Serial;
import org.apache.flink.api.common.functions.AggregateFunction;

public class UnusualSizeAggregateFunction implements
    AggregateFunction<BridgeTransferEvent, UnusualSizeAccumulator, UnusualSizeAccumulator> {

  @Serial
  private static final long serialVersionUID = 1L;

  @Override
  public UnusualSizeAccumulator createAccumulator() {
    return new UnusualSizeAccumulator();
  }

  @Override
  public UnusualSizeAccumulator add(
      final BridgeTransferEvent event,
      final UnusualSizeAccumulator acc) {

    if (acc.bridgeAddress == null) {
      acc.bridgeAddress = event.getBridgeAddress();
      acc.chain = event.getChain();
      acc.token = event.getTokenSymbol();
    }

    final double amount = event.getAmount().doubleValue();
    acc.count++;
    final double delta = amount - acc.mean;
    acc.mean += delta / acc.count;
    final double delta2 = amount - acc.mean;
    acc.m2 += delta * delta2;

    return acc;
  }

  @Override
  public UnusualSizeAccumulator getResult(final UnusualSizeAccumulator acc) {
    return acc;
  }

  @Override
  public UnusualSizeAccumulator merge(
      final UnusualSizeAccumulator a,
      final UnusualSizeAccumulator b) {

    if (a.count == 0) {
      return b;
    }
    if (b.count == 0) {
      return a;
    }

    final UnusualSizeAccumulator merged = new UnusualSizeAccumulator(
        a.bridgeAddress,
        a.chain,
        a.token,
        a.windowEnd
    );

    merged.count = a.count + b.count;
    final double delta = b.mean - a.mean;
    merged.mean = (a.count * a.mean + b.count * b.mean) / merged.count;
    merged.m2 = a.m2 + b.m2 + delta * delta * a.count * b.count / merged.count;

    return merged;
  }
}
