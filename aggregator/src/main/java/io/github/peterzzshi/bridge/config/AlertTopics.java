package io.github.peterzzshi.bridge.config;

/**
 * Kafka topic names for bridge security alerts. Each alert type writes to its own topic, consumed
 * by the alerting service via Dapr subscription.
 */
public final class AlertTopics {

  public static final String TRANSFER_VOLUME = "bridge-alerts-transfer-volume";
  public static final String SUPPLY_TRACKING = "bridge-alerts-supply-tracking";
  public static final String CROSS_CHAIN_FLOW = "bridge-alerts-cross-chain-flow";
  public static final String EXPLOIT_DETECTION = "bridge-alerts-exploit-detection";
  public static final String REENTRANCY = "bridge-alerts-reentrancy";
  public static final String UNUSUAL_SIZE = "bridge-alerts-unusual-size";
  public static final String CROSS_CHAIN_CORRELATION = "bridge-alerts-cross-chain-correlation";

  private AlertTopics() {
  }
}
