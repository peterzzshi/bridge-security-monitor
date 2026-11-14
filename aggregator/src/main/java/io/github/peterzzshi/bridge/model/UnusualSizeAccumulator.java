package io.github.peterzzshi.bridge.model;

public class UnusualSizeAccumulator implements WindowStamped {

  public String bridgeAddress;
  public String chain;
  public String token;
  public long count = 0;
  public double mean = 0.0;
  public double m2 = 0.0;
  public long windowEnd;

  public UnusualSizeAccumulator() {
  }

  public UnusualSizeAccumulator(final String bridgeAddress, final String chain,
      final String token, final long windowEnd) {
    this.bridgeAddress = bridgeAddress;
    this.chain = chain;
    this.token = token;
    this.windowEnd = windowEnd;
  }

  @Override
  public void setWindowEnd(final long windowEnd) {
    this.windowEnd = windowEnd;
  }
}
