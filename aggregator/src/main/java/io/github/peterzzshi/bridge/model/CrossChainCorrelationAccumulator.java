package io.github.peterzzshi.bridge.model;

import java.math.BigInteger;
import java.util.EnumSet;
import java.util.Set;

/**
 * Both legs of one cross-chain message, keyed by {@code message_hash}. Each side is optional: a
 * window may close holding only an unlock (forged VAA or dropped lock event) or only a lock
 * (stalled or censored message). {@code hasLock}/{@code hasUnlock} carry presence because a
 * legitimate amount can be zero.
 */
public class CrossChainCorrelationAccumulator implements WindowStamped {

  public String messageHash;
  public String bridgeAddress;
  public String protocol;
  public boolean hasLock;
  public boolean hasUnlock;
  public String lockChain;
  public String unlockChain;
  public BigInteger lockAmount;
  public BigInteger unlockAmount;
  public long lockTimestamp;
  public long unlockTimestamp;
  public Set<CrossChainPattern> patterns = EnumSet.noneOf(CrossChainPattern.class);
  public long windowEnd;

  /**
   * Copies identity and both legs but not the derived {@code patterns}, which {@code getResult}
   * computes once from the final sides rather than incrementally.
   */
  public CrossChainCorrelationAccumulator copy() {
    final CrossChainCorrelationAccumulator copy = new CrossChainCorrelationAccumulator();
    copy.messageHash = this.messageHash;
    copy.bridgeAddress = this.bridgeAddress;
    copy.protocol = this.protocol;
    copy.hasLock = this.hasLock;
    copy.hasUnlock = this.hasUnlock;
    copy.lockChain = this.lockChain;
    copy.unlockChain = this.unlockChain;
    copy.lockAmount = this.lockAmount;
    copy.unlockAmount = this.unlockAmount;
    copy.lockTimestamp = this.lockTimestamp;
    copy.unlockTimestamp = this.unlockTimestamp;
    copy.windowEnd = this.windowEnd;
    return copy;
  }

  @Override
  public void setWindowEnd(final long windowEnd) {
    this.windowEnd = windowEnd;
  }
}
