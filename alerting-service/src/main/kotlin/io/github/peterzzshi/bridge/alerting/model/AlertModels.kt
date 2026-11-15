package io.github.peterzzshi.bridge.alerting.model

import com.fasterxml.jackson.databind.ObjectMapper
import java.math.BigInteger
import java.time.Instant

enum class Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
}

enum class BridgeProtocol {
    @Suppress("ktlint:standard:enum-entry-name-case")
    wormhole,

    @Suppress("ktlint:standard:enum-entry-name-case")
    layerzero,
}

enum class SuspiciousPattern {
    RAPID_TRANSFERS,
    LARGE_TRANSFER,
    SUPPLY_MISMATCH,
    UNUSUAL_SIZE
}

enum class CrossChainPattern {
    CROSS_CHAIN_UNLOCK_WITHOUT_LOCK,
    CROSS_CHAIN_LOCK_WITHOUT_UNLOCK,
    CROSS_CHAIN_AMOUNT_MISMATCH,
    CROSS_CHAIN_SAME_CHAIN
}

sealed interface Alert {
    val bridgeAddress: String
    val windowStart: Instant
    val windowEnd: Instant
    val severity: Severity
    val alertType: String
}

data class TransferVolumeAlert(
    override val bridgeAddress: String,
    val chain: String,
    val protocol: BridgeProtocol,
    override val windowStart: Instant,
    override val windowEnd: Instant,
    override val severity: Severity,
    override val alertType: String = "TRANSFER_VOLUME",
    val lockCount: Int,
    val unlockCount: Int,
    val totalLockAmount: BigInteger,
    val totalUnlockAmount: BigInteger,
    val token0Symbol: String?,
    val token1Symbol: String?
) : Alert

data class SupplyTrackingAlert(
    override val bridgeAddress: String,
    val chain: String,
    val protocol: BridgeProtocol,
    override val windowStart: Instant,
    override val windowEnd: Instant,
    override val severity: Severity,
    override val alertType: String = "SUPPLY_TRACKING",
    val mintCount: Int,
    val burnCount: Int,
    val totalMinted: BigInteger,
    val totalBurned: BigInteger,
    val netMinted: BigInteger,
    val tokenSymbol: String?
) : Alert

data class CrossChainFlowAlert(
    override val bridgeAddress: String,
    val protocol: BridgeProtocol,
    override val windowStart: Instant,
    override val windowEnd: Instant,
    override val severity: Severity,
    override val alertType: String = "CROSS_CHAIN_FLOW",
    val totalInflow: BigInteger,
    val totalOutflow: BigInteger,
    val netFlow: BigInteger,
    val imbalanceRatio: Double
) : Alert

data class ExploitDetectionAlert(
    override val bridgeAddress: String,
    val chain: String,
    val protocol: BridgeProtocol,
    override val windowStart: Instant,
    override val windowEnd: Instant,
    override val severity: Severity,
    override val alertType: String = "EXPLOIT_DETECTION",
    val suspiciousPatterns: List<SuspiciousPattern>,
    val largestSingleTransfer: BigInteger,
    val rapidTransferCount: Int,
    val supplyMismatchDetected: Boolean,
    val totalLocked: BigInteger,
    val totalUnlocked: BigInteger,
    val totalMinted: BigInteger,
    val totalBurned: BigInteger
) : Alert

data class ReentrancyAlert(
    override val bridgeAddress: String,
    val chain: String,
    override val windowStart: Instant,
    override val windowEnd: Instant,
    override val severity: Severity,
    override val alertType: String = "REENTRANCY",
    val transactionHash: String,
    val lockCount: Int,
    val unlockCount: Int
) : Alert

data class UnusualSizeAlert(
    override val bridgeAddress: String,
    val chain: String,
    val tokenSymbol: String?,
    override val windowStart: Instant,
    override val windowEnd: Instant,
    override val severity: Severity,
    override val alertType: String = "UNUSUAL_SIZE",
    val count: Long,
    val mean: Double,
    val stddev: Double
) : Alert

fun Alert.toJson(mapper: ObjectMapper): String = mapper.writeValueAsString(this)

data class CrossChainCorrelationAlert(
    val messageHash: String,
    override val bridgeAddress: String,
    val protocol: BridgeProtocol,
    override val windowStart: Instant,
    override val windowEnd: Instant,
    override val severity: Severity,
    override val alertType: String = "CROSS_CHAIN_CORRELATION",
    val patterns: List<CrossChainPattern>,
    val lockChain: String?,
    val unlockChain: String?,
    val lockAmount: BigInteger?,
    val unlockAmount: BigInteger?,
    val timeDelta: Long?,
) : Alert
