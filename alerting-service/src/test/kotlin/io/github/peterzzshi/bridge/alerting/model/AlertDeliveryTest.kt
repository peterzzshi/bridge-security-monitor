package io.github.peterzzshi.bridge.alerting.model

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.time.Instant

class AlertDeliveryTest {
    private val windowStart = Instant.parse("2026-11-12T10:00:00Z")
    private val windowEnd = windowStart.plusSeconds(300)

    @Test
    fun `nothing stored delivers the alert`() {
        val delivery = classifyDelivery(emptyList(), alert())
        assertInstanceOf(AlertDelivery.Fresh::class.java, delivery)
    }

    @Test
    fun `identical window is a replay`() {
        val delivery = classifyDelivery(listOf(alert()), alert())
        assertInstanceOf(AlertDelivery.Replay::class.java, delivery)
    }

    @Test
    fun `replay carries the incoming alert, not the stored one`() {
        val stored = alert(lockCount = 5)
        val incoming = alert(lockCount = 7)
        val delivery = classifyDelivery(listOf(stored), incoming)
        assertEquals(7, (delivery as AlertDelivery.Replay).alert.let { it as TransferVolumeAlert }.lockCount)
    }

    @Test
    fun `same window with different totals is still a replay`() {
        val stored = alert(totalLockAmount = BigInteger.TEN)
        val incoming = alert(totalLockAmount = BigInteger("999999"))
        assertInstanceOf(
            AlertDelivery.Replay::class.java,
            classifyDelivery(listOf(stored), incoming),
        )
    }

    @Test
    fun `different window start delivers the alert`() {
        val stored = alert()
        val later =
            alert(
                windowStart = windowStart.plusSeconds(300),
                windowEnd = windowEnd.plusSeconds(300),
            )
        assertInstanceOf(AlertDelivery.Fresh::class.java, classifyDelivery(listOf(stored), later))
    }

    @Test
    fun `different bridge delivers the alert`() {
        assertInstanceOf(
            AlertDelivery.Fresh::class.java,
            classifyDelivery(listOf(alert()), alert(bridgeAddress = "0xOther")),
        )
    }

    @Test
    fun `different alert type delivers the alert`() {
        val stored = alert()
        val other = alert().copy(alertType = "SUPPLY_TRACKING")
        assertInstanceOf(AlertDelivery.Fresh::class.java, classifyDelivery(listOf(stored), other))
    }

    private fun alert(
        bridgeAddress: String = "0xBridge123",
        windowStart: Instant = this.windowStart,
        windowEnd: Instant = this.windowEnd,
        lockCount: Int = 1,
        totalLockAmount: BigInteger = BigInteger.TEN,
    ) = TransferVolumeAlert(
        bridgeAddress = bridgeAddress,
        chain = "eip155:1",
        protocol = BridgeProtocol.wormhole,
        windowStart = windowStart,
        windowEnd = windowEnd,
        severity = Severity.HIGH,
        lockCount = lockCount,
        unlockCount = 0,
        totalLockAmount = totalLockAmount,
        totalUnlockAmount = BigInteger.ZERO,
        token0Symbol = null,
        token1Symbol = null,
    )
}
