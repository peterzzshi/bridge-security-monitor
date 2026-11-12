package io.github.peterzzshi.bridge.alerting.model

import java.time.Instant

/**
 * The identity of an alert within a window. A replay re-emits the same window, so two alerts
 * with equal keys are the same alert, regardless of the aggregates they carry.
 */
data class AlertIdentity(
    val alertType: String,
    val bridgeAddress: String,
    val windowStart: Instant,
    val windowEnd: Instant,
)

val Alert.identity: AlertIdentity
    get() = AlertIdentity(alertType, bridgeAddress, windowStart, windowEnd)
