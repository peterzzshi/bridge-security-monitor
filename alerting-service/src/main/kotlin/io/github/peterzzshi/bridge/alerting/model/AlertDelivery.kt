package io.github.peterzzshi.bridge.alerting.model

/**
 * Whether an incoming alert is new or a replay of one already stored for the same window.
 * An at-least-once sink can re-emit a window after a restart, so the distinction is a normal
 * outcome rather than an error.
 */
sealed interface AlertDelivery {
    val alert: Alert

    data class Fresh(
        override val alert: Alert,
    ) : AlertDelivery

    data class Replay(
        override val alert: Alert,
    ) : AlertDelivery
}

/** Pure: given what is already stored, classify the incoming alert. */
fun classifyDelivery(
    existing: List<Alert>,
    incoming: Alert,
): AlertDelivery =
    if (existing.any { it.identity == incoming.identity }) {
        AlertDelivery.Replay(incoming)
    } else {
        AlertDelivery.Fresh(incoming)
    }
