package io.github.peterzzshi.bridge.alerting.store

import io.github.peterzzshi.bridge.alerting.model.Alert

interface AlertStore {
    suspend fun storeAlert(alert: Alert)

    /** Alerts already stored for this bridge and chain at the same [Alert.windowEnd]. */
    suspend fun alertsAt(alert: Alert): List<Alert>

    suspend fun getRecentAlerts(
        bridgeAddress: String,
        chain: String,
        limit: Int = 100
    ): List<Alert>
}
