package io.github.peterzzshi.bridge.alerting.websocket

import io.github.peterzzshi.bridge.alerting.model.Severity

data class AlertFilters(
    val bridgeAddress: String? = null,
    val chain: String? = null,
    val minSeverity: Severity? = null,
    val alertTypes: Set<String>? = null
) {
    companion object {
        fun fromQueryParams(params: Map<String, List<String>>): AlertFilters =
            AlertFilters(
                bridgeAddress = params["bridgeAddress"]?.firstOrNull(),
                chain = params["chain"]?.firstOrNull(),
                minSeverity = params["severity"]?.firstOrNull()?.let { Severity.valueOf(it.uppercase()) },
                alertTypes = params["alertTypes"]?.toSet()
            )
    }

    fun matches(alert: io.github.peterzzshi.bridge.alerting.model.Alert): Boolean {
        if (bridgeAddress != null && alert.bridgeAddress != bridgeAddress) return false

        val alertChain =
            when (alert) {
                is io.github.peterzzshi.bridge.alerting.model.TransferVolumeAlert -> alert.chain
                is io.github.peterzzshi.bridge.alerting.model.SupplyTrackingAlert -> alert.chain
                is io.github.peterzzshi.bridge.alerting.model.ExploitDetectionAlert -> alert.chain
                is io.github.peterzzshi.bridge.alerting.model.ReentrancyAlert -> alert.chain
                is io.github.peterzzshi.bridge.alerting.model.UnusualSizeAlert -> alert.chain
                is io.github.peterzzshi.bridge.alerting.model.CrossChainFlowAlert -> null
            }
        if (chain != null && alertChain != chain) return false

        if (minSeverity != null && alert.severity.ordinal < minSeverity.ordinal) return false

        if (alertTypes != null && alert.alertType !in alertTypes) return false

        return true
    }
}
