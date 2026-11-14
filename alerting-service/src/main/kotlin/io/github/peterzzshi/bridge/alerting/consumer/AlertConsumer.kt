package io.github.peterzzshi.bridge.alerting.consumer

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.ObjectMapper
import io.github.peterzzshi.bridge.alerting.model.Alert
import io.github.peterzzshi.bridge.alerting.model.AlertDelivery
import io.github.peterzzshi.bridge.alerting.model.AlertIdentity
import io.github.peterzzshi.bridge.alerting.model.classifyDelivery
import io.github.peterzzshi.bridge.alerting.model.identity
import io.github.peterzzshi.bridge.alerting.model.toKotlinAlert
import io.github.peterzzshi.bridge.alerting.store.AlertStore
import io.github.peterzzshi.bridge.alerting.websocket.AlertBroadcaster
import io.github.peterzzshi.bridge.schema.alert.CrossChainFlowAlert
import io.github.peterzzshi.bridge.schema.alert.ExploitDetectionAlert
import io.github.peterzzshi.bridge.schema.alert.ReentrancyAlert
import io.github.peterzzshi.bridge.schema.alert.SupplyTrackingAlert
import io.github.peterzzshi.bridge.schema.alert.TransferVolumeAlert
import io.github.peterzzshi.bridge.schema.alert.UnusualSizeAlert
import org.apache.avro.io.DecoderFactory
import org.apache.avro.specific.SpecificDatumReader
import org.apache.avro.specific.SpecificRecordBase
import org.slf4j.LoggerFactory
import java.util.Base64

data class CloudEventWrapper(
    val specversion: String,
    val type: String,
    val source: String,
    val id: String,
    val datacontenttype: String,
    @JsonProperty("data") val dataJson: String? = null,
    @JsonProperty("data_base64") val dataBase64: String? = null,
)

class AlertConsumer(
    private val store: AlertStore,
    private val broadcaster: AlertBroadcaster,
    private val mapper: ObjectMapper,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun handleTransferVolume(body: String) =
        handle(body, TransferVolumeAlert::class.java) { it.toKotlinAlert() }

    suspend fun handleSupplyTracking(body: String) =
        handle(body, SupplyTrackingAlert::class.java) { it.toKotlinAlert() }

    suspend fun handleCrossChainFlow(body: String) =
        handle(body, CrossChainFlowAlert::class.java) { it.toKotlinAlert() }

    suspend fun handleExploitDetection(body: String) =
        handle(body, ExploitDetectionAlert::class.java) { it.toKotlinAlert() }

    suspend fun handleReentrancy(body: String) = handle(body, ReentrancyAlert::class.java) { it.toKotlinAlert() }

    suspend fun handleUnusualSize(body: String) = handle(body, UnusualSizeAlert::class.java) { it.toKotlinAlert() }

    private suspend fun <T : SpecificRecordBase> handle(
        body: String,
        clazz: Class<T>,
        toAlert: (T) -> Alert,
    ) {
        try {
            val cloudEvent = mapper.readValue(body, CloudEventWrapper::class.java)
            val alert = toAlert(deserialize(cloudEvent, clazz))
            when (val delivery = classifyDelivery(store.alertsAt(alert), alert)) {
                is AlertDelivery.Fresh -> {
                    store.storeAlert(delivery.alert)
                    broadcaster.broadcast(delivery.alert)
                    logger.info("Delivered ${describe(delivery.alert.identity)}")
                }

                is AlertDelivery.Replay -> {
                    logger.info("Dropped replayed ${describe(delivery.alert.identity)}")
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to handle ${clazz.simpleName}", e)
        }
    }

    private fun describe(identity: AlertIdentity): String =
        "${identity.alertType} bridge=${identity.bridgeAddress} " +
            "window=${identity.windowStart}..${identity.windowEnd}"

    private fun <T : SpecificRecordBase> deserialize(
        cloudEvent: CloudEventWrapper,
        clazz: Class<T>,
    ): T {
        val base64Data =
            cloudEvent.dataBase64
                ?: throw IllegalArgumentException("Missing data_base64 field")
        val bytes = Base64.getDecoder().decode(base64Data)
        val decoder = DecoderFactory.get().binaryDecoder(bytes, null)
        val reader = SpecificDatumReader(clazz)
        return reader.read(null, decoder)
    }
}
