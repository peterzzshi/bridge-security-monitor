package io.github.peterzzshi.bridge.alerting.consumer

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.ObjectMapper
import io.github.peterzzshi.bridge.alerting.model.toKotlinAlert
import io.github.peterzzshi.bridge.alerting.store.AlertStore
import io.github.peterzzshi.bridge.alerting.websocket.AlertBroadcaster
import io.github.peterzzshi.bridge.schema.alert.CrossChainFlowAlert
import io.github.peterzzshi.bridge.schema.alert.ExploitDetectionAlert
import io.github.peterzzshi.bridge.schema.alert.ReentrancyAlert
import io.github.peterzzshi.bridge.schema.alert.SupplyTrackingAlert
import io.github.peterzzshi.bridge.schema.alert.TransferVolumeAlert
import org.apache.avro.io.DecoderFactory
import org.apache.avro.specific.SpecificDatumReader
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

    suspend fun handleTransferVolume(body: String) {
        try {
            val cloudEvent = mapper.readValue(body, CloudEventWrapper::class.java)
            val alert = deserialize(cloudEvent, TransferVolumeAlert::class.java)
            store.storeAlert(alert.toKotlinAlert())
            broadcaster.broadcast(alert.toKotlinAlert())
            logger.info(
                "Processed TransferVolumeAlert: ${alert.bridgeAddress} ${alert.chain} severity=${alert.severity}"
            )
        } catch (e: Exception) {
            logger.error("Failed to handle TransferVolumeAlert", e)
        }
    }

    suspend fun handleSupplyTracking(body: String) {
        try {
            val cloudEvent = mapper.readValue(body, CloudEventWrapper::class.java)
            val alert = deserialize(cloudEvent, SupplyTrackingAlert::class.java)
            store.storeAlert(alert.toKotlinAlert())
            broadcaster.broadcast(alert.toKotlinAlert())
            logger.info(
                "Processed SupplyTrackingAlert: ${alert.bridgeAddress} ${alert.chain} severity=${alert.severity}"
            )
        } catch (e: Exception) {
            logger.error("Failed to handle SupplyTrackingAlert", e)
        }
    }

    suspend fun handleCrossChainFlow(body: String) {
        try {
            val cloudEvent = mapper.readValue(body, CloudEventWrapper::class.java)
            val alert = deserialize(cloudEvent, CrossChainFlowAlert::class.java)
            store.storeAlert(alert.toKotlinAlert())
            broadcaster.broadcast(alert.toKotlinAlert())
            logger.info("Processed CrossChainFlowAlert: ${alert.bridgeAddress} severity=${alert.severity}")
        } catch (e: Exception) {
            logger.error("Failed to handle CrossChainFlowAlert", e)
        }
    }

    suspend fun handleExploitDetection(body: String) {
        try {
            val cloudEvent = mapper.readValue(body, CloudEventWrapper::class.java)
            val alert = deserialize(cloudEvent, ExploitDetectionAlert::class.java)
            store.storeAlert(alert.toKotlinAlert())
            broadcaster.broadcast(alert.toKotlinAlert())
            logger.info(
                "Processed ExploitDetectionAlert: ${alert.bridgeAddress} ${alert.chain} patterns=${alert.suspiciousPatterns.size}"
            )
        } catch (e: Exception) {
            logger.error("Failed to handle ExploitDetectionAlert", e)
        }
    }

    suspend fun handleReentrancy(body: String) {
        try {
            val cloudEvent = mapper.readValue(body, CloudEventWrapper::class.java)
            val alert = deserialize(cloudEvent, ReentrancyAlert::class.java)
            store.storeAlert(alert.toKotlinAlert())
            broadcaster.broadcast(alert.toKotlinAlert())
            logger.info("Processed ReentrancyAlert: ${alert.transactionHash} locks=${alert.lockCount}")
        } catch (e: Exception) {
            logger.error("Failed to handle ReentrancyAlert", e)
        }
    }

    private fun <T : org.apache.avro.specific.SpecificRecordBase> deserialize(
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
