package io.github.peterzzshi.bridge.alerting.store

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import io.github.peterzzshi.bridge.alerting.model.Alert
import io.github.peterzzshi.bridge.alerting.model.CrossChainCorrelationAlert
import io.github.peterzzshi.bridge.alerting.model.CrossChainFlowAlert
import io.github.peterzzshi.bridge.alerting.model.ExploitDetectionAlert
import io.github.peterzzshi.bridge.alerting.model.ReentrancyAlert
import io.github.peterzzshi.bridge.alerting.model.SupplyTrackingAlert
import io.github.peterzzshi.bridge.alerting.model.TransferVolumeAlert
import io.github.peterzzshi.bridge.alerting.model.UnusualSizeAlert
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import redis.clients.jedis.JedisPool
import redis.clients.jedis.params.ZAddParams

class RedisAlertStore(
    private val jedisPool: JedisPool,
    private val mapper: ObjectMapper,
    private val retentionLimit: Int = 100,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : AlertStore {
    override suspend fun storeAlert(alert: Alert): Unit =
        withContext(ioDispatcher) {
            val key = buildKey(alert)
            val score = alert.windowEnd.toEpochMilli().toDouble()
            val json = mapper.writeValueAsString(alert)

            jedisPool.resource.use { jedis ->
                jedis.zadd(key, score, json, ZAddParams().gt())
                jedis.zremrangeByRank(key, 0, -(retentionLimit + 1).toLong())
            }
        }

    override suspend fun alertsAt(alert: Alert): List<Alert> =
        withContext(ioDispatcher) {
            val key = buildKey(alert)
            val score = alert.windowEnd.toEpochMilli().toDouble()

            jedisPool.resource.use { jedis ->
                jedis
                    .zrangeByScore(key, score.toString(), score.toString())
                    .mapNotNull { runCatching { deserializeAlert(it) }.getOrNull() }
            }
        }

    override suspend fun getRecentAlerts(
        bridgeAddress: String,
        chain: String,
        limit: Int
    ): List<Alert> =
        withContext(ioDispatcher) {
            val key = "bridge:alerts:$bridgeAddress:$chain"
            jedisPool.resource.use { jedis ->
                val jsons = jedis.zrevrange(key, 0, (limit - 1).toLong())
                jsons.mapNotNull { json ->
                    try {
                        deserializeAlert(json)
                    } catch (e: Exception) {
                        null
                    }
                }
            }
        }

    private fun buildKey(alert: Alert): String {
        val chain =
            when (alert) {
                is TransferVolumeAlert -> alert.chain
                is SupplyTrackingAlert -> alert.chain
                is ExploitDetectionAlert -> alert.chain
                is ReentrancyAlert -> alert.chain
                is UnusualSizeAlert -> alert.chain
                is CrossChainFlowAlert -> "cross-chain"
                is CrossChainCorrelationAlert -> "cross-chain"
            }
        return "bridge:alerts:${alert.bridgeAddress}:$chain"
    }

    private fun deserializeAlert(json: String): Alert {
        val tree = mapper.readTree(json)
        return when (val alertType = tree["alertType"].asText()) {
            "TRANSFER_VOLUME" -> mapper.readValue<TransferVolumeAlert>(json)
            "SUPPLY_TRACKING" -> mapper.readValue<SupplyTrackingAlert>(json)
            "CROSS_CHAIN_FLOW" -> mapper.readValue<CrossChainFlowAlert>(json)
            "EXPLOIT_DETECTION" -> mapper.readValue<ExploitDetectionAlert>(json)
            "REENTRANCY" -> mapper.readValue<ReentrancyAlert>(json)
            "UNUSUAL_SIZE" -> mapper.readValue<UnusualSizeAlert>(json)
            "CROSS_CHAIN_CORRELATION" -> mapper.readValue<CrossChainCorrelationAlert>(json)
            else -> throw IllegalArgumentException("Unknown alert type: $alertType")
        }
    }
}
