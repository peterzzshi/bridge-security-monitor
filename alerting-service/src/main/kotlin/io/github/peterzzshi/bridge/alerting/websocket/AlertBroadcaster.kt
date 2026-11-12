package io.github.peterzzshi.bridge.alerting.websocket

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.peterzzshi.bridge.alerting.model.Alert
import io.ktor.websocket.DefaultWebSocketSession
import io.ktor.websocket.Frame
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.channels.ClosedSendChannelException
import org.slf4j.LoggerFactory

data class Connection(
    val session: DefaultWebSocketSession,
    val filters: AlertFilters?
)

open class AlertBroadcaster(
    private val mapper: ObjectMapper
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val connections = ConcurrentHashMap<String, Connection>()

    fun addConnection(
        sessionId: String,
        session: DefaultWebSocketSession,
        filters: AlertFilters?
    ) {
        connections[sessionId] = Connection(session, filters)
        logger.info("WebSocket connected: $sessionId (total: ${connections.size})")
    }

    fun removeConnection(sessionId: String) {
        connections.remove(sessionId)
        logger.info("WebSocket disconnected: $sessionId (total: ${connections.size})")
    }

    open suspend fun broadcast(alert: Alert) {
        val json = mapper.writeValueAsString(alert)
        val frame = Frame.Text(json)
        val deadConnections = mutableListOf<String>()

        connections.forEach { (sessionId, connection) ->
            if (connection.filters == null || connection.filters.matches(alert)) {
                try {
                    connection.session.send(frame)
                } catch (e: ClosedSendChannelException) {
                    logger.warn("Dead connection detected: $sessionId")
                    deadConnections.add(sessionId)
                } catch (e: Exception) {
                    logger.error("Failed to send to $sessionId", e)
                    deadConnections.add(sessionId)
                }
            }
        }

        deadConnections.forEach { removeConnection(it) }
    }

    fun connectionCount(): Int = connections.size
}
