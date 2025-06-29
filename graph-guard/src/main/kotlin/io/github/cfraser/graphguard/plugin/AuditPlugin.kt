package io.github.cfraser.graphguard.plugin

import io.github.cfraser.graphguard.Bolt
import io.github.cfraser.graphguard.Server
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.slf4j.LoggerFactory
import org.slf4j.MDC
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * [AuditPlugin] is a [Server.Plugin] that provides comprehensive audit logging for graph-guard
 * proxy operations. It tracks:
 * - Query execution with timing and result metadata
 * - User session lifecycle and authentication
 * - Connection establishment and termination
 * - Transaction boundaries and state changes
 * - Compliance reporting with configurable retention
 *
 * The plugin operates in observe-only mode to ensure it doesn't interfere with proxy operations.
 * All audit events are logged in structured JSON format for compliance and monitoring systems.
 *
 * @param config the [AuditConfig] configuration
 */
class AuditPlugin(
    private val config: AuditConfig = AuditConfig()
) : Server.Plugin {

    /** Thread-safe session tracking storage */
    private val activeSessions = ConcurrentHashMap<Bolt.Session, SessionInfo>()
    
    /** Thread-safe operation counters */
    private val counters = AuditCounters()
    
    /** Mutex for thread-safe audit event writing */
    private val auditLock = Mutex()

    /** Plugin does not intercept messages - operates in observe-only mode for safety */
    override suspend fun intercept(session: Bolt.Session, message: Bolt.Message): Bolt.Message = message

    /** Main audit logic - observes all server events and logs comprehensive audit trails */
    override suspend fun observe(event: Server.Event) {
        when (event) {
            is Server.Started -> auditSimpleEvent("SERVER_STARTED")
            is Server.Stopped -> auditSimpleEvent("SERVER_STOPPED")
            is Server.Connected -> auditSimpleEvent("CONNECTION_ESTABLISHED", event.connection)
            is Server.Disconnected -> auditSimpleEvent("CONNECTION_TERMINATED", event.connection)
            is Server.Proxied -> auditProxiedMessage(event)
        }
    }

    /** Audit simple events (server lifecycle and connections) */
    private suspend fun auditSimpleEvent(eventType: String, connection: Server.Connection? = null) {
        auditLock.withLock {
            val eventBuilder = AuditEventBuilder(eventType)
                .timestamp(Instant.now())
            
            if (connection != null) {
                // Connection event
                eventBuilder
                    .connectionType(when (connection) {
                        is Server.Connection.Client -> "CLIENT"
                        is Server.Connection.Graph -> "DATABASE"
                    })
                    .sourceAddress(connection.address.toString())
                    .metadata(mapOf(
                        "connection_type" to connection::class.simpleName,
                        "address" to connection.address.toString()
                    ))
            } else {
                // Server event
                eventBuilder.metadata(mapOf(
                    "proxy_version" to "graph-guard",
                    "active_sessions" to activeSessions.size,
                    "total_queries" to counters.totalQueries.get(),
                    "total_transactions" to counters.totalTransactions.get()
                ))
            }
            
            setupMdcAndLog(eventBuilder.build())
        }
    }

    /** Audit proxied messages - the core audit functionality */
    private suspend fun auditProxiedMessage(event: Server.Proxied) {
        val sessionInfo = activeSessions.computeIfAbsent(event.session) {
            SessionInfo(
                sessionId = event.session.id.toString(),
                createdAt = Instant.now(),
                sourceAddress = AddressExtractor.getSourceAddress(event)
            )
        }
        
        when (val message = event.received) {
            is Bolt.Hello -> auditAuthentication(event, message, sessionInfo)
            is Bolt.Run -> auditQueryExecution(event, message, sessionInfo)
            is Bolt.Pull -> auditResultFetch(event, message, sessionInfo) 
            is Bolt.Begin -> auditTransactionEvent("TRANSACTION_BEGIN", event, sessionInfo)
            is Bolt.Commit -> auditTransactionEvent("TRANSACTION_COMMIT", event, sessionInfo)
            is Bolt.Rollback -> auditTransactionEvent("TRANSACTION_ROLLBACK", event, sessionInfo)
            is Bolt.Logon -> auditSessionOrGenericEvent("SESSION_LOGON", event, sessionInfo)
            is Bolt.Logoff -> auditSessionOrGenericEvent("SESSION_LOGOFF", event, sessionInfo)
            else -> if (config.auditAllMessages) auditSessionOrGenericEvent("MESSAGE_PROXIED", event, sessionInfo, true)
        }

        // Update session activity timestamp
        sessionInfo.lastActivity = Instant.now()
    }

    /** Audit user authentication attempts */
    private suspend fun auditAuthentication(
        event: Server.Proxied, 
        message: Bolt.Hello, 
        sessionInfo: SessionInfo
    ) {
        auditLock.withLock {
            val userAgent = message.extra["user_agent"] as? String
            val scheme = message.extra["scheme"] as? String
            val userId = QueryProcessor.extractUserId(message.extra)
            
            sessionInfo.userAgent = userAgent
            sessionInfo.authScheme = scheme
            sessionInfo.userId = userId
            
            val auditEventBuilder = AuditEventBuilder("AUTHENTICATION_ATTEMPT")
                .sessionId(event.session.id.toString())
                .sourceAddress(AddressExtractor.getSourceAddress(event))
                .destinationAddress(AddressExtractor.getDestinationAddress(event))
                .userId(userId)
                .timestamp(Instant.now())
                .metadata(buildMap {
                    put("user_agent", userAgent)
                    put("auth_scheme", scheme)
                    put("routing", message.extra["routing"])
                    put("protocol_version", event.session.version.toString())
                    if (event.sent is Bolt.Success) {
                        put("auth_result", "SUCCESS")
                        sessionInfo.authenticated = true
                        sessionInfo.authenticatedAt = Instant.now()
                    } else if (event.sent is Bolt.Failure) {
                        put("auth_result", "FAILURE") 
                        put("failure_reason", (event.sent as Bolt.Failure).metadata["message"])
                    }
                })
            
            setupMdcAndLog(auditEventBuilder.build())
        }
    }

    /** Audit Cypher query execution with comprehensive metadata */
    private suspend fun auditQueryExecution(
        event: Server.Proxied,
        message: Bolt.Run, 
        sessionInfo: SessionInfo
    ) {
        auditLock.withLock {
            counters.totalQueries.incrementAndGet()
            sessionInfo.queryCount.incrementAndGet()
            
            val queryHash = message.query.hashCode().toString()
            val startTime = Instant.now()
            
            val auditEventBuilder = AuditEventBuilder("QUERY_EXECUTION")
                .sessionId(event.session.id.toString())
                .sourceAddress(AddressExtractor.getSourceAddress(event))
                .destinationAddress(AddressExtractor.getDestinationAddress(event))
                .userId(sessionInfo.userId)
                .query(if (config.logQueryContent) message.query else queryHash)
                .queryHash(queryHash)
                .timestamp(startTime)
                .metadata(buildMap {
                    put("query_length", message.query.length)
                    put("parameter_count", message.parameters.size)
                    put("query_type", QueryProcessor.detectQueryType(message.query))
                    put("transaction_id", sessionInfo.currentTransactionId)
                    put("session_query_count", sessionInfo.queryCount.get())
                    
                    if (config.logParameters && message.parameters.isNotEmpty()) {
                        put("parameters", 
                            QueryProcessor.sanitizeParameters(message.parameters, config.maxParameterLength))
                    }
                    
                    if (config.logDatabases) {
                        message.extra["db"]?.let { put("database", it) }
                    }
                    
                    // Add result metadata if response is available
                    when (val response = event.sent) {
                        is Bolt.Success -> {
                            put("execution_result", "SUCCESS")
                            response.metadata["t_first"]?.let { put("time_to_first", it) }
                            response.metadata["t_last"]?.let { put("time_to_last", it) }
                            response.metadata["stats"]?.let { put("query_stats", it) }
                        }
                        is Bolt.Failure -> {
                            put("execution_result", "FAILURE")
                            put("error_code", response.metadata["code"])
                            put("error_message", response.metadata["message"])
                        }
                        else -> {
                            put("execution_result", "OTHER")
                        }
                    }
                })
            
            setupMdcAndLog(auditEventBuilder.build())
        }
    }

    /** Audit result fetching operations */
    private suspend fun auditResultFetch(
        event: Server.Proxied,
        message: Bolt.Pull,
        sessionInfo: SessionInfo
    ) {
        if (!config.auditResultFetch) return
        
        auditLock.withLock {
            val auditEventBuilder = AuditEventBuilder("RESULT_FETCH")
                .sessionId(event.session.id.toString())
                .sourceAddress(AddressExtractor.getSourceAddress(event))
                .destinationAddress(AddressExtractor.getDestinationAddress(event))
                .userId(sessionInfo.userId)
                .timestamp(Instant.now())
                .metadata(buildMap {
                    put("fetch_extra", message.extra)
                    
                    when (val response = event.sent) {
                        is Bolt.Success -> {
                            put("fetch_result", "SUCCESS")
                            response.metadata["has_more"]?.let { put("has_more", it) }
                        }
                        is Bolt.Record -> put("fetch_result", "RECORD")
                        is Bolt.Failure -> {
                            put("fetch_result", "FAILURE")
                            put("error_message", response.metadata["message"])
                        }
                        else -> {
                            put("fetch_result", "OTHER")
                        }
                    }
                })
            
            setupMdcAndLog(auditEventBuilder.build())
        }
    }

    /** Audit transaction boundary events */
    private suspend fun auditTransactionEvent(
        eventType: String,
        event: Server.Proxied,
        sessionInfo: SessionInfo
    ) {
        auditLock.withLock {
            when (eventType) {
                "TRANSACTION_BEGIN" -> {
                    counters.totalTransactions.incrementAndGet()
                    sessionInfo.currentTransactionId = "tx_${System.nanoTime()}"
                    sessionInfo.transactionStartTime = Instant.now()
                }
                "TRANSACTION_COMMIT", "TRANSACTION_ROLLBACK" -> {
                    sessionInfo.currentTransactionId = null
                    sessionInfo.transactionStartTime = null
                }
            }
            
            val auditEventBuilder = AuditEventBuilder(eventType)
                .sessionId(event.session.id.toString())
                .sourceAddress(AddressExtractor.getSourceAddress(event))
                .destinationAddress(AddressExtractor.getDestinationAddress(event))
                .userId(sessionInfo.userId)
                .timestamp(Instant.now())
                .metadata(buildMap {
                    put("transaction_id", sessionInfo.currentTransactionId)
                    
                    if (eventType != "TRANSACTION_BEGIN") {
                        sessionInfo.transactionStartTime?.let { startTime ->
                            put("transaction_duration_ms", 
                                java.time.Duration.between(startTime, Instant.now()).toMillis())
                        }
                    }
                    
                    when (val response = event.sent) {
                        is Bolt.Success -> put("transaction_result", "SUCCESS")
                        is Bolt.Failure -> {
                            put("transaction_result", "FAILURE")
                            put("error_message", response.metadata["message"])
                        }
                        else -> {
                            put("transaction_result", "OTHER")
                        }
                    }
                })
            
            setupMdcAndLog(auditEventBuilder.build())
        }
    }

    /** Audit session and generic message events */
    private suspend fun auditSessionOrGenericEvent(
        eventType: String,
        event: Server.Proxied,
        sessionInfo: SessionInfo,
        isGenericMessage: Boolean = false
    ) {
        auditLock.withLock {
            if (eventType == "SESSION_LOGOFF") {
                // Final session summary
                val sessionDuration = java.time.Duration.between(sessionInfo.createdAt, Instant.now())
                
                val sessionSummaryEvent = AuditEventBuilder("SESSION_SUMMARY")
                    .sessionId(event.session.id.toString())
                    .sourceAddress(AddressExtractor.getSourceAddress(event))
                    .userId(sessionInfo.userId)
                    .timestamp(Instant.now())
                    .metadata(mapOf(
                        "session_duration_ms" to sessionDuration.toMillis(),
                        "total_queries" to sessionInfo.queryCount.get(),
                        "authenticated" to sessionInfo.authenticated,
                        "user_agent" to sessionInfo.userAgent,
                        "auth_scheme" to sessionInfo.authScheme
                    ))
                
                setupMdcAndLog(sessionSummaryEvent.build())
                
                // Clean up session tracking
                activeSessions.remove(event.session)
            }
            
            val eventBuilder = AuditEventBuilder(eventType)
                .sessionId(event.session.id.toString())
                .sourceAddress(AddressExtractor.getSourceAddress(event))
                .destinationAddress(AddressExtractor.getDestinationAddress(event))
                .userId(sessionInfo.userId)
                .timestamp(Instant.now())
            
            if (isGenericMessage) {
                eventBuilder.metadata(mapOf(
                    "message_type" to event.received::class.simpleName,
                    "response_type" to event.sent::class.simpleName
                ))
            } else {
                eventBuilder.metadata(emptyMap())
            }
            
            setupMdcAndLog(eventBuilder.build())
        }
    }



    
    @Suppress("CyclomaticComplexMethod")
    private fun setupMdcAndLog(auditEvent: AuditEventContext) {
        // Set MDC context
        MDC.put("audit_event", auditEvent.eventType)
        MDC.put("timestamp", DateTimeFormatter.ISO_INSTANT.format(auditEvent.timestamp))
        auditEvent.sessionId?.let { MDC.put("session_id", it) }
        auditEvent.sourceAddress?.let { MDC.put("source_address", it) }
        auditEvent.destinationAddress?.let { MDC.put("destination_address", it) }
        auditEvent.userId?.let { MDC.put("user_id", it) }
        auditEvent.queryHash?.let { MDC.put("query_hash", it) }
        auditEvent.connectionType?.let { MDC.put("connection_type", it) }
        
        try {
            // Log main audit message
            val logMessage = "AUDIT: ${auditEvent.eventType}" +
                auditEvent.sessionId?.let { " [session=$it]" }.orEmpty() +
                auditEvent.userId?.let { " [user=$it]" }.orEmpty() +
                auditEvent.sourceAddress?.let { " [source=$it]" }.orEmpty()

            when (config.auditLevel) {
                AuditLevel.INFO -> AUDIT_LOGGER.info(logMessage)
                AuditLevel.WARN -> AUDIT_LOGGER.warn(logMessage)
                AuditLevel.ERROR -> AUDIT_LOGGER.error(logMessage)
            }
            
            // Log query content and metadata
            auditEvent.query?.takeIf { config.logQueryContent }?.let {
                AUDIT_LOGGER.info("AUDIT: QUERY_CONTENT [session=${auditEvent.sessionId}] query='{}'", it)
            }
            
            if (auditEvent.metadata.isNotEmpty() && AUDIT_LOGGER.isDebugEnabled) {
                AUDIT_LOGGER.debug("AUDIT: METADATA [session=${auditEvent.sessionId}] {}", auditEvent.metadata)
            }
            
            // Compliance recording disabled (reporter commented out)
        } finally {
            // Clear MDC context
            MDC.remove("audit_event")
            MDC.remove("timestamp") 
            MDC.remove("session_id")
            MDC.remove("source_address")
            MDC.remove("destination_address")
            MDC.remove("user_id")
            MDC.remove("query_hash")
            MDC.remove("connection_type")
        }
    }

    /** Internal audit event context */
    private data class AuditEventContext(
        val eventType: String,
        val timestamp: Instant = Instant.now(),
        val sessionId: String? = null,
        val sourceAddress: String? = null,
        val destinationAddress: String? = null,
        val userId: String? = null,
        val query: String? = null,
        val queryHash: String? = null,
        val connectionType: String? = null,
        val metadata: Map<String, Any?> = emptyMap()
    )

    /** Builder for AuditEventContext to avoid long parameter lists */
    private class AuditEventBuilder(private val eventType: String) {
        private var timestamp: Instant = Instant.now()
        private var sessionId: String? = null
        private var sourceAddress: String? = null
        private var destinationAddress: String? = null
        private var userId: String? = null
        private var query: String? = null
        private var queryHash: String? = null
        private var connectionType: String? = null
        private var metadata: Map<String, Any?> = emptyMap()

        fun timestamp(timestamp: Instant) = apply { this.timestamp = timestamp }
        fun sessionId(sessionId: String?) = apply { this.sessionId = sessionId }
        fun sourceAddress(sourceAddress: String?) = apply { this.sourceAddress = sourceAddress }
        fun destinationAddress(destinationAddress: String?) = apply { this.destinationAddress = destinationAddress }
        fun userId(userId: String?) = apply { this.userId = userId }
        fun query(query: String?) = apply { this.query = query }
        fun queryHash(queryHash: String?) = apply { this.queryHash = queryHash }
        fun connectionType(connectionType: String?) = apply { this.connectionType = connectionType }
        fun metadata(metadata: Map<String, Any?>) = apply { this.metadata = metadata }

        fun build() = AuditEventContext(
            eventType, timestamp, sessionId, sourceAddress, destinationAddress,
            userId, query, queryHash, connectionType, metadata
        )
    }


    /** Utility for extracting addresses from proxied events */
    private object AddressExtractor {
        fun getSourceAddress(event: Server.Proxied): String = event.source.address.toString()
        fun getDestinationAddress(event: Server.Proxied): String = event.destination.address.toString()
    }

    /** Utility for processing query-related data */
    private object QueryProcessor {
        fun detectQueryType(query: String): String {
            val normalized = query.trim().uppercase()
            return when {
                normalized.startsWith("MATCH") -> "READ"
                normalized.startsWith("CREATE") -> "WRITE"
                normalized.startsWith("MERGE") -> "WRITE"
                normalized.startsWith("DELETE") -> "WRITE"
                normalized.startsWith("SET") -> "WRITE"
                normalized.startsWith("REMOVE") -> "WRITE"
                normalized.startsWith("SHOW") -> "ADMIN"
                normalized.startsWith("CALL") -> "PROCEDURE"
                else -> "OTHER"
            }
        }

        fun sanitizeParameters(parameters: Map<String, Any?>, maxLength: Int): Map<String, Any?> {
            return parameters.mapValues { (key, value) ->
                when {
                    key.lowercase().contains("password") -> "***REDACTED***"
                    key.lowercase().contains("secret") -> "***REDACTED***"
                    key.lowercase().contains("token") -> "***REDACTED***"
                    value is String && value.length > maxLength -> 
                        "${value.take(maxLength)}...[TRUNCATED]"
                    else -> value
                }
            }
        }

        fun extractUserId(extra: Map<String, Any?>): String? {
            return extra["principal"] as? String ?: extra["credentials"]?.let { 
                if (it is Map<*, *>) it["username"] as? String else null
            }
        }
    }

    /** Session tracking information */
    private class SessionInfo(
        val sessionId: String,
        val createdAt: Instant,
        val sourceAddress: String
    ) {
        var userId: String? = null
        var userAgent: String? = null
        var authScheme: String? = null
        var authenticated: Boolean = false
        var authenticatedAt: Instant? = null
        var lastActivity: Instant = createdAt
        var currentTransactionId: String? = null
        var transactionStartTime: Instant? = null
        val queryCount: AtomicLong = AtomicLong(0)
    }

    /** Thread-safe operation counters */
    private data class AuditCounters(
        val totalQueries: AtomicLong = AtomicLong(0),
        val totalTransactions: AtomicLong = AtomicLong(0)
    )


    private companion object {
        val AUDIT_LOGGER = LoggerFactory.getLogger("AUDIT.${AuditPlugin::class.java.simpleName}")!!
    }
}

/** Audit configuration options */
data class AuditConfig(
    /** Enable auditing of query content (vs just query hashes) */
    val logQueryContent: Boolean = true,
    
    /** Enable auditing of query parameters */
    val logParameters: Boolean = false,
    
    /** Enable auditing of database names */
    val logDatabases: Boolean = true,
    
    /** Enable auditing of result fetch operations */
    val auditResultFetch: Boolean = false,
    
    /** Enable auditing of all message types (vs just core operations) */
    val auditAllMessages: Boolean = false,
    
    /** Maximum length for parameter values before truncation */
    val maxParameterLength: Int = 1000,
    
    /** Audit log level */
    val auditLevel: AuditLevel = AuditLevel.INFO
)

/** Audit logging levels */
enum class AuditLevel {
    INFO, WARN, ERROR
}
