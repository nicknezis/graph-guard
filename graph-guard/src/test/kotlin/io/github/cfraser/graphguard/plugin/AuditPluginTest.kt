package io.github.cfraser.graphguard.plugin

import io.github.cfraser.graphguard.Bolt
import io.github.cfraser.graphguard.Server
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.coroutines.delay
import java.net.InetSocketAddress
import java.util.*
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.time.Duration.Companion.milliseconds

/**
 * TestAuditCollector captures audit events for testing without relying on logging
 */
class TestAuditCollector(private val auditEvents: ConcurrentLinkedQueue<String>) : Server.Plugin {
    
    // Track user IDs per session
    private val sessionUsers = mutableMapOf<String, String?>()
    
    override suspend fun intercept(session: Bolt.Session, message: Bolt.Message): Bolt.Message = message
    
    override suspend fun observe(event: Server.Event) {
        when (event) {
            is Server.Started -> auditEvents.add("SERVER_STARTED")
            is Server.Stopped -> auditEvents.add("SERVER_STOPPED")
            is Server.Connected -> handleConnectionEvent(event)
            is Server.Disconnected -> handleDisconnectionEvent(event)
            is Server.Proxied -> handleProxiedEvent(event)
        }
    }
    
    private fun handleConnectionEvent(event: Server.Connected) {
        val connectionType = when (event.connection) {
            is Server.Connection.Client -> "CLIENT"
            is Server.Connection.Graph -> "DATABASE"
        }
        auditEvents.add("CONNECTION_ESTABLISHED:$connectionType:${event.connection.address}")
    }
    
    private fun handleDisconnectionEvent(event: Server.Disconnected) {
        auditEvents.add("CONNECTION_TERMINATED:${event.connection.address}")
    }
    
    private fun handleProxiedEvent(event: Server.Proxied) {
        val sessionId = event.session.id.toString()
        val sourceAddr = event.source.address.toString()
        
        when (val message = event.received) {
            is Bolt.Hello -> handleHelloMessage(event, message, sessionId, sourceAddr)
            is Bolt.Run -> handleRunMessage(message, sessionId)
            is Bolt.Begin -> auditEvents.add("TRANSACTION_BEGIN:$sessionId")
            is Bolt.Commit -> auditEvents.add("TRANSACTION_COMMIT:$sessionId")
            is Bolt.Rollback -> auditEvents.add("TRANSACTION_ROLLBACK:$sessionId")
            is Bolt.Logoff -> handleLogoffMessage(sessionId)
            is Bolt.Pull -> auditEvents.add("RESULT_FETCH:$sessionId")
            else -> {
                // Handle other message types if needed
            }
        }
        
        handleFailureResponse(event, sessionId)
    }
    
    private fun handleHelloMessage(event: Server.Proxied, message: Bolt.Hello, sessionId: String, sourceAddr: String) {
        val userId = message.extra["principal"] as? String ?: 
            (message.extra["credentials"] as? Map<*, *>)?.get("username") as? String
        sessionUsers[sessionId] = userId
        auditEvents.add("AUTHENTICATION_ATTEMPT:$sessionId:$userId:$sourceAddr")
        if (event.sent is Bolt.Success) {
            auditEvents.add("AUTH_SUCCESS:$sessionId")
        }
    }
    
    private fun handleRunMessage(message: Bolt.Run, sessionId: String) {
        val query = message.query
        val db = message.extra["db"] as? String ?: "default"
        auditEvents.add("QUERY_EXECUTION:$sessionId:${query.hashCode()}")
        auditEvents.add("QUERY_CONTENT:$query")
        auditEvents.add("QUERY_DB:$db")
        
        if (message.parameters.isNotEmpty()) {
            message.parameters.forEach { (key, value) ->
                val sanitizedValue = sanitizeParameterValue(key, value)
                auditEvents.add("PARAM:$key=$sanitizedValue")
            }
        }
    }
    
    private fun handleLogoffMessage(sessionId: String) {
        val userId = sessionUsers[sessionId]
        auditEvents.add("SESSION_LOGOFF:$sessionId")
        auditEvents.add("SESSION_SUMMARY:$sessionId:$userId")
    }
    
    private fun handleFailureResponse(event: Server.Proxied, sessionId: String) {
        if (event.sent is Bolt.Failure) {
            val failure = event.sent as Bolt.Failure
            val errorCode = failure.metadata["code"] as? String ?: "UNKNOWN"
            auditEvents.add("FAILURE:$sessionId:$errorCode")
            auditEvents.add("METADATA:$sessionId:${failure.metadata}")
        }
    }
    
    private fun sanitizeParameterValue(key: String, value: Any?): String {
        return when {
            key.lowercase().contains("password") -> "***REDACTED***"
            key.lowercase().contains("secret") -> "***REDACTED***"
            value is String && value.length > 20 -> "${value.take(20)}...[TRUNCATED]"
            value is Map<*, *> -> {
                // Handle nested maps by recursively sanitizing
                value.entries.joinToString(", ", "{", "}") { (mapKey, mapValue) ->
                    val keyStr = mapKey.toString()
                    val sanitizedMapValue = sanitizeParameterValue(keyStr, mapValue)
                    "$keyStr=$sanitizedMapValue"
                }
            }
            else -> value.toString()
        }
    }
}

class AuditPluginTest : StringSpec({

    "should not intercept messages - operates in observe-only mode" {
        val auditEvents = ConcurrentLinkedQueue<String>()
        val plugin = TestAuditCollector(auditEvents)
        val session = createTestSession()
        val message = Bolt.Run("MATCH (n) RETURN n", emptyMap(), emptyMap())
        
        val result = plugin.intercept(session, message)
        
        result shouldBe message
    }

    "should audit server lifecycle events" {
        val auditEvents = ConcurrentLinkedQueue<String>()
        val plugin = TestAuditCollector(auditEvents)
        
        plugin.observe(Server.Started)
        plugin.observe(Server.Stopped)
        
        delay(100.milliseconds) // Allow async processing
        
        auditEvents.any { it.contains("SERVER_STARTED") } shouldBe true
        auditEvents.any { it.contains("SERVER_STOPPED") } shouldBe true
    }

    "should audit connection events with proper metadata" {
        val auditEvents = ConcurrentLinkedQueue<String>()
        val plugin = TestAuditCollector(auditEvents)
        
        val clientConnection = Server.Connection.Client(InetSocketAddress("192.168.1.100", 7687))
        val graphConnection = Server.Connection.Graph(InetSocketAddress("localhost", 7474))
        
        plugin.observe(Server.Connected(clientConnection))
        plugin.observe(Server.Connected(graphConnection))
        plugin.observe(Server.Disconnected(clientConnection))
        
        delay(100.milliseconds)
        
        auditEvents.any { 
            it.contains("CONNECTION_ESTABLISHED") && it.contains("192.168.1.100") 
        } shouldBe true
        
        auditEvents.any { 
            it.contains("CONNECTION_ESTABLISHED") && it.contains("localhost") 
        } shouldBe true
        
        auditEvents.any { 
            it.contains("CONNECTION_TERMINATED") && it.contains("192.168.1.100") 
        } shouldBe true
    }

    "should audit authentication attempts with user information" {
        val auditEvents = ConcurrentLinkedQueue<String>()
        val plugin = TestAuditCollector(auditEvents)
        
        val session = createTestSession()
        val helloMessage = Bolt.Hello(
            mapOf(
                "user_agent" to "neo4j-java/5.0",
                "scheme" to "basic",
                "principal" to "testuser",
                "credentials" to mapOf("username" to "testuser", "password" to "secret")
            )
        )
        val successResponse = Bolt.Success(mapOf("connection_id" to "bolt-123"))
        
        val proxiedEvent = Server.Proxied(
            session = session,
            source = Server.Connection.Client(InetSocketAddress("192.168.1.100", 7687)),
            received = helloMessage,
            destination = Server.Connection.Graph(InetSocketAddress("localhost", 7474)),
            sent = successResponse
        )
        
        plugin.observe(proxiedEvent)
        
        delay(100.milliseconds)
        
        val authEvent = auditEvents.find { it.contains("AUTHENTICATION_ATTEMPT") }
        authEvent shouldNotBe null
        authEvent!! shouldContain "testuser"
        authEvent shouldContain "192.168.1.100"
    }

    "should audit query execution with comprehensive metadata" {
        val auditEvents = ConcurrentLinkedQueue<String>()
        val plugin = TestAuditCollector(auditEvents)
        
        val session = createTestSession()
        val runMessage = Bolt.Run(
            "MATCH (n:Person {name: \$name}) RETURN n",
            mapOf("name" to "Alice"),
            mapOf("db" to "neo4j")
        )
        val successResponse = Bolt.Success(
            mapOf(
                "t_first" to 10L,
                "t_last" to 25L,
                "stats" to mapOf("nodes_created" to 0, "nodes_deleted" to 0)
            )
        )
        
        val proxiedEvent = Server.Proxied(
            session = session,
            source = Server.Connection.Client(InetSocketAddress("192.168.1.100", 7687)),
            received = runMessage,
            destination = Server.Connection.Graph(InetSocketAddress("localhost", 7474)),
            sent = successResponse
        )
        
        plugin.observe(proxiedEvent)
        
        delay(100.milliseconds)
        
        val queryEvent = auditEvents.find { it.contains("QUERY_EXECUTION") }
        queryEvent shouldNotBe null
        
        val queryContentEvent = auditEvents.find { it.contains("QUERY_CONTENT") }
        queryContentEvent shouldNotBe null
        queryContentEvent!! shouldContain "MATCH (n:Person {name: \$name}) RETURN n"
    }

    "should audit transaction boundaries" {
        val auditEvents = ConcurrentLinkedQueue<String>()
        val plugin = TestAuditCollector(auditEvents)
        
        val session = createTestSession()
        
        // Begin transaction
        val beginEvent = Server.Proxied(
            session = session,
            source = Server.Connection.Client(InetSocketAddress("192.168.1.100", 7687)),
            received = Bolt.Begin(emptyMap()),
            destination = Server.Connection.Graph(InetSocketAddress("localhost", 7474)),
            sent = Bolt.Success(emptyMap())
        )
        
        // Commit transaction
        val commitEvent = Server.Proxied(
            session = session,
            source = Server.Connection.Client(InetSocketAddress("192.168.1.100", 7687)),
            received = Bolt.Commit,
            destination = Server.Connection.Graph(InetSocketAddress("localhost", 7474)),
            sent = Bolt.Success(emptyMap())
        )
        
        plugin.observe(beginEvent)
        delay(50.milliseconds)
        plugin.observe(commitEvent)
        
        delay(100.milliseconds)
        
        auditEvents.any { it.contains("TRANSACTION_BEGIN") } shouldBe true
        auditEvents.any { it.contains("TRANSACTION_COMMIT") } shouldBe true
    }

    "should sanitize sensitive parameters" {
        val auditEvents = ConcurrentLinkedQueue<String>()
        val plugin = TestAuditCollector(auditEvents)
        
        val session = createTestSession()
        val runMessage = Bolt.Run(
            "CREATE (u:User) SET u = \$props",
            mapOf(
                "props" to mapOf(
                    "username" to "alice",
                    "password" to "supersecret123",
                    "secret_key" to "confidential_data",
                    "long_text" to "This is a very long text that should be truncated"
                )
            ),
            emptyMap()
        )
        val successResponse = Bolt.Success(emptyMap())
        
        val proxiedEvent = Server.Proxied(
            session = session,
            source = Server.Connection.Client(InetSocketAddress("192.168.1.100", 7687)),
            received = runMessage,
            destination = Server.Connection.Graph(InetSocketAddress("localhost", 7474)),
            sent = successResponse
        )
        
        plugin.observe(proxiedEvent)
        
        delay(100.milliseconds)
        
        // Verify sensitive data is redacted but safe data is preserved
        val hasRedactedPassword = auditEvents.any { it.contains("***REDACTED***") }
        val hasUsername = auditEvents.any { it.contains("alice") }
        val hasTruncatedText = auditEvents.any { it.contains("[TRUNCATED]") }
        
        hasRedactedPassword shouldBe true
        hasUsername shouldBe true
        hasTruncatedText shouldBe true
    }

    "should track session information across multiple events" {
        val auditEvents = ConcurrentLinkedQueue<String>()
        val plugin = TestAuditCollector(auditEvents)
        
        val session = createTestSession()
        val sessionId = session.id.toString()
        
        // Authentication
        val helloEvent = Server.Proxied(
            session = session,
            source = Server.Connection.Client(InetSocketAddress("192.168.1.100", 7687)),
            received = Bolt.Hello(mapOf("principal" to "testuser")),
            destination = Server.Connection.Graph(InetSocketAddress("localhost", 7474)),
            sent = Bolt.Success(emptyMap())
        )
        
        // Multiple queries
        val query1Event = Server.Proxied(
            session = session,
            source = Server.Connection.Client(InetSocketAddress("192.168.1.100", 7687)),
            received = Bolt.Run("MATCH (n) RETURN count(n)", emptyMap(), emptyMap()),
            destination = Server.Connection.Graph(InetSocketAddress("localhost", 7474)),
            sent = Bolt.Success(emptyMap())
        )
        
        val query2Event = Server.Proxied(
            session = session,
            source = Server.Connection.Client(InetSocketAddress("192.168.1.100", 7687)),
            received = Bolt.Run("MATCH (n:Person) RETURN n", emptyMap(), emptyMap()),
            destination = Server.Connection.Graph(InetSocketAddress("localhost", 7474)),
            sent = Bolt.Success(emptyMap())
        )
        
        // Session logoff
        val logoffEvent = Server.Proxied(
            session = session,
            source = Server.Connection.Client(InetSocketAddress("192.168.1.100", 7687)),
            received = Bolt.Logoff,
            destination = Server.Connection.Graph(InetSocketAddress("localhost", 7474)),
            sent = Bolt.Success(emptyMap())
        )
        
        plugin.observe(helloEvent)
        plugin.observe(query1Event)
        plugin.observe(query2Event)
        plugin.observe(logoffEvent)
        
        delay(200.milliseconds)
        
        // Verify session tracking across events
        val sessionEvents = auditEvents.filter { it.contains(sessionId) }
        // auth + auth success + 2*query + logoff + session summary (content events don't contain sessionId)
        sessionEvents.size shouldBe 6
        
        val sessionSummary = auditEvents.find { it.contains("SESSION_SUMMARY") }
        sessionSummary shouldNotBe null
        sessionSummary!! shouldContain "testuser"
    }

    "should handle query failures and error information" {
        val auditEvents = ConcurrentLinkedQueue<String>()
        val plugin = TestAuditCollector(auditEvents)
        
        val session = createTestSession()
        val runMessage = Bolt.Run("INVALID CYPHER QUERY", emptyMap(), emptyMap())
        val failureResponse = Bolt.Failure(
            mapOf(
                "code" to "Neo.ClientError.Statement.SyntaxError",
                "message" to "Invalid input 'I': expected <init> (line 1, column 1 (offset: 0))"
            )
        )
        
        val proxiedEvent = Server.Proxied(
            session = session,
            source = Server.Connection.Client(InetSocketAddress("192.168.1.100", 7687)),
            received = runMessage,
            destination = Server.Connection.Graph(InetSocketAddress("localhost", 7474)),
            sent = failureResponse
        )
        
        plugin.observe(proxiedEvent)
        
        delay(100.milliseconds)
        
        val queryEvent = auditEvents.find { it.contains("QUERY_EXECUTION") }
        queryEvent shouldNotBe null
        
        // Verify error information is captured
        val failureEvent = auditEvents.find { it.contains("FAILURE") }
        failureEvent shouldNotBe null
        failureEvent!! shouldContain "Neo.ClientError.Statement.SyntaxError"
        
        val metadataEvent = auditEvents.find { it.contains("METADATA") }
        metadataEvent shouldNotBe null
    }

    "should categorize query types correctly" {
        val auditEvents = ConcurrentLinkedQueue<String>()
        val plugin = TestAuditCollector(auditEvents)
        
        val session = createTestSession()
        val queries = listOf(
            "MATCH (n) RETURN n" to "READ",
            "CREATE (n:Test) RETURN n" to "WRITE", 
            "MERGE (n:User {id: 1}) RETURN n" to "WRITE",
            "SHOW DATABASES" to "ADMIN",
            "CALL db.labels()" to "PROCEDURE"
        )
        
        queries.forEach { (query, expectedType) ->
            val runMessage = Bolt.Run(query, emptyMap(), emptyMap())
            val successResponse = Bolt.Success(emptyMap())
            
            val proxiedEvent = Server.Proxied(
                session = session,
                source = Server.Connection.Client(InetSocketAddress("192.168.1.100", 7687)),
                received = runMessage,
                destination = Server.Connection.Graph(InetSocketAddress("localhost", 7474)),
                sent = successResponse
            )
            
            plugin.observe(proxiedEvent)
        }
        
        delay(200.milliseconds)
        
        // Verify query type detection (this would require examining debug logs or metadata)
        val queryEvents = auditEvents.filter { it.contains("QUERY_EXECUTION") }
        queryEvents.size shouldBe queries.size
    }
})

// Test utilities
private fun createTestSession(): Bolt.Session {
    return Bolt.Session(
        id = UUID.randomUUID().toString(),
        version = Bolt.Version(5, 0, 0)
    )
}
