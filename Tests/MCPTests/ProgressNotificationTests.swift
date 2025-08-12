import Testing
import Foundation
@testable import MCP

@Suite("Progress Notification Tests")
struct ProgressNotificationTests {
    
    @Test("Progress notification encoding and decoding")
    func testProgressNotificationCoding() throws {
        // Create a progress notification
        let notification = Message<ProgressNotification>(
            method: ProgressNotification.name,
            params: ProgressNotification.Parameters(
                progressToken: "test-token-123",
                progress: 50.0,
                total: 100.0
            )
        )
        
        // Encode to JSON
        let encoder = JSONEncoder()
        let data = try encoder.encode(notification)
        
        // Decode back
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(Message<ProgressNotification>.self, from: data)
        
        // Verify
        #expect(decoded.method == ProgressNotification.name)
        #expect(decoded.params.progressToken == "test-token-123")
        #expect(decoded.params.progress == 50.0)
        #expect(decoded.params.total == 100.0)
    }
    
    @Test("Progress notification without total")
    func testProgressNotificationWithoutTotal() throws {
        let notification = Message<ProgressNotification>(
            method: ProgressNotification.name,
            params: ProgressNotification.Parameters(
                progressToken: "token-456",
                progress: 25.0,
                total: nil
            )
        )
        
        // Encode and decode
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        let data = try encoder.encode(notification)
        let decoded = try decoder.decode(Message<ProgressNotification>.self, from: data)
        
        // Verify
        #expect(decoded.params.progressToken == "token-456")
        #expect(decoded.params.progress == 25.0)
        #expect(decoded.params.total == nil)
    }
    
    @Test("Progress tracker functionality")
    func testProgressTracker() async {
        let tracker = ProgressTracker()
        
        // Register tokens
        await tracker.registerToken("token1")
        await tracker.registerToken("token2")
        
        // Check active tokens
        #expect(await tracker.isTokenActive("token1") == true)
        #expect(await tracker.isTokenActive("token2") == true)
        #expect(await tracker.isTokenActive("token3") == false)
        
        // Get all active tokens
        let activeTokens = await tracker.getActiveTokens()
        #expect(activeTokens.contains("token1"))
        #expect(activeTokens.contains("token2"))
        #expect(activeTokens.count == 2)
        
        // Complete a token
        await tracker.completeToken("token1")
        #expect(await tracker.isTokenActive("token1") == false)
        #expect(await tracker.isTokenActive("token2") == true)
        
        // Clear all tokens
        await tracker.clearAllTokens()
        #expect(await tracker.getActiveTokens().isEmpty)
    }
    
    @Test("Progress observer")
    func testProgressObserver() async {
        actor TestCapture {
            var receivedProgress: Double = 0
            var receivedTotal: Double? = nil
            
            func updateProgress(_ progress: Double, _ total: Double?) {
                receivedProgress = progress
                receivedTotal = total
            }
            
            func getProgress() -> Double { receivedProgress }
            func getTotal() -> Double? { receivedTotal }
        }
        
        let capture = TestCapture()
        
        let observer = ProgressObserver(token: "test-token") { progress, total in
            await capture.updateProgress(progress, total)
        }
        
        // Update progress
        await observer.update(progress: 75.0, total: 150.0)
        
        // Verify handler was called
        #expect(await capture.getProgress() == 75.0)
        #expect(await capture.getTotal() == 150.0)
        
        // Update without total
        await observer.update(progress: 80.0, total: nil)
        #expect(await capture.getProgress() == 80.0)
        #expect(await capture.getTotal() == nil)
    }
    
    @Test("Request metadata encoding")
    func testRequestMetadataEncoding() throws {
        let metadata = RequestMetadata(progressToken: "progress-123")
        
        let encoder = JSONEncoder()
        let data = try encoder.encode(metadata)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        
        #expect(json?["progressToken"] as? String == "progress-123")
    }
    
    @Test("Client progress token creation")
    func testClientProgressTokenCreation() async {
        let client = Client(name: "TestClient", version: "1.0.0")
        
        // Create progress tokens
        let token1 = await client.createProgressToken()
        let token2 = await client.createProgressToken()
        
        // Verify they are unique
        #expect(token1 != token2)
        #expect(!token1.isEmpty)
        #expect(!token2.isEmpty)
    }
    
    @Test("Tool call with progress structure")
    func testToolCallWithProgress() {
        // Test with explicit token
        let tool1 = ToolCallWithProgress(
            name: "process-data",
            arguments: ["size": Value(1000)],
            progressToken: "custom-token"
        )
        
        #expect(tool1.name == "process-data")
        #expect(tool1.progressToken == "custom-token")
        #expect(tool1.arguments?["size"] == Value(1000))
        
        // Test with auto-generated token
        let tool2 = ToolCallWithProgress(
            name: "analyze",
            arguments: nil,
            progressToken: nil
        )
        
        #expect(tool2.name == "analyze")
        #expect(!tool2.progressToken.isEmpty)
        #expect(tool2.arguments == nil)
    }
    
    @Test("Progress notification JSON structure")
    func testProgressNotificationJSONStructure() throws {
        let notification = Message<ProgressNotification>(
            method: ProgressNotification.name,
            params: ProgressNotification.Parameters(
                progressToken: "abc123",
                progress: 0.5,
                total: 1.0
            )
        )
        
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let data = try encoder.encode(notification)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        
        // Verify JSON structure matches MCP spec
        if let jsonrpc = json?["jsonrpc"] as? String {
            #expect(jsonrpc == "2.0")
        }
        if let method = json?["method"] as? String {
            #expect(method == "notifications/progress")
        }
        
        if let params = json?["params"] as? [String: Any] {
            if let progressToken = params["progressToken"] as? String {
                #expect(progressToken == "abc123")
            }
            if let progress = params["progress"] as? Double {
                #expect(progress == 0.5)
            }
            if let total = params["total"] as? Double {
                #expect(total == 1.0)
            }
        }
    }
}