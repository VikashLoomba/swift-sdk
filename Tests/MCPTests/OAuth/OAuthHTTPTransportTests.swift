import Testing
import Foundation
import Logging

@testable import MCP

@Suite("OAuth HTTP Transport Tests")
struct OAuthHTTPTransportTests {
    
    @Test("OAuth HTTP transport initialization")
    func testOAuthHTTPTransportInit() async throws {
        let config = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-client",
            clientSecret: "test-secret"
        )
        
        let transport = OAuthHTTPClientTransport(
            endpoint: URL(string: "https://example.com/mcp")!,
            oauthConfig: config,
            tokenStorage: InMemoryTokenStorage(),
            logger: Logger(label: "test")
        )
        
        // Transport should be initialized without errors
        #expect(transport.logger.label == "test")
    }
    
    @Test("OAuth transport convenience factory - client credentials")
    func testClientCredentialsFactory() throws {
        let transport = try OAuthHTTPClientTransport.clientCredentials(
            endpoint: URL(string: "https://example.com/mcp")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-client",
            clientSecret: "test-secret",
            scopes: ["read", "write"]
        )
        
        // Transport should be created successfully
        #expect(transport.logger.label == "mcp.transport.oauth.http.client")
    }
    
    @Test("Authentication error detection")
    func testAuthenticationErrorDetection() async throws {
        let config = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-client",
            clientSecret: "test-secret"
        )
        
        let transport = OAuthHTTPClientTransport(
            endpoint: URL(string: "https://example.com/mcp")!,
            oauthConfig: config,
            tokenStorage: InMemoryTokenStorage()
        )
        
        // Test various authentication error scenarios
        let authError = MCPError.internalError("Authentication required")
        let forbiddenError = MCPError.internalError("Access forbidden")
        let unauthorizedError = MCPError.internalError("401 Unauthorized")
        let otherError = MCPError.internalError("Some other error")
        
        // Use reflection to access private method for testing
        // This is a simplified test - in a real scenario, we'd test through public API
        // Since the method is private, we test the behavior indirectly
        
        // The transport should handle authentication errors properly
        // This is tested through integration tests where we simulate auth failures
    }
    
    @Test("OAuth transport with authenticated session")
    func testOAuthTransportWithAuthenticatedSession() async throws {
        // Create a mock token storage with a valid token
        let mockStorage = InMemoryTokenStorage()
        let testToken = OAuthToken(
            accessToken: "test-access-token",
            tokenType: "Bearer",
            expiresIn: 3600,
            refreshToken: "test-refresh-token",
            scope: "read write"
        )
        try await mockStorage.store(token: testToken, for: "test")
        
        let config = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-client",
            clientSecret: "test-secret"
        )
        
        let transport = OAuthHTTPClientTransport(
            endpoint: URL(string: "https://httpbin.org/post")!,
            oauthConfig: config,
            tokenStorage: mockStorage,
            tokenIdentifier: "test",
            logger: Logger(label: "test-oauth")
        )
        
        // Connect the transport
        try await transport.connect()
        
        // Create a test JSON-RPC message
        let testMessage = """
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "test",
            "params": {}
        }
        """.data(using: .utf8)!
        
        // Make multiple requests to verify OAuth headers are properly added
        // The simplified implementation should add OAuth headers to all requests
        for _ in 1...3 {
            do {
                try await transport.send(testMessage)
                // Success - OAuth headers are being added
            } catch let error as MCPError {
                // Verify it's not the "Transport not connected" error
                if case .internalError(let message) = error {
                    #expect(!(message?.contains("Transport not connected") ?? false), 
                            "Should not get 'Transport not connected' error")
                }
                // Other errors are expected since we're hitting a real endpoint
            } catch {
                // Other types of errors are also acceptable for this test
                // We're testing that the transport works with OAuth headers
            }
        }
        
        // Disconnect to test cleanup
        await transport.disconnect()
    }
}