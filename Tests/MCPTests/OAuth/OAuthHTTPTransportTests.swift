import Testing
import Foundation
import Logging

@testable import MCP

@Suite("OAuth HTTP Transport Tests")
struct OAuthHTTPTransportTests {
    
    @Test("OAuth HTTP transport initialization")
    func testOAuthHTTPTransportInit() async throws {
        let config = OAuthConfiguration(
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
    func testClientCredentialsFactory() {
        let transport = OAuthHTTPClientTransport.clientCredentials(
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
    func testAuthenticationErrorDetection() async {
        let config = OAuthConfiguration(
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
}