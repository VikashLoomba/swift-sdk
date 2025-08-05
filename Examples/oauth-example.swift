#!/usr/bin/env swift

// MARK: - OAuth MCP Client Example
//
// This example demonstrates how to use the OAuth-enabled HTTP transport
// to connect to an MCP server that requires OAuth authentication.
//
// To run this example in a project that imports MCP:
//
// import Foundation
// import MCP
//
// then uncomment the code below

/*
@main
struct OAuthExample {
    static func main() async {
        await runExample()
    }
}

func runExample() async {
    print("🔐 OAuth MCP Client Example")
    print("=============================")
    
    do {
        // Example 1: Using GitHub OAuth preset
        print("\n📘 Example 1: GitHub OAuth Configuration")
        let githubConfig = OAuthConfiguration.github(
            clientId: "your-github-client-id",
            clientSecret: "your-github-client-secret",
            scopes: ["repo", "read:user"]
        )
        
        let githubTransport = OAuthHTTPClientTransport(
            endpoint: URL(string: "https://github-mcp-server.example.com")!,
            oauthConfig: githubConfig
        )
        
        print("✅ GitHub OAuth transport configured")
        
        // Example 2: Client Credentials Flow
        print("\n🔧 Example 2: Client Credentials Flow")
        let clientCredentialsTransport = OAuthHTTPClientTransport.clientCredentials(
            endpoint: URL(string: "https://api.example.com/mcp")!,
            tokenEndpoint: URL(string: "https://oauth.example.com/token")!,
            clientId: "your-service-client-id",
            clientSecret: "your-service-client-secret",
            scopes: ["mcp:read", "mcp:write"]
        )
        
        print("✅ Client credentials transport configured")
        
        // Example 3: Custom OAuth Configuration
        print("\n⚙️  Example 3: Custom OAuth Configuration")
        let customConfig = OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://oauth.custom.com/authorize")!,
            tokenEndpoint: URL(string: "https://oauth.custom.com/token")!,
            clientId: "custom-client-id",
            clientSecret: "custom-client-secret",
            scopes: ["custom:read", "custom:write"],
            additionalParameters: ["audience": "mcp-api"]
        )
        
        let customTransport = OAuthHTTPClientTransport(
            endpoint: URL(string: "https://custom-mcp-server.com")!,
            oauthConfig: customConfig,
            tokenIdentifier: "custom-service"
        )
        
        print("✅ Custom OAuth transport configured")
        
        // Example 4: Using with MCP Client
        print("\n🚀 Example 4: Connecting MCP Client with OAuth")
        
        // For this example, we'll use a mock transport since we don't have real credentials
        let mockTransport = createMockOAuthTransport()
        
        let client = Client(name: "OAuth Example App", version: "1.0.0")
        
        // Connect to the server with OAuth authentication
        print("🔌 Connecting to MCP server with OAuth...")
        
        // Note: In a real scenario, this would perform OAuth authentication
        // try await client.connect(transport: mockTransport)
        
        print("✅ Successfully connected with OAuth authentication!")
        print("🎯 All MCP requests will now include OAuth tokens automatically")
        
        // Example token operations
        print("\n🎫 Example 5: Token Operations")
        await demonstrateTokenOperations()
        
    } catch {
        print("❌ Error: \(error)")
    }
    
    print("\n🎉 OAuth example completed!")
}

func createMockOAuthTransport() -> OAuthHTTPClientTransport {
    // Create a mock configuration for demonstration
    let mockConfig = OAuthConfiguration(
        authorizationEndpoint: URL(string: "https://mock.oauth.com/authorize")!,
        tokenEndpoint: URL(string: "https://mock.oauth.com/token")!,
        clientId: "mock-client-id",
        clientSecret: "mock-client-secret",
        scopes: ["mock:read"]
    )
    
    return OAuthHTTPClientTransport(
        endpoint: URL(string: "https://mock-mcp-server.com")!,
        oauthConfig: mockConfig,
        tokenStorage: InMemoryTokenStorage() // Use in-memory storage for demo
    )
}

func demonstrateTokenOperations() async {
    print("🎫 Creating OAuth token...")
    
    let token = OAuthToken(
        accessToken: "example-access-token-123",
        tokenType: "Bearer",
        expiresIn: 3600, // 1 hour
        refreshToken: "example-refresh-token-456",
        scope: "read write"
    )
    
    print("   Access Token: \(token.accessToken)")
    print("   Token Type: \(token.tokenType)")
    print("   Expires In: \(token.expiresIn ?? 0) seconds")
    print("   Is Expired: \(token.isExpired ? "Yes" : "No")")
    
    // Demonstrate token storage
    print("\n💾 Token Storage Example...")
    let storage = InMemoryTokenStorage()
    
    do {
        try await storage.store(token: token, for: "example-service")
        print("✅ Token stored successfully")
        
        if let retrievedToken = try await storage.retrieve(for: "example-service") {
            print("✅ Token retrieved: \(retrievedToken.accessToken)")
        }
        
        try await storage.delete(for: "example-service")
        print("✅ Token deleted successfully")
        
    } catch {
        print("❌ Token storage error: \(error)")
    }
}
*/

print("🔐 OAuth MCP Client Example")
print("=============================")
print("📖 This example shows how to use OAuth with MCP Swift SDK")
print("💡 To run this example, import it into a project that includes MCP as a dependency")
print("🎯 See OAuth-README.md for complete usage examples")