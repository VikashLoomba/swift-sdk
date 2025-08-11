#!/usr/bin/env swift

// MARK: - OAuth 2.0 Dynamic Client Registration Example
//
// This example demonstrates the new OAuth 2.0 Dynamic Client Registration
// functionality added to the MCP Swift SDK. This allows applications to
// automatically register as OAuth clients at runtime, eliminating the need
// for hardcoded client_id values.
//
// To run this example in a project that imports MCP:
//
// import Foundation
// import MCP
//
// then uncomment the code below

/*
@main
struct DynamicRegistrationExample {
    static func main() async {
        await runExample()
    }
}

func runExample() async {
    print("🔐 OAuth 2.0 Dynamic Client Registration Example")
    print("================================================")
    
    do {
        // Example 1: Discovery + Dynamic Registration Flow
        print("\n🔍 Example 1: Discovery + Dynamic Registration")
        
        // Create an authenticator (normally you'd use real endpoints)
        let authenticator = OAuthAuthenticator(
            configuration: try OAuthConfiguration(
                authorizationEndpoint: URL(string: "https://oauth.example.com/authorize")!,
                tokenEndpoint: URL(string: "https://oauth.example.com/token")!,
                clientId: "temporary-id", // Will be replaced
                scopes: []
            )
        )
        
        print("📋 Discovery URL patterns:")
        print("   OAuth 2.0: https://example.com/.well-known/oauth-authorization-server")
        print("   OpenID Connect: https://example.com/.well-known/openid_configuration")
        
        // Example 2: Manual Client Registration
        print("\n🏗️  Example 2: Manual Client Registration")
        
        let registrationEndpoint = URL(string: "https://oauth.example.com/register")!
        print("Registration endpoint: \(registrationEndpoint.absoluteString)")
        
        print("✅ Registration request would include:")
        print("   • client_name: 'My Dynamic App'")
        print("   • redirect_uris: ['https://myapp.example.com/callback']")
        print("   • grant_types: ['authorization_code']")
        print("   • response_types: ['code']")
        print("   • scope: 'read write'")
        print("   • software_id: 'myapp-v1'")
        print("   • software_version: '1.0.0'")
        
        // Example 3: Configuration from Registration Response
        print("\n⚙️  Example 3: Configuration from Registration Response")
        
        // Simulate a registration response (normally received from server)
        let mockRegistrationResponse = ClientRegistrationResponse(
            clientId: "dynamic-client-abc123",
            clientSecret: "dynamic-secret-xyz789",
            clientIdIssuedAt: Int(Date().timeIntervalSince1970),
            clientSecretExpiresAt: nil,
            redirectUris: ["https://myapp.example.com/callback"],
            grantTypes: ["authorization_code", "refresh_token"],
            responseTypes: ["code"],
            scopes: "read write profile",
            clientName: "My Dynamic App",
            softwareId: "myapp-v1",
            softwareVersion: "1.0.0"
        )
        
        let config = try OAuthConfiguration.fromDynamicRegistration(
            authorizationEndpoint: URL(string: "https://oauth.example.com/authorize")!,
            tokenEndpoint: URL(string: "https://oauth.example.com/token")!,
            revocationEndpoint: URL(string: "https://oauth.example.com/revoke")!,
            registrationResponse: mockRegistrationResponse,
            scopes: ["read", "write", "profile"]
        )
        
        print("✅ Dynamic configuration created:")
        print("   • Client ID: \(config.clientId)")
        print("   • Client Type: \(config.clientType)")
        print("   • PKCE Required: \(config.usePKCE)")
        print("   • Scopes: \(config.scopes.joined(separator: ", "))")
        print("   • Redirect URI: \(config.redirectURI?.absoluteString ?? "None")")
        
        // Example 4: OAuth Transport with Dynamic Configuration
        print("\n🚀 Example 4: OAuth Transport with Dynamic Configuration")
        
        let transport = OAuthHTTPClientTransport(
            endpoint: URL(string: "https://mcp-server.example.com")!,
            oauthConfig: config
        )
        
        print("✅ OAuth transport configured with dynamic client credentials")
        print("🎯 All MCP requests will now use the dynamically registered client")
        
        // Example 5: Data Structures
        print("\n📊 Example 5: Data Structures")
        demonstrateDataStructures()
        
        // Example 6: Error Handling
        print("\n⚠️  Example 6: Error Handling")
        demonstrateErrorHandling()
        
    } catch {
        print("❌ Error: \(error)")
    }
    
    print("\n🎉 Dynamic registration example completed!")
}

func demonstrateDataStructures() {
    print("📋 Discovery Document structure:")
    print("   • issuer (optional)")
    print("   • authorization_endpoint (required)")
    print("   • token_endpoint (required)")
    print("   • registration_endpoint (optional) ← Key for dynamic registration")
    print("   • revocation_endpoint (optional)")
    print("   • scopes_supported, response_types_supported, etc.")
    
    print("\n🎫 Client Registration Response structure:")
    print("   • client_id (required)")
    print("   • client_secret (optional for public clients)")
    print("   • redirect_uris (required)")
    print("   • grant_types, response_types")
    print("   • client_name, software_id, software_version")
    print("   • Timestamps for issuance and expiration")
}

func demonstrateErrorHandling() {
    print("🔍 Discovery errors:")
    print("   • Invalid discovery document")
    print("   • Registration endpoint not found")
    print("   • HTTP errors (404, 500, etc.)")
    
    print("\n📝 Registration errors:")
    print("   • Client registration failed")
    print("   • Invalid registration response")
    print("   • Invalid redirect URI")
    
    print("\n⚡ Swift error types:")
    print("   • OAuthError.registrationEndpointNotFound")
    print("   • OAuthError.clientRegistrationFailed(statusCode, message)")
    print("   • OAuthError.invalidDiscoveryDocument(description)")
    print("   • OAuthConfigurationError.invalidRedirectURI")
}
*/

print("🔐 OAuth 2.0 Dynamic Client Registration Example")
print("================================================")
print("📖 This example shows how to use OAuth 2.0 Dynamic Client Registration with MCP Swift SDK")
print("💡 To run this example, import it into a project that includes MCP as a dependency")
print("")
print("🌟 Key Features Added:")
print("   • fetchDiscoveryDocument(from:) - Fetch OAuth 2.0 server metadata")
print("   • registerClient(...) - Register a new client dynamically")
print("   • setupOAuthWithDiscovery(...) - One-step discovery + registration")
print("   • OAuthConfiguration.fromDynamicRegistration(...) - Create config from registration")
print("")
print("📚 See OAuth-README.md for complete usage examples")
print("🔗 RFC 7591: https://datatracker.ietf.org/doc/html/rfc7591")