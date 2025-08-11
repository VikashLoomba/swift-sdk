import Testing
import Foundation

@testable import MCP

@Suite("PKCE Dynamic Registration Fix Tests")
struct PKCEDynamicRegistrationFixTests {
    
    @Test("Current approach vs suggested approach for public client PKCE")
    func testCurrentVsSuggestedApproachForPublicClientPKCE() throws {
        // Create a mock public client registration response (no client secret)
        let publicClientResponse = ClientRegistrationResponse(
            clientId: "test-public-client",
            clientSecret: nil, // No secret = public client
            clientIdIssuedAt: nil,
            clientSecretExpiresAt: nil,
            redirectUris: ["myapp://auth"],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: nil,
            clientName: "Test Public Client",
            softwareId: nil,
            softwareVersion: nil
        )
        
        let authEndpoint = URL(string: "https://oauth.provider.com/authorize")!
        let tokenEndpoint = URL(string: "https://oauth.provider.com/token")!
        let scopes = ["read", "write"]
        
        // New simplified approach (let initializer decide automatically)
        // This is what our updated fromDynamicRegistration method now does
        let config = try OAuthConfiguration.fromDynamicRegistration(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            registrationResponse: publicClientResponse,
            scopes: scopes
        )
        
        // Manual approach (directly using initializer)
        let manualConfig = try OAuthConfiguration(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            clientId: publicClientResponse.clientId,
            clientSecret: publicClientResponse.clientSecret,
            // Don't explicitly set clientType or usePKCE - let initializer determine
            scopes: scopes,
            redirectURI: URL(string: publicClientResponse.redirectUris.first!)
        )
        
        // Both should correctly detect public client and enable PKCE
        #expect(config.clientType == .public)
        #expect(config.usePKCE == true)
        #expect(config.clientSecret == nil)
        
        #expect(manualConfig.clientType == .public)
        #expect(manualConfig.usePKCE == true)
        #expect(manualConfig.clientSecret == nil)
        
        // They should be equivalent
        #expect(config.clientType == manualConfig.clientType)
        #expect(config.usePKCE == manualConfig.usePKCE)
        #expect(config.clientSecret == manualConfig.clientSecret)
    }
    
    @Test("Reproduce exact issue scenario from bug report")
    func testReproduceExactIssueScenario() throws {
        // This test reproduces the exact scenario described in the issue
        // Simulate what setupOAuthWithDiscovery would do:
        // 1. Register a client dynamically
        let mockRegistrationResponse = ClientRegistrationResponse(
            clientId: "myapp-ios-client-123",
            clientSecret: nil, // Public client - no secret
            clientIdIssuedAt: nil,
            clientSecretExpiresAt: nil,
            redirectUris: ["myapp://auth"],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: nil,
            clientName: "MyApp iOS",
            softwareId: nil,
            softwareVersion: nil
        )
        
        // 2. Create configuration from registration
        let oauthConfig = try OAuthConfiguration.fromDynamicRegistration(
            authorizationEndpoint: URL(string: "https://oauth.provider.com/authorize")!,
            tokenEndpoint: URL(string: "https://oauth.provider.com/token")!,
            registrationResponse: mockRegistrationResponse,
            scopes: []
        )
        
        // According to the issue, these should be the problematic results:
        // - oauthConfig.usePKCE is false (but should be true)
        // - oauthConfig.clientType is .public (this is correct)
        
        // With our current implementation, this should work correctly:
        #expect(oauthConfig.clientType == .public)
        #expect(oauthConfig.usePKCE == true) // This is the fix - should be true for public clients
        #expect(oauthConfig.clientSecret == nil)
        
        // The issue was that usePKCE was false even though clientType was public
        // Our current implementation should fix this
    }
    
    @Test("Test PKCE is mandatory for public clients after dynamic registration")
    func testPKCEMandatoryForPublicClientsAfterDynamicRegistration() throws {
        // Test various scenarios where PKCE should be enabled for public clients
        
        let authEndpoint = URL(string: "https://oauth.provider.com/authorize")!
        let tokenEndpoint = URL(string: "https://oauth.provider.com/token")!
        
        // Scenario 1: Mobile app (no client secret)
        let mobileClientResponse = ClientRegistrationResponse(
            clientId: "mobile-app-client",
            clientSecret: nil, // No secret
            clientIdIssuedAt: nil,
            clientSecretExpiresAt: nil,
            redirectUris: ["com.myapp://oauth"],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: nil,
            clientName: "Mobile App",
            softwareId: nil,
            softwareVersion: nil
        )
        
        let mobileConfig = try OAuthConfiguration.fromDynamicRegistration(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            registrationResponse: mobileClientResponse,
            scopes: ["openid", "profile"]
        )
        
        #expect(mobileConfig.clientType == .public)
        #expect(mobileConfig.usePKCE == true)
        
        // Scenario 2: SPA (single page application, no client secret)
        let spaClientResponse = ClientRegistrationResponse(
            clientId: "spa-client",
            clientSecret: nil, // No secret
            clientIdIssuedAt: nil,
            clientSecretExpiresAt: nil,
            redirectUris: ["https://myapp.com/callback"],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: nil,
            clientName: "SPA App",
            softwareId: nil,
            softwareVersion: nil
        )
        
        let spaConfig = try OAuthConfiguration.fromDynamicRegistration(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            registrationResponse: spaClientResponse,
            scopes: ["api:read"]
        )
        
        #expect(spaConfig.clientType == .public)
        #expect(spaConfig.usePKCE == true)
    }
    
    @Test("Scope fallback from registration response when no scopes provided")
    func testScopeFallbackFromRegistrationResponse() throws {
        // Test that when no scopes are provided to fromDynamicRegistration,
        // it falls back to parsing scopes from the registration response
        let registrationResponse = ClientRegistrationResponse(
            clientId: "scope-test-client",
            clientSecret: nil,
            clientIdIssuedAt: nil,
            clientSecretExpiresAt: nil,
            redirectUris: ["myapp://auth"],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: "openid profile email", // Space-separated scopes from server
            clientName: "Scope Test Client",
            softwareId: nil,
            softwareVersion: nil
        )
        
        let authEndpoint = URL(string: "https://oauth.provider.com/authorize")!
        let tokenEndpoint = URL(string: "https://oauth.provider.com/token")!
        
        // Test with empty scopes array - should fallback to registration response scopes
        let configWithFallback = try OAuthConfiguration.fromDynamicRegistration(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            registrationResponse: registrationResponse,
            scopes: [] // Empty scopes should trigger fallback
        )
        
        #expect(configWithFallback.scopes == ["openid", "profile", "email"])
        #expect(configWithFallback.clientType == .public)
        #expect(configWithFallback.usePKCE == true)
        
        // Test with explicit scopes - should use provided scopes, not fallback
        let configWithExplicitScopes = try OAuthConfiguration.fromDynamicRegistration(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            registrationResponse: registrationResponse,
            scopes: ["custom", "scopes"]
        )
        
        #expect(configWithExplicitScopes.scopes == ["custom", "scopes"])
        #expect(configWithExplicitScopes.clientType == .public)
        #expect(configWithExplicitScopes.usePKCE == true)
    }
}