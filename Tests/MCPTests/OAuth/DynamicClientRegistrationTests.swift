import Testing
import Foundation

@testable import MCP

@Suite("Dynamic Client Registration Tests")
struct DynamicClientRegistrationTests {
    
    @Test("Discovery document parsing")
    func testDiscoveryDocumentParsing() throws {
        let jsonData = """
        {
            "issuer": "https://oauth.provider.com",
            "authorization_endpoint": "https://oauth.provider.com/authorize",
            "token_endpoint": "https://oauth.provider.com/token",
            "registration_endpoint": "https://oauth.provider.com/register",
            "revocation_endpoint": "https://oauth.provider.com/revoke",
            "scopes_supported": ["read", "write", "admin"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256", "plain"]
        }
        """.data(using: .utf8)!
        
        let discovery = try JSONDecoder().decode(OAuthDiscoveryDocument.self, from: jsonData)
        
        #expect(discovery.issuer == "https://oauth.provider.com")
        #expect(discovery.authorizationEndpoint.absoluteString == "https://oauth.provider.com/authorize")
        #expect(discovery.tokenEndpoint.absoluteString == "https://oauth.provider.com/token")
        #expect(discovery.registrationEndpoint?.absoluteString == "https://oauth.provider.com/register")
        #expect(discovery.revocationEndpoint?.absoluteString == "https://oauth.provider.com/revoke")
        #expect(discovery.scopesSupported == ["read", "write", "admin"])
        #expect(discovery.responseTypesSupported == ["code"])
        #expect(discovery.grantTypesSupported == ["authorization_code", "refresh_token"])
        #expect(discovery.codeChallengeMethodsSupported == ["S256", "plain"])
    }
    
    @Test("Discovery document parsing without optional fields")
    func testDiscoveryDocumentParsingMinimal() throws {
        let jsonData = """
        {
            "authorization_endpoint": "https://oauth.provider.com/authorize",
            "token_endpoint": "https://oauth.provider.com/token"
        }
        """.data(using: .utf8)!
        
        let discovery = try JSONDecoder().decode(OAuthDiscoveryDocument.self, from: jsonData)
        
        #expect(discovery.issuer == nil)
        #expect(discovery.authorizationEndpoint.absoluteString == "https://oauth.provider.com/authorize")
        #expect(discovery.tokenEndpoint.absoluteString == "https://oauth.provider.com/token")
        #expect(discovery.registrationEndpoint == nil)
        #expect(discovery.revocationEndpoint == nil)
        #expect(discovery.scopesSupported == nil)
        #expect(discovery.responseTypesSupported == nil)
        #expect(discovery.grantTypesSupported == nil)
        #expect(discovery.codeChallengeMethodsSupported == nil)
    }
    
    @Test("Client registration response parsing")
    func testClientRegistrationResponseParsing() throws {
        let jsonData = """
        {
            "client_id": "test-client-123",
            "client_secret": "secret-456",
            "client_id_issued_at": 1640995200,
            "client_secret_expires_at": 1672531200,
            "redirect_uris": ["https://app.example.com/callback", "https://app.example.com/oauth"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "read write admin",
            "client_name": "Test Application",
            "software_id": "test-app-v1",
            "software_version": "1.0.0"
        }
        """.data(using: .utf8)!
        
        let response = try JSONDecoder().decode(ClientRegistrationResponse.self, from: jsonData)
        
        #expect(response.clientId == "test-client-123")
        #expect(response.clientSecret == "secret-456")
        #expect(response.clientIdIssuedAt == 1640995200)
        #expect(response.clientSecretExpiresAt == 1672531200)
        #expect(response.redirectUris == ["https://app.example.com/callback", "https://app.example.com/oauth"])
        #expect(response.grantTypes == ["authorization_code", "refresh_token"])
        #expect(response.responseTypes == ["code"])
        #expect(response.scopes == "read write admin")
        #expect(response.clientName == "Test Application")
        #expect(response.softwareId == "test-app-v1")
        #expect(response.softwareVersion == "1.0.0")
    }
    
    @Test("Client registration response parsing for public client")
    func testClientRegistrationResponseParsingPublicClient() throws {
        let jsonData = """
        {
            "client_id": "public-client-789",
            "redirect_uris": ["myapp://oauth/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "client_name": "Mobile App"
        }
        """.data(using: .utf8)!
        
        let response = try JSONDecoder().decode(ClientRegistrationResponse.self, from: jsonData)
        
        #expect(response.clientId == "public-client-789")
        #expect(response.clientSecret == nil)
        #expect(response.clientIdIssuedAt == nil)
        #expect(response.clientSecretExpiresAt == nil)
        #expect(response.redirectUris == ["myapp://oauth/callback"])
        #expect(response.grantTypes == ["authorization_code"])
        #expect(response.responseTypes == ["code"])
        #expect(response.scopes == nil)
        #expect(response.clientName == "Mobile App")
        #expect(response.softwareId == nil)
        #expect(response.softwareVersion == nil)
    }
    
    @Test("OAuth configuration from dynamic registration - confidential client")
    func testOAuthConfigurationFromDynamicRegistrationConfidential() throws {
        let registrationResponse = ClientRegistrationResponse(
            clientId: "dynamic-client-123",
            clientSecret: "dynamic-secret-456",
            clientIdIssuedAt: nil,
            clientSecretExpiresAt: nil,
            redirectUris: ["https://app.example.com/callback"],
            grantTypes: ["authorization_code", "refresh_token"],
            responseTypes: ["code"],
            scopes: "read write",
            clientName: "Dynamic App",
            softwareId: nil,
            softwareVersion: nil
        )
        
        let config = try OAuthConfiguration.fromDynamicRegistration(
            authorizationEndpoint: URL(string: "https://oauth.provider.com/authorize")!,
            tokenEndpoint: URL(string: "https://oauth.provider.com/token")!,
            revocationEndpoint: URL(string: "https://oauth.provider.com/revoke")!,
            registrationResponse: registrationResponse,
            scopes: ["read", "write"]
        )
        
        #expect(config.authorizationEndpoint.absoluteString == "https://oauth.provider.com/authorize")
        #expect(config.tokenEndpoint.absoluteString == "https://oauth.provider.com/token")
        #expect(config.revocationEndpoint?.absoluteString == "https://oauth.provider.com/revoke")
        #expect(config.clientId == "dynamic-client-123")
        #expect(config.clientSecret == "dynamic-secret-456")
        #expect(config.clientType == .confidential)
        #expect(config.scopes == ["read", "write"])
        #expect(config.redirectURI?.absoluteString == "https://app.example.com/callback")
        #expect(config.usePKCE == false) // Confidential client doesn't require PKCE by default
    }
    
    @Test("OAuth configuration from dynamic registration - public client")
    func testOAuthConfigurationFromDynamicRegistrationPublic() throws {
        let registrationResponse = ClientRegistrationResponse(
            clientId: "public-client-789",
            clientSecret: nil,
            clientIdIssuedAt: nil,
            clientSecretExpiresAt: nil,
            redirectUris: ["myapp://oauth/callback"],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: nil,
            clientName: "Public Mobile App",
            softwareId: nil,
            softwareVersion: nil
        )
        
        let config = try OAuthConfiguration.fromDynamicRegistration(
            authorizationEndpoint: URL(string: "https://oauth.provider.com/authorize")!,
            tokenEndpoint: URL(string: "https://oauth.provider.com/token")!,
            registrationResponse: registrationResponse,
            scopes: ["openid", "profile"]
        )
        
        #expect(config.authorizationEndpoint.absoluteString == "https://oauth.provider.com/authorize")
        #expect(config.tokenEndpoint.absoluteString == "https://oauth.provider.com/token")
        #expect(config.clientId == "public-client-789")
        #expect(config.clientSecret == nil)
        #expect(config.clientType == .public)
        #expect(config.scopes == ["openid", "profile"])
        #expect(config.redirectURI?.absoluteString == "myapp://oauth/callback")
        #expect(config.usePKCE == true) // Public client requires PKCE
    }
    
    @Test("OAuth configuration from dynamic registration - invalid redirect URI")
    func testOAuthConfigurationFromDynamicRegistrationInvalidRedirectURI() {
        let registrationResponse = ClientRegistrationResponse(
            clientId: "client-with-bad-uri",
            clientSecret: nil,
            clientIdIssuedAt: nil,
            clientSecretExpiresAt: nil,
            redirectUris: [], // Empty redirect URIs should cause error
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: nil,
            clientName: "Bad URI App",
            softwareId: nil,
            softwareVersion: nil
        )
        
        #expect(throws: OAuthConfigurationError.invalidRedirectURI) {
            _ = try OAuthConfiguration.fromDynamicRegistration(
                authorizationEndpoint: URL(string: "https://oauth.provider.com/authorize")!,
                tokenEndpoint: URL(string: "https://oauth.provider.com/token")!,
                registrationResponse: registrationResponse,
                scopes: ["openid"]
            )
        }
    }
    
    @Test("Discovery document URL construction")
    func testDiscoveryDocumentURLConstruction() {
        // Test common discovery endpoint patterns
        let baseURL = URL(string: "https://oauth.provider.com")!
        let discoveryURL = baseURL.appendingPathComponent(".well-known/oauth-authorization-server")
        
        #expect(discoveryURL.absoluteString == "https://oauth.provider.com/.well-known/oauth-authorization-server")
        
        // Test OpenID Connect discovery
        let oidcDiscoveryURL = baseURL.appendingPathComponent(".well-known/openid_configuration")
        #expect(oidcDiscoveryURL.absoluteString == "https://oauth.provider.com/.well-known/openid_configuration")
    }
    
    @Test("OAuth error cases")
    func testOAuthErrors() {
        let registrationError = OAuthError.registrationEndpointNotFound
        let clientRegError = OAuthError.clientRegistrationFailed(400, "Invalid request")
        let discoveryError = OAuthError.invalidDiscoveryDocument("test error")
        let responseError = OAuthError.invalidClientRegistrationResponse("test error")
        
        #expect(registrationError.errorDescription == "Registration endpoint not found in discovery document")
        #expect(clientRegError.errorDescription == "Client registration failed with status 400: Invalid request")
        #expect(discoveryError.errorDescription?.contains("Invalid discovery document") == true)
        #expect(responseError.errorDescription?.contains("Invalid client registration response") == true)
    }
    
    @Test("OAuth configuration error cases")
    func testOAuthConfigurationErrors() {
        let invalidRedirectError = OAuthConfigurationError.invalidRedirectURI
        
        #expect(invalidRedirectError.errorDescription == "Invalid redirect URI in client registration response")
    }
}

// Test helper
private enum TestError: Error {
    case testError
}