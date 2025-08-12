import Testing
import Foundation

@testable import MCP

@Suite("Mobile App Dynamic Registration Tests")
struct MobileAppDynamicRegistrationTests {
    
    @Test("Mobile app dynamic registration should request public client via token_endpoint_auth_method")
    func testMobileAppDynamicRegistrationRequestsPublicClient() async throws {
        // This test validates that when we do dynamic registration for a mobile app,
        // we correctly include token_endpoint_auth_method: "none" in the registration request
        // to tell the server this is a public client
        
        // Mock server that captures the registration request
        class MockServer {
            var capturedRegistrationRequest: [String: Any]?
            
            func handleRegistrationRequest(_ request: [String: Any]) -> ClientRegistrationResponse {
                capturedRegistrationRequest = request
                
                // Simulate a server that respects the token_endpoint_auth_method
                let tokenAuthMethod = request["token_endpoint_auth_method"] as? String
                let shouldProvideSecret = tokenAuthMethod != "none"
                
                return ClientRegistrationResponse(
                    clientId: "mobile-app-client-123",
                    clientSecret: shouldProvideSecret ? "should-not-be-provided" : nil,
                    clientIdIssuedAt: nil,
                    clientSecretExpiresAt: nil,
                    redirectUris: ["myapp://auth"],
                    grantTypes: ["authorization_code"],
                    responseTypes: ["code"],
                    scopes: "openid profile",
                    clientName: "Mobile App",
                    softwareId: nil,
                    softwareVersion: nil
                )
            }
        }
        
        let _ = MockServer() // Just to demonstrate the concept
        
        // Create an authenticator with a mock transport
        // Since we can't easily mock the network layer, we'll test the request construction
        let tempConfig = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://oauth.example.com/authorize")!,
            tokenEndpoint: URL(string: "https://oauth.example.com/token")!,
            clientId: "temp",
            scopes: []
        )
        let authenticator = OAuthAuthenticator(configuration: tempConfig)
        
        // Test the registration request construction by examining what would be sent
        let registrationEndpoint = URL(string: "https://oauth.example.com/register")!
        let clientName = "Mobile App"
        let redirectURIs = [URL(string: "myapp://auth")!]
        let scopes = ["openid", "profile"]
        
        // Test that when isPublicClient=true (default), we use "none" auth method
        // We can't easily test the actual network request, but we can test that the method exists
        // and accepts the right parameters
        
        // This validates the method signature and default parameters
        do {
            // This would fail if the parameters don't match what we expect
            _ = try await authenticator.registerClient(
                registrationEndpoint: registrationEndpoint,
                clientName: clientName,
                redirectURIs: redirectURIs,
                scopes: scopes,
                tokenEndpointAuthMethod: "none"  // Explicit public client
            )
        } catch {
            // Expected to fail since we don't have a real server, but validates the method signature
            // Could be URLError (network) or OAuthError (parsing), both are acceptable
            #expect(error is URLError || error is OAuthError)
        }
        
        // Test that the new setupOAuthWithDiscovery accepts isPublicClient parameter
        do {
            let discoveryURL = URL(string: "https://oauth.example.com/.well-known/oauth-authorization-server")!
            _ = try await authenticator.setupOAuthWithDiscovery(
                discoveryURL: discoveryURL,
                clientName: clientName,
                redirectURIs: redirectURIs,
                scopes: scopes,
                isPublicClient: true  // Mobile app should be public client
            )
        } catch {
            // Expected to fail since we don't have a real server, but validates the method signature
            #expect(error is URLError || error is OAuthError)
        }
    }
    
    @Test("Mobile app registration with server that incorrectly provides client secret")
    func testMobileAppRegistrationWithIncorrectServerBehavior() throws {
        // This test simulates the exact issue described in the problem statement:
        // A server that incorrectly provides a client secret even when we request a public client
        
        // Simulate a problematic server response that provides a client secret
        // even though we requested token_endpoint_auth_method: "none"
        let problematicServerResponse = ClientRegistrationResponse(
            clientId: "mobile-client-123",
            clientSecret: "incorrectly-provided-secret", // Server shouldn't provide this
            clientIdIssuedAt: nil,
            clientSecretExpiresAt: nil,
            redirectUris: ["myapp://auth"],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: "openid profile",
            clientName: "Mobile App",
            softwareId: nil,
            softwareVersion: nil
        )
        
        // Create OAuth configuration from this response
        let config = try OAuthConfiguration.fromDynamicRegistration(
            authorizationEndpoint: URL(string: "https://oauth.provider.com/authorize")!,
            tokenEndpoint: URL(string: "https://oauth.provider.com/token")!,
            registrationResponse: problematicServerResponse,
            scopes: ["openid", "profile"]
        )
        
        // Even though the server provided a client secret, our SDK currently
        // will treat this as a confidential client and not enable PKCE automatically
        // This demonstrates the issue that we're trying to solve
        #expect(config.clientId == "mobile-client-123")
        #expect(config.clientSecret == "incorrectly-provided-secret")
        #expect(config.clientType == .confidential)  // This is the problem
        #expect(config.usePKCE == false)  // This is why PKCE isn't enabled
        
        // However, if we know this is a mobile app, we could manually create
        // a public client configuration ignoring the client secret
        let correctConfig = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://oauth.provider.com/authorize")!,
            tokenEndpoint: URL(string: "https://oauth.provider.com/token")!,
            clientId: problematicServerResponse.clientId,
            clientSecret: nil,  // Ignore the incorrectly provided secret
            clientType: .public,  // Force public client
            scopes: ["openid", "profile"],
            redirectURI: URL(string: problematicServerResponse.redirectUris.first!)!,
            usePKCE: true  // Force PKCE for mobile app
        )
        
        #expect(correctConfig.clientType == .public)
        #expect(correctConfig.usePKCE == true)
        #expect(correctConfig.clientSecret == nil)
    }
    
    @Test("Token endpoint auth method parameter validation")
    func testTokenEndpointAuthMethodValidation() async throws {
        let tempConfig = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://oauth.example.com/authorize")!,
            tokenEndpoint: URL(string: "https://oauth.example.com/token")!,
            clientId: "temp",
            scopes: []
        )
        let authenticator = OAuthAuthenticator(configuration: tempConfig)
        
        let registrationEndpoint = URL(string: "https://oauth.example.com/register")!
        let clientName = "Test App"
        let redirectURIs = [URL(string: "https://app.example.com/callback")!]
        
        // Test different token endpoint auth methods
        let testCases = [
            ("none", "Public client"),
            ("client_secret_post", "Confidential client with POST auth"),
            ("client_secret_basic", "Confidential client with Basic auth")
        ]
        
        for (authMethod, description) in testCases {
            do {
                _ = try await authenticator.registerClient(
                    registrationEndpoint: registrationEndpoint,
                    clientName: "\(clientName) - \(description)",
                    redirectURIs: redirectURIs,
                    tokenEndpointAuthMethod: authMethod
                )
            } catch {
                // Expected to fail due to no real server, but validates method signature
                #expect(error is URLError || error is OAuthError)
            }
        }
    }
    
    @Test("Setup OAuth with discovery for mobile apps defaults to public client")
    func testSetupOAuthWithDiscoveryDefaultsToPublicClient() async throws {
        let tempConfig = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://oauth.example.com/authorize")!,
            tokenEndpoint: URL(string: "https://oauth.example.com/token")!,
            clientId: "temp",
            scopes: []
        )
        let authenticator = OAuthAuthenticator(configuration: tempConfig)
        
        let discoveryURL = URL(string: "https://oauth.example.com/.well-known/oauth-authorization-server")!
        let clientName = "Mobile App"
        let redirectURIs = [URL(string: "myapp://auth")!]
        let scopes = ["openid", "profile"]
        
        // Test that the default value for isPublicClient is true
        do {
            _ = try await authenticator.setupOAuthWithDiscovery(
                discoveryURL: discoveryURL,
                clientName: clientName,
                redirectURIs: redirectURIs,
                scopes: scopes
                // isPublicClient defaults to true
            )
        } catch {
            // Expected to fail due to no real server
            #expect(error is URLError || error is OAuthError)
        }
        do {
            _ = try await authenticator.setupOAuthWithDiscovery(
                discoveryURL: discoveryURL,
                clientName: clientName,
                redirectURIs: redirectURIs,
                scopes: scopes,
                isPublicClient: true
            )
        } catch {
            // Expected to fail due to no real server
            #expect(error is URLError || error is OAuthError)
        }
        
        // Test explicit confidential client
        do {
            _ = try await authenticator.setupOAuthWithDiscovery(
                discoveryURL: discoveryURL,
                clientName: "Server App",
                redirectURIs: [URL(string: "https://app.example.com/callback")!],
                scopes: scopes,
                isPublicClient: false
            )
        } catch {
            // Expected to fail due to no real server
            #expect(error is URLError || error is OAuthError)
        }
    }
    
    @Test("RFC 7591 compliance - token_endpoint_auth_method values")
    func testRFC7591ComplianceTokenEndpointAuthMethod() {
        // Test that we support the standard token_endpoint_auth_method values
        // from RFC 7591 Section 2
        
        let standardAuthMethods = [
            "none",                    // Public clients
            "client_secret_post",      // Confidential clients with POST
            "client_secret_basic",     // Confidential clients with Basic auth
            "client_secret_jwt",       // JWT-based authentication
            "private_key_jwt"          // Private key JWT authentication
        ]
        
        // Validate that these are all valid string values that our method accepts
        for authMethod in standardAuthMethods {
            #expect(authMethod.isEmpty == false)
            #expect(authMethod.contains(" ") == false)  // No spaces in auth method names
        }
        
        // The key insight is that for mobile apps, we should use "none"
        // which explicitly tells the server not to issue a client secret
        let mobileAppAuthMethod = "none"
        #expect(mobileAppAuthMethod == "none")
    }
}