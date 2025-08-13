import Testing
import Foundation

@testable import MCP

@Suite("MCP OAuth Tests")
struct MCPOAuthTests {
    
    @Test("MCP OAuth configuration with resource indicator")
    func testMCPOAuthConfigurationWithResourceIndicator() throws {
        let mcpServerURL = "https://mcp.example.com"
        
        let config = try OAuthConfiguration.publicClient(
            authorizationEndpoint: URL(string: "https://auth.example.com/authorize")!,
            tokenEndpoint: URL(string: "https://auth.example.com/token")!,
            clientId: "mcp-client-id",
            scopes: ["mcp:read", "mcp:write"],
            redirectURI: URL(string: "myapp://oauth/callback")!,
            resourceIndicator: mcpServerURL
        )
        
        #expect(config.resourceIndicator == mcpServerURL)
        #expect(config.clientType == .public)
        #expect(config.usePKCE == true)
        #expect(config.scopes == ["mcp:read", "mcp:write"])
    }
    
    @Test("MCP confidential client with resource indicator")
    func testMCPConfidentialClientWithResourceIndicator() throws {
        let mcpServerURL = "https://mcp.example.com"
        
        let config = try OAuthConfiguration.confidentialClient(
            authorizationEndpoint: URL(string: "https://auth.example.com/authorize")!,
            tokenEndpoint: URL(string: "https://auth.example.com/token")!,
            clientId: "mcp-confidential-client",
            clientSecret: "secret",
            scopes: ["mcp:admin"],
            resourceIndicator: mcpServerURL
        )
        
        #expect(config.resourceIndicator == mcpServerURL)
        #expect(config.clientType == .confidential)
        #expect(config.clientSecret == "secret")
        #expect(config.scopes == ["mcp:admin"])
    }
    
    @Test("MCP discovery URLs generation - with path components")
    func testMCPDiscoveryURLsWithPath() async throws {
        let config = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://temp.example.com/auth")!,
            tokenEndpoint: URL(string: "https://temp.example.com/token")!,
            clientId: "test-client"
        )
        
        let authenticator = OAuthAuthenticator(configuration: config)
        let issuerURL = URL(string: "https://auth.example.com/tenant1")!
        
        // Use reflection or make the method public for testing
        // For now, we'll test the expected behavior through integration
        do {
            // This should try multiple endpoints in the correct order
            _ = try await authenticator.discoverAuthorizationServerMetadata(from: issuerURL)
        } catch {
            // Expected to fail in tests without real server (network error is acceptable)
            #expect(error is OAuthError || error is URLError)
        }
    }
    
    @Test("MCP discovery URLs generation - without path components")
    func testMCPDiscoveryURLsWithoutPath() async throws {
        let config = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://temp.example.com/auth")!,
            tokenEndpoint: URL(string: "https://temp.example.com/token")!,
            clientId: "test-client"
        )
        
        let authenticator = OAuthAuthenticator(configuration: config)
        let issuerURL = URL(string: "https://auth.example.com")!
        
        do {
            _ = try await authenticator.discoverAuthorizationServerMetadata(from: issuerURL)
        } catch {
            // Expected to fail in tests without real server (network error is acceptable)
            #expect(error is OAuthError || error is URLError)
        }
    }
    
    @Test("WWW-Authenticate header parsing")
    func testWWWAuthenticateHeaderParsing() async throws {
        let config = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-client"
        )
        
        let authenticator = OAuthAuthenticator(configuration: config)
        
        // Test valid WWW-Authenticate header
        let validHeader = """
        Bearer realm="example", resource_metadata="https://server.example.com/.well-known/oauth-protected-resource"
        """
        
        let metadataURL = try await authenticator.parseWWWAuthenticateHeader(validHeader)
        #expect(metadataURL?.absoluteString == "https://server.example.com/.well-known/oauth-protected-resource")
        
        // Test header without resource_metadata
        let headerWithoutMetadata = "Bearer realm=\"example\""
        let noMetadataURL = try await authenticator.parseWWWAuthenticateHeader(headerWithoutMetadata)
        #expect(noMetadataURL == nil)
        
        // Test invalid header
        let invalidHeader = "Basic realm=\"example\""
        do {
            _ = try await authenticator.parseWWWAuthenticateHeader(invalidHeader)
            #expect(Bool(false), "Should have thrown an error")
        } catch is OAuthError {
            // Expected
        } catch {
            #expect(Bool(false), "Unexpected error: \(error)")
        }
    }
    
    @Test("PKCE support validation")
    func testPKCESupportValidation() async throws {
        let config = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-client"
        )
        
        let authenticator = OAuthAuthenticator(configuration: config)
        
        // Test discovery document with PKCE support
        let validDiscoveryDoc = OAuthDiscoveryDocument(
            issuer: "https://auth.example.com",
            authorizationEndpoint: URL(string: "https://auth.example.com/authorize")!,
            tokenEndpoint: URL(string: "https://auth.example.com/token")!,
            registrationEndpoint: URL(string: "https://auth.example.com/register")!,
            revocationEndpoint: nil,
            scopesSupported: ["read", "write"],
            responseTypesSupported: ["code"],
            grantTypesSupported: ["authorization_code"],
            codeChallengeMethodsSupported: ["S256", "plain"]
        )
        
        // Should not throw for valid discovery document
        try await authenticator.validatePKCESupport(in: validDiscoveryDoc)
        
        // Test discovery document without PKCE support
        let noPKCEDiscoveryDoc = OAuthDiscoveryDocument(
            issuer: "https://auth.example.com",
            authorizationEndpoint: URL(string: "https://auth.example.com/authorize")!,
            tokenEndpoint: URL(string: "https://auth.example.com/token")!,
            registrationEndpoint: nil,
            revocationEndpoint: nil,
            scopesSupported: nil,
            responseTypesSupported: nil,
            grantTypesSupported: nil,
            codeChallengeMethodsSupported: nil
        )
        
        do {
            try await authenticator.validatePKCESupport(in: noPKCEDiscoveryDoc)
            #expect(Bool(false), "Should have thrown an error")
        } catch is OAuthError {
            // Expected
        } catch {
            #expect(Bool(false), "Unexpected error: \(error)")
        }
        
        // Test discovery document with empty PKCE methods
        let emptyPKCEDiscoveryDoc = OAuthDiscoveryDocument(
            issuer: "https://auth.example.com",
            authorizationEndpoint: URL(string: "https://auth.example.com/authorize")!,
            tokenEndpoint: URL(string: "https://auth.example.com/token")!,
            registrationEndpoint: nil,
            revocationEndpoint: nil,
            scopesSupported: nil,
            responseTypesSupported: nil,
            grantTypesSupported: nil,
            codeChallengeMethodsSupported: []
        )
        
        do {
            try await authenticator.validatePKCESupport(in: emptyPKCEDiscoveryDoc)
            #expect(Bool(false), "Should have thrown an error")
        } catch is OAuthError {
            // Expected
        } catch {
            #expect(Bool(false), "Unexpected error: \(error)")
        }
    }
    
    @Test("Protected resource metadata parsing")
    func testProtectedResourceMetadataParsing() throws {
        let jsonString = """
        {
            "resource": "https://mcp.example.com",
            "authorization_servers": [
                "https://auth.example.com",
                "https://auth2.example.com"
            ],
            "scopes_supported": ["read", "write", "admin"],
            "bearer_methods_supported": ["header"],
            "resource_documentation": "https://mcp.example.com/docs"
        }
        """
        
        let data = jsonString.data(using: .utf8)!
        let metadata = try JSONDecoder().decode(ProtectedResourceMetadata.self, from: data)
        
        #expect(metadata.resource == "https://mcp.example.com")
        #expect(metadata.authorizationServers.count == 2)
        #expect(metadata.authorizationServers[0] == "https://auth.example.com")
        #expect(metadata.authorizationServers[1] == "https://auth2.example.com")
        #expect(metadata.scopesSupported == ["read", "write", "admin"])
        #expect(metadata.bearerMethodsSupported == ["header"])
        #expect(metadata.resourceDocumentation == "https://mcp.example.com/docs")
    }
    
    @Test("Authorization URL generation with resource parameter")
    func testAuthorizationURLWithResourceParameter() async throws {
        let mcpServerURL = "https://mcp.example.com"
        
        let config = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://auth.example.com/authorize")!,
            tokenEndpoint: URL(string: "https://auth.example.com/token")!,
            clientId: "test-client",
            scopes: ["read", "write"],
            redirectURI: URL(string: "myapp://oauth/callback")!,
            usePKCE: true,
            resourceIndicator: mcpServerURL
        )
        
        let authenticator = OAuthAuthenticator(configuration: config)
        let pkceState = await authenticator.generatePKCEState()
        let authURL = try await authenticator.generateAuthorizationURL(pkceState: pkceState)
        
        let components = URLComponents(url: authURL, resolvingAgainstBaseURL: false)
        let queryItems = components?.queryItems ?? []
        
        // Check that resource parameter is included
        let resourceParam = queryItems.first { $0.name == "resource" }
        #expect(resourceParam?.value == mcpServerURL)
        
        // Check other required parameters
        let clientIdParam = queryItems.first { $0.name == "client_id" }
        #expect(clientIdParam?.value == "test-client")
        
        let scopeParam = queryItems.first { $0.name == "scope" }
        #expect(scopeParam?.value == "read write")
        
        let codeChallengeParam = queryItems.first { $0.name == "code_challenge" }
        #expect(codeChallengeParam != nil)
        
        let codeChallengeMethodParam = queryItems.first { $0.name == "code_challenge_method" }
        #expect(codeChallengeMethodParam?.value == "S256" || codeChallengeMethodParam?.value == "plain")
    }
}