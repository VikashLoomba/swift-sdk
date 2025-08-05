import Testing
import Foundation

@testable import MCP

@Suite("OAuth 2.1 PKCE Tests")
struct OAuth21PKCETests {
    
    @Test("PKCE state generation")
    func testPKCEStateGeneration() async throws {
        let config = try OAuthConfiguration.publicClient(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-client",
            redirectURI: URL(string: "https://example.com/callback")!
        )
        
        let authenticator = OAuthAuthenticator(configuration: config)
        let pkceState = await authenticator.generatePKCEState()
        
        // Verify code verifier is properly formatted
        #expect(pkceState.codeVerifier.count == 128)
        #expect(pkceState.codeVerifier.allSatisfy { char in
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~".contains(char)
        })
        
        // Verify code challenge is different from verifier (S256 hashed) or same (plain method)
        #if canImport(CryptoKit) || canImport(CommonCrypto)
        #expect(pkceState.codeChallenge != pkceState.codeVerifier)
        #else
        // On platforms without crypto libraries, challenge equals verifier (plain method)
        #expect(pkceState.codeChallenge == pkceState.codeVerifier)
        #endif
        #expect(pkceState.codeChallenge.count > 0)
        
        // Verify state parameter
        #expect(pkceState.state.count > 0)
        #expect(pkceState.state != pkceState.codeVerifier)
        #expect(pkceState.state != pkceState.codeChallenge)
    }
    
    @Test("Authorization URL generation with PKCE")
    func testAuthorizationURLGenerationWithPKCE() async throws {
        let config = try OAuthConfiguration.publicClient(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-client",
            scopes: ["openid", "profile"],
            redirectURI: URL(string: "https://example.com/callback")!
        )
        
        let authenticator = OAuthAuthenticator(configuration: config)
        let pkceState = await authenticator.generatePKCEState()
        let authURL = try await authenticator.generateAuthorizationURL(pkceState: pkceState)
        
        let components = URLComponents(url: authURL, resolvingAgainstBaseURL: false)
        let queryItems = components?.queryItems ?? []
        
        // Verify required OAuth 2.1 parameters
        #expect(queryItems.first { $0.name == "response_type" }?.value == "code")
        #expect(queryItems.first { $0.name == "client_id" }?.value == "test-client")
        #expect(queryItems.first { $0.name == "redirect_uri" }?.value == "https://example.com/callback")
        #expect(queryItems.first { $0.name == "state" }?.value == pkceState.state)
        #expect(queryItems.first { $0.name == "scope" }?.value == "openid profile")
        
        // Verify PKCE parameters
        #expect(queryItems.first { $0.name == "code_challenge" }?.value == pkceState.codeChallenge)
        #if canImport(CryptoKit) || canImport(CommonCrypto)
        #expect(queryItems.first { $0.name == "code_challenge_method" }?.value == "S256")
        #else
        #expect(queryItems.first { $0.name == "code_challenge_method" }?.value == "plain")
        #endif
    }
    
    @Test("Authorization URL generation without redirect URI fails")
    func testAuthorizationURLGenerationWithoutRedirectURIFails() async throws {
        let config = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-client",
            clientSecret: nil,
            redirectURI: nil // Missing redirect URI
        )
        
        let authenticator = OAuthAuthenticator(configuration: config)
        let pkceState = await authenticator.generatePKCEState()
        
        do {
            _ = try await authenticator.generateAuthorizationURL(pkceState: pkceState)
            Issue.record("Expected redirectURIRequired error")
        } catch OAuthError.redirectURIRequired {
            // Expected error
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
    
    @Test("PKCE code verifier uniqueness")
    func testPKCECodeVerifierUniqueness() async throws {
        let config = try OAuthConfiguration.publicClient(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-client",
            redirectURI: URL(string: "https://example.com/callback")!
        )
        
        let authenticator = OAuthAuthenticator(configuration: config)
        
        // Generate multiple PKCE states and verify they're unique
        let state1 = await authenticator.generatePKCEState()
        let state2 = await authenticator.generatePKCEState()
        let state3 = await authenticator.generatePKCEState()
        
        #expect(state1.codeVerifier != state2.codeVerifier)
        #expect(state1.codeVerifier != state3.codeVerifier)
        #expect(state2.codeVerifier != state3.codeVerifier)
        
        #expect(state1.codeChallenge != state2.codeChallenge)
        #expect(state1.codeChallenge != state3.codeChallenge)
        #expect(state2.codeChallenge != state3.codeChallenge)
        
        #expect(state1.state != state2.state)
        #expect(state1.state != state3.state)
        #expect(state2.state != state3.state)
    }
    
    @Test("Client credentials flow rejected for public clients")
    func testClientCredentialsFlowRejectedForPublicClients() async throws {
        let config = try OAuthConfiguration.publicClient(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-public-client",
            redirectURI: URL(string: "https://example.com/callback")!
        )
        
        let authenticator = OAuthAuthenticator(configuration: config)
        
        do {
            _ = try await authenticator.authenticateWithClientCredentials()
            Issue.record("Expected clientCredentialsNotAllowedForPublicClients error")
        } catch OAuthError.clientCredentialsNotAllowedForPublicClients {
            // Expected error for OAuth 2.1 compliance
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
}