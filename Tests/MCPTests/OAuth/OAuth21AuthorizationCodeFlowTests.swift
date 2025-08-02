import Testing
import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

@testable import MCP

@Suite("OAuth 2.1 Authorization Code Flow Tests")
struct OAuth21AuthorizationCodeFlowTests {
    
    @Test("Authorization code exchange with state mismatch fails")
    func testAuthorizationCodeExchangeWithStateMismatchFails() async throws {
        let config = try OAuthConfiguration.publicClient(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-client",
            redirectURI: URL(string: "https://example.com/callback")!
        )
        
        let authenticator = OAuthAuthenticator(configuration: config)
        let pkceState = await authenticator.generatePKCEState()
        
        do {
            _ = try await authenticator.exchangeAuthorizationCode(
                code: "auth-code-123",
                pkceState: pkceState,
                receivedState: "different-state" // Mismatched state
            )
            Issue.record("Expected stateMismatch error")
        } catch OAuthError.stateMismatch {
            // Expected error
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
    
    @Test("Authorization code exchange without redirect URI fails")
    func testAuthorizationCodeExchangeWithoutRedirectURIFails() async throws {
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
            _ = try await authenticator.exchangeAuthorizationCode(
                code: "auth-code-123",
                pkceState: pkceState
            )
            Issue.record("Expected redirectURIRequired error")
        } catch OAuthError.redirectURIRequired {
            // Expected error
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
}