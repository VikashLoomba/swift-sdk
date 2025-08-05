import Testing
import Foundation

@testable import MCP

@Suite("OAuth Configuration Tests")
struct OAuthConfigurationTests {
    
    @Test("OAuth 2.1 confidential client configuration")
    func testOAuth21ConfidentialClientConfiguration() throws {
        let config = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-client-id",
            clientSecret: "test-secret",
            scopes: ["read", "write"],
            redirectURI: URL(string: "https://example.com/callback"),
            additionalParameters: ["custom": "value"]
        )
        
        #expect(config.authorizationEndpoint.absoluteString == "https://example.com/auth")
        #expect(config.tokenEndpoint.absoluteString == "https://example.com/token")
        #expect(config.clientId == "test-client-id")
        #expect(config.clientSecret == "test-secret")
        #expect(config.clientType == .confidential)
        #expect(config.scopes == ["read", "write"])
        #expect(config.redirectURI?.absoluteString == "https://example.com/callback")
        #expect(config.additionalParameters?["custom"] == "value")
        #expect(config.usePKCE == false) // Confidential client doesn't require PKCE
        #if canImport(CryptoKit) || canImport(CommonCrypto)
        #expect(config.pkceCodeChallengeMethod == .S256)
        #else
        #expect(config.pkceCodeChallengeMethod == .plain) // Fallback on platforms without crypto
        #endif
    }
    
    @Test("OAuth 2.1 public client configuration with mandatory PKCE")
    func testOAuth21PublicClientConfiguration() throws {
        let config = try OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-client-id",
            clientSecret: nil, // Public client
            scopes: ["read", "write"],
            redirectURI: URL(string: "https://example.com/callback")
        )
        
        #expect(config.clientType == .public)
        #expect(config.clientSecret == nil)
        #expect(config.usePKCE == true) // OAuth 2.1 mandates PKCE for public clients
        #if canImport(CryptoKit) || canImport(CommonCrypto)
        #expect(config.pkceCodeChallengeMethod == .S256)
        #else
        #expect(config.pkceCodeChallengeMethod == .plain) // Fallback on platforms without crypto
        #endif
    }
    
    @Test("OAuth 2.1 public client preset configurations")
    func testOAuth21PublicClientPresets() throws {
        // GitHub public client
        let githubConfig = try OAuthConfiguration.github(
            clientId: "github-public-client",
            scopes: ["repo", "user"]
        )
        
        #expect(githubConfig.clientType == .public)
        #expect(githubConfig.clientSecret == nil)
        #expect(githubConfig.usePKCE == true)
        
        // Google public client
        let googleConfig = try OAuthConfiguration.google(
            clientId: "google-public-client",
            scopes: ["openid", "profile"]
        )
        
        #expect(googleConfig.clientType == .public)
        #expect(googleConfig.clientSecret == nil)
        #expect(googleConfig.usePKCE == true)
        
        // Microsoft public client
        let microsoftConfig = try OAuthConfiguration.microsoft(
            clientId: "microsoft-public-client",
            scopes: ["User.Read"]
        )
        
        #expect(microsoftConfig.clientType == .public)
        #expect(microsoftConfig.clientSecret == nil)
        #expect(microsoftConfig.usePKCE == true)
    }
    
    @Test("OAuth 2.1 generic public client factory method")
    func testOAuth21GenericPublicClient() throws {
        let config = try OAuthConfiguration.publicClient(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-public-client",
            scopes: ["openid"],
            redirectURI: URL(string: "https://example.com/callback")!
        )
        
        #expect(config.clientType == .public)
        #expect(config.clientSecret == nil)
        #expect(config.usePKCE == true)
        #if canImport(CryptoKit) || canImport(CommonCrypto)
        #expect(config.pkceCodeChallengeMethod == .S256)
        #else
        #expect(config.pkceCodeChallengeMethod == .plain) // Fallback on platforms without crypto
        #endif
    }
    
    @Test("OAuth 2.1 generic confidential client factory method")
    func testOAuth21GenericConfidentialClient() throws {
        let config = try OAuthConfiguration.confidentialClient(
            authorizationEndpoint: URL(string: "https://example.com/auth")!,
            tokenEndpoint: URL(string: "https://example.com/token")!,
            clientId: "test-confidential-client",
            clientSecret: "secret",
            scopes: ["api:read"],
            usePKCE: true // Confidential client can optionally use PKCE
        )
        
        #expect(config.clientType == .confidential)
        #expect(config.clientSecret == "secret")
        #expect(config.usePKCE == true)
        #if canImport(CryptoKit) || canImport(CommonCrypto)
        #expect(config.pkceCodeChallengeMethod == .S256)
        #else
        #expect(config.pkceCodeChallengeMethod == .plain) // Fallback on platforms without crypto
        #endif
    }
    
    @Test("GitHub OAuth 2.1 configuration preset")
    func testGitHubConfigurationPreset() throws {
        let config = try OAuthConfiguration.github(
            clientId: "github-client-id",
            clientSecret: "github-secret",
            scopes: ["repo", "user"]
        )
        
        #expect(config.authorizationEndpoint.absoluteString == "https://github.com/login/oauth/authorize")
        #expect(config.tokenEndpoint.absoluteString == "https://github.com/login/oauth/access_token")
        #expect(config.clientId == "github-client-id")
        #expect(config.clientSecret == "github-secret")
        #expect(config.clientType == .confidential)
        #expect(config.scopes == ["repo", "user"])
        #expect(config.usePKCE == false) // Confidential client default
    }
    
    @Test("Google OAuth 2.1 configuration preset")
    func testGoogleConfigurationPreset() throws {
        let config = try OAuthConfiguration.google(
            clientId: "google-client-id",
            clientSecret: "google-secret",
            scopes: ["openid", "profile"]
        )
        
        #expect(config.authorizationEndpoint.absoluteString == "https://accounts.google.com/o/oauth2/v2/auth")
        #expect(config.tokenEndpoint.absoluteString == "https://oauth2.googleapis.com/token")
        #expect(config.clientId == "google-client-id")
        #expect(config.clientSecret == "google-secret")
        #expect(config.clientType == .confidential)
        #expect(config.scopes == ["openid", "profile"])
    }
    
    @Test("Microsoft OAuth 2.1 configuration preset")
    func testMicrosoftConfigurationPreset() throws {
        let config = try OAuthConfiguration.microsoft(
            clientId: "microsoft-client-id",
            clientSecret: "microsoft-secret",
            tenantId: "custom-tenant",
            scopes: ["User.Read", "Mail.Read"]
        )
        
        #expect(config.authorizationEndpoint.absoluteString == "https://login.microsoftonline.com/custom-tenant/oauth2/v2.0/authorize")
        #expect(config.tokenEndpoint.absoluteString == "https://login.microsoftonline.com/custom-tenant/oauth2/v2.0/token")
        #expect(config.clientId == "microsoft-client-id")
        #expect(config.clientSecret == "microsoft-secret")
        #expect(config.clientType == .confidential)
        #expect(config.scopes == ["User.Read", "Mail.Read"])
    }
    
    @Test("PKCE code challenge methods")
    func testPKCECodeChallengeMethods() {
        #expect(PKCECodeChallengeMethod.plain.rawValue == "plain")
        #expect(PKCECodeChallengeMethod.S256.rawValue == "S256")
        #expect(PKCECodeChallengeMethod.allCases.count == 2)
    }
    
    @Test("OAuth 2.1 public client with secret should throw error")
    func testPublicClientWithSecretThrowsError() {
        #expect(throws: OAuthConfigurationError.publicClientWithSecret) {
            _ = try OAuthConfiguration(
                authorizationEndpoint: URL(string: "https://example.com/auth")!,
                tokenEndpoint: URL(string: "https://example.com/token")!,
                clientId: "test-client",
                clientSecret: "secret", // This should cause an error for public client
                clientType: .public
            )
        }
    }
    
    @Test("OAuth 2.1 public client without PKCE should throw error")
    func testPublicClientWithoutPKCEThrowsError() {
        #expect(throws: OAuthConfigurationError.publicClientWithoutPKCE) {
            _ = try OAuthConfiguration(
                authorizationEndpoint: URL(string: "https://example.com/auth")!,
                tokenEndpoint: URL(string: "https://example.com/token")!,
                clientId: "test-client",
                clientSecret: nil,
                clientType: .public,
                usePKCE: false // This should cause an error for public client
            )
        }
    }
}