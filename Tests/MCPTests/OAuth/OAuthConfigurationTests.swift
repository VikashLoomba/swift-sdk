import Testing
import Foundation

@testable import MCP

@Suite("OAuth Configuration Tests")
struct OAuthConfigurationTests {
    
    @Test("OAuth configuration initialization")
    func testOAuthConfigurationInit() {
        let config = OAuthConfiguration(
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
        #expect(config.scopes == ["read", "write"])
        #expect(config.redirectURI?.absoluteString == "https://example.com/callback")
        #expect(config.additionalParameters?["custom"] == "value")
    }
    
    @Test("GitHub OAuth configuration preset")
    func testGitHubConfigurationPreset() {
        let config = OAuthConfiguration.github(
            clientId: "github-client-id",
            clientSecret: "github-secret",
            scopes: ["repo", "user"]
        )
        
        #expect(config.authorizationEndpoint.absoluteString == "https://github.com/login/oauth/authorize")
        #expect(config.tokenEndpoint.absoluteString == "https://github.com/login/oauth/access_token")
        #expect(config.clientId == "github-client-id")
        #expect(config.clientSecret == "github-secret")
        #expect(config.scopes == ["repo", "user"])
    }
    
    @Test("Google OAuth configuration preset")
    func testGoogleConfigurationPreset() {
        let config = OAuthConfiguration.google(
            clientId: "google-client-id",
            clientSecret: "google-secret",
            scopes: ["openid", "profile"]
        )
        
        #expect(config.authorizationEndpoint.absoluteString == "https://accounts.google.com/o/oauth2/auth")
        #expect(config.tokenEndpoint.absoluteString == "https://oauth2.googleapis.com/token")
        #expect(config.clientId == "google-client-id")
        #expect(config.clientSecret == "google-secret")
        #expect(config.scopes == ["openid", "profile"])
    }
}