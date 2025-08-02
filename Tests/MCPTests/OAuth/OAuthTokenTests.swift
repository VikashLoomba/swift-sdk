import Testing
import Foundation

@testable import MCP

@Suite("OAuth Token Tests")
struct OAuthTokenTests {
    
    @Test("OAuth token initialization")
    func testOAuthTokenInit() {
        let issuedAt = Date()
        let token = OAuthToken(
            accessToken: "access-token-123",
            tokenType: "Bearer",
            expiresIn: 3600,
            refreshToken: "refresh-token-456",
            scope: "read write",
            issuedAt: issuedAt
        )
        
        #expect(token.accessToken == "access-token-123")
        #expect(token.tokenType == "Bearer")
        #expect(token.expiresIn == 3600)
        #expect(token.refreshToken == "refresh-token-456")
        #expect(token.scope == "read write")
        #expect(token.issuedAt == issuedAt)
    }
    
    @Test("OAuth token expiration check - not expired")
    func testTokenNotExpired() {
        let token = OAuthToken(
            accessToken: "access-token",
            tokenType: "Bearer",
            expiresIn: 3600, // 1 hour
            issuedAt: Date() // Just issued
        )
        
        #expect(!token.isExpired)
    }
    
    @Test("OAuth token expiration check - expired")
    func testTokenExpired() {
        let token = OAuthToken(
            accessToken: "access-token",
            tokenType: "Bearer",
            expiresIn: 3600, // 1 hour
            issuedAt: Date().addingTimeInterval(-3700) // Issued more than 1 hour ago
        )
        
        #expect(token.isExpired)
    }
    
    @Test("OAuth token expiration check - no expiration")
    func testTokenNoExpiration() {
        let token = OAuthToken(
            accessToken: "access-token",
            tokenType: "Bearer",
            expiresIn: nil // Never expires
        )
        
        #expect(!token.isExpired)
    }
    
    @Test("OAuth token JSON serialization")
    func testTokenJSONSerialization() throws {
        let originalToken = OAuthToken(
            accessToken: "access-token-123",
            tokenType: "Bearer",
            expiresIn: 3600,
            refreshToken: "refresh-token-456",
            scope: "read write"
        )
        
        // Encode to JSON
        let encoder = JSONEncoder()
        let jsonData = try encoder.encode(originalToken)
        
        // Decode from JSON
        let decoder = JSONDecoder()
        let decodedToken = try decoder.decode(OAuthToken.self, from: jsonData)
        
        #expect(decodedToken.accessToken == originalToken.accessToken)
        #expect(decodedToken.tokenType == originalToken.tokenType)
        #expect(decodedToken.expiresIn == originalToken.expiresIn)
        #expect(decodedToken.refreshToken == originalToken.refreshToken)
        #expect(decodedToken.scope == originalToken.scope)
    }
}