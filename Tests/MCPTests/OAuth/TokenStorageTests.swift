import Testing
import Foundation

@testable import MCP

@Suite("Token Storage Tests")
struct TokenStorageTests {
    
    @Test("In-memory token storage operations")
    func testInMemoryTokenStorage() async throws {
        let storage = InMemoryTokenStorage()
        let token = OAuthToken(
            accessToken: "test-token",
            tokenType: "Bearer"
        )
        
        // Test store
        try await storage.store(token: token, for: "test-identifier")
        
        // Test retrieve
        let retrievedToken = try await storage.retrieve(for: "test-identifier")
        #expect(retrievedToken?.accessToken == "test-token")
        #expect(retrievedToken?.tokenType == "Bearer")
        
        // Test delete
        try await storage.delete(for: "test-identifier")
        let deletedToken = try await storage.retrieve(for: "test-identifier")
        #expect(deletedToken == nil)
    }
    
    @Test("In-memory token storage - retrieve non-existent token")
    func testInMemoryTokenStorageNonExistent() async throws {
        let storage = InMemoryTokenStorage()
        
        let retrievedToken = try await storage.retrieve(for: "non-existent")
        #expect(retrievedToken == nil)
    }
    
    @Test("In-memory token storage - multiple tokens")
    func testInMemoryTokenStorageMultiple() async throws {
        let storage = InMemoryTokenStorage()
        
        let token1 = OAuthToken(accessToken: "token1", tokenType: "Bearer")
        let token2 = OAuthToken(accessToken: "token2", tokenType: "Bearer")
        
        // Store multiple tokens
        try await storage.store(token: token1, for: "identifier1")
        try await storage.store(token: token2, for: "identifier2")
        
        // Retrieve both
        let retrievedToken1 = try await storage.retrieve(for: "identifier1")
        let retrievedToken2 = try await storage.retrieve(for: "identifier2")
        
        #expect(retrievedToken1?.accessToken == "token1")
        #expect(retrievedToken2?.accessToken == "token2")
        
        // Delete one
        try await storage.delete(for: "identifier1")
        
        let deletedToken1 = try await storage.retrieve(for: "identifier1")
        let stillExistsToken2 = try await storage.retrieve(for: "identifier2")
        
        #expect(deletedToken1 == nil)
        #expect(stillExistsToken2?.accessToken == "token2")
    }

#if os(Linux)
    @Test("File token storage operations")
    func testFileTokenStorage() async throws {
        // Create a temporary directory for testing
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("oauth-test-\(UUID().uuidString)")
        
        let storage = try FileTokenStorage(directory: tempDir)
        let token = OAuthToken(
            accessToken: "file-test-token",
            tokenType: "Bearer",
            expiresIn: 3600
        )
        
        // Test store
        try await storage.store(token: token, for: "file-test-identifier")
        
        // Test retrieve
        let retrievedToken = try await storage.retrieve(for: "file-test-identifier")
        #expect(retrievedToken?.accessToken == "file-test-token")
        #expect(retrievedToken?.tokenType == "Bearer")
        #expect(retrievedToken?.expiresIn == 3600)
        
        // Test delete
        try await storage.delete(for: "file-test-identifier")
        let deletedToken = try await storage.retrieve(for: "file-test-identifier")
        #expect(deletedToken == nil)
        
        // Clean up
        try? FileManager.default.removeItem(at: tempDir)
    }
    
    @Test("File token storage - filename sanitization")
    func testFileTokenStorageFilenamesanitization() async throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("oauth-test-sanitize-\(UUID().uuidString)")
        
        let storage = try FileTokenStorage(directory: tempDir)
        let token = OAuthToken(accessToken: "sanitize-test", tokenType: "Bearer")
        
        // Use an identifier with special characters
        let unsafeIdentifier = "test/identifier:with?special#chars"
        
        try await storage.store(token: token, for: unsafeIdentifier)
        let retrievedToken = try await storage.retrieve(for: unsafeIdentifier)
        
        #expect(retrievedToken?.accessToken == "sanitize-test")
        
        // Clean up
        try? FileManager.default.removeItem(at: tempDir)
    }
#endif
}