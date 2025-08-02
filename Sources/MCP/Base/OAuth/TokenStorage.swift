import Foundation

/// Protocol for securely storing and retrieving OAuth tokens
public protocol TokenStorage: Actor {
    /// Store a token for the given identifier
    func store(token: OAuthToken, for identifier: String) async throws
    
    /// Retrieve a token for the given identifier
    func retrieve(for identifier: String) async throws -> OAuthToken?
    
    /// Delete a token for the given identifier
    func delete(for identifier: String) async throws
}

/// In-memory token storage (for testing and non-persistent scenarios)
public actor InMemoryTokenStorage: TokenStorage {
    private var tokens: [String: OAuthToken] = [:]
    
    public init() {}
    
    public func store(token: OAuthToken, for identifier: String) async throws {
        tokens[identifier] = token
    }
    
    public func retrieve(for identifier: String) async throws -> OAuthToken? {
        return tokens[identifier]
    }
    
    public func delete(for identifier: String) async throws {
        tokens.removeValue(forKey: identifier)
    }
}

#if canImport(Security)
import Security

/// Keychain-based token storage for Apple platforms
public actor KeychainTokenStorage: TokenStorage {
    private let service: String
    private let accessGroup: String?
    
    public init(service: String = "mcp-oauth-tokens", accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }
    
    public func store(token: OAuthToken, for identifier: String) async throws {
        let tokenData = try JSONEncoder().encode(token)
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: identifier,
            kSecValueData as String: tokenData
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        // Delete existing item first
        SecItemDelete(query as CFDictionary)
        
        // Add new item
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw TokenStorageError.keychainError(status)
        }
    }
    
    public func retrieve(for identifier: String) async throws -> OAuthToken? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: identifier,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                return nil
            }
            throw TokenStorageError.keychainError(status)
        }
        
        guard let tokenData = result as? Data else {
            return nil
        }
        
        return try JSONDecoder().decode(OAuthToken.self, from: tokenData)
    }
    
    public func delete(for identifier: String) async throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: identifier
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw TokenStorageError.keychainError(status)
        }
    }
}
#endif

#if os(Linux)

/// File-based encrypted token storage for Linux
public actor FileTokenStorage: TokenStorage {
    private let directory: URL
    
    public init(directory: URL? = nil) throws {
        if let directory = directory {
            self.directory = directory
        } else {
            // Use user's cache directory
            let homeDir = ProcessInfo.processInfo.environment["HOME"] ?? "/tmp"
            self.directory = URL(fileURLWithPath: homeDir).appendingPathComponent(".mcp-oauth-tokens")
        }
        
        // Create directory if it doesn't exist
        try FileManager.default.createDirectory(at: self.directory, withIntermediateDirectories: true)
    }
    
    public func store(token: OAuthToken, for identifier: String) async throws {
        let tokenData = try JSONEncoder().encode(token)
        let filename = sanitizeFilename(identifier)
        let fileURL = directory.appendingPathComponent("\(filename).json")
        
        try tokenData.write(to: fileURL)
    }
    
    public func retrieve(for identifier: String) async throws -> OAuthToken? {
        let filename = sanitizeFilename(identifier)
        let fileURL = directory.appendingPathComponent("\(filename).json")
        
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        
        let tokenData = try Data(contentsOf: fileURL)
        return try JSONDecoder().decode(OAuthToken.self, from: tokenData)
    }
    
    public func delete(for identifier: String) async throws {
        let filename = sanitizeFilename(identifier)
        let fileURL = directory.appendingPathComponent("\(filename).json")
        
        if FileManager.default.fileExists(atPath: fileURL.path) {
            try FileManager.default.removeItem(at: fileURL)
        }
    }
    
    private func sanitizeFilename(_ identifier: String) -> String {
        return identifier
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: ":", with: "_")
            .replacingOccurrences(of: "?", with: "_")
            .replacingOccurrences(of: "#", with: "_")
    }
}
#endif

/// Errors that can occur during token storage operations
public enum TokenStorageError: Swift.Error {
#if canImport(Security)
    case keychainError(OSStatus)
#endif
    case fileSystemError(Swift.Error)
    case encodingError(Swift.Error)
    
    public var localizedDescription: String {
        switch self {
#if canImport(Security)
        case .keychainError(let status):
            return "Keychain error: \(status)"
#endif
        case .fileSystemError(let error):
            return "File system error: \(error.localizedDescription)"
        case .encodingError(let error):
            return "Encoding error: \(error.localizedDescription)"
        }
    }
}