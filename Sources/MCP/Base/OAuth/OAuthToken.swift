import Foundation

/// Represents an OAuth 2.0 access token
public struct OAuthToken: Codable, Sendable {
    /// The access token string
    public let accessToken: String
    
    /// The token type (usually "Bearer")
    public let tokenType: String
    
    /// Token expiration time in seconds
    public let expiresIn: Int?
    
    /// Refresh token for obtaining new access tokens
    public let refreshToken: String?
    
    /// The scope of the access token
    public let scope: String?
    
    /// When this token was issued
    public let issuedAt: Date
    
    /// Checks if the token is expired (with 60 second buffer)
    public var isExpired: Bool {
        guard let expiresIn = expiresIn else { return false }
        return Date().timeIntervalSince(issuedAt) > TimeInterval(expiresIn - 60)
    }
    
    public init(
        accessToken: String,
        tokenType: String = "Bearer",
        expiresIn: Int? = nil,
        refreshToken: String? = nil,
        scope: String? = nil,
        issuedAt: Date = Date()
    ) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.refreshToken = refreshToken
        self.scope = scope
        self.issuedAt = issuedAt
    }
}