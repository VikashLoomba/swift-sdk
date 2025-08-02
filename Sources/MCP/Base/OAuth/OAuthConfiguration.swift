import Foundation

/// Configuration for OAuth 2.0 authentication
public struct OAuthConfiguration: Sendable {
    /// The authorization endpoint URL
    public let authorizationEndpoint: URL
    
    /// The token endpoint URL  
    public let tokenEndpoint: URL
    
    /// The client identifier
    public let clientId: String
    
    /// The client secret (optional for PKCE flows)
    public let clientSecret: String?
    
    /// The requested scopes
    public let scopes: [String]
    
    /// The redirect URI (optional for device code flows)
    public let redirectURI: URL?
    
    /// Additional parameters to include in requests
    public let additionalParameters: [String: String]?
    
    public init(
        authorizationEndpoint: URL,
        tokenEndpoint: URL,
        clientId: String,
        clientSecret: String? = nil,
        scopes: [String] = [],
        redirectURI: URL? = nil,
        additionalParameters: [String: String]? = nil
    ) {
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.scopes = scopes
        self.redirectURI = redirectURI
        self.additionalParameters = additionalParameters
    }
}