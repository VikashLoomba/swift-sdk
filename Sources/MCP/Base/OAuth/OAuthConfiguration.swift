import Foundation

/// OAuth client types as defined in OAuth 2.1
public enum OAuthClientType: Sendable {
    /// Confidential clients can maintain client secret securely
    case confidential
    /// Public clients cannot maintain client secret securely (mobile apps, SPAs, etc.)
    case `public`
}

/// Configuration for OAuth 2.0/2.1 authentication
public struct OAuthConfiguration: Sendable {
    /// The authorization endpoint URL
    public let authorizationEndpoint: URL
    
    /// The token endpoint URL  
    public let tokenEndpoint: URL
    
    /// The token revocation endpoint URL (optional)
    public let revocationEndpoint: URL?
    
    /// The client identifier
    public let clientId: String
    
    /// The client secret (only for confidential clients)
    public let clientSecret: String?
    
    /// The client type (public or confidential)
    public let clientType: OAuthClientType
    
    /// The requested scopes
    public let scopes: [String]
    
    /// The redirect URI (required for authorization code flows)
    public let redirectURI: URL?
    
    /// Additional parameters to include in requests
    public let additionalParameters: [String: String]?
    
    /// Whether to use PKCE (OAuth 2.1 requires PKCE for public clients)
    public let usePKCE: Bool
    
    /// PKCE code challenge method (S256 recommended)
    public let pkceCodeChallengeMethod: PKCECodeChallengeMethod
    
    public init(
        authorizationEndpoint: URL,
        tokenEndpoint: URL,
        revocationEndpoint: URL? = nil,
        clientId: String,
        clientSecret: String? = nil,
        clientType: OAuthClientType? = nil,
        scopes: [String] = [],
        redirectURI: URL? = nil,
        additionalParameters: [String: String]? = nil,
        usePKCE: Bool? = nil,
        pkceCodeChallengeMethod: PKCECodeChallengeMethod = .S256
    ) {
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.revocationEndpoint = revocationEndpoint
        self.clientId = clientId
        self.clientSecret = clientSecret
        
        // Determine client type based on client secret if not explicitly provided
        if let clientType = clientType {
            self.clientType = clientType
        } else {
            self.clientType = clientSecret != nil ? .confidential : .public
        }
        
        self.scopes = scopes
        self.redirectURI = redirectURI
        self.additionalParameters = additionalParameters
        
        // OAuth 2.1 requires PKCE for public clients
        if let usePKCE = usePKCE {
            self.usePKCE = usePKCE
        } else {
            self.usePKCE = self.clientType == .public
        }
        
        // Use appropriate PKCE method based on platform capabilities
        #if canImport(CryptoKit) || canImport(CommonCrypto)
        self.pkceCodeChallengeMethod = pkceCodeChallengeMethod
        #else
        // Fall back to plain method when crypto libraries are not available
        if pkceCodeChallengeMethod == .S256 {
            self.pkceCodeChallengeMethod = .plain
        } else {
            self.pkceCodeChallengeMethod = pkceCodeChallengeMethod
        }
        #endif
        
        // Validate OAuth 2.1 requirements
        if self.clientType == .public && clientSecret != nil {
            // OAuth 2.1: Public clients MUST NOT use client secret
            preconditionFailure("OAuth 2.1: Public clients cannot have a client secret")
        }
        
        if self.clientType == .public && !self.usePKCE {
            // OAuth 2.1: Public clients MUST use PKCE
            preconditionFailure("OAuth 2.1: Public clients must use PKCE")
        }
    }
}

/// PKCE code challenge methods as defined in RFC 7636
public enum PKCECodeChallengeMethod: String, Sendable, CaseIterable {
    /// Plain text challenge (not recommended for security)
    case plain = "plain"
    /// SHA256 hash challenge (recommended)
    case S256 = "S256"
}

// MARK: - OAuth 2.1 Provider Presets

extension OAuthConfiguration {
    /// GitHub OAuth 2.1 configuration with PKCE support
    public static func github(
        clientId: String,
        clientSecret: String? = nil,
        scopes: [String] = ["read:user"],
        redirectURI: URL? = nil,
        usePKCE: Bool? = nil
    ) -> OAuthConfiguration {
        let clientType: OAuthClientType = clientSecret != nil ? .confidential : .public
        
        return OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://github.com/login/oauth/authorize")!,
            tokenEndpoint: URL(string: "https://github.com/login/oauth/access_token")!,
            revocationEndpoint: URL(string: "https://github.com/settings/connections/applications/\(clientId)")!,
            clientId: clientId,
            clientSecret: clientSecret,
            clientType: clientType,
            scopes: scopes,
            redirectURI: redirectURI,
            usePKCE: usePKCE ?? (clientType == .public)
        )
    }
    
    /// Google OAuth 2.1 configuration with PKCE support
    public static func google(
        clientId: String,
        clientSecret: String? = nil,
        scopes: [String] = ["openid", "profile", "email"],
        redirectURI: URL? = nil,
        usePKCE: Bool? = nil
    ) -> OAuthConfiguration {
        let clientType: OAuthClientType = clientSecret != nil ? .confidential : .public
        
        return OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://accounts.google.com/o/oauth2/v2/auth")!,
            tokenEndpoint: URL(string: "https://oauth2.googleapis.com/token")!,
            revocationEndpoint: URL(string: "https://oauth2.googleapis.com/revoke")!,
            clientId: clientId,
            clientSecret: clientSecret,
            clientType: clientType,
            scopes: scopes,
            redirectURI: redirectURI,
            usePKCE: usePKCE ?? (clientType == .public)
        )
    }
    
    /// Microsoft OAuth 2.1 configuration with PKCE support
    public static func microsoft(
        clientId: String,
        clientSecret: String? = nil,
        tenantId: String = "common",
        scopes: [String] = ["User.Read"],
        redirectURI: URL? = nil,
        usePKCE: Bool? = nil
    ) -> OAuthConfiguration {
        let clientType: OAuthClientType = clientSecret != nil ? .confidential : .public
        
        return OAuthConfiguration(
            authorizationEndpoint: URL(string: "https://login.microsoftonline.com/\(tenantId)/oauth2/v2.0/authorize")!,
            tokenEndpoint: URL(string: "https://login.microsoftonline.com/\(tenantId)/oauth2/v2.0/token")!,
            revocationEndpoint: URL(string: "https://login.microsoftonline.com/\(tenantId)/oauth2/v2.0/logout")!,
            clientId: clientId,
            clientSecret: clientSecret,
            clientType: clientType,
            scopes: scopes,
            redirectURI: redirectURI,
            usePKCE: usePKCE ?? (clientType == .public)
        )
    }
    
    /// Generic OAuth 2.1 public client configuration with mandatory PKCE
    public static func publicClient(
        authorizationEndpoint: URL,
        tokenEndpoint: URL,
        revocationEndpoint: URL? = nil,
        clientId: String,
        scopes: [String] = [],
        redirectURI: URL,
        additionalParameters: [String: String]? = nil
    ) -> OAuthConfiguration {
        return OAuthConfiguration(
            authorizationEndpoint: authorizationEndpoint,
            tokenEndpoint: tokenEndpoint,
            revocationEndpoint: revocationEndpoint,
            clientId: clientId,
            clientSecret: nil,
            clientType: .public,
            scopes: scopes,
            redirectURI: redirectURI,
            additionalParameters: additionalParameters,
            usePKCE: true,  // OAuth 2.1 mandatory for public clients
            pkceCodeChallengeMethod: .S256  // Will fallback to .plain if crypto unavailable
        )
    }
    
    /// Generic OAuth 2.1 confidential client configuration
    public static func confidentialClient(
        authorizationEndpoint: URL,
        tokenEndpoint: URL,
        revocationEndpoint: URL? = nil,
        clientId: String,
        clientSecret: String,
        scopes: [String] = [],
        redirectURI: URL? = nil,
        additionalParameters: [String: String]? = nil,
        usePKCE: Bool = false
    ) -> OAuthConfiguration {
        return OAuthConfiguration(
            authorizationEndpoint: authorizationEndpoint,
            tokenEndpoint: tokenEndpoint,
            revocationEndpoint: revocationEndpoint,
            clientId: clientId,
            clientSecret: clientSecret,
            clientType: .confidential,
            scopes: scopes,
            redirectURI: redirectURI,
            additionalParameters: additionalParameters,
            usePKCE: usePKCE,
            pkceCodeChallengeMethod: .S256
        )
    }
}