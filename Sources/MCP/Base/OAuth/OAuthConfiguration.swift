import Foundation

/// OAuth configuration validation errors
public enum OAuthConfigurationError: Swift.Error, LocalizedError {
    case publicClientWithSecret
    case publicClientWithoutPKCE
    case invalidRedirectURI
    
    public var errorDescription: String? {
        switch self {
        case .publicClientWithSecret:
            return "OAuth 2.1: Public clients cannot have a client secret"
        case .publicClientWithoutPKCE:
            return "OAuth 2.1: Public clients must use PKCE"
        case .invalidRedirectURI:
            return "Invalid redirect URI in client registration response"
        }
    }
}

/// OAuth client types as defined in OAuth 2.1
public enum OAuthClientType: Sendable {
    /// Confidential clients can maintain client secret securely
    case confidential
    /// Public clients cannot maintain client secret securely (mobile apps, SPAs, etc.)
    case `public`
}

/// Configuration for OAuth 2.0/2.1 authentication with MCP support
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
    
    /// Resource parameter for RFC 8707 Resource Indicators (MCP requirement)
    public let resourceIndicator: String?
    
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
        pkceCodeChallengeMethod: PKCECodeChallengeMethod = .S256,
        resourceIndicator: String? = nil
    ) throws {
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
        
        // MCP OAuth Resource Indicator (RFC 8707)
        self.resourceIndicator = resourceIndicator
        
        // Validate OAuth 2.1 requirements
        if self.clientType == .public && clientSecret != nil {
            // OAuth 2.1: Public clients MUST NOT use client secret
            throw OAuthConfigurationError.publicClientWithSecret
        }
        
        if self.clientType == .public && !self.usePKCE {
            // OAuth 2.1: Public clients MUST use PKCE
            throw OAuthConfigurationError.publicClientWithoutPKCE
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
    ) throws -> OAuthConfiguration {
        let clientType: OAuthClientType = clientSecret != nil ? .confidential : .public
        
        guard let authEndpoint = URL(string: "https://github.com/login/oauth/authorize"),
              let tokenEndpoint = URL(string: "https://github.com/login/oauth/access_token"),
              let revocationEndpoint = URL(string: "https://github.com/settings/connections/applications/\(clientId)") else {
            throw OAuthError.invalidConfiguration("Invalid GitHub OAuth endpoints")
        }
        
        return try OAuthConfiguration(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            revocationEndpoint: revocationEndpoint,
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
    ) throws -> OAuthConfiguration {
        let clientType: OAuthClientType = clientSecret != nil ? .confidential : .public
        
        guard let authEndpoint = URL(string: "https://accounts.google.com/o/oauth2/v2/auth"),
              let tokenEndpoint = URL(string: "https://oauth2.googleapis.com/token"),
              let revocationEndpoint = URL(string: "https://oauth2.googleapis.com/revoke") else {
            throw OAuthError.invalidConfiguration("Invalid Google OAuth endpoints")
        }
        
        return try OAuthConfiguration(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            revocationEndpoint: revocationEndpoint,
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
    ) throws -> OAuthConfiguration {
        let clientType: OAuthClientType = clientSecret != nil ? .confidential : .public
        
        guard let authEndpoint = URL(string: "https://login.microsoftonline.com/\(tenantId)/oauth2/v2.0/authorize"),
              let tokenEndpoint = URL(string: "https://login.microsoftonline.com/\(tenantId)/oauth2/v2.0/token"),
              let revocationEndpoint = URL(string: "https://login.microsoftonline.com/\(tenantId)/oauth2/v2.0/logout") else {
            throw OAuthError.invalidConfiguration("Invalid Microsoft OAuth endpoints for tenant: \(tenantId)")
        }
        
        return try OAuthConfiguration(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            revocationEndpoint: revocationEndpoint,
            clientId: clientId,
            clientSecret: clientSecret,
            clientType: clientType,
            scopes: scopes,
            redirectURI: redirectURI,
            usePKCE: usePKCE ?? (clientType == .public)
        )
    }
    
    /// Generic OAuth 2.1 public client configuration with mandatory PKCE for MCP
    public static func publicClient(
        authorizationEndpoint: URL,
        tokenEndpoint: URL,
        revocationEndpoint: URL? = nil,
        clientId: String,
        scopes: [String] = [],
        redirectURI: URL,
        additionalParameters: [String: String]? = nil,
        resourceIndicator: String? = nil
    ) throws -> OAuthConfiguration {
        return try OAuthConfiguration(
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
            pkceCodeChallengeMethod: .S256,  // Will fallback to .plain if crypto unavailable
            resourceIndicator: resourceIndicator
        )
    }
    
    /// Generic OAuth 2.1 confidential client configuration for MCP
    public static func confidentialClient(
        authorizationEndpoint: URL,
        tokenEndpoint: URL,
        revocationEndpoint: URL? = nil,
        clientId: String,
        clientSecret: String,
        scopes: [String] = [],
        redirectURI: URL? = nil,
        additionalParameters: [String: String]? = nil,
        usePKCE: Bool = false,
        resourceIndicator: String? = nil
    ) throws -> OAuthConfiguration {
        return try OAuthConfiguration(
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
            pkceCodeChallengeMethod: .S256,
            resourceIndicator: resourceIndicator
        )
    }
    
    /// Create OAuth configuration from dynamic client registration response
    public static func fromDynamicRegistration(
        authorizationEndpoint: URL,
        tokenEndpoint: URL,
        revocationEndpoint: URL? = nil,
        registrationResponse: ClientRegistrationResponse,
        scopes: [String] = []
    ) throws -> OAuthConfiguration {
        guard let firstRedirectURI = registrationResponse.redirectUris.first,
              let redirectURI = URL(string: firstRedirectURI) else {
            throw OAuthConfigurationError.invalidRedirectURI
        }
        
        // Let the OAuthConfiguration initializer automatically determine clientType and usePKCE
        // based on the presence of clientSecret (OAuth 2.1 automatic client type detection)
        return try OAuthConfiguration(
            authorizationEndpoint: authorizationEndpoint,
            tokenEndpoint: tokenEndpoint,
            revocationEndpoint: revocationEndpoint,
            clientId: registrationResponse.clientId,
            clientSecret: registrationResponse.clientSecret,
            scopes: scopes.isEmpty ? (registrationResponse.scopes?.split(separator: " ").map(String.init) ?? []) : scopes,
            redirectURI: redirectURI
        )
    }
}