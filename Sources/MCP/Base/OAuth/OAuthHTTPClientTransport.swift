import Foundation
import Logging

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// An HTTP transport that automatically handles OAuth authentication
///
/// This transport extends the functionality of HTTPClientTransport by automatically
/// injecting OAuth tokens into requests and handling token refresh when needed.
public actor OAuthHTTPClientTransport: Transport {
    /// The underlying HTTP transport
    private let baseTransport: HTTPClientTransport
    
    /// OAuth authenticator for managing tokens
    private let authenticator: OAuthAuthenticator
    
    /// Identifier for token storage (allows multiple token sets)
    private let tokenIdentifier: String
    
    /// Logger instance for transport-related events
    public nonisolated let logger: Logger
    
    /// Creates a new OAuth-enabled HTTP transport
    ///
    /// - Parameters:
    ///   - endpoint: The server URL to connect to
    ///   - oauthConfig: OAuth configuration
    ///   - tokenStorage: Optional token storage (defaults to platform-appropriate storage)
    ///   - tokenIdentifier: Identifier for token storage (default: "default")
    ///   - configuration: URLSession configuration
    ///   - streaming: Whether to enable SSE streaming
    ///   - logger: Optional logger instance
    public init(
        endpoint: URL,
        oauthConfig: OAuthConfiguration,
        tokenStorage: TokenStorage? = nil,
        tokenIdentifier: String = "default",
        configuration: URLSessionConfiguration = .default,
        streaming: Bool = true,
        logger: Logger? = nil
    ) {
        let effectiveLogger = logger ?? Logger(label: "mcp.transport.oauth.http.client")
        
        // Create authenticated URL session
        let authenticatedConfig = configuration.copy() as! URLSessionConfiguration
        let session = URLSession(configuration: authenticatedConfig)
        
        self.baseTransport = HTTPClientTransport(
            endpoint: endpoint,
            session: session,
            streaming: streaming,
            logger: effectiveLogger
        )
        
        let storage: TokenStorage
#if canImport(Security)
        storage = tokenStorage ?? KeychainTokenStorage()
#elseif os(Linux)
        storage = tokenStorage ?? (try? FileTokenStorage()) ?? InMemoryTokenStorage()
#else
        storage = tokenStorage ?? InMemoryTokenStorage()
#endif
        
        self.authenticator = OAuthAuthenticator(
            configuration: oauthConfig,
            tokenStorage: storage,
            urlSession: session,
            logger: effectiveLogger
        )
        
        self.tokenIdentifier = tokenIdentifier
        self.logger = effectiveLogger
    }
    
    /// Establishes connection with OAuth authentication
    public func connect() async throws {
        logger.info("Connecting OAuth HTTP transport")
        
        // Perform initial authentication if needed
        do {
            _ = try await authenticator.getValidToken(for: tokenIdentifier)
            logger.debug("OAuth token available")
        } catch OAuthError.authenticationRequired {
            logger.info("No valid token found, performing client credentials authentication")
            _ = try await authenticator.authenticateWithClientCredentials(identifier: tokenIdentifier)
        }
        
        // Connect the base transport
        try await baseTransport.connect()
        
        logger.info("OAuth HTTP transport connected")
    }
    
    /// Disconnects from the transport
    public func disconnect() async {
        logger.info("Disconnecting OAuth HTTP transport")
        await baseTransport.disconnect()
    }
    
    /// Sends data with automatic OAuth token injection
    public func send(_ data: Data) async throws {
        do {
            try await sendWithAuthentication(data)
        } catch {
            // Check if this is an authentication error
            if isAuthenticationError(error) {
                logger.info("Authentication error detected, refreshing token and retrying")
                
                // Get current token and try to refresh it
                do {
                    let currentToken = try await authenticator.getValidToken(for: tokenIdentifier)
                    _ = try await authenticator.refreshToken(currentToken, identifier: tokenIdentifier)
                    
                    // Retry the request with the new token
                    try await sendWithAuthentication(data)
                } catch {
                    logger.error("Failed to refresh token and retry request", metadata: ["error": "\(error)"])
                    throw error
                }
            } else {
                throw error
            }
        }
    }
    
    /// Receives data from the transport
    public func receive() -> AsyncThrowingStream<Data, Swift.Error> {
        return AsyncThrowingStream { continuation in
            Task {
                for try await data in await baseTransport.receive() {
                    continuation.yield(data)
                }
                continuation.finish()
            }
        }
    }
    
    // MARK: - Private Methods
    
    private func sendWithAuthentication(_ data: Data) async throws {
        // Get valid token
        let token = try await authenticator.getValidToken(for: tokenIdentifier)
        
        // Create authenticated session with token
        let authenticatedSession = createAuthenticatedSession(token: token)
        
        // Update the base transport's session
        let authenticatedTransport = HTTPClientTransport(
            endpoint: baseTransport.endpoint,
            session: authenticatedSession,
            streaming: false, // Use base transport's streaming for SSE
            logger: logger
        )
        
        // Send the request
        try await authenticatedTransport.send(data)
    }
    
    private func createAuthenticatedSession(token: OAuthToken) -> URLSession {
        let config = URLSessionConfiguration.default
        
        // Add OAuth authorization header
        var headers = config.httpAdditionalHeaders as? [String: String] ?? [:]
        headers["Authorization"] = "\(token.tokenType) \(token.accessToken)"
        config.httpAdditionalHeaders = headers
        
        return URLSession(configuration: config)
    }
    
    private func isAuthenticationError(_ error: Swift.Error) -> Bool {
        // Check if this is an MCP authentication error
        if let mcpError = error as? MCPError,
           case .internalError(let message) = mcpError {
            return (message?.contains("Authentication required") ?? false) || 
                   (message?.contains("Access forbidden") ?? false) ||
                   (message?.contains("401") ?? false)
        }
        
        return false
    }
}

// MARK: - Convenience Initializers

extension OAuthHTTPClientTransport {
    /// Creates an OAuth transport with client credentials flow
    public static func clientCredentials(
        endpoint: URL,
        tokenEndpoint: URL,
        clientId: String,
        clientSecret: String,
        scopes: [String] = [],
        tokenStorage: TokenStorage? = nil,
        logger: Logger? = nil
    ) -> OAuthHTTPClientTransport {
        let config = OAuthConfiguration(
            authorizationEndpoint: tokenEndpoint, // Not used for client credentials
            tokenEndpoint: tokenEndpoint,
            clientId: clientId,
            clientSecret: clientSecret,
            scopes: scopes
        )
        
        return OAuthHTTPClientTransport(
            endpoint: endpoint,
            oauthConfig: config,
            tokenStorage: tokenStorage,
            logger: logger
        )
    }
}