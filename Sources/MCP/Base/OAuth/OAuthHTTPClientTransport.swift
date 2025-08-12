import Foundation
import Logging

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// An HTTP transport that automatically handles OAuth authentication
///
/// This transport extends the functionality of HTTPClientTransport by automatically
/// injecting OAuth tokens into ALL requests (including SSE) and handling token refresh when needed.
public actor OAuthHTTPClientTransport: Transport {
    /// The endpoint URL for the MCP server
    internal let endpoint: URL
    
    /// OAuth authenticator for managing tokens
    private let authenticator: OAuthAuthenticator
    
    /// Identifier for token storage (allows multiple token sets)
    private let tokenIdentifier: String
    
    /// Logger instance for transport-related events
    public nonisolated let logger: Logger
    
    /// The underlying HTTP transport - recreated when token changes
    private var baseTransport: HTTPClientTransport?
    
    /// URLSession configuration template
    private let sessionConfiguration: URLSessionConfiguration
    
    /// Whether streaming is enabled
    private let streaming: Bool
    
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
        self.endpoint = endpoint
        self.sessionConfiguration = configuration
        self.streaming = streaming
        
        let effectiveLogger = logger ?? Logger(label: "mcp.transport.oauth.http.client")
        self.logger = effectiveLogger
        self.tokenIdentifier = tokenIdentifier
        
        // Set up token storage
        let storage: TokenStorage
#if canImport(Security)
        storage = tokenStorage ?? KeychainTokenStorage()
#elseif os(Linux)
        storage = tokenStorage ?? (try? FileTokenStorage()) ?? InMemoryTokenStorage()
#else
        storage = tokenStorage ?? InMemoryTokenStorage()
#endif
        
        // Create URLSession for the authenticator
        let session = URLSession(configuration: configuration)
        
        self.authenticator = OAuthAuthenticator(
            configuration: oauthConfig,
            tokenStorage: storage,
            urlSession: session,
            logger: effectiveLogger
        )
    }
    
    /// Creates or updates the base transport with current OAuth token
    private func updateBaseTransport(with token: OAuthToken) {
        // Create a new configuration with OAuth headers
        let config = sessionConfiguration.copy() as! URLSessionConfiguration
        var headers = config.httpAdditionalHeaders as? [String: String] ?? [:]
        headers["Authorization"] = "\(token.tokenType) \(token.accessToken)"
        config.httpAdditionalHeaders = headers
        
        // Create a new session with the updated configuration
        let authenticatedSession = URLSession(configuration: config)
        
        // Create new transport with authenticated session
        self.baseTransport = HTTPClientTransport(
            endpoint: endpoint,
            session: authenticatedSession,
            streaming: streaming,
            logger: logger
        )
        
        logger.debug("Updated base transport with new OAuth token")
    }
    
    /// Establishes connection with OAuth authentication
    public func connect() async throws {
        logger.info("Connecting OAuth HTTP transport")
        
        // Perform initial authentication if needed
        let token: OAuthToken
        do {
            token = try await authenticator.getValidToken(for: tokenIdentifier)
            logger.debug("OAuth token available")
        } catch OAuthError.authenticationRequired {
            logger.info("No valid token found, performing client credentials authentication")
            token = try await authenticator.authenticateWithClientCredentials(identifier: tokenIdentifier)
        }
        
        // Create base transport with authenticated session
        updateBaseTransport(with: token)
        
        // Connect the base transport
        guard let transport = baseTransport else {
            throw MCPError.internalError("Failed to create base transport")
        }
        try await transport.connect()
        
        logger.info("OAuth HTTP transport connected")
    }
    
    /// Disconnects from the transport
    public func disconnect() async {
        logger.info("Disconnecting OAuth HTTP transport")
        
        // Disconnect the base transport
        if let transport = baseTransport {
            await transport.disconnect()
        }
        
        self.baseTransport = nil
    }
    
    /// Sends data with automatic OAuth token injection and refresh
    public func send(_ data: Data) async throws {
        guard let transport = baseTransport else {
            throw MCPError.internalError("Transport not connected")
        }
        
        // Try to send with current token
        do {
            try await transport.send(data)
        } catch {
            // Check if this is an authentication error
            if isAuthenticationError(error) {
                logger.info("Authentication error detected, refreshing token and retrying")
                
                // Try to refresh the token
                do {
                    let currentToken = try await authenticator.getValidToken(for: tokenIdentifier)
                    let newToken = try await authenticator.refreshToken(currentToken, identifier: tokenIdentifier)
                    
                    // Disconnect old transport
                    await transport.disconnect()
                    
                    // Update transport with new token
                    updateBaseTransport(with: newToken)
                    
                    // Reconnect with new token
                    guard let newTransport = baseTransport else {
                        throw MCPError.internalError("Failed to create transport with new token")
                    }
                    try await newTransport.connect()
                    
                    // Retry the request with the new token
                    try await newTransport.send(data)
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
                guard let transport = self.baseTransport else {
                    continuation.finish(throwing: MCPError.internalError("Transport not connected"))
                    return
                }
                
                // Delegate to base transport - SSE will have OAuth headers via URLSession configuration
                for try await data in await transport.receive() {
                    continuation.yield(data)
                }
                continuation.finish()
            }
        }
    }
    
    // MARK: - Private Methods
    
    private func isAuthenticationError(_ error: Swift.Error) -> Bool {
        // Check if this is an MCP authentication error
        if let mcpError = error as? MCPError,
           case .internalError(let message) = mcpError {
            return (message?.contains("Authentication required") ?? false) || 
                   (message?.contains("Access forbidden") ?? false) ||
                   (message?.contains("401") ?? false) ||
                   (message?.contains("403") ?? false)
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
    ) throws -> OAuthHTTPClientTransport {
        let config = try OAuthConfiguration(
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