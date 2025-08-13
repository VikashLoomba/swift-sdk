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
    
    /// Creates a new OAuth-enabled HTTP transport for MCP servers
    ///
    /// - Parameters:
    ///   - endpoint: The MCP server URL to connect to
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
        guard let config = sessionConfiguration.copy() as? URLSessionConfiguration else {
            logger.error("Failed to copy URLSession configuration")
            return
        }
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
    
    /// Establishes connection with OAuth authentication for MCP
    public func connect() async throws {
        logger.info("Connecting OAuth HTTP transport to MCP server")
        
        // Try to get existing valid token first
        do {
            let token = try await authenticator.getValidToken(for: tokenIdentifier)
            logger.debug("Existing OAuth token available")
            
            // Create base transport with authenticated session
            updateBaseTransport(with: token)
            
            // Connect the base transport
            guard let transport = baseTransport else {
                throw MCPError.internalError("Failed to create base transport")
            }
            try await transport.connect()
            
            logger.info("OAuth HTTP transport connected with existing token")
            return
        } catch OAuthError.authenticationRequired {
            logger.info("No valid token found, will attempt MCP OAuth discovery on first request")
            
            // For MCP, we'll discover OAuth requirements when we get a 401 response
            // Create an unauthenticated transport for the initial discovery request
            self.baseTransport = HTTPClientTransport(
                endpoint: endpoint,
                session: URLSession(configuration: sessionConfiguration),
                streaming: streaming,
                logger: logger
            )
            
            guard let transport = baseTransport else {
                throw MCPError.internalError("Failed to create base transport")
            }
            try await transport.connect()
            
            logger.info("OAuth HTTP transport connected, awaiting OAuth discovery")
        } catch {
            // For confidential clients, try client credentials flow
            if await authenticator.configuration.clientType == .confidential {
                logger.info("Attempting client credentials authentication")
                let token = try await authenticator.authenticateWithClientCredentials(identifier: tokenIdentifier)
                
                updateBaseTransport(with: token)
                
                guard let transport = baseTransport else {
                    throw MCPError.internalError("Failed to create base transport")
                }
                try await transport.connect()
                
                logger.info("OAuth HTTP transport connected with client credentials")
            } else {
                throw error
            }
        }
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
    
    /// Sends data with automatic OAuth token injection, refresh, and MCP discovery
    public func send(_ data: Data) async throws {
        guard let transport = baseTransport else {
            throw MCPError.internalError("Transport not connected")
        }
        
        // Try to send with current token (or no token for initial discovery)
        do {
            try await transport.send(data)
        } catch {
            // Check if this is a 401 authentication error that might trigger MCP OAuth discovery
            if let mcpError = error as? MCPError,
               case .internalError(let message) = mcpError,
               message?.contains("401") == true {
                
                logger.info("Received 401 response, attempting MCP OAuth discovery")
                
                // Extract WWW-Authenticate header from the error message
                var wwwAuthenticateHeader: String? = nil
                if let message = message, message.contains("401 Unauthorized: ") {
                    // Extract the header value after "401 Unauthorized: "
                    wwwAuthenticateHeader = String(message.dropFirst("401 Unauthorized: ".count))
                }
                
                try await performMCPOAuthDiscovery(wwwAuthenticateHeader: wwwAuthenticateHeader)
                
                // Retry the request with the new token
                guard let newTransport = baseTransport else {
                    throw MCPError.internalError("Failed to create transport after OAuth setup")
                }
                try await newTransport.send(data)
                
            } else if isAuthenticationError(error) {
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
                
                do {
                    // Delegate to base transport - SSE will have OAuth headers via URLSession configuration
                    for try await data in await transport.receive() {
                        continuation.yield(data)
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
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
    
    /// Perform MCP OAuth discovery and authentication flow
    private func performMCPOAuthDiscovery(wwwAuthenticateHeader: String? = nil) async throws {
        logger.info("Starting MCP OAuth discovery process")
        
        let (authServerURL, discoveryDocument) = try await discoverOAuthServerMetadata(wwwAuthenticateHeader: wwwAuthenticateHeader)
        
        if await authenticator.configuration.clientType == .public {
            try await handlePublicClientFlow(discoveryDocument: discoveryDocument)
        } else {
            try await handleConfidentialClientFlow(discoveryDocument: discoveryDocument)
        }
    }
    
    private func discoverOAuthServerMetadata(wwwAuthenticateHeader: String? = nil) async throws -> (URL, OAuthDiscoveryDocument) {
        // Step 1: Try to get metadata URL from WWW-Authenticate header if available
        var metadataURL: URL
        
        if let wwwAuthHeader = wwwAuthenticateHeader {
            // Parse the WWW-Authenticate header for resource_metadata URL
            if let parsedURL = try await authenticator.parseWWWAuthenticateHeader(wwwAuthHeader) {
                logger.info("Found resource metadata URL in WWW-Authenticate header", metadata: ["url": "\(parsedURL.absoluteString)"])
                metadataURL = parsedURL
            } else {
                // Fallback to default well-known location
                logger.info("No resource_metadata in WWW-Authenticate header, using default location")
                metadataURL = endpoint.appendingPathComponent(".well-known/oauth-protected-resource")
            }
        } else {
            // No WWW-Authenticate header, use default well-known location
            metadataURL = endpoint.appendingPathComponent(".well-known/oauth-protected-resource")
        }
        
        // Step 2: Fetch protected resource metadata from MCP server
        let metadata = try await authenticator.fetchProtectedResourceMetadata(from: metadataURL)
        
        // Step 3: Select the first authorization server from the metadata
        guard let firstAuthServerString = metadata.authorizationServers.first,
              let authServerURL = URL(string: firstAuthServerString) else {
            throw OAuthError.authorizationServerNotFound
        }
        
        logger.info("Found authorization server", metadata: ["server": "\(authServerURL.absoluteString)"])
        
        // Step 4: Discover authorization server metadata using MCP priority order
        let discoveryDocument = try await authenticator.discoverAuthorizationServerMetadata(from: authServerURL)
        
        // Step 5: Validate PKCE support (required by MCP)
        try await authenticator.validatePKCESupport(in: discoveryDocument)
        
        return (authServerURL, discoveryDocument)
    }
    
    private func handlePublicClientFlow(discoveryDocument: OAuthDiscoveryDocument) async throws {
        logger.info("Public client detected - authorization code flow with PKCE required")
        
        // Generate PKCE state
        let pkceState = await authenticator.generatePKCEState()
        
        // Create a new configuration with the discovered endpoints and resource indicator
        let currentConfig = await authenticator.configuration
        let mcpConfig = try createMCPConfiguration(
            from: discoveryDocument,
            basedOn: currentConfig,
            usePKCE: true,
            includeRedirectURI: true
        )
        
        // Update authenticator with new configuration
        let newAuthenticator = try await createAuthenticator(with: mcpConfig)
        
        // Generate authorization URL
        let authURL = try await newAuthenticator.generateAuthorizationURL(pkceState: pkceState)
        
        // For now, throw an error indicating manual authorization is needed
        // In a real implementation, this would open a browser or return the URL to the caller
        logger.error("Manual authorization required", metadata: ["authURL": "\(authURL.absoluteString)"])
        throw OAuthError.authenticationRequired
    }
    
    private func handleConfidentialClientFlow(discoveryDocument: OAuthDiscoveryDocument) async throws {
        logger.info("Confidential client detected - using client credentials flow")
        
        // Create authenticator with discovered endpoints and resource indicator
        let originalConfig = await authenticator.configuration
        let mcpConfig = try createMCPConfiguration(
            from: discoveryDocument,
            basedOn: originalConfig,
            usePKCE: false,
            includeRedirectURI: false
        )
        
        let mcpAuthenticator = try await createAuthenticator(with: mcpConfig)
        
        // Perform client credentials authentication
        let token = try await mcpAuthenticator.authenticateWithClientCredentials(identifier: tokenIdentifier)
        
        // Update transport and reconnect
        try await updateTransportWithToken(token)
        
        logger.info("MCP OAuth discovery and authentication completed")
    }
    
    private func createMCPConfiguration(
        from discoveryDocument: OAuthDiscoveryDocument,
        basedOn originalConfig: OAuthConfiguration,
        usePKCE: Bool,
        includeRedirectURI: Bool
    ) throws -> OAuthConfiguration {
        return try OAuthConfiguration(
            authorizationEndpoint: discoveryDocument.authorizationEndpoint,
            tokenEndpoint: discoveryDocument.tokenEndpoint,
            revocationEndpoint: discoveryDocument.revocationEndpoint,
            clientId: originalConfig.clientId,
            clientSecret: originalConfig.clientSecret,
            clientType: originalConfig.clientType,
            scopes: originalConfig.scopes,
            redirectURI: includeRedirectURI ? originalConfig.redirectURI : nil,
            usePKCE: usePKCE,
            resourceIndicator: endpoint.absoluteString  // MCP server as resource
        )
    }
    
    private func createAuthenticator(with configuration: OAuthConfiguration) async throws -> OAuthAuthenticator {
        return OAuthAuthenticator(
            configuration: configuration,
            tokenStorage: await authenticator.tokenStorage,
            urlSession: await authenticator.urlSession,
            logger: await authenticator.logger
        )
    }
    
    private func updateTransportWithToken(_ token: OAuthToken) async throws {
        // Disconnect old transport
        if let oldTransport = baseTransport {
            await oldTransport.disconnect()
        }
        
        // Update transport with new token
        updateBaseTransport(with: token)
        
        // Reconnect with new token
        guard let newTransport = baseTransport else {
            throw MCPError.internalError("Failed to create transport with new token")
        }
        try await newTransport.connect()
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