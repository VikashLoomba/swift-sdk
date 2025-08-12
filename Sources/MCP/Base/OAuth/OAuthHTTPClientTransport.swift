import Foundation
import Logging

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

#if canImport(CryptoKit)
import CryptoKit
#endif

#if !canImport(CryptoKit) && canImport(CommonCrypto)
import CommonCrypto
#endif

/// An HTTP transport that automatically handles OAuth authentication
///
/// This transport extends the functionality of HTTPClientTransport by automatically
/// injecting OAuth tokens into requests and handling token refresh when needed.
/// Uses session reuse and request interception for efficient authentication.
public actor OAuthHTTPClientTransport: Transport {
    /// The underlying HTTP transport
    private let baseTransport: HTTPClientTransport
    
    /// OAuth authenticator for managing tokens
    private let authenticator: OAuthAuthenticator
    
    /// Identifier for token storage (allows multiple token sets)
    private let tokenIdentifier: String
    
    /// Logger instance for transport-related events
    public nonisolated let logger: Logger
    
    /// Pool of reusable authenticated URLSession instances
    private var authenticatedSessionPool: [String: URLSession] = [:]
    
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
        
        // Create URLSession for the base transport (unauthenticated)
        let session = URLSession(configuration: configuration)
        
        self.authenticator = OAuthAuthenticator(
            configuration: oauthConfig,
            tokenStorage: storage,
            urlSession: session,
            logger: effectiveLogger
        )
        
        // Create base transport without authentication (we'll handle auth in send method)
        self.baseTransport = HTTPClientTransport(
            endpoint: endpoint,
            session: session,
            streaming: streaming,
            logger: effectiveLogger
        )
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
        
        // Clean up authenticated session pool
        await cleanupSessionPool()
        
        // Disconnect the base transport
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
        
        // Get or create an authenticated session for this token
        let authenticatedSession = getOrCreateAuthenticatedSession(for: token)
        
        // Use the authenticated session directly instead of creating a new transport
        var request = URLRequest(url: baseTransport.endpoint)
        request.httpMethod = "POST"
        request.httpBody = data
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let (_, response) = try await authenticatedSession.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw MCPError.internalError("Invalid response type")
        }
        
        guard 200...299 ~= httpResponse.statusCode else {
            throw MCPError.internalError("HTTP request failed with status \(httpResponse.statusCode)")
        }
    }
    
    /// Gets or creates an authenticated URLSession for the given token
    /// Implements session pooling to reuse sessions with the same token
    private func getOrCreateAuthenticatedSession(for token: OAuthToken) -> URLSession {
        let sessionKey = hashAccessToken(token.accessToken) // Use hash of access token for security
        
        if let existingSession = authenticatedSessionPool[sessionKey] {
            logger.trace("Reusing authenticated session from pool")
            return existingSession
        }
        
        // Create new authenticated session
        let config = URLSessionConfiguration.default
        var headers = config.httpAdditionalHeaders as? [String: String] ?? [:]
        headers["Authorization"] = "\(token.tokenType) \(token.accessToken)"
        config.httpAdditionalHeaders = headers
        
        let authenticatedSession = URLSession(configuration: config)
        
        // Add to pool for reuse
        authenticatedSessionPool[sessionKey] = authenticatedSession
        logger.trace("Created new authenticated session and added to pool")
        
        return authenticatedSession
    }
    
    /// Creates a secure hash of the access token for use as a session key
    /// This prevents token exposure in memory dumps and logs
    private func hashAccessToken(_ accessToken: String) -> String {
        let data = Data(accessToken.utf8)
        
        #if canImport(CryptoKit)
        let digest = SHA256.hash(data: data)
        return digest.compactMap { String(format: "%02x", $0) }.joined()
        #elseif canImport(CommonCrypto)
        // Fallback implementation for platforms with CommonCrypto
        let digest = sha256Fallback(data)
        return digest.map { String(format: "%02x", $0) }.joined()
        #else
        // Last resort: use simple hash (not cryptographically secure)
        logger.warning("No cryptographic hashing available, using simple hash for session keys")
        return String(accessToken.hashValue)
        #endif
    }
    
    #if !canImport(CryptoKit) && canImport(CommonCrypto)
    /// Fallback SHA256 implementation for platforms with CommonCrypto
    private func sha256Fallback(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
    #endif
    
    /// Cleans up the authenticated session pool
    /// Invalidates all sessions synchronously since invalidateAndCancel is not async
    private func cleanupSessionPool() async {
        logger.debug("Cleaning up \(authenticatedSessionPool.count) authenticated sessions")
        
        // Invalidate all sessions - invalidateAndCancel is synchronous
        for (_, session) in authenticatedSessionPool {
            session.invalidateAndCancel()
        }
        
        authenticatedSessionPool.removeAll()
        logger.debug("Cleaned up authenticated session pool")
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