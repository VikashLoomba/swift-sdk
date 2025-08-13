import Foundation
import Logging

#if canImport(CryptoKit)
import CryptoKit
#endif

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

#if !canImport(CryptoKit) && canImport(CommonCrypto)
import CommonCrypto
#endif

/// Actor responsible for OAuth authentication and token management
public actor OAuthAuthenticator {
    internal let configuration: OAuthConfiguration
    internal let tokenStorage: TokenStorage
    internal let urlSession: URLSession
    internal let logger: Logger
    
    /// Current cached token
    private var currentToken: OAuthToken?
    
    /// Ongoing token refresh task to prevent concurrent refreshes
    private var refreshTask: Task<OAuthToken, Swift.Error>?
    
    public init(
        configuration: OAuthConfiguration,
        tokenStorage: TokenStorage? = nil,
        urlSession: URLSession = .shared,
        logger: Logger? = nil
    ) {
        self.configuration = configuration
        self.tokenStorage = tokenStorage ?? InMemoryTokenStorage()
        self.urlSession = urlSession
        self.logger = logger ?? Logger(label: "mcp.oauth.authenticator")
    }
    
    // MARK: - PKCE Support
    
    /// PKCE state for authorization code flow
    public struct PKCEState: Sendable {
        public let codeVerifier: String
        public let codeChallenge: String
        public let state: String
        
        public init(codeVerifier: String, codeChallenge: String, state: String) {
            self.codeVerifier = codeVerifier
            self.codeChallenge = codeChallenge
            self.state = state
        }
    }
    
    /// Generate PKCE state for authorization code flow
    public func generatePKCEState() -> PKCEState {
        let codeVerifier = generateCodeVerifier()
        let codeChallenge = generateCodeChallenge(from: codeVerifier, method: configuration.pkceCodeChallengeMethod)
        let state = generateState()
        
        return PKCEState(
            codeVerifier: codeVerifier,
            codeChallenge: codeChallenge,
            state: state
        )
    }
    
    /// Generate authorization URL for OAuth 2.1 authorization code flow with PKCE and resource indicators (MCP)
    public func generateAuthorizationURL(pkceState: PKCEState) throws -> URL {
        guard let redirectURI = configuration.redirectURI else {
            throw OAuthError.redirectURIRequired
        }
        
        var components = URLComponents(url: configuration.authorizationEndpoint, resolvingAgainstBaseURL: false)
        
        var queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: configuration.clientId),
            URLQueryItem(name: "redirect_uri", value: redirectURI.absoluteString),
            URLQueryItem(name: "state", value: pkceState.state)
        ]
        
        // Add scopes if specified
        if !configuration.scopes.isEmpty {
            queryItems.append(URLQueryItem(name: "scope", value: configuration.scopes.joined(separator: " ")))
        }
        
        // Add PKCE parameters if enabled
        if configuration.usePKCE {
            queryItems.append(URLQueryItem(name: "code_challenge", value: pkceState.codeChallenge))
            queryItems.append(URLQueryItem(name: "code_challenge_method", value: configuration.pkceCodeChallengeMethod.rawValue))
        }
        
        // Add resource parameter for MCP (RFC 8707 Resource Indicators)
        if let resourceIndicator = configuration.resourceIndicator {
            queryItems.append(URLQueryItem(name: "resource", value: resourceIndicator))
        }
        
        // Add additional parameters
        if let additionalParams = configuration.additionalParameters {
            for (key, value) in additionalParams {
                queryItems.append(URLQueryItem(name: key, value: value))
            }
        }
        
        components?.queryItems = queryItems
        
        guard let authorizationURL = components?.url else {
            throw OAuthError.invalidAuthorizationURL
        }
        
        return authorizationURL
    }
    
    /// Exchange authorization code for tokens using OAuth 2.1 with PKCE
    public func exchangeAuthorizationCode(
        code: String,
        pkceState: PKCEState,
        receivedState: String? = nil,
        identifier: String = "default"
    ) async throws -> OAuthToken {
        // Verify state parameter to prevent CSRF attacks
        if let receivedState = receivedState {
            guard receivedState == pkceState.state else {
                throw OAuthError.stateMismatch
            }
        }
        
        guard let redirectURI = configuration.redirectURI else {
            throw OAuthError.redirectURIRequired
        }
        
        logger.info("Exchanging authorization code for tokens")
        
        var request = URLRequest(url: configuration.tokenEndpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        var parameters = [
            "grant_type": "authorization_code",
            "code": code,
            "client_id": configuration.clientId,
            "redirect_uri": redirectURI.absoluteString
        ]
        
        // Add client secret for confidential clients
        if configuration.clientType == .confidential, let clientSecret = configuration.clientSecret {
            parameters["client_secret"] = clientSecret
        }
        
        // Add PKCE code verifier if enabled
        if configuration.usePKCE {
            parameters["code_verifier"] = pkceState.codeVerifier
        }
        
        // Add resource parameter for MCP (RFC 8707 Resource Indicators) 
        if let resourceIndicator = configuration.resourceIndicator {
            parameters["resource"] = resourceIndicator
        }
        
        // Add additional parameters
        if let additionalParams = configuration.additionalParameters {
            for (key, value) in additionalParams {
                parameters[key] = value
            }
        }
        
        request.httpBody = formURLEncode(parameters).data(using: .utf8)
        
        let token = try await performTokenRequest(request)
        
        // Store and cache the token
        try await tokenStorage.store(token: token, for: identifier)
        currentToken = token
        
        logger.info("Authorization code exchange successful")
        return token
    }
    
    /// Get a valid access token, refreshing if necessary
    public func getValidToken(for identifier: String = "default") async throws -> OAuthToken {
        // If we have a cached token and it's not expired, return it
        if let token = currentToken, !token.isExpired {
            return token
        }
        
        // If there's already a refresh in progress, wait for it
        if let refreshTask = refreshTask {
            return try await refreshTask.value
        }
        
        // Try to load token from storage
        if let storedToken = try await tokenStorage.retrieve(for: identifier) {
            if !storedToken.isExpired {
                currentToken = storedToken
                return storedToken
            }
            
            // Token is expired, try to refresh it
            if storedToken.refreshToken != nil {
                return try await refreshToken(storedToken, identifier: identifier)
            }
        }
        
        // No valid token available, need to authenticate
        throw OAuthError.authenticationRequired
    }
    
    /// Perform client credentials flow authentication (for confidential clients only)
    public func authenticateWithClientCredentials(identifier: String = "default") async throws -> OAuthToken {
        // OAuth 2.1: Client credentials flow is only for confidential clients
        guard configuration.clientType == .confidential else {
            throw OAuthError.clientCredentialsNotAllowedForPublicClients
        }
        
        guard let clientSecret = configuration.clientSecret else {
            throw OAuthError.clientSecretRequired
        }
        
        logger.info("Performing client credentials authentication")
        
        var request = URLRequest(url: configuration.tokenEndpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        var parameters = [
            "grant_type": "client_credentials",
            "client_id": configuration.clientId,
            "client_secret": clientSecret
        ]
        
        if !configuration.scopes.isEmpty {
            parameters["scope"] = configuration.scopes.joined(separator: " ")
        }
        
        // Add resource parameter for MCP (RFC 8707 Resource Indicators)
        if let resourceIndicator = configuration.resourceIndicator {
            parameters["resource"] = resourceIndicator
        }
        
        // Add additional parameters
        if let additionalParams = configuration.additionalParameters {
            for (key, value) in additionalParams {
                parameters[key] = value
            }
        }
        
        request.httpBody = formURLEncode(parameters).data(using: .utf8)
        
        let token = try await performTokenRequest(request)
        
        // Store and cache the token
        try await tokenStorage.store(token: token, for: identifier)
        currentToken = token
        
        logger.info("Client credentials authentication successful")
        return token
    }
    
    /// Refresh an expired token using its refresh token
    public func refreshToken(_ token: OAuthToken, identifier: String = "default") async throws -> OAuthToken {
        // Prevent concurrent refresh attempts
        if let existingTask = refreshTask {
            return try await existingTask.value
        }
        
        guard let refreshToken = token.refreshToken else {
            throw OAuthError.refreshTokenNotAvailable
        }
        
        logger.info("Refreshing access token")
        
        let task = Task<OAuthToken, Swift.Error> {
            defer { refreshTask = nil }
            
            var request = URLRequest(url: configuration.tokenEndpoint)
            request.httpMethod = "POST"
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            
            var parameters = [
                "grant_type": "refresh_token",
                "refresh_token": refreshToken,
                "client_id": configuration.clientId
            ]
            
            // Add client secret for confidential clients
            if configuration.clientType == .confidential, let clientSecret = configuration.clientSecret {
                parameters["client_secret"] = clientSecret
            }
            
            // Add resource parameter for MCP token refresh (RFC 8707 Resource Indicators)
            if let resourceIndicator = configuration.resourceIndicator {
                parameters["resource"] = resourceIndicator
            }
            
            request.httpBody = formURLEncode(parameters).data(using: .utf8)
            
            let newToken = try await performTokenRequest(request)
            
            // Store and cache the new token
            try await tokenStorage.store(token: newToken, for: identifier)
            currentToken = newToken
            
            logger.info("Token refresh successful")
            return newToken
        }
        
        refreshTask = task
        return try await task.value
    }
    
    /// Revoke a token
    public func revokeToken(_ token: OAuthToken, identifier: String = "default") async throws {
        logger.info("Revoking access token")
        
        // Clear cached token
        if currentToken?.accessToken == token.accessToken {
            currentToken = nil
        }
        
        // Remove from storage
        try await tokenStorage.delete(for: identifier)
        
        // If the server supports token revocation endpoint, call it
        if let revocationEndpoint = configuration.revocationEndpoint {
            do {
                try await performTokenRevocation(token: token, endpoint: revocationEndpoint)
                logger.info("Token revoked from server")
            } catch {
                logger.warning("Failed to revoke token from server", metadata: [
                    "error": "\(error.localizedDescription)"
                ])
                // Don't throw here as token was already removed from local storage
            }
        } else {
            logger.info("Token revoked locally (no revocation endpoint configured)")
        }
    }
    
    // MARK: - MCP Authorization Server Discovery
    
    /// Attempt authorization server discovery using MCP priority order
    /// Tries OAuth 2.0 Authorization Server Metadata and OpenID Connect Discovery endpoints
    public func discoverAuthorizationServerMetadata(from issuerURL: URL) async throws -> OAuthDiscoveryDocument {
        logger.info("Attempting MCP authorization server discovery", metadata: ["issuer": "\(issuerURL.absoluteString)"])
        
        let discoveryURLs = buildMCPDiscoveryURLs(from: issuerURL)
        
        for (index, discoveryURL) in discoveryURLs.enumerated() {
            logger.debug("Trying discovery endpoint \(index + 1)/\(discoveryURLs.count)", metadata: ["url": "\(discoveryURL.absoluteString)"])
            
            do {
                let document = try await fetchDiscoveryDocument(from: discoveryURL)
                logger.info("Successfully discovered authorization server metadata", metadata: ["endpoint": "\(discoveryURL.absoluteString)"])
                return document
            } catch {
                logger.debug("Discovery attempt \(index + 1) failed", metadata: ["url": "\(discoveryURL.absoluteString)", "error": "\(error.localizedDescription)"])
                
                // If this is the last attempt, throw the error
                if index == discoveryURLs.count - 1 {
                    throw error
                }
            }
        }
        
        throw OAuthError.invalidDiscoveryDocument("No valid discovery endpoints found")
    }
    
    /// Build discovery URLs according to MCP specification priority order
    private func buildMCPDiscoveryURLs(from issuerURL: URL) -> [URL] {
        var discoveryURLs: [URL] = []
        
        let pathComponents = issuerURL.pathComponents.filter { $0 != "/" }
        let hasPathComponents = !pathComponents.isEmpty
        
        if hasPathComponents {
            // For issuer URLs with path components (e.g., https://auth.example.com/tenant1)
            let pathString = pathComponents.joined(separator: "/")
            
            // Priority 1: OAuth 2.0 Authorization Server Metadata with path insertion
            if let oauthPathInsertionURL = URL(string: "\(issuerURL.scheme!)://\(issuerURL.host!)\(issuerURL.port.map { ":\($0)" } ?? "")/.well-known/oauth-authorization-server/\(pathString)") {
                discoveryURLs.append(oauthPathInsertionURL)
            }
            
            // Priority 2: OpenID Connect Discovery 1.0 with path insertion
            if let oidcPathInsertionURL = URL(string: "\(issuerURL.scheme!)://\(issuerURL.host!)\(issuerURL.port.map { ":\($0)" } ?? "")/.well-known/openid-configuration/\(pathString)") {
                discoveryURLs.append(oidcPathInsertionURL)
            }
            
            // Priority 3: OpenID Connect Discovery 1.0 path appending
            if let oidcPathAppendingURL = URL(string: "\(issuerURL.absoluteString)/.well-known/openid-configuration") {
                discoveryURLs.append(oidcPathAppendingURL)
            }
        } else {
            // For issuer URLs without path components (e.g., https://auth.example.com)
            
            // Priority 1: OAuth 2.0 Authorization Server Metadata
            if let oauthURL = URL(string: "\(issuerURL.absoluteString)/.well-known/oauth-authorization-server") {
                discoveryURLs.append(oauthURL)
            }
            
            // Priority 2: OpenID Connect Discovery 1.0
            if let oidcURL = URL(string: "\(issuerURL.absoluteString)/.well-known/openid-configuration") {
                discoveryURLs.append(oidcURL)
            }
        }
        
        return discoveryURLs
    }
    
    /// Parse WWW-Authenticate header for OAuth 2.0 Protected Resource Metadata URL
    public func parseWWWAuthenticateHeader(_ headerValue: String) throws -> URL? {
        // Parse WWW-Authenticate header as per RFC 9728 Section 5.1
        // Example: Bearer realm="example", resource_metadata="https://server.example.com/.well-known/oauth-protected-resource"
        
        let bearerPrefix = "Bearer "
        guard headerValue.hasPrefix(bearerPrefix) else {
            throw OAuthError.invalidWWWAuthenticateHeader("Not a Bearer challenge")
        }
        
        let parameters = String(headerValue.dropFirst(bearerPrefix.count))
        let components = parameters.components(separatedBy: ", ")
        
        for component in components {
            let keyValue = component.components(separatedBy: "=")
            if keyValue.count == 2 && keyValue[0] == "resource_metadata" {
                let urlString = keyValue[1].trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                return URL(string: urlString)
            }
        }
        
        return nil
    }
    
    /// Fetch OAuth 2.0 Protected Resource Metadata (RFC 9728)
    public func fetchProtectedResourceMetadata(from metadataURL: URL) async throws -> ProtectedResourceMetadata {
        logger.info("Fetching protected resource metadata", metadata: ["url": "\(metadataURL.absoluteString)"])
        
        var request = URLRequest(url: metadataURL)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        
        let (data, response) = try await urlSession.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuthError.invalidResponse
        }
        
        guard 200..<300 ~= httpResponse.statusCode else {
            let errorBody = String(data: data, encoding: .utf8) ?? "Unknown error"
            logger.error("Protected resource metadata request failed", metadata: [
                "statusCode": "\(httpResponse.statusCode)",
                "error": "\(errorBody)"
            ])
            throw OAuthError.protectedResourceMetadataFailed(httpResponse.statusCode, errorBody)
        }
        
        do {
            let metadata = try JSONDecoder().decode(ProtectedResourceMetadata.self, from: data)
            logger.info("Successfully fetched protected resource metadata")
            return metadata
        } catch {
            logger.error("Failed to decode protected resource metadata", metadata: ["error": "\(error)"])
            throw OAuthError.invalidProtectedResourceMetadata(error.localizedDescription)
        }
    }
    
    /// Validate PKCE support in authorization server metadata (MCP requirement)
    public func validatePKCESupport(in discoveryDocument: OAuthDiscoveryDocument) throws {
        guard let supportedMethods = discoveryDocument.codeChallengeMethodsSupported else {
            throw OAuthError.pkceNotSupported("Authorization server does not advertise PKCE support")
        }
        
        // MCP requires PKCE support verification
        if supportedMethods.isEmpty {
            throw OAuthError.pkceNotSupported("Authorization server advertises empty PKCE methods")
        }
        
        logger.info("PKCE support validated", metadata: ["methods": "\(supportedMethods.joined(separator: ", "))"])
    }
    
    // MARK: - OAuth 2.0 Dynamic Client Registration (RFC 7591)
    
    /// Fetch OAuth 2.0 Authorization Server Metadata (RFC 8414)
    public func fetchDiscoveryDocument(from discoveryURL: URL) async throws -> OAuthDiscoveryDocument {
        logger.info("Fetching OAuth discovery document", metadata: ["url": "\(discoveryURL.absoluteString)"])
        
        var request = URLRequest(url: discoveryURL)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        
        let (data, response) = try await urlSession.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuthError.invalidResponse
        }
        
        guard 200..<300 ~= httpResponse.statusCode else {
            let errorBody = String(data: data, encoding: .utf8) ?? "Unknown error"
            logger.error("Discovery document request failed", metadata: [
                "statusCode": "\(httpResponse.statusCode)",
                "error": "\(errorBody)"
            ])
            throw OAuthError.clientRegistrationFailed(httpResponse.statusCode, errorBody)
        }
        
        do {
            let discoveryDocument = try JSONDecoder().decode(OAuthDiscoveryDocument.self, from: data)
            logger.info("Successfully fetched discovery document")
            return discoveryDocument
        } catch {
            logger.error("Failed to decode discovery document", metadata: ["error": "\(error)"])
            throw OAuthError.invalidDiscoveryDocument(error.localizedDescription)
        }
    }
    
    /// Register a new OAuth client dynamically using RFC 7591
    public func registerClient(
        registrationEndpoint: URL,
        clientName: String,
        redirectURIs: [URL],
        grantTypes: [String] = ["authorization_code"],
        responseTypes: [String] = ["code"],
        scopes: [String]? = nil,
        tokenEndpointAuthMethod: String = "none",
        softwareId: String? = nil,
        softwareVersion: String? = nil
    ) async throws -> ClientRegistrationResponse {
        logger.info("Registering OAuth client dynamically", metadata: [
            "endpoint": "\(registrationEndpoint.absoluteString)",
            "clientName": "\(clientName)"
        ])
        
        var request = URLRequest(url: registrationEndpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        
        var registrationRequest: [String: Any] = [
            "client_name": clientName,
            "redirect_uris": redirectURIs.map { $0.absoluteString },
            "grant_types": grantTypes,
            "response_types": responseTypes,
            "token_endpoint_auth_method": tokenEndpointAuthMethod
        ]
        
        if let scopes = scopes {
            registrationRequest["scope"] = scopes.joined(separator: " ")
        }
        
        if let softwareId = softwareId {
            registrationRequest["software_id"] = softwareId
        }
        
        if let softwareVersion = softwareVersion {
            registrationRequest["software_version"] = softwareVersion
        }
        
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: registrationRequest)
        } catch {
            throw OAuthError.invalidClientRegistrationResponse(error.localizedDescription)
        }
        
        let (data, response) = try await urlSession.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuthError.invalidResponse
        }
        
        guard 200..<300 ~= httpResponse.statusCode else {
            let errorBody = String(data: data, encoding: .utf8) ?? "Unknown error"
            logger.error("Client registration failed", metadata: [
                "statusCode": "\(httpResponse.statusCode)",
                "error": "\(errorBody)"
            ])
            throw OAuthError.clientRegistrationFailed(httpResponse.statusCode, errorBody)
        }
        
        do {
            let registrationResponse = try JSONDecoder().decode(ClientRegistrationResponse.self, from: data)
            logger.info("Client registration successful", metadata: [
                "clientId": "\(registrationResponse.clientId)"
            ])
            return registrationResponse
        } catch {
            logger.error("Failed to decode client registration response", metadata: ["error": "\(error)"])
            throw OAuthError.invalidClientRegistrationResponse(error.localizedDescription)
        }
    }
    
    /// Perform OAuth discovery and dynamic client registration in one step
    public func setupOAuthWithDiscovery(
        discoveryURL: URL,
        clientName: String,
        redirectURIs: [URL],
        scopes: [String],
        isPublicClient: Bool = true
    ) async throws -> OAuthConfiguration {
        logger.info("Setting up OAuth with discovery and dynamic registration")
        
        // 1. Fetch discovery document
        let discovery = try await fetchDiscoveryDocument(from: discoveryURL)
        
        // 2. Register client if registration endpoint exists
        guard let registrationEndpoint = discovery.registrationEndpoint else {
            throw OAuthError.registrationEndpointNotFound
        }
        
        let registration = try await registerClient(
            registrationEndpoint: registrationEndpoint,
            clientName: clientName,
            redirectURIs: redirectURIs,
            scopes: scopes,
            tokenEndpointAuthMethod: isPublicClient ? "none" : "client_secret_post"
        )
        
        // 3. Create configuration from registration
        return try OAuthConfiguration.fromDynamicRegistration(
            authorizationEndpoint: discovery.authorizationEndpoint,
            tokenEndpoint: discovery.tokenEndpoint,
            revocationEndpoint: discovery.revocationEndpoint,
            registrationResponse: registration,
            scopes: scopes
        )
    }
    
    // MARK: - Private Methods
    
    /// Generate a cryptographically secure code verifier for PKCE
    private func generateCodeVerifier() -> String {
        let allowedCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        let length = 128 // RFC 7636 recommends 43-128 characters
        
        var codeVerifier = ""
        for _ in 0..<length {
            let randomIndex = Int.random(in: 0..<allowedCharacters.count)
            let character = allowedCharacters[allowedCharacters.index(allowedCharacters.startIndex, offsetBy: randomIndex)]
            codeVerifier.append(character)
        }
        
        return codeVerifier
    }
    
    /// Generate code challenge from code verifier using specified method
    private func generateCodeChallenge(from codeVerifier: String, method: PKCECodeChallengeMethod) -> String {
        switch method {
        case .plain:
            return codeVerifier
        case .S256:
            #if canImport(CryptoKit) || canImport(CommonCrypto)
            return sha256Base64URL(codeVerifier)
            #else
            // Fallback to plain method when crypto libraries are not available
            logger.warning("SHA256 hashing not available, falling back to plain PKCE method")
            return codeVerifier
            #endif
        }
    }
    
    #if canImport(CryptoKit) || canImport(CommonCrypto)
    /// Generate SHA256 hash and base64URL encode (compatible with all platforms)
    private func sha256Base64URL(_ input: String) -> String {
        let data = Data(input.utf8)
        
        #if canImport(CryptoKit)
        let digest = SHA256.hash(data: data)
        return Data(digest).base64URLEncodedString()
        #elseif canImport(CommonCrypto)
        // Fallback implementation for platforms with CommonCrypto
        let digest = sha256Fallback(data)
        return digest.base64URLEncodedString()
        #endif
    }
    #endif
    
    #if canImport(CommonCrypto) && !canImport(CryptoKit)
    /// Fallback SHA256 implementation for platforms with CommonCrypto
    private func sha256Fallback(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
    #endif
    
    /// Generate a cryptographically secure state parameter for CSRF protection
    private func generateState() -> String {
        let bytes = (0..<32).map { _ in UInt8.random(in: 0...255) }
        return Data(bytes).base64URLEncodedString()
    }
    
    // MARK: - Private Methods
    
    private func performTokenRequest(_ request: URLRequest) async throws -> OAuthToken {
        let (data, response) = try await urlSession.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuthError.invalidResponse
        }
        
        guard 200..<300 ~= httpResponse.statusCode else {
            let errorBody = String(data: data, encoding: .utf8) ?? "Unknown error"
            // Sanitize error body for logging to prevent sensitive information leakage
            let sanitizedErrorBody: String
            if let errorData = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let error = errorData["error"] as? String {
                sanitizedErrorBody = error
            } else {
                sanitizedErrorBody = "HTTP \(httpResponse.statusCode)"
            }
            
            logger.error("Token request failed", metadata: [
                "statusCode": "\(httpResponse.statusCode)",
                "error": "\(sanitizedErrorBody)"
            ])
            throw OAuthError.tokenRequestFailed(httpResponse.statusCode, errorBody)
        }
        
        do {
            let tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
            return OAuthToken(
                accessToken: tokenResponse.access_token,
                tokenType: tokenResponse.token_type ?? "Bearer",
                expiresIn: tokenResponse.expires_in,
                refreshToken: tokenResponse.refresh_token,
                scope: tokenResponse.scope,
                issuedAt: Date()
            )
        } catch {
            logger.error("Failed to decode token response", metadata: ["error": "\(error)"])
            throw OAuthError.invalidTokenResponse("Failed to decode token response")
        }
    }
    
    private func formURLEncode(_ parameters: [String: String]) -> String {
        return parameters
            .map { key, value in
                let encodedKey = key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? key
                let encodedValue = value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value
                return "\(encodedKey)=\(encodedValue)"
            }
            .joined(separator: "&")
    }
    
    private func performTokenRevocation(token: OAuthToken, endpoint: URL) async throws {
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        var parameters: [String: String] = [
            "token": token.accessToken,
            "token_type_hint": "access_token"
        ]
        
        // Add client authentication if available
        if let clientSecret = configuration.clientSecret {
            parameters["client_id"] = configuration.clientId
            parameters["client_secret"] = clientSecret
        } else {
            parameters["client_id"] = configuration.clientId
        }
        
        request.httpBody = formURLEncode(parameters).data(using: .utf8)
        
        let (_, response) = try await urlSession.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuthError.invalidResponse
        }
        
        // RFC 7009: The authorization server responds with HTTP status code 200 if the
        // revocation is successful or if the client submitted an invalid token
        guard 200..<300 ~= httpResponse.statusCode else {
            throw OAuthError.tokenRequestFailed(httpResponse.statusCode, "Revocation failed")
        }
    }
}

// MARK: - Supporting Types

/// OAuth token response from server
private struct TokenResponse: Codable {
    let access_token: String
    let token_type: String?
    let expires_in: Int?
    let refresh_token: String?
    let scope: String?
}

/// OAuth 2.0 Discovery Document as per RFC 8414
public struct OAuthDiscoveryDocument: Codable, Sendable {
    /// The authorization server's issuer identifier
    public let issuer: String?
    
    /// URL of the authorization endpoint
    public let authorizationEndpoint: URL
    
    /// URL of the token endpoint
    public let tokenEndpoint: URL
    
    /// URL of the registration endpoint (optional, used for dynamic client registration)
    public let registrationEndpoint: URL?
    
    /// URL of the revocation endpoint (optional)
    public let revocationEndpoint: URL?
    
    /// JSON array of supported scopes
    public let scopesSupported: [String]?
    
    /// JSON array of supported response types
    public let responseTypesSupported: [String]?
    
    /// JSON array of supported grant types
    public let grantTypesSupported: [String]?
    
    /// JSON array of supported code challenge methods for PKCE
    public let codeChallengeMethodsSupported: [String]?
    
    enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case registrationEndpoint = "registration_endpoint"
        case revocationEndpoint = "revocation_endpoint"
        case scopesSupported = "scopes_supported"
        case responseTypesSupported = "response_types_supported"
        case grantTypesSupported = "grant_types_supported"
        case codeChallengeMethodsSupported = "code_challenge_methods_supported"
    }
}

/// OAuth 2.0 Protected Resource Metadata as per RFC 9728
public struct ProtectedResourceMetadata: Codable, Sendable {
    /// URI of the resource server
    public let resource: String?
    
    /// Array of authorization server URIs
    public let authorizationServers: [String]
    
    /// Array of supported scopes
    public let scopesSupported: [String]?
    
    /// Array of supported bearer token methods
    public let bearerMethodsSupported: [String]?
    
    /// Resource server metadata extensions
    public let resourceDocumentation: String?
    
    enum CodingKeys: String, CodingKey {
        case resource
        case authorizationServers = "authorization_servers"
        case scopesSupported = "scopes_supported"
        case bearerMethodsSupported = "bearer_methods_supported"
        case resourceDocumentation = "resource_documentation"
    }
}

/// OAuth 2.0 Dynamic Client Registration Response as per RFC 7591
public struct ClientRegistrationResponse: Codable, Sendable {
    /// The client identifier issued by the authorization server
    public let clientId: String
    
    /// The client secret issued by the authorization server (optional for public clients)
    public let clientSecret: String?
    
    /// The time at which the client identifier was issued
    public let clientIdIssuedAt: Int?
    
    /// The time at which the client secret will expire (if issued)
    public let clientSecretExpiresAt: Int?
    
    /// Array of redirect URIs for the client
    public let redirectUris: [String]
    
    /// Array of OAuth grant types that the client can use
    public let grantTypes: [String]
    
    /// Array of OAuth response types that the client can use
    public let responseTypes: [String]
    
    /// Space-separated list of scopes the client can request
    public let scopes: String?
    
    /// Client name for human display
    public let clientName: String?
    
    /// URL of the client's software version or software statement
    public let softwareId: String?
    
    /// Version of the client software
    public let softwareVersion: String?
    
    enum CodingKeys: String, CodingKey {
        case clientId = "client_id"
        case clientSecret = "client_secret"
        case clientIdIssuedAt = "client_id_issued_at"
        case clientSecretExpiresAt = "client_secret_expires_at"
        case redirectUris = "redirect_uris"
        case grantTypes = "grant_types"
        case responseTypes = "response_types"
        case scopes = "scope"
        case clientName = "client_name"
        case softwareId = "software_id"
        case softwareVersion = "software_version"
    }
}

/// OAuth-related errors
public enum OAuthError: Swift.Error, LocalizedError, Equatable {
    case authenticationRequired
    case clientSecretRequired
    case clientCredentialsNotAllowedForPublicClients
    case redirectURIRequired
    case invalidAuthorizationURL
    case stateMismatch
    case refreshTokenNotAvailable
    case invalidResponse
    case tokenRequestFailed(Int, String)
    case invalidTokenResponse(String)
    case registrationEndpointNotFound
    case clientRegistrationFailed(Int, String)
    case invalidDiscoveryDocument(String)
    case invalidClientRegistrationResponse(String)
    case invalidConfiguration(String)
    // MCP-specific errors
    case invalidWWWAuthenticateHeader(String)
    case protectedResourceMetadataFailed(Int, String)
    case invalidProtectedResourceMetadata(String)
    case pkceNotSupported(String)
    case authorizationServerNotFound
    
    public var errorDescription: String? {
        switch self {
        case .authenticationRequired:
            return "Authentication is required"
        case .clientSecretRequired:
            return "Client secret is required for this OAuth flow"
        case .clientCredentialsNotAllowedForPublicClients:
            return "OAuth 2.1: Client credentials flow is not allowed for public clients"
        case .redirectURIRequired:
            return "Redirect URI is required for authorization code flow"
        case .invalidAuthorizationURL:
            return "Could not generate valid authorization URL"
        case .stateMismatch:
            return "State parameter mismatch - possible CSRF attack"
        case .refreshTokenNotAvailable:
            return "No refresh token available for token refresh"
        case .invalidResponse:
            return "Invalid response from OAuth server"
        case .tokenRequestFailed(let statusCode, let body):
            return "Token request failed with status \(statusCode): \(body)"
        case .invalidTokenResponse(let error):
            return "Invalid token response: \(error)"
        case .registrationEndpointNotFound:
            return "Registration endpoint not found in discovery document"
        case .clientRegistrationFailed(let statusCode, let body):
            return "Client registration failed with status \(statusCode): \(body)"
        case .invalidDiscoveryDocument(let error):
            return "Invalid discovery document: \(error)"
        case .invalidClientRegistrationResponse(let error):
            return "Invalid client registration response: \(error)"
        case .invalidConfiguration(let error):
            return "Invalid OAuth configuration: \(error)"
        // MCP-specific error descriptions
        case .invalidWWWAuthenticateHeader(let error):
            return "Invalid WWW-Authenticate header: \(error)"
        case .protectedResourceMetadataFailed(let statusCode, let body):
            return "Protected resource metadata request failed with status \(statusCode): \(body)"
        case .invalidProtectedResourceMetadata(let error):
            return "Invalid protected resource metadata: \(error)"
        case .pkceNotSupported(let error):
            return "PKCE not supported: \(error)"
        case .authorizationServerNotFound:
            return "No authorization server found in protected resource metadata"
        }
    }
}

// MARK: - Extensions

extension Data {
    /// Base64URL encoding without padding as per RFC 7636
    func base64URLEncodedString() -> String {
        return self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}