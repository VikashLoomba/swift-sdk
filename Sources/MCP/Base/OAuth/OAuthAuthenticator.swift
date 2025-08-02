import Foundation
import Logging

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Actor responsible for OAuth authentication and token management
public actor OAuthAuthenticator {
    private let configuration: OAuthConfiguration
    private let tokenStorage: TokenStorage
    private let urlSession: URLSession
    private let logger: Logger
    
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
    
    /// Perform client credentials flow authentication
    public func authenticateWithClientCredentials(identifier: String = "default") async throws -> OAuthToken {
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
            
            if let clientSecret = configuration.clientSecret {
                parameters["client_secret"] = clientSecret
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
        
        // TODO: If the server supports token revocation endpoint, call it here
        logger.info("Token revoked")
    }
    
    // MARK: - Private Methods
    
    private func performTokenRequest(_ request: URLRequest) async throws -> OAuthToken {
        let (data, response) = try await urlSession.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuthError.invalidResponse
        }
        
        guard 200..<300 ~= httpResponse.statusCode else {
            let errorBody = String(data: data, encoding: .utf8) ?? "Unknown error"
            logger.error("Token request failed", metadata: [
                "statusCode": "\(httpResponse.statusCode)",
                "body": "\(errorBody)"
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
            throw OAuthError.invalidTokenResponse(error)
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

/// OAuth-related errors
public enum OAuthError: Swift.Error, LocalizedError {
    case authenticationRequired
    case clientSecretRequired
    case refreshTokenNotAvailable
    case invalidResponse
    case tokenRequestFailed(Int, String)
    case invalidTokenResponse(Swift.Error)
    
    public var errorDescription: String? {
        switch self {
        case .authenticationRequired:
            return "Authentication is required"
        case .clientSecretRequired:
            return "Client secret is required for this OAuth flow"
        case .refreshTokenNotAvailable:
            return "No refresh token available for token refresh"
        case .invalidResponse:
            return "Invalid response from OAuth server"
        case .tokenRequestFailed(let statusCode, let body):
            return "Token request failed with status \(statusCode): \(body)"
        case .invalidTokenResponse(let error):
            return "Invalid token response: \(error.localizedDescription)"
        }
    }
}