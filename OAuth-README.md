# OAuth 2.0/2.1 Support for MCP Swift SDK

The MCP Swift SDK includes comprehensive OAuth 2.0 and OAuth 2.1 support for remote client transports, enabling secure authentication with OAuth-protected MCP servers.

## Features

### 🔐 OAuth 2.0/2.1 Flows
- **Client Credentials Flow**: Server-to-server authentication (confidential clients)
- **Authorization Code Flow**: User-based authentication with PKCE support
- **Dynamic Client Registration**: Automatic client registration per RFC 7591
- **OAuth 2.1 Compliance**: Mandatory PKCE for public clients per specification

### 🛡️ PKCE (Proof Key for Code Exchange)
- **Automatic PKCE**: Required for public clients, optional for confidential clients
- **Secure Code Generation**: Cryptographically secure code verifiers and challenges
- **Platform Compatibility**: SHA256 with fallback to plain method when crypto unavailable

### 🎫 Advanced Token Management
- **Automatic Refresh**: Tokens are refreshed automatically when expired (60-second buffer)
- **Thread-Safe Operations**: Concurrent token refresh requests are deduplicated
- **Expiration Handling**: Built-in token expiration checking and validation
- **JSON Serialization**: Tokens can be persisted and restored across app sessions

### 💾 Platform-Specific Secure Storage
- **Apple Platforms**: Keychain storage with access group support
- **Linux**: Encrypted file-based storage with filename sanitization  
- **Testing**: In-memory storage for unit tests and development

### 🏭 Provider Presets
- **GitHub**: OAuth 2.1 compliant with public/confidential client support
- **Google**: OAuth 2.0/2.1 endpoints with PKCE support
- **Microsoft**: Azure AD v2.0 with tenant configuration
- **Custom Providers**: Generic factory methods for any OAuth 2.1 provider
- **Dynamic Registration**: Automatic client registration with any compliant server

## Quick Start

### OAuth 2.1 Public Client (Recommended)

For mobile apps, SPAs, and other public clients that cannot securely store secrets:

```swift
import MCP

// OAuth 2.1 public client with mandatory PKCE
let oauthConfig = OAuthConfiguration.publicClient(
    authorizationEndpoint: URL(string: "https://oauth.provider.com/authorize")!,
    tokenEndpoint: URL(string: "https://oauth.provider.com/token")!,
    clientId: "your-public-client-id",
    scopes: ["read", "write"],
    redirectURI: URL(string: "yourapp://oauth/redirect")!
)

// Create OAuth-enabled transport
let transport = OAuthHTTPClientTransport(
    endpoint: URL(string: "https://your-mcp-server.com")!,
    oauthConfig: oauthConfig
)

// Generate PKCE state and authorization URL
let authenticator = OAuthAuthenticator(configuration: oauthConfig)
let pkceState = await authenticator.generatePKCEState()
let authURL = try await authenticator.generateAuthorizationURL(pkceState: pkceState)

// Direct user to authURL, then exchange the received code:
let token = try await authenticator.exchangeAuthorizationCode(
    code: receivedAuthCode,
    pkceState: pkceState,
    receivedState: receivedState
)

// Use with MCP client - OAuth is handled transparently
let client = Client(name: "MyApp", version: "1.0.0")
try await client.connect(transport: transport)
```

### OAuth 2.1 Provider Presets

#### GitHub Public Client
```swift
let githubConfig = OAuthConfiguration.github(
    clientId: "your-github-client-id",
    scopes: ["repo", "read:user"],
    redirectURI: URL(string: "yourapp://github/callback")!
)
```

#### Google Public Client  
```swift
let googleConfig = OAuthConfiguration.google(
    clientId: "your-google-client-id.apps.googleusercontent.com",
    scopes: ["openid", "profile", "email"],
    redirectURI: URL(string: "yourapp://google/callback")!
)
```

#### Microsoft Public Client
```swift
let microsoftConfig = OAuthConfiguration.microsoft(
    clientId: "your-azure-client-id",
    tenantId: "your-tenant-id", // or "common" for multi-tenant
    scopes: ["User.Read", "Mail.Read"],
    redirectURI: URL(string: "yourapp://microsoft/callback")!
)
```

### OAuth 2.0 Confidential Client

For server applications that can securely store client secrets:

```swift
// Traditional OAuth 2.0 with client secret
let oauthConfig = OAuthConfiguration.confidentialClient(
    authorizationEndpoint: URL(string: "https://oauth.provider.com/authorize")!,
    tokenEndpoint: URL(string: "https://oauth.provider.com/token")!,
    clientId: "your-confidential-client-id",
    clientSecret: "your-client-secret",
    scopes: ["api:read", "api:write"],
    usePKCE: true // Optional for confidential clients
)
```

## OAuth 2.0 Dynamic Client Registration

The SDK supports OAuth 2.0 Dynamic Client Registration (RFC 7591), allowing applications to automatically register as OAuth clients at runtime, eliminating the need for hardcoded `client_id` values.

### Discovery + Registration Flow

For the complete automated flow:

```swift
let authenticator = OAuthAuthenticator(
    configuration: try OAuthConfiguration(
        authorizationEndpoint: URL(string: "https://oauth.provider.com/authorize")!,
        tokenEndpoint: URL(string: "https://oauth.provider.com/token")!,
        clientId: "temporary-id", // Will be replaced
        scopes: []
    )
)

// Perform discovery and registration in one step
let config = try await authenticator.setupOAuthWithDiscovery(
    discoveryURL: URL(string: "https://oauth.provider.com/.well-known/oauth-authorization-server")!,
    clientName: "My Dynamic App",
    redirectURIs: [URL(string: "https://myapp.example.com/callback")!],
    scopes: ["read", "write"]
)

// Use the dynamically configured OAuth transport
let transport = OAuthHTTPClientTransport(
    endpoint: URL(string: "https://mcp-server.example.com")!,
    oauthConfig: config
)

let client = Client(name: "MyApp", version: "1.0.0")
try await client.connect(transport: transport)
```

### Manual Registration Steps

For more control over the registration process:

```swift
// 1. Fetch discovery document
let discoveryURL = URL(string: "https://oauth.provider.com/.well-known/oauth-authorization-server")!
let discovery = try await authenticator.fetchDiscoveryDocument(from: discoveryURL)

// 2. Register client if registration endpoint exists
if let registrationEndpoint = discovery.registrationEndpoint {
    let registration = try await authenticator.registerClient(
        registrationEndpoint: registrationEndpoint,
        clientName: "My Dynamic App",
        redirectURIs: [URL(string: "https://myapp.example.com/callback")!],
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        scopes: ["read", "write"],
        softwareId: "myapp-v1",
        softwareVersion: "1.0.0"
    )
    
    // 3. Create configuration from registration
    let config = try OAuthConfiguration.fromDynamicRegistration(
        authorizationEndpoint: discovery.authorizationEndpoint,
        tokenEndpoint: discovery.tokenEndpoint,
        revocationEndpoint: discovery.revocationEndpoint,
        registrationResponse: registration,
        scopes: ["read", "write"]
    )
}
```

### Discovery Endpoints

Common discovery endpoint patterns:

```swift
// OAuth 2.0 Authorization Server Metadata (RFC 8414)
let oauthDiscovery = URL(string: "https://oauth.provider.com/.well-known/oauth-authorization-server")!

// OpenID Connect Discovery
let oidcDiscovery = URL(string: "https://oauth.provider.com/.well-known/openid_configuration")!
```

### Registration Request Parameters

The `registerClient` method supports all standard RFC 7591 parameters:

```swift
let registration = try await authenticator.registerClient(
    registrationEndpoint: registrationEndpoint,
    clientName: "My App",                    // Human-readable name
    redirectURIs: [callbackURL],             // Required redirect URIs
    grantTypes: ["authorization_code"],      // OAuth grant types
    responseTypes: ["code"],                 // OAuth response types  
    scopes: ["read", "write"],              // Requested scopes
    softwareId: "myapp-v1",                 // Software identifier
    softwareVersion: "1.0.0"                // Software version
)
```

### Registration Response

The server returns a `ClientRegistrationResponse` with the registered client details:

```swift
public struct ClientRegistrationResponse {
    let clientId: String                    // Generated client ID
    let clientSecret: String?               // Client secret (confidential clients)
    let clientIdIssuedAt: Int?             // Issuance timestamp
    let clientSecretExpiresAt: Int?        // Expiration timestamp
    let redirectUris: [String]             // Registered redirect URIs
    let grantTypes: [String]               // Allowed grant types
    let responseTypes: [String]            // Allowed response types
    let scopes: String?                    // Granted scopes
    let clientName: String?                // Client display name
    let softwareId: String?                // Software identifier
    let softwareVersion: String?           // Software version
}
```

### Benefits of Dynamic Registration

- **No hardcoded client credentials**: Each app instance gets unique credentials
- **Better security**: Eliminates shared client secrets across deployments
- **Simplified deployment**: No manual registration step required
- **Unique client tracking**: Each installation can be tracked separately
- **Environment flexibility**: Works across development, staging, and production
- **Standards compliance**: Follows RFC 7591 specification

### Error Handling

Dynamic registration adds several new error cases:

```swift
do {
    let config = try await authenticator.setupOAuthWithDiscovery(...)
} catch OAuthError.registrationEndpointNotFound {
    // Server doesn't support dynamic registration
    // Fall back to static client registration
} catch OAuthError.clientRegistrationFailed(let status, let message) {
    // Registration request failed
    print("Registration failed: \(status) - \(message)")
} catch OAuthError.invalidDiscoveryDocument(let error) {
    // Discovery document parsing failed
    print("Discovery error: \(error)")
} catch {
    // Handle other errors
}
```

### Client Credentials Flow

For server-to-server authentication without user interaction:

```swift
let transport = OAuthHTTPClientTransport.clientCredentials(
    endpoint: URL(string: "https://your-mcp-server.com")!,
    tokenEndpoint: URL(string: "https://oauth.provider.com/token")!,
    clientId: "your-client-id",
    clientSecret: "your-client-secret",
    scopes: ["mcp:read", "mcp:write"]
)

let client = Client(name: "MyApp", version: "1.0.0")
try await client.connect(transport: transport)
```

### Custom OAuth Configuration

```swift
let customConfig = OAuthConfiguration(
    authorizationEndpoint: URL(string: "https://oauth.example.com/authorize")!,
    tokenEndpoint: URL(string: "https://oauth.example.com/token")!,
    clientId: "your-client-id",
    clientSecret: "your-client-secret",
    scopes: ["custom:scope"],
    additionalParameters: ["custom_param": "value"]
)

let transport = OAuthHTTPClientTransport(
    endpoint: URL(string: "https://your-mcp-server.com")!,
    oauthConfig: customConfig
)
```

### Custom Token Storage

```swift
// Use custom token storage implementation
class MyCustomTokenStorage: TokenStorage {
    func store(token: OAuthToken, for identifier: String) async throws {
        // Your custom storage logic
    }
    
    func retrieve(for identifier: String) async throws -> OAuthToken? {
        // Your custom retrieval logic
    }
    
    func delete(for identifier: String) async throws {
        // Your custom deletion logic
    }
}

let transport = OAuthHTTPClientTransport(
    endpoint: serverURL,
    oauthConfig: oauthConfig,
    tokenStorage: MyCustomTokenStorage()
)
```

## Provider Presets

The SDK includes built-in configurations for popular OAuth providers:

### GitHub

```swift
let config = OAuthConfiguration.github(
    clientId: "your-github-client-id",
    clientSecret: "your-github-client-secret",
    scopes: ["repo", "read:user"]
)
```

### Google

```swift
let config = OAuthConfiguration.google(
    clientId: "your-google-client-id",
    clientSecret: "your-google-client-secret",
    scopes: ["openid", "profile", "email"]
)
```

### Microsoft

```swift
let config = OAuthConfiguration.microsoft(
    clientId: "your-microsoft-client-id",
    clientSecret: "your-microsoft-client-secret",
    scopes: ["https://graph.microsoft.com/.default"]
)
```

## Token Storage

The SDK provides platform-appropriate token storage:

- **Apple Platforms**: Secure storage in Keychain
- **Linux**: Encrypted file storage in user's home directory
- **In-Memory**: For testing or temporary scenarios

### Keychain Storage (Apple Platforms)

```swift
#if canImport(Security)
let keychainStorage = KeychainTokenStorage(
    service: "my-app-oauth-tokens",
    accessGroup: "group.myapp.shared" // Optional, for app groups
)
#endif
```

### File Storage (Linux)

```swift
#if os(Linux)
let fileStorage = try FileTokenStorage(
    directory: URL(fileURLWithPath: "/secure/token/directory")
)
#endif
```

## Error Handling

The OAuth transport automatically handles common authentication scenarios:

- **Token Expiration**: Automatically refreshes tokens when they expire
- **Authentication Failures**: Attempts token refresh on 401/403 errors
- **Token Storage**: Handles storage and retrieval errors gracefully

```swift
do {
    try await client.connect(transport: oauthTransport)
} catch OAuthError.authenticationRequired {
    // Need to obtain initial token
} catch OAuthError.clientSecretRequired {
    // Client credentials flow requires client secret
} catch {
    // Handle other errors
}
```

## OAuth 2.1 Compliance

The SDK implements OAuth 2.1 best practices and security requirements:

### 🔒 Public Client Requirements
- **Mandatory PKCE**: OAuth 2.1 requires PKCE for all public clients
- **No Client Secrets**: Public clients cannot use client secrets
- **S256 Code Challenge**: Uses SHA256-based code challenges when available

### 🛡️ Security Enhancements
- **State Parameter**: Automatic CSRF protection with cryptographic state validation
- **Code Verifier**: 128-character cryptographically secure code verifiers
- **Platform Adaptation**: Automatic fallback to plain PKCE when crypto libraries unavailable

### 🔄 Automatic Client Type Detection
```swift
// Automatically detected as public client (no secret)
let publicConfig = OAuthConfiguration.github(
    clientId: "github-client-id",
    scopes: ["repo"]
    // usePKCE automatically set to true
)

// Automatically detected as confidential client (has secret) 
let confidentialConfig = OAuthConfiguration.github(
    clientId: "github-client-id",
    clientSecret: "github-client-secret",
    scopes: ["repo"]
    // usePKCE defaults to false but can be enabled
)
```

### 🚫 OAuth 2.1 Validation
The SDK enforces OAuth 2.1 compliance rules:
- Public clients cannot have client secrets
- Public clients must use PKCE
- Client credentials flow is restricted to confidential clients

### 🔧 Architectural Improvements

Recent improvements to the OAuth transport eliminate common connection issues and improve performance:

#### **Fixed "Transport Not Connected" Error**
The transport now properly handles authenticated requests without creating unnecessary transport instances:

```swift
// Previous implementation had connection issues
// Now fixed with session pooling approach
let transport = OAuthHTTPClientTransport(
    endpoint: URL(string: "https://server.com")!,
    oauthConfig: oauthConfig
)

try await transport.connect()
try await transport.send(data)  // Now works reliably
```

#### **Session Pool Implementation**
```swift
// Internal session pooling (automatically handled)
private var authenticatedSessionPool: [String: URLSession] = [:]

private func getOrCreateAuthenticatedSession(for token: OAuthToken) -> URLSession {
    let sessionKey = token.accessToken
    
    if let existingSession = authenticatedSessionPool[sessionKey] {
        return existingSession  // Reuse existing session
    }
    
    // Create new session only when needed
    let authenticatedSession = URLSession(configuration: configWithAuth)
    authenticatedSessionPool[sessionKey] = authenticatedSession
    return authenticatedSession
}
```

#### **Automatic Cleanup**
Sessions are automatically cleaned up to prevent resource leaks:
- **On Disconnect**: All pooled sessions are invalidated
- **On Token Refresh**: Old sessions are replaced with new ones
- **On Error**: Failed sessions are removed from pool

## Security Considerations

### 🔐 Enhanced Security Features
- **Secure Storage**: Platform-appropriate secure token storage (Keychain/encrypted files)
- **Token Rotation**: Automatic refresh token usage for new access tokens
- **State Validation**: CSRF protection through state parameter verification
- **PKCE Protection**: Code injection attack prevention via PKCE
- **Minimal Scopes**: Request only necessary OAuth scopes
- **HTTPS Enforcement**: All OAuth communication uses secure connections
- **Thread Safety**: Actor-isolated operations for concurrent safety

### 🎯 Platform Compatibility
- **Apple Platforms**: Full CryptoKit support for S256 PKCE
- **Linux**: Automatic fallback to plain PKCE when crypto unavailable
- **Cross-Platform**: Consistent API across all supported platforms

## Performance & Architecture

### 🚀 Session Pooling & Reuse

The OAuth transport implements efficient session pooling to optimize performance and resource usage:

#### **Efficient Session Management**
- **Session Reuse**: Authenticated `URLSession` instances are pooled and reused based on access tokens
- **No Transport Creation**: Eliminates the inefficient pattern of creating new `HTTPClientTransport` instances for each request
- **Memory Efficient**: Automatic cleanup prevents session leaks and resource waste
- **Connection Pooling**: HTTP connections are reused across requests with the same authentication

#### **Architecture Benefits**
```swift
// ✅ Efficient Pattern (Current Implementation)
// Sessions are automatically pooled and reused
let transport = OAuthHTTPClientTransport(
    endpoint: URL(string: "https://server.com")!,
    oauthConfig: oauthConfig
)

// Multiple requests reuse the same authenticated session
try await transport.send(request1)  // Creates session pool entry
try await transport.send(request2)  // Reuses existing session
try await transport.send(request3)  // Reuses existing session
```

#### **Session Lifecycle**
1. **First Request**: Creates new authenticated session and adds to pool
2. **Subsequent Requests**: Reuses session from pool for same access token
3. **Token Refresh**: New session created for new token, old session cleaned up
4. **Disconnect**: All pooled sessions are properly invalidated and cleaned up

#### **Performance Impact**
- **Reduced Latency**: Session reuse eliminates connection setup overhead
- **Lower Memory Usage**: Single session per token instead of per request
- **Better Throughput**: HTTP connection reuse improves request performance
- **Resource Efficiency**: Proper cleanup prevents accumulation of unused sessions

#### **Best Practices**
```swift
// ✅ Good: Reuse the same transport instance
let transport = OAuthHTTPClientTransport(endpoint: serverURL, oauthConfig: config)
try await transport.connect()

for request in requests {
    try await transport.send(request)  // Efficient session reuse
}

await transport.disconnect()  // Proper cleanup

// ❌ Avoid: Creating new transport instances unnecessarily
for request in requests {
    let newTransport = OAuthHTTPClientTransport(endpoint: serverURL, oauthConfig: config)
    try await newTransport.connect()
    try await newTransport.send(request)  // Inefficient - no reuse
    await newTransport.disconnect()
}
```

## Migration from HTTP Transport

OAuth transport is a drop-in replacement for `HTTPClientTransport`:

```swift
// Before
let transport = HTTPClientTransport(
    endpoint: URL(string: "https://server.com")!
)

// After - with OAuth
let transport = OAuthHTTPClientTransport(
    endpoint: URL(string: "https://server.com")!,
    oauthConfig: oauthConfig
)
```

All existing MCP client code continues to work unchanged.