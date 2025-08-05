# OAuth 2.0/2.1 Support for MCP Swift SDK

The MCP Swift SDK includes comprehensive OAuth 2.0 and OAuth 2.1 support for remote client transports, enabling secure authentication with OAuth-protected MCP servers.

## Features

### 🔐 OAuth 2.0/2.1 Flows
- **Client Credentials Flow**: Server-to-server authentication (confidential clients)
- **Authorization Code Flow**: User-based authentication with PKCE support
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