# OAuth Support for MCP Swift SDK

The MCP Swift SDK now includes comprehensive OAuth 2.0 support for remote client transports, enabling secure authentication with OAuth-protected MCP servers.

## Features

- **OAuth 2.0 Support**: Client credentials and authorization code flows
- **Token Management**: Automatic token refresh, expiration checking, and secure storage
- **Platform Integration**: Keychain storage on Apple platforms, encrypted file storage on Linux
- **Provider Presets**: Built-in configurations for GitHub, Google, and Microsoft
- **Seamless Integration**: Drop-in replacement for existing HTTP transports

## Quick Start

### Basic OAuth Setup

```swift
import MCP

// Configure OAuth for your provider
let oauthConfig = OAuthConfiguration.github(
    clientId: "your-github-client-id",
    clientSecret: "your-github-client-secret",
    scopes: ["repo", "read:user"]
)

// Create OAuth-enabled transport
let transport = OAuthHTTPClientTransport(
    endpoint: URL(string: "https://your-mcp-server.com")!,
    oauthConfig: oauthConfig
)

// Use with MCP client - OAuth is handled transparently
let client = Client(name: "MyApp", version: "1.0.0")
try await client.connect(transport: transport)

// All requests now include OAuth authentication automatically
let tools = try await client.listTools()
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

## Security Considerations

- **Secure Storage**: Tokens are stored securely using platform-appropriate mechanisms
- **Token Rotation**: Refresh tokens are used to obtain new access tokens
- **Minimal Scopes**: Only request the scopes your application needs
- **HTTPS Only**: All OAuth communication uses HTTPS

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