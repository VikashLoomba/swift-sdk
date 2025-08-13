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

### 🔍 MCP OAuth Discovery
- **WWW-Authenticate Header Parsing**: Automatic extraction of OAuth metadata URLs from 401 responses
- **Protected Resource Metadata**: Support for RFC 9728 resource metadata discovery
- **Authorization Server Discovery**: MCP-compliant priority order for discovering OAuth endpoints
- **Resource Indicators**: RFC 8707 support for targeting specific MCP servers

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

## Connecting to OAuth-Protected MCP Servers

This section demonstrates how a public client can connect to an OAuth-protected MCP server using dynamic registration and automatic discovery.

### Complete Flow: Public Client with Dynamic Registration

This example shows the full flow for a mobile app or SPA connecting to an MCP server that requires OAuth authentication:

```swift
import MCP

// Step 1: Create OAuth transport with dynamic discovery - no configuration needed!
let mcpServerURL = URL(string: "https://mcp-server.example.com")!
let transport = OAuthHTTPClientTransport.withDynamicDiscovery(
    endpoint: mcpServerURL
)

// Step 2: Attempt to connect - this will trigger OAuth discovery
let client = Client(name: "MyMobileApp", version: "1.0.0")

do {
    try await client.connect(transport: transport)
} catch {
    // Server returned 401 with WWW-Authenticate header
    // The transport automatically extracted the OAuth metadata URL
    print("Server requires OAuth, proceeding with registration...")
}

// Step 3: Perform dynamic client registration
let oauthConfig = try await transport.performDynamicRegistration(
    clientName: "My Mobile App",
    redirectURIs: [URL(string: "myapp://oauth/callback")!],
    scopes: ["mcp:read", "mcp:write"],
    softwareId: "com.example.myapp",
    softwareVersion: "1.0.0"
)

// Step 4: Perform OAuth authorization flow with PKCE (required for public clients)
// The transport's authenticator now has the registered configuration
let pkceState = await transport.authenticator.generatePKCEState()
let authURL = try await transport.authenticator.generateAuthorizationURL(pkceState: pkceState)

// Step 5: Direct user to authorization URL
// In a real app, you would open this URL in a browser or web view
print("Please authorize at: \(authURL)")
// ... user authorizes and is redirected back with code ...

// Step 6: Exchange authorization code for tokens
let token = try await transport.authenticator.exchangeAuthorizationCode(
    code: "received-auth-code",
    pkceState: pkceState,
    receivedState: "received-state"
)

// Step 7: Connect to MCP server with OAuth tokens
// The transport is now fully configured and authenticated
try await client.connect(transport: transport)

// Now you can use the MCP client normally - all requests are authenticated
let response = try await client.request(...)
```

### Simplified Flow Example

Here's how you could structure a helper class to streamline the OAuth flow:

```swift
import MCP

class MCPOAuthConnector {
    let mcpServerURL = URL(string: "https://mcp-server.example.com")!
    let redirectURI = URL(string: "myapp://oauth/callback")!
    
    func connectToMCPServer() async throws -> Client {
        // Step 1: Try connecting without OAuth first
        let httpTransport = HTTPClientTransport(endpoint: mcpServerURL)
        let client = Client(name: "MyApp", version: "1.0.0")
        
        do {
            try await client.connect(transport: httpTransport)
            return client // Server doesn't require OAuth
        } catch {
            // Server requires OAuth - proceed with discovery
        }
        
        // Step 2: Extract OAuth metadata URL from WWW-Authenticate header
        // Parse error message for resource_metadata URL
        
        // Step 3: Perform dynamic registration and create OAuth transport
        let oauthTransport = try await setupOAuthTransport()
        
        // Step 4: Connect with OAuth
        try await client.connect(transport: oauthTransport)
        return client
    }
    
    private func handleOAuthFlow(transport: OAuthHTTPClientTransport) async throws {
        // Handle dynamic registration, authorization, and token exchange
        // See the complete flow example above for details
    }
}
```

**Note**: The simplified example above shows the concept. The `withDynamicDiscovery` method and `performDynamicRegistration` are now available in the SDK to handle the discovery flow without requiring an initial OAuth configuration.

### Handling MCP OAuth Discovery

The SDK automatically handles the MCP OAuth discovery process:

1. **Initial Request**: Client attempts to connect to MCP server
2. **401 Response**: Server returns 401 with WWW-Authenticate header
3. **Header Parsing**: SDK extracts `resource_metadata` URL from header
4. **Metadata Fetch**: SDK fetches OAuth protected resource metadata
5. **Server Discovery**: SDK discovers authorization server from metadata
6. **Dynamic Registration**: SDK registers client with authorization server
7. **Authorization Flow**: User authorizes the application
8. **Token Exchange**: SDK exchanges code for access tokens
9. **Authenticated Connection**: All subsequent requests include OAuth tokens

### WWW-Authenticate Header Format

MCP servers return OAuth metadata in the WWW-Authenticate header:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="mcp", 
    resource_metadata="https://server.com/.well-known/oauth-protected-resource"
```

The SDK automatically parses this header and uses the `resource_metadata` URL to discover OAuth configuration.

### Protected Resource Metadata

The metadata document at the `resource_metadata` URL contains:

```json
{
    "resource": "https://mcp-server.example.com",
    "authorization_servers": [
        "https://oauth.example.com",
        "https://oauth2.example.com"
    ],
    "scopes_supported": ["mcp:read", "mcp:write", "mcp:admin"],
    "bearer_methods_supported": ["header"]
}
```

### Authorization Server Discovery Priority

For MCP servers, the SDK tries discovery endpoints in this order:

1. **With Path Components** (e.g., `https://auth.example.com/tenant1`):
   - `/.well-known/oauth-authorization-server/tenant1`
   - `/.well-known/openid-configuration/tenant1`
   - `/tenant1/.well-known/openid-configuration`

2. **Without Path Components** (e.g., `https://auth.example.com`):
   - `/.well-known/oauth-authorization-server`
   - `/.well-known/openid-configuration`

### Resource Indicators (RFC 8707)

The SDK includes the MCP server URL as a resource indicator in OAuth requests:

```swift
// Resource indicator is automatically added to OAuth requests
let config = try OAuthConfiguration.publicClient(
    authorizationEndpoint: authEndpoint,
    tokenEndpoint: tokenEndpoint,
    clientId: clientId,
    scopes: ["mcp:read"],
    redirectURI: redirectURI,
    resourceIndicator: "https://mcp-server.example.com" // Target MCP server
)
```

This ensures tokens are scoped to the specific MCP server.

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

Recent improvements to the OAuth transport fix critical SSE authentication issues and simplify the architecture:

#### **Full SSE Support for OAuth-Protected Servers**
The transport now properly authenticates ALL requests, including Server-Sent Events (SSE):

```swift
// OAuth headers are automatically added to both POST and SSE GET requests
let transport = OAuthHTTPClientTransport(
    endpoint: URL(string: "https://server.com")!,
    oauthConfig: oauthConfig
)

try await transport.connect()
// Both regular requests and SSE streaming are authenticated
try await transport.send(data)  // POST requests work
let stream = transport.receive()  // SSE GET requests also authenticated
```

#### **Simplified Architecture**
The OAuth transport uses a clean, maintainable approach:
- **Single Transport**: One HTTPClientTransport with OAuth headers in URLSession configuration
- **Automatic Authentication**: OAuth headers added to ALL requests via httpAdditionalHeaders
- **Token Refresh**: Recreates transport with new authenticated session when token changes
- **No Complex Pooling**: Removed unnecessary session/transport pooling complexity

#### **How It Works**
```swift
// OAuth headers are baked into the URLSession configuration
let config = URLSessionConfiguration.default
config.httpAdditionalHeaders = ["Authorization": "Bearer \(token)"]
let authenticatedSession = URLSession(configuration: config)

// All requests through this session are authenticated
// Including both POST (send) and GET (SSE receive) requests
```

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

### 🚀 Simplified OAuth Transport

The OAuth transport provides secure authentication with a clean, maintainable architecture:

#### **Key Features**
- **Full SSE Support**: OAuth headers are added to ALL requests, including Server-Sent Events
- **Automatic Token Management**: Handles token refresh transparently
- **Simple Architecture**: Straightforward implementation without complex state management
- **Correct Authentication**: All HTTP requests (POST, GET, SSE) include OAuth headers

#### **How It Works**
```swift
// OAuth transport wraps HTTPClientTransport with authentication
let transport = OAuthHTTPClientTransport(
    endpoint: URL(string: "https://server.com")!,
    oauthConfig: oauthConfig
)

// All requests are automatically authenticated
try await transport.send(request1)  // Authenticated POST
try await transport.send(request2)  // Authenticated POST
let stream = transport.receive()    // Authenticated SSE GET
```

#### **Token Lifecycle**
1. **Initial Connection**: Obtains or validates OAuth token
2. **Request Handling**: All requests use authenticated URLSession
3. **Token Refresh**: On 401/403 errors, automatically refreshes token and retries
4. **Transport Recreation**: Creates new transport with fresh token (rare event)
5. **Disconnect**: Properly cleans up resources

#### **Design Trade-offs**
- **Simplicity over micro-optimization**: Prioritizes maintainability and correctness
- **Transport recreation on token refresh**: Acceptable overhead for infrequent token refreshes (typically hourly)
- **No complex pooling**: Reduces potential bugs and edge cases
- **Clear architecture**: Easy to understand and debug

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