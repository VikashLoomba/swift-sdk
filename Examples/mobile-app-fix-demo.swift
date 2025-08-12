#!/usr/bin/env swift

// MARK: - Mobile App Dynamic Registration Fix Validation
//
// This script demonstrates how the fix solves the original issue where
// dynamic client registration created confidential clients for mobile apps,
// breaking PKCE.

import Foundation

// Mock the MCP types to demonstrate the fix
struct MockClientRegistrationResponse {
    let clientId: String
    let clientSecret: String?
    let redirectUris: [String]
    let grantTypes: [String]
    let responseTypes: [String]
    let scopes: String?
    let clientName: String?
}

enum MockClientType {
    case `public`
    case confidential
}

struct MockOAuthConfiguration {
    let clientId: String
    let clientSecret: String?
    let clientType: MockClientType
    let usePKCE: Bool
    let scopes: [String]
    let redirectURI: String?
    
    init(clientId: String, clientSecret: String?, scopes: [String], redirectURI: String?) {
        self.clientId = clientId
        self.clientSecret = clientSecret
        // Auto-detect client type based on presence of secret
        self.clientType = clientSecret != nil ? .confidential : .`public`
        // Auto-enable PKCE for public clients
        self.usePKCE = self.clientType == .`public`
        self.scopes = scopes
        self.redirectURI = redirectURI
    }
}

struct MobileAppDynamicRegistrationFixDemo {
    static func main() {
        print("🔐 Mobile App Dynamic Registration Fix Demonstration")
        print("===================================================")
        
        demonstrateIssue()
        print()
        demonstrateSolution()
    }
    
    static func demonstrateIssue() {
        print("❌ BEFORE: The Issue")
        print("-------------------")
        
        // Simulate server response that incorrectly provides client secret
        let problematicServerResponse = MockClientRegistrationResponse(
            clientId: "mobile-app-client",
            clientSecret: "incorrectly-provided-secret", // Server shouldn't provide this
            redirectUris: ["myapp://auth"],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: "openid profile",
            clientName: "Mobile App"
        )
        
        // Old behavior: Configuration based directly on server response
        let problematicConfig = MockOAuthConfiguration(
            clientId: problematicServerResponse.clientId,
            clientSecret: problematicServerResponse.clientSecret, // This causes the issue
            scopes: ["openid", "profile"],
            redirectURI: problematicServerResponse.redirectUris.first
        )
        
        print("📱 Mobile app registration response from server:")
        print("   • Client ID: \(problematicServerResponse.clientId)")
        print("   • Client Secret: \(problematicServerResponse.clientSecret ?? "nil") ⚠️ (Server incorrectly provided this)")
        print("   • Redirect URI: \(problematicServerResponse.redirectUris.first ?? "nil")")
        
        print("\n⚙️ Resulting OAuth configuration:")
        print("   • Client Type: \(problematicConfig.clientType) ❌ (Should be public)")
        print("   • PKCE Enabled: \(problematicConfig.usePKCE) ❌ (Should be true for mobile apps)")
        print("   • Client Secret: \(problematicConfig.clientSecret != nil ? "present" : "nil") ❌")
        
        print("\n💥 This would cause authorization to fail with 'pkce+is+required' error!")
    }
    
    static func demonstrateSolution() {
        print("✅ AFTER: The Solution")
        print("---------------------")
        
        print("🔧 New approach: Use token_endpoint_auth_method during registration")
        print("\n📝 Registration request now includes:")
        print("   • client_name: 'Mobile App'")
        print("   • redirect_uris: ['myapp://auth']")
        print("   • grant_types: ['authorization_code']")
        print("   • response_types: ['code']")
        print("   • token_endpoint_auth_method: 'none' ✅ (Explicitly request public client)")
        
        // Simulate server response that respects token_endpoint_auth_method
        let correctServerResponse = MockClientRegistrationResponse(
            clientId: "mobile-app-client",
            clientSecret: nil, // Server correctly omits secret when auth_method is "none"
            redirectUris: ["myapp://auth"],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: "openid profile",
            clientName: "Mobile App"
        )
        
        // New behavior: Configuration correctly detects public client
        let correctConfig = MockOAuthConfiguration(
            clientId: correctServerResponse.clientId,
            clientSecret: correctServerResponse.clientSecret,
            scopes: ["openid", "profile"],
            redirectURI: correctServerResponse.redirectUris.first
        )
        
        print("\n📱 Mobile app registration response from server:")
        print("   • Client ID: \(correctServerResponse.clientId)")
        print("   • Client Secret: \(correctServerResponse.clientSecret ?? "nil") ✅ (Correctly omitted)")
        print("   • Redirect URI: \(correctServerResponse.redirectUris.first ?? "nil")")
        
        print("\n⚙️ Resulting OAuth configuration:")
        print("   • Client Type: \(correctConfig.clientType) ✅ (Correctly detected as public)")
        print("   • PKCE Enabled: \(correctConfig.usePKCE) ✅ (Automatically enabled for public clients)")
        print("   • Client Secret: \(correctConfig.clientSecret != nil ? "present" : "nil") ✅")
        
        print("\n🎉 Authorization will now succeed with PKCE parameters included!")
        
        print("\n📋 Usage in your app:")
        print("```swift")
        print("let config = try await authenticator.setupOAuthWithDiscovery(")
        print("    discoveryURL: discoveryURL,")
        print("    clientName: \"Mobile App\",")
        print("    redirectURIs: [URL(string: \"myapp://auth\")!],")
        print("    scopes: [\"openid\", \"profile\"],")
        print("    isPublicClient: true  // Default value, explicit for clarity")
        print(")")
        print("```")
        
        print("\n🔗 RFC 7591 Reference:")
        print("   token_endpoint_auth_method values:")
        print("   • 'none' - Public clients (mobile apps, SPAs)")
        print("   • 'client_secret_post' - Confidential clients")
        print("   • 'client_secret_basic' - Confidential clients with Basic auth")
    }
}

// Run the demonstration
MobileAppDynamicRegistrationFixDemo.main()