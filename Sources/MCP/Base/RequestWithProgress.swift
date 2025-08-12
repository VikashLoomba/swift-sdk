import Foundation

// MARK: - Request Metadata

/// Request metadata for progress tracking
public struct RequestMeta: Codable, Hashable, Sendable {
    public let progressToken: String
    
    public init(progressToken: String) {
        self.progressToken = progressToken
    }
}

// MARK: - Progress-aware Tool Call Helper

/// Helper extension to create tool call with progress metadata
extension Client {
    /// Internal helper to create a tool call method with progress metadata
    internal struct CallToolWithMeta: Method {
        static let name = "tools/call"
        
        struct Parameters: Hashable, Codable, Sendable {
            let name: String
            let arguments: [String: Value]?
            let _meta: MetaField
            
            struct MetaField: Hashable, Codable, Sendable {
                let progressToken: String
            }
            
            init(name: String, arguments: [String: Value]?, progressToken: String) {
                self.name = name
                self.arguments = arguments
                self._meta = MetaField(progressToken: progressToken)
            }
        }
        
        typealias Result = CallTool.Result
    }
}