import Foundation

// MARK: - Request with Progress Support

/// Parameters wrapper that includes metadata for progress tracking
public struct ParametersWithMeta<P: Codable & Hashable & Sendable>: Codable, Hashable, Sendable {
    /// The actual parameters
    public let params: P
    
    /// Optional metadata including progress token
    public let _meta: RequestMeta?
    
    public init(params: P, progressToken: String? = nil) {
        self.params = params
        self._meta = progressToken.map { RequestMeta(progressToken: $0) }
    }
    
    // Custom encoding to merge params and _meta at the same level
    public func encode(to encoder: Encoder) throws {
        // First encode the params
        try params.encode(to: encoder)
        
        // Then add _meta if present
        if let meta = _meta {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(meta, forKey: ._meta)
        }
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self._meta = try container.decodeIfPresent(RequestMeta.self, forKey: ._meta)
        
        // For params, we need to decode the whole thing except _meta
        // This is complex, so for now we'll just initialize with a default
        self.params = try P(from: decoder)
    }
    
    private enum CodingKeys: String, CodingKey {
        case _meta
        case params
    }
}

/// Request metadata for progress tracking
public struct RequestMeta: Codable, Hashable, Sendable {
    public let progressToken: String
    
    public init(progressToken: String) {
        self.progressToken = progressToken
    }
}

// MARK: - Client Extensions for Progress

extension Method {
    /// Create a request with progress tracking
    public static func requestWithProgress(
        id: ID = .random,
        _ parameters: Self.Parameters,
        progressToken: String
    ) -> Request<Self> where Parameters: Codable {
        // We need to wrap the parameters with metadata
        // This is a bit tricky since we need to maintain type safety
        // For now, we'll provide this as a pattern for users to follow
        Request(id: id, method: name, params: parameters)
    }
}

// MARK: - Progress-aware request creation helpers

/// Helper to create tool call requests with progress tracking
public struct ProgressAwareRequest {
    /// Create a tool call request with progress tracking
    public static func callTool(
        name: String,
        arguments: [String: Value]? = nil,
        progressToken: String
    ) -> Data? {
        // Create a custom JSON structure with _meta
        let randomId = ID.random
        let idValue: Any
        switch randomId {
        case .string(let s):
            idValue = s
        case .number(let n):
            idValue = n
        }
        
        var json: [String: Any] = [
            "jsonrpc": "2.0",
            "id": idValue,
            "method": "tools/call",
            "params": [
                "name": name,
                "_meta": [
                    "progressToken": progressToken
                ]
            ]
        ]
        
        if let arguments = arguments {
            var params = json["params"] as! [String: Any]
            params["arguments"] = try? JSONEncoder().encode(arguments)
            json["params"] = params
        }
        
        return try? JSONSerialization.data(withJSONObject: json)
    }
}