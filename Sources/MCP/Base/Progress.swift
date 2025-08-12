import Foundation

// MARK: - Progress Notification

/// A notification sent to report progress on a long-running operation
public struct ProgressNotification: Notification {
    public static let name: String = "notifications/progress"
    
    public struct Parameters: Hashable, Codable, Sendable {
        /// The progress token that identifies which operation this progress update is for
        public let progressToken: String
        
        /// The current progress value. Must increase with each notification.
        public let progress: Double
        
        /// The total amount of work, if known. May be nil if total is unknown.
        public let total: Double?
        
        public init(progressToken: String, progress: Double, total: Double? = nil) {
            self.progressToken = progressToken
            self.progress = progress
            self.total = total
        }
    }
}

// MARK: - Request Metadata

/// Metadata that can be included with requests to enable features like progress tracking
public struct RequestMetadata: Hashable, Codable, Sendable {
    /// An optional progress token for receiving progress notifications
    public let progressToken: String?
    
    public init(progressToken: String? = nil) {
        self.progressToken = progressToken
    }
    
    private enum CodingKeys: String, CodingKey {
        case progressToken
    }
}

// MARK: - Progress Tracking

/// A progress tracker that manages active progress tokens
public actor ProgressTracker {
    private var activeTokens: Set<String> = []
    
    /// Register a new progress token as active
    public func registerToken(_ token: String) {
        activeTokens.insert(token)
    }
    
    /// Remove a progress token when the operation completes
    public func completeToken(_ token: String) {
        activeTokens.remove(token)
    }
    
    /// Check if a progress token is currently active
    public func isTokenActive(_ token: String) -> Bool {
        activeTokens.contains(token)
    }
    
    /// Get all active progress tokens
    public func getActiveTokens() -> Set<String> {
        activeTokens
    }
    
    /// Clear all active tokens (useful for cleanup)
    public func clearAllTokens() {
        activeTokens.removeAll()
    }
}

// MARK: - Progress Handler

/// A closure type for handling progress updates
public typealias ProgressHandler = @Sendable (Double, Double?) async -> Void

/// A helper to track progress for a specific operation
public struct ProgressObserver: Sendable {
    public let token: String
    private let handler: ProgressHandler
    
    public init(token: String = UUID().uuidString, handler: @escaping ProgressHandler) {
        self.token = token
        self.handler = handler
    }
    
    /// Call the handler with progress update
    internal func update(progress: Double, total: Double?) async {
        await handler(progress, total)
    }
}