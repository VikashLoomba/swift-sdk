import Foundation
import Logging

// MARK: - Progress Support

// Create a global actor-protected storage for progress observers and trackers
private actor ProgressStorage {
    static let shared = ProgressStorage()
    private var observers: [String: ProgressObserver] = [:]
    private var trackers: [ObjectIdentifier: ProgressTracker] = [:]
    
    func addObserver(_ observer: ProgressObserver, for token: String) {
        observers[token] = observer
    }
    
    func removeObserver(for token: String) {
        observers.removeValue(forKey: token)
    }
    
    func getObserver(for token: String) -> ProgressObserver? {
        observers[token]
    }
    
    func removeAllObservers() {
        observers.removeAll()
    }
    
    func getTracker(for client: Client) -> ProgressTracker {
        let id = ObjectIdentifier(client)
        if let tracker = trackers[id] {
            return tracker
        }
        let tracker = ProgressTracker()
        trackers[id] = tracker
        return tracker
    }
    
    func removeTracker(for client: Client) {
        let id = ObjectIdentifier(client)
        trackers.removeValue(forKey: id)
    }
}

extension Client {
    /// Get the progress tracker for this client instance
    private func getProgressTracker() async -> ProgressTracker {
        await ProgressStorage.shared.getTracker(for: self)
    }
    
    /// Call a tool with progress tracking
    public func callTool(
        name: String,
        arguments: [String: Value]? = nil,
        progressToken: String? = nil,
        onProgress: ProgressHandler? = nil
    ) async throws -> CallTool.Result {
        let tracker = await getProgressTracker()
        
        // If progress tracking is requested, register the observer
        if let token = progressToken, let handler = onProgress {
            let observer = ProgressObserver(token: token, handler: handler)
            await tracker.registerToken(token)
            await ProgressStorage.shared.addObserver(observer, for: token)
        }
        
        // Create the request with progress token if provided
        let result: CallTool.Result
        
        if let progressToken = progressToken {
            // Create a request with _meta field for progress tracking
            let params = CallToolWithMeta.Parameters(
                name: name,
                arguments: arguments,
                progressToken: progressToken
            )
            
            result = try await send(CallToolWithMeta.request(params))
        } else {
            // Standard request without progress
            let params = CallTool.Parameters(
                name: name,
                arguments: arguments
            )
            result = try await send(CallTool.request(params))
        }
        
        // Clean up progress tracking if it was used
        if let token = progressToken {
            await tracker.completeToken(token)
            await ProgressStorage.shared.removeObserver(for: token)
        }
        
        return result
    }
    
    /// Register a handler for progress notifications
    @discardableResult
    public func onProgress(
        handler: @escaping @Sendable (String, Double, Double?) async -> Void
    ) async -> Self {
        // Register a handler for ProgressNotification
        await onNotification(ProgressNotification.self) { message in
            let params = message.params
            
            // Check if this token is being tracked
            let tracker = await self.getProgressTracker()
            if await tracker.isTokenActive(params.progressToken) {
                // Call the registered observer if it exists
                if let observer = await ProgressStorage.shared.getObserver(for: params.progressToken) {
                    await observer.update(progress: params.progress, total: params.total)
                }
                
                // Also call the general handler
                await handler(params.progressToken, params.progress, params.total)
            }
        }
        
        return self
    }
    
    /// Helper method to create a progress-tracked request
    public func createProgressToken() -> String {
        return UUID().uuidString
    }
    
    /// Clean up all progress tracking (useful on disconnect)
    internal func cleanupProgressTracking() async {
        let tracker = await getProgressTracker()
        await tracker.clearAllTokens()
        await ProgressStorage.shared.removeAllObservers()
        await ProgressStorage.shared.removeTracker(for: self)
    }
}

// MARK: - Enhanced Tool Call with Progress

public struct ToolCallWithProgress {
    public let name: String
    public let arguments: [String: Value]?
    public let progressToken: String
    
    public init(
        name: String,
        arguments: [String: Value]? = nil,
        progressToken: String? = nil
    ) {
        self.name = name
        self.arguments = arguments
        self.progressToken = progressToken ?? UUID().uuidString
    }
}

extension Client {
    /// Execute a tool call with automatic progress tracking
    public func executeToolWithProgress(
        _ tool: ToolCallWithProgress,
        onProgress: @escaping ProgressHandler
    ) async throws -> CallTool.Result {
        return try await callTool(
            name: tool.name,
            arguments: tool.arguments,
            progressToken: tool.progressToken,
            onProgress: onProgress
        )
    }
}