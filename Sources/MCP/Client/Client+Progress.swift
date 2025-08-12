import Foundation
import Logging

// MARK: - Progress Support

// Create a global actor-protected storage for progress observers
private actor ProgressObserverStorage {
    static let shared = ProgressObserverStorage()
    private var observers: [String: ProgressObserver] = [:]
    
    func add(_ observer: ProgressObserver, for token: String) {
        observers[token] = observer
    }
    
    func remove(for token: String) {
        observers.removeValue(forKey: token)
    }
    
    func get(for token: String) -> ProgressObserver? {
        observers[token]
    }
    
    func removeAll() {
        observers.removeAll()
    }
}

extension Client {
    /// Progress tracker for managing active progress tokens
    private static let progressTracker = ProgressTracker()
    
    /// Call a tool with progress tracking
    public func callTool(
        name: String,
        arguments: [String: Value]? = nil,
        progressToken: String? = nil,
        onProgress: ProgressHandler? = nil
    ) async throws -> CallTool.Result {
        // If progress tracking is requested, register the observer
        if let token = progressToken, let handler = onProgress {
            let observer = ProgressObserver(token: token, handler: handler)
            await Self.progressTracker.registerToken(token)
            await ProgressObserverStorage.shared.add(observer, for: token)
        }
        
        // Create the request with progress token if provided
        let params: CallTool.Parameters
        if let progressToken = progressToken {
            // We need to include _meta in the params
            // This requires a custom encoding approach
            params = CallTool.Parameters(
                name: name,
                arguments: arguments
            )
            // Note: Actual _meta injection would need to be done at the transport level
            // or by modifying the CallTool.Parameters structure
        } else {
            params = CallTool.Parameters(
                name: name,
                arguments: arguments
            )
        }
        
        do {
            let result = try await send(CallTool.request(params))
            
            // Clean up progress tracking if it was used
            if let token = progressToken {
                await Self.progressTracker.completeToken(token)
                await ProgressObserverStorage.shared.remove(for: token)
            }
            
            return result
        } catch {
            // Clean up on error too
            if let token = progressToken {
                await Self.progressTracker.completeToken(token)
                await ProgressObserverStorage.shared.remove(for: token)
            }
            throw error
        }
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
            if await Self.progressTracker.isTokenActive(params.progressToken) {
                // Call the registered observer if it exists
                if let observer = await ProgressObserverStorage.shared.get(for: params.progressToken) {
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
        await Self.progressTracker.clearAllTokens()
        await ProgressObserverStorage.shared.removeAll()
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