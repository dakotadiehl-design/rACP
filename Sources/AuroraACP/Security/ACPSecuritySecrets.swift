import Foundation

public final class ACPSecretBytes: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    private var storage: Data
    private let lock = NSRecursiveLock()
    public init?(_ value: Data, label: String = "secret") {
        guard !value.isEmpty else { return nil }
        storage = value
        _ = label
    }
    public var description: String {
        lock.lock(); defer { lock.unlock() }
        return "ACPSecretBytes(redacted: true, length: \(storage.count))"
    }
    public var debugDescription: String { description }
    public func withUnsafeBytes<T>(_ operation: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        lock.lock(); defer { lock.unlock() }
        return try storage.withUnsafeBytes(operation)
    }
    public func clear() {
        lock.lock(); defer { lock.unlock() }
        storage.resetBytes(in: storage.indices)
    }
    deinit { clear() }
}
