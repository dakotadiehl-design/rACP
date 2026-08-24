import Foundation

public final class ACPSecretBytes: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    private var storage: Data
    public init?(_ value: Data, label: String = "secret") {
        guard !value.isEmpty else { return nil }
        storage = value
        _ = label
    }
    public var description: String { "ACPSecretBytes(redacted: true, length: \(storage.count))" }
    public var debugDescription: String { description }
    public func withUnsafeBytes<T>(_ operation: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        try storage.withUnsafeBytes(operation)
    }
    public func clear() { storage.resetBytes(in: storage.indices) }
    deinit { clear() }
}
