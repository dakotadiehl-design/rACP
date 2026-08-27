import Foundation

public final class ACPSecretBytes: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    private let storage: UnsafeMutableRawPointer
    private let count: Int
    private let lock = NSRecursiveLock()

    /// Copies `value` into an ACP-owned allocation that is zeroized before it
    /// is released. The caller remains responsible for clearing any `Data`
    /// instances that held the secret before or after this boundary.
    public init?(_ value: Data, label: String = "secret") {
        guard !value.isEmpty else { return nil }
        count = value.count
        storage = .allocate(byteCount: value.count, alignment: MemoryLayout<UInt8>.alignment)
        value.withUnsafeBytes { input in
            storage.copyMemory(from: input.baseAddress!, byteCount: input.count)
        }
        _ = label
    }
    public var description: String {
        lock.lock(); defer { lock.unlock() }
        return "ACPSecretBytes(redacted: true, length: \(count))"
    }
    public var debugDescription: String { description }
    public func withUnsafeBytes<T>(_ operation: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        lock.lock(); defer { lock.unlock() }
        return try operation(UnsafeRawBufferPointer(start: storage, count: count))
    }
    public func clear() {
        lock.lock(); defer { lock.unlock() }
        storage.initializeMemory(as: UInt8.self, repeating: 0, count: count)
    }
    deinit {
        clear()
        storage.deallocate()
    }
}
