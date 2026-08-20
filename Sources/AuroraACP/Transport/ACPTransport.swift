import Foundation

public protocol ACPTransport: Sendable {
    func send(_ data: Data, text: Bool) async throws
    func recv() async throws -> (Data, Bool)
    func close() async
}

public actor ACPLoopback: ACPTransport {
    private var peer: ACPLoopback?
    private var queue: [(Data, Bool)] = []
    private var waiters: [UUID: CheckedContinuation<(Data, Bool), Error>] = [:]
    private var closed = false

    public init() {}

    public func attach(_ other: ACPLoopback) {
        peer = other
    }

    public func send(_ data: Data, text: Bool = false) async throws {
        guard !closed, let peer else { throw ACPSessionError("unavailable", "closed") }
        await peer.deliver(data, text: text)
    }

    func deliver(_ data: Data, text: Bool) {
        if let id = waiters.keys.first, let waiter = waiters.removeValue(forKey: id) {
            waiter.resume(returning: (data, text))
        } else {
            queue.append((data, text))
        }
    }

    public func recv() async throws -> (Data, Bool) {
        if closed { throw ACPSessionError("unavailable", "eof") }
        if !queue.isEmpty { return queue.removeFirst() }
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { cont in
                waiters[id] = cont
            }
        } onCancel: {
            Task { await self.cancelWaiter(id) }
        }
    }

    func cancelWaiter(_ id: UUID) {
        if let waiter = waiters.removeValue(forKey: id) {
            waiter.resume(throwing: ACPSessionError("timeout", "recv cancelled"))
        }
    }

    public func close() {
        closed = true
        for w in waiters.values { w.resume(throwing: ACPSessionError("unavailable", "eof")) }
        waiters.removeAll()
    }
}

public func acpLinkedTransports() async -> (ACPLoopback, ACPLoopback) {
    let a = ACPLoopback()
    let b = ACPLoopback()
    await a.attach(b)
    await b.attach(a)
    return (a, b)
}
