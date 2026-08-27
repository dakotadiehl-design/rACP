import Foundation

public protocol RACPByteStream: Sendable {
  func read(maximum: Int) async throws -> Data
  func write(_ data: Data) async throws
  func close() async
}

public enum RACPConnectionError: Error, Sendable, Equatable {
  case outputQueueFull
  case handshakeTimeout
  case connectionLost
  case writeFailed
  case requestTimeout
  case tooManyPendingRequests
  case cancelled
  case disconnected(String)
  case manualRequestIDNotAllowed
  case requestIDExhausted
}

public struct RACPRemoteError: Error, Sendable, Equatable {
  public let requestID: UInt64
  public let code: String
  public init(requestID: UInt64, code: String) {
    self.requestID = requestID
    self.code = code
  }
}

public enum RACPConnectionState: Sendable, Equatable {
  case connecting
  case handshaking
  case ready(RACPHello)
  case disconnected(String)
}

private actor OutboundQueue {
  private let maximum: Int
  private var items: [Data] = []
  private var nextWaiter: CheckedContinuation<Data?, Never>?
  private var flushWaiters: [CheckedContinuation<Void, Never>] = []
  private var pending = 0
  private var finished = false

  init(maximum: Int) { self.maximum = maximum }

  func enqueue(_ data: Data) throws {
    try enqueue([data])
  }

  func enqueue(_ batch: [Data]) throws {
    guard !finished else { throw RACPSessionError.closed("closing") }
    guard batch.count <= maximum - pending else { throw RACPConnectionError.outputQueueFull }
    pending += batch.count
    var remaining = batch
    if let nextWaiter, let first = remaining.first {
      self.nextWaiter = nil
      remaining.removeFirst()
      nextWaiter.resume(returning: first)
    }
    items.append(contentsOf: remaining)
  }

  func next() async -> Data? {
    if !items.isEmpty { return items.removeFirst() }
    if finished { return nil }
    return await withCheckedContinuation { nextWaiter = $0 }
  }

  func completed() {
    if pending > 0 { pending -= 1 }
    if pending == 0 {
      let waiters = flushWaiters
      flushWaiters.removeAll()
      for waiter in waiters { waiter.resume() }
    }
  }

  func flush() async {
    if pending == 0 { return }
    await withCheckedContinuation { flushWaiters.append($0) }
  }

  func finish() {
    finished = true
    nextWaiter?.resume(returning: nil)
    nextWaiter = nil
    let waiters = flushWaiters
    flushWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
  }

  func abort() {
    finished = true
    items.removeAll()
    pending = 0
    nextWaiter?.resume(returning: nil)
    nextWaiter = nil
    let waiters = flushWaiters
    flushWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
  }
}

public struct RACPReconnectPolicy: Sendable, Equatable {
  public let initial: TimeInterval
  public let maximum: TimeInterval
  public let multiplier: Double
  public let jitter: Double

  public init(
    initial: TimeInterval = 0.25, maximum: TimeInterval = 5, multiplier: Double = 2,
    jitter: Double = 0.2
  ) {
    precondition(initial > 0 && maximum >= initial && multiplier >= 1 && (0...1).contains(jitter))
    self.initial = initial
    self.maximum = maximum
    self.multiplier = multiplier
    self.jitter = jitter
  }

  public func delay(attempt: Int, randomValue: Double = Double.random(in: 0...1)) -> Duration {
    precondition(attempt >= 0 && (0...1).contains(randomValue))
    let base = min(maximum, initial * pow(multiplier, Double(attempt)))
    let spread = base * jitter
    return .seconds(base - spread + 2 * spread * randomValue)
  }
}

public actor RACPConnection {
  public static let defaultOutputMessages = 256
  public static let helloTimeout: Duration = .seconds(5)

  private let stream: any RACPByteStream
  private let session: RACPSession
  private let output: OutboundQueue
  private var decoder = RACPLineDecoder()
  private var closing = false
  private var hasRun = false
  private var nextNonce: UInt64 = 1
  private var publishedRevisions: [String: UInt64] = [:]
  private let allowUnsolicitedState: Bool
  private let maximumPendingRequests: Int
  private var nextRequestID: UInt64? = 1
  private var pendingRequests: [UInt64: PendingRequest] = [:]
  private var observers: [UUID: AsyncStream<RACPConnectionState>.Continuation] = [:]
  public private(set) var lifecycleState: RACPConnectionState = .connecting
  public private(set) var closeReason: String?

  private struct PendingRequest {
    let continuation: CheckedContinuation<Void, any Error>
    let timeout: Task<Void, Never>
  }

  public init(
    stream: any RACPByteStream,
    session: sending RACPSession,
    outputMessages: Int = defaultOutputMessages,
    maximumPendingRequests: Int = 1_024,
    allowUnsolicitedState: Bool = false
  ) {
    precondition(outputMessages > 0 && maximumPendingRequests > 0)
    self.stream = stream
    self.session = session
    output = OutboundQueue(maximum: outputMessages)
    self.maximumPendingRequests = maximumPendingRequests
    self.allowUnsolicitedState = allowUnsolicitedState
  }

  public func stateUpdates() -> AsyncStream<RACPConnectionState> {
    let id = UUID()
    return AsyncStream { continuation in
      observers[id] = continuation
      continuation.yield(lifecycleState)
      continuation.onTermination = { _ in Task { await self.removeObserver(id) } }
    }
  }

  public func waitUntilReady() async throws -> RACPHello {
    for await state in stateUpdates() {
      switch state {
      case .ready(let peer): return peer
      case .disconnected(let reason): throw RACPConnectionError.disconnected(reason)
      case .connecting, .handshaking: continue
      }
    }
    throw RACPConnectionError.disconnected("state_stream_ended")
  }

  /// Sends a command and waits for its ACK or ERR terminal response.
  ///
  /// Timeout or task cancellation only stops the local caller from waiting. Once
  /// bytes have been written, the remote peer may already have executed the command.
  public func command(
    _ name: String, arguments: JSONValue? = nil, timeout: Duration = .seconds(5)
  ) async throws {
    try await terminalRequest(timeout: timeout) { id in
      .command(Command(requestID: id, name: name, value: arguments, hasValue: arguments != nil))
    }
  }

  /// Requests a subscription. Local timeout or cancellation does not retract a
  /// request that may already have reached the peer.
  public func subscribe(_ name: String, timeout: Duration = .seconds(5)) async throws {
    try await terminalRequest(timeout: timeout) { .subscribe($0, name) }
  }

  /// Requests unsubscription. Local timeout or cancellation does not prove the
  /// peer did not process the request.
  public func unsubscribe(_ name: String, timeout: Duration = .seconds(5)) async throws {
    try await terminalRequest(timeout: timeout) { .unsubscribe($0, name) }
  }

  /// Sends messages that do not create correlated requests.
  ///
  /// Use `command`, `subscribe`, or `unsubscribe` for request-bearing messages.
  public func send(_ messages: RACPMessage...) async throws {
    guard !messages.contains(where: \._isRequest) else {
      throw RACPConnectionError.manualRequestIDNotAllowed
    }
    try await enqueue(messages)
  }

  /// Sends manual request IDs for wire-conformance tooling only.
  @_spi(RACPTesting)
  public func sendRawRequests(_ messages: RACPMessage...) async throws {
    try await enqueue(messages)
  }

  private func enqueue(_ messages: [RACPMessage]) async throws {
    guard !closing else { throw RACPSessionError.closed(closeReason ?? "closing") }
    guard session.state == .established else { throw RACPProtocolError.handshakeRequired }
    var revisions = publishedRevisions
    for message in messages {
      if case .state(let state) = message {
        guard allowUnsolicitedState || session.subscriptions.contains(state.name) else {
          throw RACPProtocolError.unsupportedCapability
        }
        guard
          state.revision > revisions[state.name, default: 0]
            || revisions[state.name] == nil && state.revision == 0
        else {
          throw RACPProtocolError.invalidValue
        }
        revisions[state.name] = state.revision
      }
    }
    let encoded = try messages.map { try RACPSession.encode([$0]) }
    do {
      try await output.enqueue(encoded)
    } catch RACPConnectionError.outputQueueFull {
      await close(reason: "output_queue_full")
      throw RACPConnectionError.outputQueueFull
    }
    publishedRevisions = revisions
  }

  public func run() async {
    guard !hasRun, !closing else { return }
    hasRun = true
    transition(to: .handshaking)
    let writer = Task { await writerLoop() }
    let heartbeat = Task { await heartbeatLoop() }
    let handshakeTimer = Task {
      try? await Task.sleep(for: Self.helloTimeout)
      guard !Task.isCancelled else { return }
      await self.expireHandshake()
    }
    do {
      try await output.enqueue(session.local.encoded)
      await output.flush()
      try await readUntilEstablished()
      handshakeTimer.cancel()
      guard let peer = session.peer else { throw RACPProtocolError.handshakeRequired }
      transition(to: .ready(peer))
      try await readEstablished()
    } catch let error as RACPProtocolError {
      closeReason = error.code
      try? await output.enqueue(try RACPSession.encode([.error(0, error.code)]))
    } catch RACPConnectionError.outputQueueFull {
      closeReason = "output_queue_full"
      await close(reason: "output_queue_full")
    } catch {
      closeReason = closeReason ?? "connection_lost"
    }
    handshakeTimer.cancel()
    heartbeat.cancel()
    await output.flush()
    await output.finish()
    _ = await writer.result
    await close(reason: closeReason ?? "eof")
  }

  public func close(reason: String = "closed") async {
    guard !closing else { return }
    closing = true
    closeReason = closeReason ?? reason
    session.markClosed()
    failAllPending(with: RACPConnectionError.disconnected(closeReason ?? reason))
    transition(to: .disconnected(closeReason ?? reason))
    await output.abort()
    await stream.close()
  }

  private func readUntilEstablished() async throws {
    while session.state == .hello {
      guard try await readOnce() else { throw RACPConnectionError.connectionLost }
    }
  }

  private func readEstablished() async throws {
    while session.state == .established {
      guard try await readOnce() else { return }
    }
    if session.state == .closing { closeReason = "peer_bye" }
  }

  private func readOnce() async throws -> Bool {
    let data = try await stream.read(maximum: 4_096)
    guard !data.isEmpty else {
      decoder.eof()
      return false
    }
    for line in try decoder.feed(data) {
      let responses = try session.receive(line: line)
      if let message = session.lastMessage { resolveTerminal(message) }
      for response in responses { try await output.enqueue(try RACPSession.encode([response])) }
    }
    return true
  }

  private func writerLoop() async {
    while let data = await output.next() {
      do {
        try await stream.write(data)
        await output.completed()
      } catch {
        await output.completed()
        closeReason = "write_failed"
        await close(reason: "write_failed")
        return
      }
    }
  }

  private func heartbeatLoop() async {
    while !Task.isCancelled {
      try? await Task.sleep(for: .seconds(1))
      guard !Task.isCancelled else { return }
      do {
        for message in try session.heartbeat(nonce: nextNonce) {
          try await output.enqueue(try RACPSession.encode([message]))
          nextNonce = nextNonce == racpMaximumSafeInteger ? 1 : nextNonce + 1
        }
      } catch {
        await close(reason: "heartbeat_timeout")
        return
      }
    }
  }

  private func expireHandshake() async {
    if session.state == .hello {
      closeReason = "handshake_timeout"
      await close(reason: "handshake_timeout")
    }
  }

  private func terminalRequest(
    timeout: Duration, message: @escaping (UInt64) -> RACPMessage
  ) async throws {
    guard case .ready = lifecycleState else { throw RACPConnectionError.disconnected("not_ready") }
    guard pendingRequests.count < maximumPendingRequests else {
      throw RACPConnectionError.tooManyPendingRequests
    }
    let id = try allocateRequestID()
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, any Error>) in
        if Task.isCancelled {
          continuation.resume(throwing: RACPConnectionError.cancelled)
          return
        }
        let timeoutTask = Task {
          try? await Task.sleep(for: timeout)
          guard !Task.isCancelled else { return }
          self.expireRequest(id)
        }
        pendingRequests[id] = PendingRequest(continuation: continuation, timeout: timeoutTask)
        Task {
          do { try await self.enqueue([message(id)]) } catch { self.failRequest(id, with: error) }
        }
      }
    } onCancel: {
      Task { await self.failRequest(id, with: RACPConnectionError.cancelled) }
    }
  }

  private func allocateRequestID() throws -> UInt64 {
    guard let id = nextRequestID else { throw RACPConnectionError.requestIDExhausted }
    nextRequestID = id == racpMaximumSafeInteger ? nil : id + 1
    return id
  }

  private func resolveTerminal(_ message: RACPMessage) {
    switch message {
    case .ack(let id): completeRequest(id, result: .success(()))
    case .error(let id, let code) where id != 0:
      completeRequest(id, result: .failure(RACPRemoteError(requestID: id, code: code)))
    default: break
    }
  }

  private func expireRequest(_ id: UInt64) {
    failRequest(id, with: RACPConnectionError.requestTimeout)
  }

  private func failRequest(_ id: UInt64, with error: any Error) {
    completeRequest(id, result: .failure(error))
  }

  private func completeRequest(_ id: UInt64, result: Result<Void, any Error>) {
    guard let pending = pendingRequests.removeValue(forKey: id) else { return }
    pending.timeout.cancel()
    pending.continuation.resume(with: result)
  }

  private func failAllPending(with error: any Error) {
    let requests = pendingRequests
    pendingRequests.removeAll()
    for pending in requests.values {
      pending.timeout.cancel()
      pending.continuation.resume(throwing: error)
    }
  }

  private func transition(to state: RACPConnectionState) {
    lifecycleState = state
    for observer in observers.values { observer.yield(state) }
    if case .disconnected = state {
      let current = observers
      observers.removeAll()
      for observer in current.values { observer.finish() }
    }
  }

  private func removeObserver(_ id: UUID) { observers.removeValue(forKey: id) }
}
