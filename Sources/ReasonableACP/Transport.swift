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
  private var nextNonce: UInt64 = 1
  private var publishedRevisions: [String: UInt64] = [:]
  private let allowUnsolicitedState: Bool
  public private(set) var closeReason: String?

  public init(
    stream: any RACPByteStream,
    session: sending RACPSession,
    outputMessages: Int = defaultOutputMessages,
    allowUnsolicitedState: Bool = false
  ) {
    precondition(outputMessages > 0)
    self.stream = stream
    self.session = session
    output = OutboundQueue(maximum: outputMessages)
    self.allowUnsolicitedState = allowUnsolicitedState
  }

  public func send(_ messages: RACPMessage...) async throws {
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
}
