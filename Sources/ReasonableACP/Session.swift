import Foundation

public struct RACPHello: Sendable, Equatable {
  public let peerType: String
  public let peerID: String
  public let capabilities: [String]

  public init(peerType: String, peerID: String, capabilities: [String] = []) throws {
    try validatePeer(peerType)
    try validatePeer(peerID)
    guard capabilities == capabilities.sorted(), Set(capabilities).count == capabilities.count
    else {
      throw RACPProtocolError.malformedMessage()
    }
    for capability in capabilities { try validateName(capability) }
    self.peerType = peerType
    self.peerID = peerID
    self.capabilities = capabilities
  }

  public var lines: [String] {
    ["RACP/1 HELLO", "PEER \(peerType) \(peerID)"] + capabilities.map { "CAP \($0)" } + ["END"]
  }

  public var encoded: Data { Data((lines.joined(separator: "\n") + "\n").utf8) }
}

public enum RACPSessionState: Sendable, Equatable {
  case hello
  case established
  case closing
  case closed
}

public enum RACPSessionError: Error, Sendable, Equatable {
  case closed(String)
  case asynchronousCommandHandler
}

public enum RACPCommandDisposition: Sendable, Equatable {
  case success
  case error(String)
}

public enum RACPSubscriptionEvent: Sendable, Equatable {
  case subscribed(String)
  case unsubscribed(String)
}

public final class RACPSession {
  public typealias CommandHandler = (Command) -> String?
  public typealias AsyncCommandHandler = (Command) async throws -> RACPCommandDisposition
  public typealias StateHandler = (StateMessage) -> Void

  public let local: RACPHello
  public private(set) var peer: RACPHello?
  public private(set) var state: RACPSessionState = .hello
  public private(set) var subscriptions: Set<String> = []
  public private(set) var stateRevisions: [String: UInt64] = [:]
  public private(set) var malformedCount = 0
  public private(set) var lastReceived: TimeInterval
  public private(set) var outstandingPing: (nonce: UInt64, sentAt: TimeInterval)?
  public private(set) var lastMessage: RACPMessage?
  public private(set) var lastSubscriptionEvent: RACPSubscriptionEvent?

  private let handler: CommandHandler?
  private let asyncHandler: AsyncCommandHandler?
  private let stateHandler: StateHandler
  private let ledgerSize: Int
  private let now: () -> TimeInterval
  private var helloLines: [String] = []
  private var ledger: [UInt64: LedgerEntry] = [:]
  private var ledgerOrder: [UInt64] = []

  private struct LedgerEntry {
    let command: Command
    let response: RACPMessage
  }

  public init(
    local: RACPHello,
    ledgerSize: Int = 1_024,
    now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
    commandHandler: @escaping CommandHandler = { _ in nil },
    stateHandler: @escaping StateHandler = { _ in }
  ) {
    precondition(ledgerSize > 0)
    self.local = local
    self.ledgerSize = ledgerSize
    self.now = now
    handler = commandHandler
    asyncHandler = nil
    self.stateHandler = stateHandler
    lastReceived = now()
  }

  public init(
    local: RACPHello,
    ledgerSize: Int = 1_024,
    now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
    asyncCommandHandler: @escaping AsyncCommandHandler,
    stateHandler: @escaping StateHandler = { _ in }
  ) {
    precondition(ledgerSize > 0)
    self.local = local
    self.ledgerSize = ledgerSize
    self.now = now
    handler = nil
    asyncHandler = asyncCommandHandler
    self.stateHandler = stateHandler
    lastReceived = now()
  }

  public func receive(line: String) throws -> [RACPMessage] {
    guard state != .closing, state != .closed else { throw RACPSessionError.closed("closed") }
    lastReceived = now()
    lastSubscriptionEvent = nil
    if state == .hello {
      lastMessage = nil
      helloLines.append(line)
      guard helloLines.count <= 1_027 else { throw RACPProtocolError.malformedMessage(fatal: true) }
      if line == "END" {
        peer = try Self.parseHello(helloLines)
        helloLines.removeAll(keepingCapacity: false)
        state = .established
      }
      return []
    }
    do {
      let message = try RACPMessage.parse(line)
      lastMessage = message
      return try receive(message: message)
    } catch let error as RACPProtocolError {
      malformedCount += 1
      if malformedCount >= 3 { throw RACPProtocolError.malformedMessage(fatal: true) }
      throw error
    }
  }

  /// Receives one wire line, awaiting application command completion before
  /// returning its terminal ACK or ERR response.
  public nonisolated(nonsending) func receiveAsync(line: String) async throws -> [RACPMessage] {
    guard state != .closing, state != .closed else { throw RACPSessionError.closed("closed") }
    lastReceived = now()
    lastSubscriptionEvent = nil
    if state == .hello {
      return try receiveHello(line: line)
    }
    do {
      let message = try RACPMessage.parse(line)
      lastMessage = message
      return try await receiveAsync(message: message)
    } catch let error as RACPProtocolError {
      malformedCount += 1
      if malformedCount >= 3 { throw RACPProtocolError.malformedMessage(fatal: true) }
      throw error
    }
  }

  public func receive(message: RACPMessage) throws -> [RACPMessage] {
    guard state == .established else { throw RACPProtocolError.handshakeRequired }
    lastSubscriptionEvent = nil
    switch message {
    case .ping(let nonce): return [.pong(nonce)]
    case .pong(let nonce):
      if outstandingPing?.nonce == nonce { outstandingPing = nil }
      return []
    case .bye:
      state = .closing
      return []
    case .command(let command):
      guard asyncHandler == nil else { throw RACPSessionError.asynchronousCommandHandler }
      return [handle(command)]
    case .subscribe(let id, let name): return [subscribe(id: id, name: name)]
    case .unsubscribe(let id, let name):
      subscriptions.remove(name)
      lastSubscriptionEvent = .unsubscribed(name)
      return [.ack(id)]
    case .state(let message):
      let previous = stateRevisions[message.name]
      if previous == nil || message.revision > previous! {
        stateRevisions[message.name] = message.revision
        stateHandler(message)
      }
      return []
    case .ack, .error: return []
    }
  }

  public nonisolated(nonsending) func receiveAsync(message: RACPMessage) async throws
    -> [RACPMessage]
  {
    guard state == .established else { throw RACPProtocolError.handshakeRequired }
    lastSubscriptionEvent = nil
    if case .command(let command) = message { return [await handleAsync(command)] }
    return try receive(message: message)
  }

  public func heartbeat(nonce: UInt64) throws -> [RACPMessage] {
    let current = now()
    if let outstandingPing {
      if current - outstandingPing.sentAt >= 5 {
        state = .closed
        throw RACPSessionError.closed("heartbeat_timeout")
      }
      return []
    }
    if current - lastReceived >= 10 {
      try validateRequestIDForSession(nonce)
      outstandingPing = (nonce, current)
      return [.ping(nonce)]
    }
    return []
  }

  public func markClosed() { state = .closed }

  public static func encode(_ messages: [RACPMessage]) throws -> Data {
    var output = Data()
    for message in messages {
      let line = try message.encoded()
      guard line.utf8.count <= racpMaximumLineBytes else { throw RACPProtocolError.lineTooLong }
      output.append(contentsOf: line.utf8)
      output.append(0x0A)
    }
    return output
  }

  private func handle(_ command: Command) -> RACPMessage {
    if let previous = ledger[command.requestID] {
      return previous.command == command
        ? previous.response : .error(command.requestID, "request_id_conflict")
    }
    let response: RACPMessage
    if !local.capabilities.contains(command.name) {
      response = .error(command.requestID, "unsupported_capability")
    } else if let code = handler?(command) {
      response = validatedError(id: command.requestID, code: code)
    } else {
      response = .ack(command.requestID)
    }
    record(command: command, response: response)
    return response
  }

  private nonisolated(nonsending) func handleAsync(_ command: Command) async -> RACPMessage {
    if let previous = ledger[command.requestID] {
      return previous.command == command
        ? previous.response : .error(command.requestID, "request_id_conflict")
    }
    let response: RACPMessage
    if !local.capabilities.contains(command.name) {
      response = .error(command.requestID, "unsupported_capability")
    } else if let asyncHandler {
      do {
        switch try await asyncHandler(command) {
        case .success: response = .ack(command.requestID)
        case .error(let code): response = validatedError(id: command.requestID, code: code)
        }
      } catch {
        response = .error(command.requestID, "application_error")
      }
    } else if let code = handler?(command) {
      response = validatedError(id: command.requestID, code: code)
    } else {
      response = .ack(command.requestID)
    }
    record(command: command, response: response)
    return response
  }

  private func validatedError(id: UInt64, code: String) -> RACPMessage {
    do {
      try validateName(code)
      return .error(id, code)
    } catch {
      return .error(id, "application_error")
    }
  }

  private func record(command: Command, response: RACPMessage) {
    ledger[command.requestID] = LedgerEntry(command: command, response: response)
    ledgerOrder.append(command.requestID)
    if ledgerOrder.count > ledgerSize { ledger.removeValue(forKey: ledgerOrder.removeFirst()) }
  }

  private func subscribe(id: UInt64, name: String) -> RACPMessage {
    guard local.capabilities.contains("state.subscribe"), local.capabilities.contains(name) else {
      return .error(id, "unsupported_capability")
    }
    subscriptions.insert(name)
    lastSubscriptionEvent = .subscribed(name)
    return .ack(id)
  }

  private func receiveHello(line: String) throws -> [RACPMessage] {
    lastMessage = nil
    helloLines.append(line)
    guard helloLines.count <= 1_027 else { throw RACPProtocolError.malformedMessage(fatal: true) }
    if line == "END" {
      peer = try Self.parseHello(helloLines)
      helloLines.removeAll(keepingCapacity: false)
      state = .established
    }
    return []
  }

  private static func parseHello(_ lines: [String]) throws -> RACPHello {
    guard lines.count >= 3, lines.last == "END" else {
      throw RACPProtocolError.malformedMessage(fatal: true)
    }
    guard lines[0] == "RACP/1 HELLO" else {
      if lines[0].hasPrefix("RACP/") { throw RACPProtocolError.unsupportedVersion }
      throw RACPProtocolError.malformedMessage(fatal: true)
    }
    let peer = lines[1].split(separator: " ", omittingEmptySubsequences: false).map(String.init)
    guard peer.count == 3, peer[0] == "PEER" else {
      throw RACPProtocolError.malformedMessage(fatal: true)
    }
    var capabilities: [String] = []
    for line in lines.dropFirst(2).dropLast() {
      let fields = line.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
      guard fields.count == 2, fields[0] == "CAP" else {
        throw RACPProtocolError.malformedMessage(fatal: true)
      }
      capabilities.append(fields[1])
    }
    do {
      return try RACPHello(peerType: peer[1], peerID: peer[2], capabilities: capabilities)
    } catch {
      throw RACPProtocolError.malformedMessage(fatal: true)
    }
  }
}

private func validateRequestIDForSession(_ value: UInt64) throws {
  guard value > 0, value <= racpMaximumSafeInteger else {
    throw RACPProtocolError.malformedMessage()
  }
}
