import Foundation

public let racpMaximumLineBytes = 16_384
public let racpMaximumSafeInteger: UInt64 = 9_007_199_254_740_991

public enum RACPProtocolError: Error, Sendable, Equatable {
  case malformedMessage(fatal: Bool = false)
  case invalidValue
  case lineTooLong
  case unsupportedVersion
  case handshakeRequired
  case unsupportedCapability

  public var code: String {
    switch self {
    case .malformedMessage: "malformed_message"
    case .invalidValue: "invalid_value"
    case .lineTooLong: "line_too_long"
    case .unsupportedVersion: "unsupported_version"
    case .handshakeRequired: "handshake_required"
    case .unsupportedCapability: "unsupported_capability"
    }
  }
}

public struct Command: Sendable, Equatable {
  public let requestID: UInt64
  public let name: String
  public let value: JSONValue?
  public let hasValue: Bool

  public init(requestID: UInt64, name: String, value: JSONValue? = nil, hasValue: Bool = false) {
    self.requestID = requestID
    self.name = name
    self.value = value
    self.hasValue = hasValue
  }

  public static func == (lhs: Command, rhs: Command) -> Bool {
    guard lhs.requestID == rhs.requestID, lhs.name == rhs.name, lhs.hasValue == rhs.hasValue else {
      return false
    }
    return !lhs.hasValue || (lhs.value ?? .null) == (rhs.value ?? .null)
  }
}

public struct StateMessage: Sendable, Equatable {
  public let name: String
  public let revision: UInt64
  public let value: JSONValue
  public init(name: String, revision: UInt64, value: JSONValue) {
    self.name = name
    self.revision = revision
    self.value = value
  }
}

public enum RACPMessage: Sendable, Equatable {
  case command(Command)
  case ack(UInt64)
  case error(UInt64, String)
  case state(StateMessage)
  case subscribe(UInt64, String)
  case unsubscribe(UInt64, String)
  case ping(UInt64)
  case pong(UInt64)
  case bye

  public static func parse(_ line: String) throws -> RACPMessage {
    guard !line.isEmpty, !line.hasPrefix(" "), !line.hasSuffix(" ") else {
      throw RACPProtocolError.malformedMessage()
    }
    guard !line.unicodeScalars.contains(where: { $0.value < 0x20 }) else {
      throw RACPProtocolError.malformedMessage(fatal: true)
    }

    let fields = line.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: false).map(
      String.init)
    switch fields.first {
    case "CMD" where fields.count == 3 || fields.count == 4:
      let id = try requestID(fields[1])
      try validateName(fields[2])
      return .command(
        Command(
          requestID: id,
          name: fields[2],
          value: fields.count == 4 ? try JSONValue.parse(fields[3]) : nil,
          hasValue: fields.count == 4
        ))
    case "ACK" where fields.count == 2: return .ack(try requestID(fields[1]))
    case "ERR" where fields.count == 3:
      try validateName(fields[2])
      return .error(try requestID(fields[1], allowZero: true), fields[2])
    case "STATE" where fields.count == 4:
      try validateName(fields[1])
      return .state(
        StateMessage(
          name: fields[1], revision: try requestID(fields[2], allowZero: true),
          value: try JSONValue.parse(fields[3])
        ))
    case "SUB" where fields.count == 3:
      try validateName(fields[2])
      return .subscribe(try requestID(fields[1]), fields[2])
    case "UNSUB" where fields.count == 3:
      try validateName(fields[2])
      return .unsubscribe(try requestID(fields[1]), fields[2])
    case "PING" where fields.count == 2: return .ping(try requestID(fields[1]))
    case "PONG" where fields.count == 2: return .pong(try requestID(fields[1]))
    case "BYE" where fields.count == 1: return .bye
    default: throw RACPProtocolError.malformedMessage()
    }
  }

  public func encoded() throws -> String {
    switch self {
    case .command(let command):
      try validateRequestID(command.requestID)
      try validateName(command.name)
      let base = "CMD \(command.requestID) \(command.name)"
      guard command.hasValue else { return base }
      return base + " " + (try (command.value ?? .null).encoded())
    case .ack(let id):
      try validateRequestID(id)
      return "ACK \(id)"
    case .error(let id, let code):
      try validateRequestID(id, allowZero: true)
      try validateName(code)
      return "ERR \(id) \(code)"
    case .state(let state):
      try validateName(state.name)
      try validateRequestID(state.revision, allowZero: true)
      return "STATE \(state.name) \(state.revision) \(try state.value.encoded())"
    case .subscribe(let id, let name):
      try validateRequestID(id)
      try validateName(name)
      return "SUB \(id) \(name)"
    case .unsubscribe(let id, let name):
      try validateRequestID(id)
      try validateName(name)
      return "UNSUB \(id) \(name)"
    case .ping(let id):
      try validateRequestID(id)
      return "PING \(id)"
    case .pong(let id):
      try validateRequestID(id)
      return "PONG \(id)"
    case .bye: return "BYE"
    }
  }
}

func validateName(_ value: String) throws {
  guard value.utf8.count <= 128, let first = value.utf8.first, (0x61...0x7A).contains(first) else {
    throw RACPProtocolError.malformedMessage()
  }
  var afterDot = false
  for byte in value.utf8.dropFirst() {
    if byte == 0x2E {
      guard !afterDot else { throw RACPProtocolError.malformedMessage() }
      afterDot = true
    } else {
      let valid = (0x61...0x7A).contains(byte) || (0x30...0x39).contains(byte) || byte == 0x5F
      guard valid, !afterDot || (0x61...0x7A).contains(byte) else {
        throw RACPProtocolError.malformedMessage()
      }
      afterDot = false
    }
  }
  guard !afterDot else { throw RACPProtocolError.malformedMessage() }
}

func validatePeer(_ value: String) throws {
  let bytes = Array(value.utf8)
  guard (1...64).contains(bytes.count),
    bytes.allSatisfy({
      (0x41...0x5A).contains($0) || (0x61...0x7A).contains($0) || (0x30...0x39).contains($0)
        || [0x2E, 0x5F, 0x2D].contains($0)
    }), let first = bytes.first, first != 0x2E, first != 0x5F, first != 0x2D
  else {
    throw RACPProtocolError.malformedMessage()
  }
}

private func requestID(_ token: String, allowZero: Bool = false) throws -> UInt64 {
  guard token == "0" ? allowZero : token.first != "0", token.allSatisfy(\.isNumber),
    let value = UInt64(token)
  else {
    throw RACPProtocolError.malformedMessage()
  }
  try validateRequestID(value, allowZero: allowZero)
  return value
}

private func validateRequestID(_ value: UInt64, allowZero: Bool = false) throws {
  guard value <= racpMaximumSafeInteger, allowZero || value > 0 else {
    throw RACPProtocolError.malformedMessage()
  }
}
