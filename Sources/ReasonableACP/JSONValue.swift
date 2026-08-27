import Foundation

public struct JSONMember: Sendable, Equatable {
  public let key: String
  public let value: JSONValue

  public init(_ key: String, _ value: JSONValue) {
    self.key = key
    self.value = value
  }

  public static func == (lhs: JSONMember, rhs: JSONMember) -> Bool {
    scalarEqual(lhs.key, rhs.key) && lhs.value == rhs.value
  }
}

public enum JSONValue: Sendable, Equatable {
  case null
  case bool(Bool)
  case integer(Int64)
  case number(Double)
  case string(String)
  case array([JSONValue])
  case object([JSONMember])
}

extension JSONValue {
  public static func == (lhs: JSONValue, rhs: JSONValue) -> Bool {
    guard let left = try? lhs.encoded(), let right = try? rhs.encoded() else { return false }
    return scalarEqual(left, right)
  }

  public static func parse(_ text: String) throws -> JSONValue {
    var parser = JSONParser(text)
    let value = try parser.parse()
    return value
  }

  public func encoded() throws -> String {
    switch self {
    case .null: return "null"
    case .bool(let value): return value ? "true" : "false"
    case .integer(let value):
      guard value >= -9_007_199_254_740_991, value <= 9_007_199_254_740_991 else {
        throw RACPProtocolError.invalidValue
      }
      return String(value)
    case .number(let value): return try Self.encodeNumber(value)
    case .string(let value): return Self.encodeString(value)
    case .array(let values):
      return "[" + (try values.map { try $0.encoded() }).joined(separator: ",") + "]"
    case .object(let members):
      var seen: [String] = []
      for member in members {
        guard !seen.contains(where: { scalarEqual($0, member.key) }) else {
          throw RACPProtocolError.invalidValue
        }
        seen.append(member.key)
      }
      return "{"
        + (try members.sorted { Self.scalarLess($0.key, $1.key) }.map {
          Self.encodeString($0.key) + ":" + (try $0.value.encoded())
        }).joined(separator: ",") + "}"
    }
  }

  private static func scalarLess(_ lhs: String, _ rhs: String) -> Bool {
    lhs.unicodeScalars.lexicographicallyPrecedes(rhs.unicodeScalars) { $0.value < $1.value }
  }

  private static func encodeNumber(_ value: Double) throws -> String {
    guard value.isFinite else { throw RACPProtocolError.invalidValue }
    if value == 0 { return value.sign == .minus ? "-0.0" : "0.0" }
    return String(value).replacingOccurrences(of: "E", with: "e")
  }

  private static func encodeString(_ value: String) -> String {
    var result = "\""
    for scalar in value.unicodeScalars {
      switch scalar.value {
      case 0x08: result += "\\b"
      case 0x09: result += "\\t"
      case 0x0A: result += "\\n"
      case 0x0C: result += "\\f"
      case 0x0D: result += "\\r"
      case 0x22: result += "\\\""
      case 0x5C: result += "\\\\"
      case 0..<0x20: result += String(format: "\\u%04x", scalar.value)
      default: result.unicodeScalars.append(scalar)
      }
    }
    return result + "\""
  }
}

private struct JSONParser {
  private let scalars: [Unicode.Scalar]
  private var index = 0
  private static let maximumSafeInteger: Int64 = 9_007_199_254_740_991

  init(_ text: String) {
    scalars = Array(text.unicodeScalars)
  }

  mutating func parse() throws -> JSONValue {
    skipWhitespace()
    let value = try parseValue()
    skipWhitespace()
    guard index == scalars.count else { throw RACPProtocolError.invalidValue }
    return value
  }

  private mutating func parseValue() throws -> JSONValue {
    guard let scalar = peek else { throw RACPProtocolError.invalidValue }
    switch scalar.value {
    case 0x6E:
      try consume("null")
      return .null
    case 0x74:
      try consume("true")
      return .bool(true)
    case 0x66:
      try consume("false")
      return .bool(false)
    case 0x22: return .string(try parseString())
    case 0x5B: return try parseArray()
    case 0x7B: return try parseObject()
    case 0x2D, 0x30...0x39: return try parseNumber()
    default: throw RACPProtocolError.invalidValue
    }
  }

  private mutating func parseArray() throws -> JSONValue {
    index += 1
    skipWhitespace()
    var values: [JSONValue] = []
    if take(0x5D) { return .array(values) }
    while true {
      skipWhitespace()
      values.append(try parseValue())
      skipWhitespace()
      if take(0x5D) { return .array(values) }
      guard take(0x2C) else { throw RACPProtocolError.invalidValue }
    }
  }

  private mutating func parseObject() throws -> JSONValue {
    index += 1
    skipWhitespace()
    var members: [JSONMember] = []
    if take(0x7D) { return .object(members) }
    while true {
      skipWhitespace()
      guard take(0x22) else { throw RACPProtocolError.invalidValue }
      index -= 1
      let key = try parseString()
      guard !members.contains(where: { scalarEqual($0.key, key) }) else {
        throw RACPProtocolError.invalidValue
      }
      skipWhitespace()
      guard take(0x3A) else { throw RACPProtocolError.invalidValue }
      skipWhitespace()
      members.append(JSONMember(key, try parseValue()))
      skipWhitespace()
      if take(0x7D) { return .object(members) }
      guard take(0x2C) else { throw RACPProtocolError.invalidValue }
    }
  }

  private mutating func parseString() throws -> String {
    guard take(0x22) else { throw RACPProtocolError.invalidValue }
    var output = String.UnicodeScalarView()
    while let scalar = peek {
      index += 1
      if scalar.value == 0x22 { return String(output) }
      if scalar.value < 0x20 { throw RACPProtocolError.invalidValue }
      if scalar.value != 0x5C {
        output.append(scalar)
        continue
      }
      guard let escaped = peek else { throw RACPProtocolError.invalidValue }
      index += 1
      switch escaped.value {
      case 0x22, 0x2F, 0x5C: output.append(escaped)
      case 0x62: output.append("\u{8}")
      case 0x66: output.append("\u{C}")
      case 0x6E: output.append("\n")
      case 0x72: output.append("\r")
      case 0x74: output.append("\t")
      case 0x75:
        let first = try hexQuad()
        if (0xD800...0xDBFF).contains(first) {
          guard take(0x5C), take(0x75) else { throw RACPProtocolError.invalidValue }
          let second = try hexQuad()
          guard (0xDC00...0xDFFF).contains(second) else { throw RACPProtocolError.invalidValue }
          let combined = 0x10000 + ((first - 0xD800) << 10) + second - 0xDC00
          guard let decoded = Unicode.Scalar(combined) else { throw RACPProtocolError.invalidValue }
          output.append(decoded)
        } else {
          guard !(0xDC00...0xDFFF).contains(first), let decoded = Unicode.Scalar(first) else {
            throw RACPProtocolError.invalidValue
          }
          output.append(decoded)
        }
      default: throw RACPProtocolError.invalidValue
      }
    }
    throw RACPProtocolError.invalidValue
  }

  private mutating func hexQuad() throws -> UInt32 {
    var value: UInt32 = 0
    for _ in 0..<4 {
      guard let scalar = peek else { throw RACPProtocolError.invalidValue }
      index += 1
      let digit: UInt32
      switch scalar.value {
      case 0x30...0x39: digit = scalar.value - 0x30
      case 0x41...0x46: digit = scalar.value - 0x41 + 10
      case 0x61...0x66: digit = scalar.value - 0x61 + 10
      default: throw RACPProtocolError.invalidValue
      }
      value = value * 16 + digit
    }
    return value
  }

  private mutating func parseNumber() throws -> JSONValue {
    let start = index
    _ = take(0x2D)
    if take(0x30) {
      if let scalar = peek, (0x30...0x39).contains(scalar.value) {
        throw RACPProtocolError.invalidValue
      }
    } else {
      guard take(range: 0x31...0x39) else { throw RACPProtocolError.invalidValue }
      while take(range: 0x30...0x39) {}
    }
    var isInteger = true
    if take(0x2E) {
      isInteger = false
      guard take(range: 0x30...0x39) else { throw RACPProtocolError.invalidValue }
      while take(range: 0x30...0x39) {}
    }
    if take(0x65) || take(0x45) {
      isInteger = false
      _ = take(0x2B) || take(0x2D)
      guard take(range: 0x30...0x39) else { throw RACPProtocolError.invalidValue }
      while take(range: 0x30...0x39) {}
    }
    let token = String(String.UnicodeScalarView(scalars[start..<index]))
    if isInteger {
      guard let value = Int64(token),
        value >= -Self.maximumSafeInteger, value <= Self.maximumSafeInteger
      else {
        throw RACPProtocolError.invalidValue
      }
      return .integer(value)
    }
    guard let value = Double(token), value.isFinite else { throw RACPProtocolError.invalidValue }
    return .number(value)
  }

  private var peek: Unicode.Scalar? { index < scalars.count ? scalars[index] : nil }
  private mutating func skipWhitespace() {
    while let scalar = peek, [0x20, 0x09, 0x0A, 0x0D].contains(scalar.value) { index += 1 }
  }
  private mutating func take(_ value: UInt32) -> Bool {
    guard peek?.value == value else { return false }
    index += 1
    return true
  }
  private mutating func take(range: ClosedRange<UInt32>) -> Bool {
    guard let value = peek?.value, range.contains(value) else { return false }
    index += 1
    return true
  }
  private mutating func consume(_ text: String) throws {
    for scalar in text.unicodeScalars {
      guard take(scalar.value) else { throw RACPProtocolError.invalidValue }
    }
  }
}

private func scalarEqual(_ lhs: String, _ rhs: String) -> Bool {
  lhs.unicodeScalars.elementsEqual(rhs.unicodeScalars) { $0.value == $1.value }
}
