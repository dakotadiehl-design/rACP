import Foundation

public struct RACPLineDecoder: Sendable {
  public let maximum: Int
  private var buffer = Data()
  private var discarding = false

  public init(maximum: Int = racpMaximumLineBytes) {
    precondition(maximum > 0)
    self.maximum = maximum
  }

  public mutating func feed(_ data: Data) throws -> [String] {
    var lines: [String] = []
    for byte in data {
      if discarding {
        if byte == 0x0A { discarding = false }
        continue
      }
      if byte == 0x0A {
        if buffer.last == 0x0D { buffer.removeLast() }
        guard !buffer.isEmpty else { throw RACPProtocolError.malformedMessage() }
        guard let line = String(data: buffer, encoding: .utf8) else {
          throw RACPProtocolError.malformedMessage(fatal: true)
        }
        buffer.removeAll(keepingCapacity: true)
        lines.append(line)
      } else {
        buffer.append(byte)
        let possibleCRLF = buffer.count == maximum + 1 && byte == 0x0D
        if buffer.count > maximum && !possibleCRLF {
          buffer.removeAll(keepingCapacity: true)
          discarding = true
          throw RACPProtocolError.lineTooLong
        }
      }
    }
    return lines
  }

  public mutating func eof() {
    buffer.removeAll(keepingCapacity: true)
    discarding = false
  }
}
