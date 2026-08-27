import Foundation
import Testing

@testable import ReasonableACP

private func established(
  clock: @escaping () -> TimeInterval = { 0 },
  ledgerSize: Int = 1_024,
  handler: @escaping RACPSession.CommandHandler = { _ in nil }
) throws -> RACPSession {
  let session = RACPSession(
    local: try RACPHello(
      peerType: "device", peerID: "prism-main",
      capabilities: ["cue.current", "cue.go", "state.subscribe"]
    ),
    ledgerSize: ledgerSize,
    now: clock,
    commandHandler: handler
  )
  for line in ["RACP/1 HELLO", "PEER remote desk", "CAP cue.go", "END"] {
    _ = try session.receive(line: line)
  }
  return session
}

@Test func goldenHelloParsesExactly() throws {
  let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent()
  let lines = try String(
    contentsOf: root.appending(path: "vectors/racp-v1/hello.txt"), encoding: .utf8
  )
  .split(separator: "\n").map(String.init)
  let session = RACPSession(local: try RACPHello(peerType: "diagnostic", peerID: "test"))
  for line in lines { _ = try session.receive(line: line) }
  #expect(session.peer?.lines == lines)
  #expect(session.state == .established)
}

@Test func commandCapabilityAndLedger() throws {
  var applied: [Command] = []
  let session = try established(handler: { command in
    applied.append(command)
    return nil
  })
  let command = Command(requestID: 1, name: "cue.go")
  #expect(try session.receive(message: .command(command)) == [.ack(1)])
  #expect(try session.receive(message: .command(command)) == [.ack(1)])
  #expect(applied == [command])
  #expect(
    try session.receive(
      message: .command(Command(requestID: 1, name: "cue.go", value: .null, hasValue: true))) == [
        .error(1, "request_id_conflict")
      ])
  #expect(
    try session.receive(message: .command(Command(requestID: 2, name: "cue.back"))) == [
      .error(2, "unsupported_capability")
    ])
}

@Test func duplicateCommandUsesCanonicalJSONIdentity() throws {
  var applied: [Command] = []
  let session = try established(handler: { command in
    applied.append(command)
    return nil
  })
  let first = JSONValue.object([JSONMember("a", .integer(1)), JSONMember("b", .integer(2))])
  let reordered = JSONValue.object([JSONMember("b", .integer(2)), JSONMember("a", .integer(1))])
  #expect(
    try session.receive(
      message: .command(Command(requestID: 1, name: "cue.go", value: first, hasValue: true))) == [
        .ack(1)
      ])
  #expect(
    try session.receive(
      message: .command(Command(requestID: 1, name: "cue.go", value: reordered, hasValue: true)))
      == [.ack(1)])
  #expect(
    try session.receive(
      message: .command(Command(requestID: 1, name: "cue.go", value: .bool(true), hasValue: true)))
      == [.error(1, "request_id_conflict")])
  #expect(applied.count == 1)

  let noValue = Command(requestID: 2, name: "cue.go")
  #expect(try session.receive(message: .command(noValue)) == [.ack(2)])
  #expect(
    try session.receive(
      message: .command(Command(requestID: 2, name: "cue.go", value: .string("ignored")))) == [
        .ack(2)
      ])
}

@Test func subscriptionsAndStateRevision() throws {
  let session = try established()
  #expect(try session.receive(message: .subscribe(1, "cue.current")) == [.ack(1)])
  #expect(
    try session.receive(message: .subscribe(2, "unknown.state")) == [
      .error(2, "unsupported_capability")
    ])
  _ = try session.receive(
    message: .state(StateMessage(name: "cue.current", revision: 3, value: .integer(10))))
  _ = try session.receive(
    message: .state(StateMessage(name: "cue.current", revision: 2, value: .integer(9))))
  #expect(session.stateRevisions == ["cue.current": 3])
}

@Test func heartbeatRequiresMatchingPong() throws {
  var time: TimeInterval = 0
  let session = try established(clock: { time })
  time = 10
  #expect(try session.heartbeat(nonce: 7) == [.ping(7)])
  _ = try session.receive(message: .pong(8))
  #expect(session.outstandingPing?.nonce == 7)
  _ = try session.receive(message: .pong(7))
  #expect(session.outstandingPing == nil)
  time = 20
  _ = try session.heartbeat(nonce: 8)
  time = 25
  #expect(throws: RACPSessionError.self) { try session.heartbeat(nonce: 9) }
}
