import Foundation
import Testing

@testable import ReasonableACP

final class CommandRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [Command] = []
  func append(_ command: Command) { lock.withLock { storage.append(command) } }
  var commands: [Command] { lock.withLock { storage } }
}

private actor MemoryByteStream: RACPByteStream {
  private var reads: [Data]
  private(set) var writes: [Data] = []
  private(set) var isClosed = false

  init(reads: [Data]) { self.reads = reads }

  func read(maximum _: Int) async throws -> Data {
    reads.isEmpty ? Data() : reads.removeFirst()
  }

  func write(_ data: Data) async throws { writes.append(data) }
  func close() async { isClosed = true }

  var output: Data { writes.reduce(into: Data()) { $0.append($1) } }
}

@Test func memoryTransportHandshakeCommandAndClose() async throws {
  let applied = CommandRecorder()
  let peer = Data("RACP/1 HELLO\nPEER remote desk\nCAP cue.go\nEND\nCMD 1 cue.go\nBYE\n".utf8)
  let stream = MemoryByteStream(reads: [
    peer.prefix(7), peer.dropFirst(7).prefix(26), peer.dropFirst(33),
  ])
  let session = RACPSession(
    local: try RACPHello(peerType: "device", peerID: "prism", capabilities: ["cue.go"]),
    commandHandler: { command in
      applied.append(command)
      return nil
    }
  )
  let connection = RACPConnection(stream: stream, session: session)
  await connection.run()
  let output = String(decoding: await stream.output, as: UTF8.self)
  #expect(output.hasPrefix("RACP/1 HELLO\nPEER device prism\nCAP cue.go\nEND\n"))
  #expect(output.contains("ACK 1\n"))
  #expect(applied.commands == [Command(requestID: 1, name: "cue.go")])
  #expect(await connection.closeReason == "peer_bye")
  #expect(await stream.isClosed)
}

@Test func outputQueueIsBoundedByMessage() async throws {
  let stream = MemoryByteStream(reads: [])
  let session = RACPSession(local: try RACPHello(peerType: "device", peerID: "x"))
  for line in ["RACP/1 HELLO", "PEER remote desk", "END"] { _ = try session.receive(line: line) }
  let connection = RACPConnection(stream: stream, session: session, outputMessages: 1)
  try await connection.send(.ack(1))
  await #expect(throws: RACPConnectionError.outputQueueFull) { try await connection.send(.ack(2)) }
  #expect(await stream.isClosed)
}

@Test func publicSendRejectsManualRequestIDs() async throws {
  let stream = MemoryByteStream(reads: [])
  let session = RACPSession(local: try RACPHello(peerType: "device", peerID: "x"))
  for line in ["RACP/1 HELLO", "PEER remote desk", "END"] {
    _ = try session.receive(line: line)
  }
  let connection = RACPConnection(stream: stream, session: session)
  for message in [
    RACPMessage.command(Command(requestID: 17, name: "cue.go")),
    .subscribe(17, "cue.current"),
    .unsubscribe(17, "cue.current"),
  ] {
    await #expect(throws: RACPConnectionError.manualRequestIDNotAllowed) {
      try await connection.send(message)
    }
  }
  #expect(await stream.output.isEmpty)
}

@Test func oversizedBatchIsRejectedAtomically() async throws {
  let stream = MemoryByteStream(reads: [])
  let session = RACPSession(local: try RACPHello(peerType: "device", peerID: "x"))
  for line in ["RACP/1 HELLO", "PEER remote desk", "END"] { _ = try session.receive(line: line) }
  let connection = RACPConnection(stream: stream, session: session, outputMessages: 2)
  await #expect(throws: RACPConnectionError.outputQueueFull) {
    try await connection.send(.ack(1), .ack(2), .ack(3))
  }
  #expect(await stream.output.isEmpty)
}

@Test func reconnectBackoffIsCapped() {
  let policy = RACPReconnectPolicy(initial: 0.25, maximum: 1, jitter: 0)
  #expect(
    [0, 1, 2, 3, 4].map { policy.delay(attempt: $0) } == [
      .milliseconds(250), .milliseconds(500), .seconds(1), .seconds(1), .seconds(1),
    ])
}
