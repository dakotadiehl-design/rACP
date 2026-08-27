import Foundation
@_spi(RACPTesting) import ReasonableACP

final class InteropRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var commandsStorage: [Command] = []
  private var statesStorage: [StateMessage] = []
  private var connectionStorage: RACPConnection?

  func command(_ value: Command) { lock.withLock { commandsStorage.append(value) } }
  func state(_ value: StateMessage) { lock.withLock { statesStorage.append(value) } }
  func connection(_ value: RACPConnection) { lock.withLock { connectionStorage = value } }
  var commands: [Command] { lock.withLock { commandsStorage } }
  var states: [StateMessage] { lock.withLock { statesStorage } }
  var connection: RACPConnection? { lock.withLock { connectionStorage } }
}

@main
enum InteropPeer {
  static func main() async throws {
    guard CommandLine.arguments.count >= 2 else { throw RACPConnectionError.connectionLost }
    if CommandLine.arguments[1] == "client" {
      try await client(host: CommandLine.arguments[2], port: UInt16(CommandLine.arguments[3])!)
    } else if CommandLine.arguments[1] == "server" {
      try await server(port: UInt16(CommandLine.arguments[2])!)
    } else {
      throw RACPConnectionError.connectionLost
    }
  }

  private static func hello(_ type: String, _ id: String) throws -> RACPHello {
    try RACPHello(
      peerType: type, peerID: id,
      capabilities: ["cue.current", "cue.go", "cue.null", "state.subscribe"])
  }

  private static func client(host: String, port: UInt16) async throws {
    let recorder = InteropRecorder()
    let stream = try await NetworkByteStream.connect(host: host, port: port)
    let session = RACPSession(
      local: try hello("remote", "swift-client"),
      stateHandler: { recorder.state($0) })
    let connection = RACPConnection(stream: stream, session: session)
    let run = Task { await connection.run() }
    _ = try await connection.waitUntilReady()
    try await connection.command("cue.go")
    try await connection.command("cue.null", arguments: .null)
    try await connection.subscribe("cue.current")
    for _ in 0..<100 where recorder.states.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
    guard recorder.states.last?.revision == 3 else { throw RACPConnectionError.connectionLost }
    try await connection.unsubscribe("cue.current")
    try await connection.send(.ping(7))
    try await connection.sendRawRequests(.command(Command(requestID: 99, name: "cue.go")))
    try await connection.sendRawRequests(.command(Command(requestID: 99, name: "cue.go")))
    try await connection.sendRawRequests(
      .command(Command(requestID: 99, name: "cue.null", value: .null, hasValue: true)))
    try await Task.sleep(for: .milliseconds(50))
    try await connection.send(.bye)
    await run.value
    print("SWIFT_CLIENT_OK")
  }

  private static func server(port: UInt16) async throws {
    let recorder = InteropRecorder()
    let local = try hello("device", "swift-server")
    let server = try RACPNetworkServer(
      port: port,
      connectionHandler: { recorder.connection($0) },
      sessionFactory: {
        RACPSession(
          local: local,
          commandHandler: { command in
            recorder.command(command)
            return nil
          })
      })
    try await server.start()
    print("PORT \(server.port!)")
    fflush(stdout)
    var published = false
    for _ in 0..<500 {
      if recorder.commands.count >= 4, let connection = recorder.connection {
        do {
          try await connection.send(
            .state(StateMessage(name: "cue.current", revision: 3, value: .string("ready"))))
          published = true
        } catch {}
      }
      if published { break }
      try await Task.sleep(for: .milliseconds(10))
    }
    let commands = recorder.commands
    guard
      commands.contains(where: { $0.requestID == 1 && !$0.hasValue }),
      commands.contains(where: { $0.requestID == 2 && $0.hasValue && $0.value == .null }),
      commands.filter({ $0.requestID == 99 }).count == 1,
      commands.contains(where: {
        $0.requestID == 5
          && $0.value
            == .object([JSONMember("a", .integer(1)), JSONMember("label", .string("A  B"))])
      })
    else { throw RACPConnectionError.connectionLost }
    try await Task.sleep(for: .milliseconds(200))
    server.cancel()
    print("SWIFT_SERVER_OK \(commands.count)")
  }
}
