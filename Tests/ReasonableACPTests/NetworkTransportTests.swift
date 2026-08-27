#if canImport(Network)
  import Foundation
  import Network
  import Testing
  @testable import ReasonableACP

  private func receiveUntilCommandThenClose(_ connection: NWConnection) {
    connection.receive(minimumIncompleteLength: 1, maximumLength: 4_096) { data, _, complete, _ in
      if let data, String(decoding: data, as: UTF8.self).contains("CMD ") {
        connection.cancel()
      } else if !complete {
        receiveUntilCommandThenClose(connection)
      }
    }
  }

  @Test func networkByteStreamLoopback() async throws {
    let listener = try NWListener(using: .tcp, on: .any)
    let queue = DispatchQueue(label: "org.aurora.racp.tests.loopback")
    listener.newConnectionHandler = { connection in
      connection.start(queue: queue)
      connection.receive(minimumIncompleteLength: 1, maximumLength: 4_096) { data, _, _, error in
        guard error == nil, let data else {
          connection.cancel()
          return
        }
        connection.send(content: data, completion: .contentProcessed { _ in connection.cancel() })
      }
    }

    let states = AsyncStream<NWListener.State> { continuation in
      listener.stateUpdateHandler = { continuation.yield($0) }
    }
    listener.start(queue: queue)
    var ready = false
    for await state in states {
      switch state {
      case .ready: ready = true
      case .failed(let error): throw error
      default: continue
      }
      break
    }
    #expect(ready)
    let port = try #require(listener.port?.rawValue)

    let stream = try await NetworkByteStream.connect(host: "127.0.0.1", port: port)
    let payload = Data("PING 7\n".utf8)
    try await stream.write(payload)
    #expect(try await stream.read(maximum: 4_096) == payload)
    await stream.close()
    listener.cancel()
  }

  @Test func productionTCPConversationAndCorrelation() async throws {
    let applied = CommandRecorder()
    let serverHello = try RACPHello(peerType: "device", peerID: "server", capabilities: ["cue.go"])
    let server = try RACPNetworkServer(port: 0) {
      RACPSession(
        local: serverHello,
        commandHandler: { command in
          applied.append(command)
          return nil
        })
    }
    try await server.start()
    let port = try #require(server.port)

    let stream = try await NetworkByteStream.connect(host: "127.0.0.1", port: port)
    let session = RACPSession(
      local: try RACPHello(peerType: "remote", peerID: "client", capabilities: ["cue.go"]))
    let connection = RACPConnection(stream: stream, session: session)
    let states = await connection.stateUpdates()
    let run = Task { await connection.run() }
    let peer = try await connection.waitUntilReady()
    #expect(peer.peerID == "server")

    try await connection.command("cue.go", arguments: .object([JSONMember("number", .integer(7))]))
    await #expect(throws: RACPRemoteError(requestID: 2, code: "unsupported_capability")) {
      try await connection.command("cue.stop")
    }
    try await withThrowingTaskGroup(of: Void.self) { group in
      for number in 0..<8 {
        group.addTask { try await connection.command("cue.go", arguments: .integer(Int64(number))) }
      }
      try await group.waitForAll()
    }
    #expect(applied.commands.count == 9)

    await connection.close(reason: "test_complete")
    await run.value
    var observedReady = false
    var observedDisconnect = false
    for await state in states {
      if case .ready = state { observedReady = true }
      if case .disconnected = state { observedDisconnect = true }
    }
    #expect(observedReady && observedDisconnect)
    server.cancel()
  }

  @Test func pendingRequestFailsWhenTCPDisconnects() async throws {
    let listener = try NWListener(using: .tcp, on: .any)
    let queue = DispatchQueue(label: "org.aurora.racp.tests.pending-disconnect")
    listener.newConnectionHandler = { connection in
      connection.start(queue: queue)
      connection.send(
        content: Data("RACP/1 HELLO\nPEER device dropper\nCAP cue.go\nEND\n".utf8),
        completion: .contentProcessed { error in
          if error == nil { receiveUntilCommandThenClose(connection) }
        })
    }
    let states = AsyncStream<NWListener.State> { continuation in
      listener.stateUpdateHandler = { continuation.yield($0) }
    }
    listener.start(queue: queue)
    for await state in states {
      if case .ready = state { break }
      if case .failed(let error) = state { throw error }
    }
    let port = try #require(listener.port?.rawValue)
    let stream = try await NetworkByteStream.connect(host: "127.0.0.1", port: port)
    let session = RACPSession(
      local: try RACPHello(peerType: "remote", peerID: "client", capabilities: ["cue.go"]))
    let connection = RACPConnection(stream: stream, session: session)
    let run = Task { await connection.run() }
    _ = try await connection.waitUntilReady()
    await #expect(throws: RACPConnectionError.self) {
      try await connection.command("cue.go", timeout: .seconds(1))
    }
    await run.value
    listener.cancel()
  }

  @Test func pendingRequestTimesOutWithoutTerminalResponse() async throws {
    let listener = try NWListener(using: .tcp, on: .any)
    let queue = DispatchQueue(label: "org.aurora.racp.tests.pending-timeout")
    listener.newConnectionHandler = { connection in
      connection.start(queue: queue)
      connection.send(
        content: Data("RACP/1 HELLO\nPEER device silent\nCAP cue.go\nEND\n".utf8),
        completion: .contentProcessed { error in
          if error == nil {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4_096) { _, _, _, _ in }
          }
        })
    }
    let states = AsyncStream<NWListener.State> { continuation in
      listener.stateUpdateHandler = { continuation.yield($0) }
    }
    listener.start(queue: queue)
    for await state in states {
      if case .ready = state { break }
      if case .failed(let error) = state { throw error }
    }
    let stream = try await NetworkByteStream.connect(
      host: "127.0.0.1", port: try #require(listener.port?.rawValue))
    let session = RACPSession(
      local: try RACPHello(peerType: "remote", peerID: "client", capabilities: ["cue.go"]))
    let connection = RACPConnection(stream: stream, session: session)
    let run = Task { await connection.run() }
    _ = try await connection.waitUntilReady()
    await #expect(throws: RACPConnectionError.requestTimeout) {
      try await connection.command("cue.go", timeout: .milliseconds(20))
    }
    await connection.close(reason: "test_complete")
    await run.value
    listener.cancel()
  }

  @Test func malformedMessageReturnsErrorAndClosesProductionTCP() async throws {
    let local = try RACPHello(peerType: "device", peerID: "malformed-test")
    let server = try RACPNetworkServer(port: 0) { RACPSession(local: local) }
    try await server.start()
    let stream = try await NetworkByteStream.connect(
      host: "127.0.0.1", port: try #require(server.port))
    let serverHello = try await stream.read(maximum: 4_096)
    #expect(String(decoding: serverHello, as: UTF8.self).contains("RACP/1 HELLO"))
    try await stream.write(Data("RACP/1 HELLO\nPEER remote malformed\nEND\nWAT 1\n".utf8))
    let response = try await stream.read(maximum: 4_096)
    #expect(String(decoding: response, as: UTF8.self).contains("ERR 0 malformed_message\n"))
    await stream.close()
    server.cancel()
  }
#endif
