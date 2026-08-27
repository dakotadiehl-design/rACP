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

  private final class ConnectionStore: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [RACPConnection] = []
    func append(_ connection: RACPConnection) { lock.withLock { storage.append(connection) } }
    var connections: [RACPConnection] { lock.withLock { storage } }
  }

  private final class StateRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [StateMessage] = []
    func append(_ state: StateMessage) { lock.withLock { storage.append(state) } }
    var states: [StateMessage] { lock.withLock { storage } }
  }

  private actor AsyncExecutionRecorder {
    private var started = 0
    private var completed = 0
    func start() { started += 1 }
    func complete() { completed += 1 }
    func counts() -> (Int, Int) { (started, completed) }
  }

  private func waitForConnections(_ store: ConnectionStore, count: Int) async throws {
    for _ in 0..<100 {
      if store.connections.count >= count { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw RACPConnectionError.connectionLost
  }

  private func waitForStates(_ recorder: StateRecorder, count: Int) async throws {
    for _ in 0..<100 {
      if recorder.states.count >= count { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw RACPConnectionError.connectionLost
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
    var currentState = (await connection.stateUpdates()).makeAsyncIterator()
    #expect(await currentState.next() == .ready(peer))

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
    await #expect(throws: RACPConnectionError.disconnected("test_complete")) {
      try await connection.waitUntilReady()
    }
    var observedReady = false
    var observedDisconnect = false
    for await state in states {
      if case .ready = state { observedReady = true }
      if case .disconnected = state { observedDisconnect = true }
    }
    #expect(observedReady && observedDisconnect)
    server.cancel()
  }

  @Test func subscriptionEventsAndPublicationArePerConnection() async throws {
    let hosts = ConnectionStore()
    let hello = try RACPHello(
      peerType: "device", peerID: "publisher",
      capabilities: ["cue.current", "state.subscribe"])
    let server = try RACPNetworkServer(
      port: 0, connectionHandler: { hosts.append($0) },
      sessionFactory: { RACPSession(local: hello) })
    try await server.start()
    let port = try #require(server.port)

    let firstStates = StateRecorder()
    let first = RACPConnection(
      stream: try await NetworkByteStream.connect(host: "127.0.0.1", port: port),
      session: RACPSession(
        local: try RACPHello(peerType: "remote", peerID: "first"),
        stateHandler: { firstStates.append($0) }))
    let firstRun = Task { await first.run() }
    _ = try await first.waitUntilReady()
    try await waitForConnections(hosts, count: 1)
    let firstHost = hosts.connections[0]
    var events = (await firstHost.subscriptionUpdates()).makeAsyncIterator()

    await #expect(throws: RACPRemoteError.self) { try await first.subscribe("unknown.state") }
    try await first.subscribe("cue.current")
    #expect(await events.next() == .subscribed("cue.current"))
    let initial = StateMessage(name: "cue.current", revision: 1, value: .integer(7))
    #expect(try await firstHost.publish(initial) == .published)
    try await waitForStates(firstStates, count: 1)
    #expect(firstStates.states == [initial])
    await #expect(throws: RACPProtocolError.invalidValue) {
      try await firstHost.publish(
        StateMessage(name: "cue.current", revision: 1, value: .integer(8)))
    }

    try await first.subscribe("cue.current")
    #expect(await events.next() == .subscribed("cue.current"))
    try await first.unsubscribe("cue.current")
    #expect(await events.next() == .unsubscribed("cue.current"))
    #expect(
      try await firstHost.publish(
        StateMessage(name: "cue.current", revision: 2, value: .integer(9))) == .notSubscribed)

    let second = RACPConnection(
      stream: try await NetworkByteStream.connect(host: "127.0.0.1", port: port),
      session: RACPSession(local: try RACPHello(peerType: "remote", peerID: "second")))
    let secondRun = Task { await second.run() }
    _ = try await second.waitUntilReady()
    try await waitForConnections(hosts, count: 2)
    #expect(
      try await hosts.connections[1].publish(
        StateMessage(name: "cue.current", revision: 1, value: .integer(1))) == .notSubscribed)

    await first.close(reason: "test_complete")
    await second.close(reason: "test_complete")
    await firstRun.value
    await secondRun.value
    server.cancel()
  }

  @Test func asyncCommandsRunConcurrentlyAcrossClientsAndSurviveDisconnect() async throws {
    let execution = AsyncExecutionRecorder()
    let hello = try RACPHello(peerType: "device", peerID: "async", capabilities: ["cue.go"])
    let server = try RACPNetworkServer(port: 0) {
      RACPSession(
        local: hello,
        asyncCommandHandler: { _ in
          await execution.start()
          try await Task.sleep(for: .milliseconds(30))
          await execution.complete()
          return .success
        })
    }
    try await server.start()
    let port = try #require(server.port)
    func client(_ id: String) async throws -> (RACPConnection, Task<Void, Never>) {
      let connection = RACPConnection(
        stream: try await NetworkByteStream.connect(host: "127.0.0.1", port: port),
        session: RACPSession(
          local: try RACPHello(peerType: "remote", peerID: id, capabilities: ["cue.go"])))
      let run = Task { await connection.run() }
      _ = try await connection.waitUntilReady()
      return (connection, run)
    }
    let (first, firstRun) = try await client("first")
    let (second, secondRun) = try await client("second")
    async let firstCommand: Void = first.command("cue.go")
    async let secondCommand: Void = second.command("cue.go")
    try await firstCommand
    try await secondCommand
    #expect(await execution.counts().0 == 2)

    let disconnected = Task { try await first.command("cue.go") }
    for _ in 0..<100 {
      if await execution.counts().0 == 3 { break }
      try await Task.sleep(for: .milliseconds(2))
    }
    await first.close(reason: "client_disconnect")
    await #expect(throws: RACPConnectionError.disconnected("client_disconnect")) {
      try await disconnected.value
    }
    for _ in 0..<100 {
      if await execution.counts().1 == 3 { break }
      try await Task.sleep(for: .milliseconds(2))
    }
    #expect(await execution.counts().1 == 3)

    await second.close(reason: "test_complete")
    await firstRun.value
    await secondRun.value
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
    let cancelled = Task { try await connection.command("cue.go", timeout: .seconds(1)) }
    try await Task.sleep(for: .milliseconds(10))
    cancelled.cancel()
    await #expect(throws: RACPConnectionError.cancelled) { try await cancelled.value }

    let locallyDisconnected = Task { try await connection.command("cue.go", timeout: .seconds(1)) }
    try await Task.sleep(for: .milliseconds(10))
    await connection.close(reason: "test_complete")
    await #expect(throws: RACPConnectionError.disconnected("test_complete")) {
      try await locallyDisconnected.value
    }
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
