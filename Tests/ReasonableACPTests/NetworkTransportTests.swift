#if canImport(Network)
  import Foundation
  import Network
  import Testing
  @testable import ReasonableACP

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
#endif
