#if canImport(Network)
  import Foundation
  import Network

  private final class ResumeGate: @unchecked Sendable {
    private let lock = NSLock()
    private var resumed = false

    func claim() -> Bool {
      lock.lock()
      defer { lock.unlock() }
      guard !resumed else { return false }
      resumed = true
      return true
    }
  }

  public final class NetworkByteStream: RACPByteStream, @unchecked Sendable {
    private let connection: NWConnection

    public init(connection: NWConnection) { self.connection = connection }

    public static func connect(host: String, port: UInt16) async throws -> NetworkByteStream {
      let connection = NWConnection(
        host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!,
        using: racpTCPParameters()
      )
      let stream = NetworkByteStream(connection: connection)
      try await stream.start()
      return stream
    }

    public func start() async throws {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, any Error>) in
        let gate = ResumeGate()
        connection.stateUpdateHandler = { state in
          switch state {
          case .ready:
            guard gate.claim() else { return }
            continuation.resume()
          case .failed(let error), .waiting(let error):
            guard gate.claim() else { return }
            continuation.resume(throwing: error)
          case .cancelled:
            guard gate.claim() else { return }
            continuation.resume(throwing: RACPConnectionError.connectionLost)
          default: break
          }
        }
        connection.start(queue: DispatchQueue(label: "org.aurora.racp.connection"))
      }
    }

    public func read(maximum: Int) async throws -> Data {
      try await withCheckedThrowingContinuation { continuation in
        connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) {
          data, _, complete, error in
          if let error {
            continuation.resume(throwing: error)
          } else if let data {
            continuation.resume(returning: data)
          } else if complete {
            continuation.resume(returning: Data())
          } else {
            continuation.resume(throwing: RACPConnectionError.connectionLost)
          }
        }
      }
    }

    public func write(_ data: Data) async throws {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, any Error>) in
        connection.send(
          content: data,
          completion: .contentProcessed { error in
            if let error { continuation.resume(throwing: error) } else { continuation.resume() }
          })
      }
    }

    public func close() async { connection.cancel() }
  }

  public final class RACPNetworkServer: @unchecked Sendable {
    private let listener: NWListener
    private let sessionFactory: @Sendable () -> RACPSession
    private let maximumConnections: Int
    private let lock = NSLock()
    private var activeConnections = 0

    public init(
      port: UInt16,
      maximumConnections: Int = 64,
      sessionFactory: @escaping @Sendable () -> RACPSession
    ) throws {
      guard maximumConnections > 0, let port = NWEndpoint.Port(rawValue: port) else {
        throw RACPConnectionError.connectionLost
      }
      listener = try NWListener(using: racpTCPParameters(), on: port)
      self.maximumConnections = maximumConnections
      self.sessionFactory = sessionFactory
    }

    public func start(queue: DispatchQueue = DispatchQueue(label: "org.aurora.racp.listener")) {
      listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
      listener.start(queue: queue)
    }

    public func cancel() { listener.cancel() }

    private func accept(_ connection: NWConnection) {
      lock.lock()
      guard activeConnections < maximumConnections else {
        lock.unlock()
        connection.cancel()
        return
      }
      activeConnections += 1
      lock.unlock()
      Task {
        let stream = NetworkByteStream(connection: connection)
        do {
          try await stream.start()
          await RACPConnection(stream: stream, session: sessionFactory()).run()
        } catch {
          await stream.close()
        }
        lock.withLock { activeConnections -= 1 }
      }
    }
  }

  private func racpTCPParameters() -> NWParameters {
    let tcp = NWProtocolTCP.Options()
    tcp.enableKeepalive = true
    return NWParameters(tls: nil, tcp: tcp)
  }
#endif
