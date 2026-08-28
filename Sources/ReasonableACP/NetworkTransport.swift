#if canImport(Network)
  import Foundation
  import Network

  private final class ResumeGate: @unchecked Sendable {
    private let lock = NSLock()
    private var resumed = false
    private var timeout: DispatchWorkItem?

    func install(timeout: DispatchWorkItem) {
      lock.lock()
      if resumed {
        lock.unlock()
        timeout.cancel()
      } else {
        self.timeout = timeout
        lock.unlock()
      }
    }

    func claim() -> Bool {
      lock.lock()
      guard !resumed else {
        lock.unlock()
        return false
      }
      resumed = true
      let timeout = timeout
      self.timeout = nil
      lock.unlock()
      timeout?.cancel()
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

    public static func connect(endpoint: RACPNetworkEndpoint) async throws -> NetworkByteStream {
      let networkEndpoint: NWEndpoint
      if let retained = endpoint.platformEndpoint as? NWEndpoint {
        networkEndpoint = retained
      } else {
        switch endpoint.kind {
        case .hostPort(let host, let port):
          guard let networkPort = NWEndpoint.Port(rawValue: port) else {
            throw RACPNetworkDiscoveryError.invalidConfiguration
          }
          networkEndpoint = .hostPort(host: NWEndpoint.Host(host), port: networkPort)
        case .service(let name, let type, let domain, _):
          networkEndpoint = .service(name: name, type: type, domain: domain, interface: nil)
        }
      }
      let connection = NWConnection(to: networkEndpoint, using: racpTCPParameters())
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
          case .failed(let error):
            guard gate.claim() else { return }
            continuation.resume(throwing: error)
          case .waiting:
            // Waiting may recover after a network path change. The bounded
            // startup timer remains authoritative while Network retries.
            break
          case .cancelled:
            guard gate.claim() else { return }
            continuation.resume(throwing: RACPConnectionError.connectionLost)
          default: break
          }
        }
        connection.start(queue: DispatchQueue(label: "org.aurora.racp.connection"))
        let timeout = DispatchWorkItem {
          guard gate.claim() else { return }
          self.connection.cancel()
          continuation.resume(throwing: RACPConnectionError.connectionLost)
        }
        gate.install(timeout: timeout)
        DispatchQueue.global().asyncAfter(deadline: .now() + 5, execute: timeout)
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

  public enum RACPNetworkServerBinding: Sendable, Equatable {
    /// Preserve the production default by accepting connections on all interfaces.
    case allInterfaces
    /// Bind only to the IPv4 loopback interface, primarily for local integration tests.
    case loopback
  }

  public final class RACPNetworkServer: @unchecked Sendable {
    private let listener: NWListener
    private let sessionFactory: @Sendable () -> RACPSession
    private let connectionHandler: @Sendable (RACPConnection) -> Void
    private let maximumConnections: Int
    private let lock = NSLock()
    private var activeConnections = 0

    public init(
      port: UInt16,
      binding: RACPNetworkServerBinding = .allInterfaces,
      maximumConnections: Int = 64,
      advertisement: RACPNetworkAdvertisement? = nil,
      connectionHandler: @escaping @Sendable (RACPConnection) -> Void = { _ in },
      sessionFactory: @escaping @Sendable () -> RACPSession
    ) throws {
      guard maximumConnections > 0, let port = NWEndpoint.Port(rawValue: port) else {
        throw RACPConnectionError.connectionLost
      }
      let parameters = racpTCPParameters()
      switch binding {
      case .allInterfaces:
        listener = try NWListener(using: parameters, on: port)
      case .loopback:
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: port)
        listener = try NWListener(using: parameters)
      }
      if let advertisement {
        let txtRecord = NWTXTRecord(advertisement.txtValues)
        guard txtRecord.data.count <= RACPNetworkDiscoveryProfile.maximumTXTBytes else {
          throw RACPNetworkDiscoveryError.invalidConfiguration
        }
        listener.service = NWListener.Service(
          name: advertisement.instanceName, type: RACPNetworkDiscoveryProfile.serviceType,
          domain: RACPNetworkDiscoveryProfile.domain, txtRecord: txtRecord)
      }
      self.maximumConnections = maximumConnections
      self.connectionHandler = connectionHandler
      self.sessionFactory = sessionFactory
    }

    public var port: UInt16? { listener.port?.rawValue }

    public func start(queue: DispatchQueue = DispatchQueue(label: "org.aurora.racp.listener"))
      async throws
    {
      listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, any Error>) in
        let gate = ResumeGate()
        listener.stateUpdateHandler = { state in
          switch state {
          case .ready:
            guard gate.claim() else { return }
            continuation.resume()
          case .failed(let error):
            guard gate.claim() else { return }
            continuation.resume(throwing: error)
          case .cancelled:
            guard gate.claim() else { return }
            continuation.resume(throwing: RACPConnectionError.connectionLost)
          case .waiting:
            break
          default:
            break
          }
        }
        listener.start(queue: queue)
        let timeout = DispatchWorkItem {
          guard gate.claim() else { return }
          self.listener.cancel()
          continuation.resume(throwing: RACPConnectionError.connectionLost)
        }
        gate.install(timeout: timeout)
        DispatchQueue.global().asyncAfter(deadline: .now() + 5, execute: timeout)
      }
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
          let racpConnection = RACPConnection(stream: stream, session: sessionFactory())
          connectionHandler(racpConnection)
          await racpConnection.run()
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
