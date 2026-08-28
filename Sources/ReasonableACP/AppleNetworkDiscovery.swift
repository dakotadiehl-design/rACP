#if canImport(Network)
  import Foundation
  import Network

  private final class RACPDiscoveryCallbackSequence: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64 = 0

    func next() -> UInt64 {
      lock.withLock {
        value &+= 1
        return value
      }
    }
  }

  public actor RACPNetworkDiscovery {
    private enum Lifecycle { case idle, running, stopped, failed }

    private let browser: NWBrowser
    private let queue: DispatchQueue
    private let callbackSequence = RACPDiscoveryCallbackSequence()
    private var lifecycle: Lifecycle = .idle
    private var lastAppliedCallback: UInt64 = 0
    private var services: [RACPDiscoveryID: RACPDiscoveredService] = [:]
    private var observers:
      [UUID: AsyncThrowingStream<RACPNetworkDiscoveryEvent, any Error>.Continuation] = [:]

    public init() {
      browser = NWBrowser(
        for: .bonjourWithTXTRecord(
          type: RACPNetworkDiscoveryProfile.serviceType,
          domain: RACPNetworkDiscoveryProfile.domain),
        using: .tcp)
      queue = DispatchQueue(label: "org.aurora.racp.discovery")
    }

    public func start() throws {
      guard lifecycle == .idle else { throw RACPNetworkDiscoveryError.invalidConfiguration }
      lifecycle = .running
      browser.stateUpdateHandler = { [weak self] state in
        guard let self else { return }
        Task { await self.browserStateChanged(state) }
      }
      browser.browseResultsChangedHandler = { [weak self] results, _ in
        guard let self else { return }
        let sequence = self.callbackSequence.next()
        Task { await self.replaceResults(results, sequence: sequence) }
      }
      browser.start(queue: queue)
    }

    public func observe() -> RACPDiscoveryObservation {
      let id = UUID()
      let stream = AsyncThrowingStream<RACPNetworkDiscoveryEvent, any Error>(
        bufferingPolicy: .bufferingNewest(64)
      ) { continuation in
        guard lifecycle == .running || lifecycle == .idle else {
          continuation.finish()
          return
        }
        observers[id] = continuation
        continuation.onTermination = { [weak self] _ in
          guard let self else { return }
          Task { await self.removeObserver(id) }
        }
      }
      return RACPDiscoveryObservation(
        initialServices: services.values.sorted(by: Self.sortServices), events: stream)
    }

    public func discoveredServices() -> [RACPDiscoveredService] {
      services.values.sorted(by: Self.sortServices)
    }

    public func stop() {
      guard lifecycle == .idle || lifecycle == .running else { return }
      lifecycle = .stopped
      browser.cancel()
      finishObservers()
      services.removeAll()
    }

    private func browserStateChanged(_ state: NWBrowser.State) {
      switch state {
      case .failed(let error):
        lifecycle = .failed
        finishObservers(throwing: RACPNetworkDiscoveryError.failed(String(describing: error)))
      case .cancelled:
        if lifecycle == .running {
          lifecycle = .stopped
          finishObservers()
        }
      default: break
      }
    }

    private func replaceResults(_ results: Set<NWBrowser.Result>, sequence: UInt64) {
      guard lifecycle == .running, sequence > lastAppliedCallback else { return }
      lastAppliedCallback = sequence
      var replacement: [RACPDiscoveryID: RACPDiscoveredService] = [:]
      for result in results {
        guard let service = try? Self.makeService(result) else { continue }
        replacement[service.id] = service
      }
      for id in services.keys where replacement[id] == nil {
        emit(.removed(id))
      }
      for (id, service) in replacement {
        if let old = services[id] {
          if old != service { emit(.updated(service)) }
        } else {
          emit(.added(service))
        }
      }
      services = replacement
    }

    private func emit(_ event: RACPNetworkDiscoveryEvent) {
      for continuation in observers.values {
        if case .dropped = continuation.yield(event) {
          continuation.yield(.resyncRequired)
        }
      }
    }

    private func finishObservers(throwing error: (any Error)? = nil) {
      let current = Array(observers.values)
      observers.removeAll()
      for observer in current {
        if let error { observer.finish(throwing: error) } else { observer.finish() }
      }
    }

    private func removeObserver(_ id: UUID) { observers.removeValue(forKey: id) }

    private static func makeService(_ result: NWBrowser.Result) throws -> RACPDiscoveredService {
      guard case .service(let name, let type, let domain, let scopedInterface) = result.endpoint,
        case .bonjour(let txtRecord) = result.metadata
      else { throw RACPNetworkDiscoveryError.invalidTXTRecord }
      let validated = try RACPDiscoveryTXT.validate(txtRecord.data)
      let interfaces = result.interfaces.map(Self.makeInterface).sorted {
        ($0.name, $0.kind.rawValue) < ($1.name, $1.kind.rawValue)
      }
      let id = RACPDiscoveryID.service(
        instanceName: name, type: type, domain: domain,
        interfaceNames: scopedInterface.map { [$0.name] } ?? interfaces.map(\.name))
      let endpoint = RACPNetworkEndpoint(
        kind: .service(
          name: name, type: type, domain: domain, interfaceName: scopedInterface?.name),
        platformEndpoint: result.endpoint)
      return RACPDiscoveredService(
        id: id, instanceName: name, domain: domain, interfaces: interfaces,
        peerIDHint: validated.id, peerTypeHint: validated.type,
        profileVersion: validated.version, endpoint: endpoint)
    }

    private static func makeInterface(_ interface: NWInterface) -> RACPNetworkInterface {
      let kind: RACPNetworkInterface.Kind =
        switch interface.type {
        case .wifi: .wifi
        case .wiredEthernet: .wiredEthernet
        case .cellular: .cellular
        case .loopback: .loopback
        default: .other
        }
      return RACPNetworkInterface(name: interface.name, kind: kind)
    }

    private static func sortServices(_ lhs: RACPDiscoveredService, _ rhs: RACPDiscoveredService)
      -> Bool
    {
      (lhs.instanceName, lhs.id.rawValue) < (rhs.instanceName, rhs.id.rawValue)
    }
  }

  extension RACPNetworkEndpoint {
    fileprivate init(kind: Kind, platformEndpoint: NWEndpoint) {
      self.kind = kind
      self.platformEndpoint = platformEndpoint
    }
  }
#endif
