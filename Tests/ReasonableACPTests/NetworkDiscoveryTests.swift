import Foundation
import Testing

@testable import ReasonableACP

@Test func discoveryAdvertisementAndTXTValidation() throws {
  let advertisement = try RACPNetworkAdvertisement(
    instanceName: "Prism Stage Left", peerID: "prism-a1b2c3", peerType: "prism")
  #expect(advertisement.txtValues == ["v": "1", "id": "prism-a1b2c3", "type": "prism"])
  let parsed = try RACPDiscoveryTXT.validate(advertisement.txtValues)
  #expect(parsed.version == 1)
  #expect(parsed.id == "prism-a1b2c3")
  #expect(parsed.type == "prism")

  #expect(throws: RACPNetworkDiscoveryError.invalidConfiguration) {
    try RACPNetworkAdvertisement(instanceName: "Prism", peerID: "not valid", peerType: "prism")
  }
  #expect(throws: RACPNetworkDiscoveryError.invalidConfiguration) {
    try RACPNetworkAdvertisement(instanceName: "Prism\nHidden", peerID: "prism", peerType: "prism")
  }
  #expect(throws: RACPNetworkDiscoveryError.invalidTXTRecord) {
    try RACPDiscoveryTXT.validate([
      ("v", "1"), ("id", "one"), ("id", "two"), ("type", "prism"),
    ])
  }
  var duplicateWireRecord = Data()
  for item in ["v=1", "id=one", "id=two", "type=prism"] {
    duplicateWireRecord.append(UInt8(item.utf8.count))
    duplicateWireRecord.append(contentsOf: item.utf8)
  }
  #expect(throws: RACPNetworkDiscoveryError.invalidTXTRecord) {
    try RACPDiscoveryTXT.validate(duplicateWireRecord)
  }
  #expect(throws: RACPNetworkDiscoveryError.unsupportedProfileVersion(2)) {
    try RACPDiscoveryTXT.validate(["v": "2", "id": "prism", "type": "prism"])
  }
  #expect(throws: RACPNetworkDiscoveryError.invalidTXTRecord) {
    try RACPDiscoveryTXT.validate(["v": "01", "id": "prism", "type": "prism"])
  }
  #expect(throws: RACPNetworkDiscoveryError.invalidTXTRecord) {
    try RACPDiscoveryTXT.validate(["v": "1", "id": "prism"])
  }
}

@Test func discoveryIDsCannotCollideThroughComponentSeparators() {
  let first = RACPDiscoveryID.service(
    instanceName: "a|1:b", type: "_racp._tcp", domain: "local.", interfaceNames: ["en0"])
  let second = RACPDiscoveryID.service(
    instanceName: "a", type: "1:b|_racp._tcp", domain: "local.", interfaceNames: ["en0"])
  #expect(first != second)
  #expect(
    RACPDiscoveryID.service(
      instanceName: "a", type: "_racp._tcp", domain: "local.", interfaceNames: ["a,b"])
      != RACPDiscoveryID.service(
        instanceName: "a", type: "_racp._tcp", domain: "local.", interfaceNames: ["a", "b"]))
}

@Test func discoveryHelloValidationReportsMatchesAndMismatches() throws {
  let service = RACPDiscoveredService(
    id: RACPDiscoveryID(rawValue: "test"), instanceName: "Prism", domain: "local.",
    interfaces: [], peerIDHint: "prism-one", peerTypeHint: "prism", profileVersion: 1,
    endpoint: RACPNetworkEndpoint(host: "127.0.0.1", port: 9000))
  #expect(
    service.validate(peer: try RACPHello(peerType: "prism", peerID: "prism-one"))
      == RACPDiscoveryValidationResult(peerID: .matches, peerType: .matches))
  #expect(
    service.validate(peer: try RACPHello(peerType: "bridge", peerID: "other"))
      == RACPDiscoveryValidationResult(peerID: .mismatch, peerType: .mismatch))
  let withoutHints = RACPDiscoveredService(
    id: RACPDiscoveryID(rawValue: "manual"), instanceName: "Manual", domain: "local.",
    interfaces: [], peerIDHint: nil, peerTypeHint: nil, profileVersion: 1,
    endpoint: RACPNetworkEndpoint(host: "127.0.0.1", port: 9000))
  #expect(
    withoutHints.validate(peer: try RACPHello(peerType: "bridge", peerID: "other"))
      == RACPDiscoveryValidationResult(peerID: .unavailable, peerType: .unavailable))
}

#if canImport(Network)
  @Test func portableEndpointConnectsToNetworkServer() async throws {
    let serverHello = try RACPHello(peerType: "prism", peerID: "endpoint-test")
    let server = try RACPNetworkServer(port: 0, binding: .loopback) {
      RACPSession(local: serverHello)
    }
    try await server.start()
    defer { server.cancel() }
    let endpoint = RACPNetworkEndpoint(host: "127.0.0.1", port: try #require(server.port))
    let connection = RACPConnection(
      stream: try await NetworkByteStream.connect(endpoint: endpoint),
      session: RACPSession(local: try RACPHello(peerType: "remote", peerID: "client")))
    let run = Task { await connection.run() }
    #expect(try await connection.waitUntilReady() == serverHello)
    await connection.close(reason: "test_complete")
    await run.value
  }

  @Test func networkDiscoveryIsSingleUseAndStopIsIdempotent() async throws {
    let discovery = RACPNetworkDiscovery()
    let observation = await discovery.observe()
    #expect(observation.initialServices.isEmpty)
    try await discovery.start()
    await #expect(throws: RACPNetworkDiscoveryError.invalidConfiguration) {
      try await discovery.start()
    }
    await discovery.stop()
    await discovery.stop()
    var iterator = observation.events.makeAsyncIterator()
    #expect(try await iterator.next() == nil)
  }

  @Test(.timeLimit(.minutes(1)))
  func advertisedServerCanBeDiscoveredAndConnected() async throws {
    let serverHello = try RACPHello(peerType: "prism", peerID: "discovery-integration")
    let advertisement = try RACPNetworkAdvertisement(
      instanceName: "rACP Test \(UUID().uuidString)", peerID: serverHello.peerID,
      peerType: serverHello.peerType)
    let server = try RACPNetworkServer(port: 0, advertisement: advertisement) {
      RACPSession(local: serverHello)
    }
    let discovery = RACPNetworkDiscovery()
    let observation = await discovery.observe()
    try await discovery.start()
    try await server.start()
    defer {
      server.cancel()
      Task { await discovery.stop() }
    }

    let service = try await withThrowingTaskGroup(of: RACPDiscoveredService.self) { group in
      group.addTask {
        for try await event in observation.events {
          switch event {
          case .added(let service),
            .updated(let service)
          where service.peerIDHint == serverHello.peerID:
            return service
          default: continue
          }
        }
        throw RACPNetworkDiscoveryError.unavailable
      }
      group.addTask {
        try await Task.sleep(for: .seconds(10))
        throw RACPNetworkDiscoveryError.unavailable
      }
      defer { group.cancelAll() }
      return try await group.next()!
    }

    let connection = RACPConnection(
      stream: try await NetworkByteStream.connect(endpoint: service.endpoint),
      session: RACPSession(local: try RACPHello(peerType: "remote", peerID: "client")))
    let run = Task { await connection.run() }
    let peer = try await connection.waitUntilReady()
    #expect(peer == serverHello)
    #expect(service.validate(peer: peer).peerID == .matches)
    #expect(service.validate(peer: peer).peerType == .matches)
    await connection.close(reason: "test_complete")
    await run.value
  }
#endif
