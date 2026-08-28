import Foundation

public enum RACPNetworkDiscoveryProfile {
  public static let serviceType = "_racp._tcp"
  public static let domain = "local."
  public static let version: UInt = 1
  public static let maximumTXTBytes = 512
}

public struct RACPNetworkAdvertisement: Sendable, Equatable {
  public let instanceName: String
  public let peerID: String
  public let peerType: String

  public init(instanceName: String, peerID: String, peerType: String) throws {
    guard !instanceName.isEmpty, instanceName.utf8.count <= 63,
      Self.validPeerToken(peerID), Self.validPeerToken(peerType)
    else { throw RACPNetworkDiscoveryError.invalidConfiguration }
    self.instanceName = instanceName
    self.peerID = peerID
    self.peerType = peerType
  }

  public var txtValues: [String: String] {
    ["v": String(RACPNetworkDiscoveryProfile.version), "id": peerID, "type": peerType]
  }

  static func validPeerToken(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 64,
      let first = value.utf8.first, Self.isASCIIAlphanumeric(first)
    else { return false }
    return value.utf8.dropFirst().allSatisfy {
      Self.isASCIIAlphanumeric($0) || $0 == 46 || $0 == 95 || $0 == 45
    }
  }

  private static func isASCIIAlphanumeric(_ byte: UInt8) -> Bool {
    (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte)
  }
}

public enum RACPNetworkDiscoveryError: Error, Sendable, Equatable {
  case unavailable
  case invalidConfiguration
  case invalidTXTRecord
  case unsupportedProfileVersion(UInt)
  case failed(String)
}

public struct RACPDiscoveryID: Sendable, Hashable, CustomStringConvertible {
  public let rawValue: String
  public init(rawValue: String) { self.rawValue = rawValue }
  public var description: String { rawValue }
}

public struct RACPNetworkInterface: Sendable, Hashable {
  public enum Kind: String, Sendable, Hashable {
    case wifi, wiredEthernet, cellular, loopback, other
  }

  public let name: String
  public let kind: Kind

  public init(name: String, kind: Kind) {
    self.name = name
    self.kind = kind
  }
}

public struct RACPNetworkEndpoint: @unchecked Sendable, Hashable {
  public enum Kind: Sendable, Hashable {
    case hostPort(host: String, port: UInt16)
    case service(name: String, type: String, domain: String, interfaceName: String?)
  }

  public let kind: Kind

  #if canImport(Network)
    let platformEndpoint: Any?
  #endif

  public init(host: String, port: UInt16) {
    kind = .hostPort(host: host, port: port)
    #if canImport(Network)
      platformEndpoint = nil
    #endif
  }

  public init(serviceName: String, type: String, domain: String, interfaceName: String? = nil) {
    kind = .service(name: serviceName, type: type, domain: domain, interfaceName: interfaceName)
    #if canImport(Network)
      platformEndpoint = nil
    #endif
  }

  public static func == (lhs: Self, rhs: Self) -> Bool { lhs.kind == rhs.kind }
  public func hash(into hasher: inout Hasher) { hasher.combine(kind) }
}

enum RACPDiscoveryTXT {
  static func validate(_ values: [String: String]) throws -> (
    version: UInt, id: String, type: String
  ) {
    try validate(values.map { ($0.key, Optional($0.value)) })
  }

  static func validate(_ entries: [(String, String?)]) throws -> (
    version: UInt, id: String, type: String
  ) {
    var values: [String: String] = [:]
    var seen = Set<String>()
    var encodedBytes = 0
    for (key, value) in entries {
      guard seen.insert(key).inserted else { throw RACPNetworkDiscoveryError.invalidTXTRecord }
      encodedBytes += 1 + key.utf8.count + (value.map { 1 + $0.utf8.count } ?? 0)
      guard key.utf8.allSatisfy({ $0 < 128 }),
        key.utf8.count + (value?.utf8.count ?? 0) + (value == nil ? 0 : 1) <= 255
      else { throw RACPNetworkDiscoveryError.invalidTXTRecord }
      if let value { values[key] = value }
    }
    guard encodedBytes <= RACPNetworkDiscoveryProfile.maximumTXTBytes,
      let versionValue = values["v"], !versionValue.isEmpty,
      versionValue.utf8.allSatisfy({ (48...57).contains($0) }),
      let version = UInt(versionValue),
      let id = values["id"], RACPNetworkAdvertisement.validPeerToken(id),
      let type = values["type"], RACPNetworkAdvertisement.validPeerToken(type)
    else { throw RACPNetworkDiscoveryError.invalidTXTRecord }
    guard version == RACPNetworkDiscoveryProfile.version else {
      throw RACPNetworkDiscoveryError.unsupportedProfileVersion(version)
    }
    return (version, id, type)
  }
}

public struct RACPDiscoveredService: Sendable, Hashable, Identifiable {
  public let id: RACPDiscoveryID
  public let instanceName: String
  public let domain: String
  public let interfaces: [RACPNetworkInterface]
  public let peerIDHint: String?
  public let peerTypeHint: String?
  public let profileVersion: UInt
  public let endpoint: RACPNetworkEndpoint

  public init(
    id: RACPDiscoveryID, instanceName: String, domain: String,
    interfaces: [RACPNetworkInterface], peerIDHint: String?, peerTypeHint: String?,
    profileVersion: UInt, endpoint: RACPNetworkEndpoint
  ) {
    self.id = id
    self.instanceName = instanceName
    self.domain = domain
    self.interfaces = interfaces
    self.peerIDHint = peerIDHint
    self.peerTypeHint = peerTypeHint
    self.profileVersion = profileVersion
    self.endpoint = endpoint
  }
}

public enum RACPNetworkDiscoveryEvent: Sendable, Equatable {
  case added(RACPDiscoveredService)
  case updated(RACPDiscoveredService)
  case removed(RACPDiscoveryID)
  case resyncRequired
}

public struct RACPDiscoveryObservation: Sendable {
  public let initialServices: [RACPDiscoveredService]
  public let events: AsyncThrowingStream<RACPNetworkDiscoveryEvent, any Error>
}

public enum RACPDiscoveryHintMatch: Sendable, Equatable {
  case unavailable
  case matches
  case mismatch
}

public struct RACPDiscoveryValidationResult: Sendable, Equatable {
  public let peerID: RACPDiscoveryHintMatch
  public let peerType: RACPDiscoveryHintMatch
}

extension RACPDiscoveredService {
  public func validate(peer: RACPHello) -> RACPDiscoveryValidationResult {
    RACPDiscoveryValidationResult(
      peerID: peerIDHint.map { $0 == peer.peerID ? .matches : .mismatch } ?? .unavailable,
      peerType: peerTypeHint.map { $0 == peer.peerType ? .matches : .mismatch } ?? .unavailable)
  }
}
