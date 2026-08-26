import Foundation

/// Diagnostic metadata only. This type can never be admitted as identity.
public struct ACPUnverifiedPeerObservation: Sendable, Equatable, Codable {
    public let protocolVersion: String?
    public let certificateSubject: String?
    public let claimedNodeID: String?
    public let claimedTrustDomainID: String?

    public init(
        protocolVersion: String? = nil,
        certificateSubject: String? = nil,
        claimedNodeID: String? = nil,
        claimedTrustDomainID: String? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.certificateSubject = certificateSubject
        self.claimedNodeID = claimedNodeID
        self.claimedTrustDomainID = claimedTrustDomainID
    }
}

public enum ACPAuthenticatedConnectionError: String, Error, Sendable {
    case alreadyConsumed = "security.connection_already_consumed"
    case invalidProviderProvenance = "security.provider_unqualified"
}

/// A provider-owned, non-Codable capability tied to one live transport.
///
/// Product targets can inspect the peer identity but cannot initialize this
/// value. Consuming it transfers the transport/evidence into one ACP session.
public final class ACPAuthenticatedConnection: @unchecked Sendable {
    package struct Payload: Sendable {
        let transport: any ACPTransport
        let evidence: ACPTransportEvidence
    }

    private let lock = NSLock()
    private var payload: Payload?
    public let providerManifestDigest: String
    public let observation: ACPUnverifiedPeerObservation

    package init(
        transport: any ACPTransport,
        evidence: ACPTransportEvidence,
        providerProvenance: ACPProviderProvenance,
        observation: ACPUnverifiedPeerObservation = .init()
    ) throws {
        guard providerProvenance.qualificationStatus == .pass
        else { throw ACPAuthenticatedConnectionError.invalidProviderProvenance }
        self.payload = Payload(transport: transport, evidence: evidence)
        self.providerManifestDigest = providerProvenance.manifestDigest
        self.observation = observation
    }

    public var peerNodeID: String? {
        lock.withLock { payload?.evidence.nodeID }
    }

    public var trustDomainID: String? {
        lock.withLock { payload?.evidence.trustDomainID }
    }

    package func consume() throws -> Payload {
        try lock.withLock {
            guard let payload else { throw ACPAuthenticatedConnectionError.alreadyConsumed }
            self.payload = nil
            return payload
        }
    }
}

private extension NSLock {
    func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock(); defer { unlock() }
        return try operation()
    }
}
