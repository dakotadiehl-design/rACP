import AuroraACP
import Dispatch
import Foundation
import Network
import Security

public struct ACPAppleFullProviderConfiguration {
    public let localIdentity: sec_identity_t
    public let anchors: [SecCertificate]
    public let trustDomainID: ACPTrustDomainID
    public let expectedPeerNodeID: ACPSecurityNodeID?
    public let providerProvenance: ACPProviderProvenance
    public let revocation: (any ACPAppleRevocationChecking)?

    public init(
        localIdentity: sec_identity_t,
        anchors: [SecCertificate],
        trustDomainID: ACPTrustDomainID,
        expectedPeerNodeID: ACPSecurityNodeID? = nil,
        providerProvenance: ACPProviderProvenance,
        revocation: (any ACPAppleRevocationChecking)? = nil
    ) {
        self.localIdentity = localIdentity
        self.anchors = anchors
        self.trustDomainID = trustDomainID
        self.expectedPeerNodeID = expectedPeerNodeID
        self.providerProvenance = providerProvenance
        self.revocation = revocation
    }
}

/// ACP-owned Network.framework TLS 1.3 client. It validates and exports from
/// the same `NWConnection`, then seals that live connection into one opaque
/// ACP capability.
public enum ACPAppleFullConnectionFactory {
    @available(*, unavailable, message: "S10 live HELLO/session binding and server qualification are not complete")
    public static func connect(
        host: String,
        port: UInt16,
        hello: [String: AnySendable],
        configuration: ACPAppleFullProviderConfiguration,
        timeout: TimeInterval = 10
    ) async throws -> ACPAuthenticatedConnection {
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_peer_authentication_required(options, true)
        sec_protocol_options_set_tls_tickets_enabled(options, false)
        sec_protocol_options_set_tls_resumption_enabled(options, false)
        sec_protocol_options_set_local_identity(options, configuration.localIdentity)
        sec_protocol_options_set_verify_block(options, { metadata, _, complete in
            do {
                let chain = certificateChain(metadata)
                _ = try ACPAppleCertificatePolicy.validate(
                    chain: chain, anchors: configuration.anchors,
                    expectedDomain: configuration.trustDomainID,
                    expectedNode: configuration.expectedPeerNodeID,
                    revocation: configuration.revocation
                )
                complete(true)
            } catch {
                complete(false)
            }
        }, .global(qos: .userInitiated))

        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        let connection = NWConnection(
            host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: parameters
        )
        try await start(connection, timeout: timeout)
        do {
            guard let tlsMetadata = connection.metadata(definition: NWProtocolTLS.definition)
                    as? NWProtocolTLS.Metadata
            else { throw ACPAppleSecurityError.providerUnavailable }
            let metadata = tlsMetadata.securityProtocolMetadata
            guard sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata) == .TLSv13,
                  !sec_protocol_metadata_get_early_data_accepted(metadata)
            else { throw ACPAppleSecurityError.earlyData }
            let verified = try ACPAppleCertificatePolicy.validate(
                chain: certificateChain(metadata), anchors: configuration.anchors,
                expectedDomain: configuration.trustDomainID,
                expectedNode: configuration.expectedPeerNodeID,
                revocation: configuration.revocation
            )
            let context = try ACPAuthenticatedTransport.helloExporterContext(hello)
            guard let exported = export(metadata: metadata, context: context, length: 32) else {
                throw ACPAppleSecurityError.exporterFailure
            }
            let exporter = FixedExporter(value: exported, expectedContext: context)
            let handshake = ACPFullTLSHandshake(
                protocolVersion: "TLSv1.3", mutualAuthentication: true, isolatedTrustStore: true,
                peerCertificateValid: true, localCredentialSelected: true, peerSANExtracted: true,
                trustDomainID: verified.trustDomainID.rawValue, nodeID: verified.nodeID.rawValue,
                credentialID: verified.credentialID.rawValue, identityKeyID: verified.identityKeyID.rawValue,
                roleConstraints: [], credentialState: .active
            )
            let evidence = try ACPAuthenticatedTransport.fullEvidence(
                hello: hello, handshake: handshake, exporter: exporter
            )
            let framed = ACPFramedConnection(connection: connection)
            return try ACPAuthenticatedConnection(
                transport: framed, evidence: evidence,
                providerProvenance: configuration.providerProvenance,
                observation: .init(
                    protocolVersion: "TLSv1.3", claimedNodeID: verified.nodeID.rawValue,
                    claimedTrustDomainID: verified.trustDomainID.rawValue
                )
            )
        } catch {
            connection.cancel()
            throw error
        }
    }

    private static func start(_ connection: NWConnection, timeout: TimeInterval) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { continuation in
                    let gate = CompletionGate()
                    connection.stateUpdateHandler = { state in
                        switch state {
                        case .ready: gate.run { continuation.resume() }
                        case .failed(let error): gate.run { continuation.resume(throwing: error) }
                        case .cancelled: gate.run { continuation.resume(throwing: ACPAppleSecurityError.providerUnavailable) }
                        default: break
                        }
                    }
                    connection.start(queue: .global(qos: .userInitiated))
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(max(timeout, 0.01) * 1_000_000_000))
                throw ACPAppleSecurityError.providerUnavailable
            }
            defer { group.cancelAll() }
            _ = try await group.next()
            connection.stateUpdateHandler = nil
        }
    }

    private static func export(metadata: sec_protocol_metadata_t, context: Data, length: Int) -> Data? {
        let label = Array(ACPHelloExporterLabel.utf8CString)
        return label.withUnsafeBufferPointer { labelBuffer in
            context.withUnsafeBytes { contextBuffer -> Data? in
                guard let secret = sec_protocol_metadata_create_secret_with_context(
                    metadata, label.count - 1, labelBuffer.baseAddress!, length,
                    contextBuffer.bindMemory(to: UInt8.self).baseAddress!, context.count
                ) else { return nil }
                let dispatch = secret as DispatchData
                return dispatch.withUnsafeBytes { (pointer: UnsafePointer<UInt8>) in
                    Data(bytes: pointer, count: dispatch.count)
                }
            }
        }
    }
}

private func certificateChain(_ metadata: sec_protocol_metadata_t) -> [SecCertificate] {
    var result: [SecCertificate] = []
    sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
        result.append(sec_certificate_copy_ref(certificate).takeRetainedValue())
    }
    return result
}

private struct FixedExporter: ACPTLSExporter {
    let value: Data
    let expectedContext: Data
    func export(label: String, context: Data, length: Int) throws -> Data {
        guard label == ACPHelloExporterLabel, context == expectedContext, length == value.count else {
            throw ACPAppleSecurityError.exporterFailure
        }
        return value
    }
}

private final class CompletionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    func run(_ operation: () -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard !completed else { return }
        completed = true
        operation()
    }
}
