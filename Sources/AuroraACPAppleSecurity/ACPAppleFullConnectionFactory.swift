import AuroraACP
import Dispatch
import Foundation
import Network
import Security

public struct ACPAppleFullProviderConfiguration {
    package let localIdentity: sec_identity_t
    package let localCertificateChain: [SecCertificate]
    public let localACPIdentity: ACPIdentity
    public let anchors: [SecCertificate]
    public let trustDomainID: ACPTrustDomainID
    public let expectedPeerNodeID: ACPSecurityNodeID?
    public let providerProvenance: ACPProviderProvenance
    public let trustStore: ACPAppleTrustedPeerStore

    public init(localIdentity: ACPAppleLocalIdentity, anchors: [SecCertificate],
                trustDomainID: ACPTrustDomainID, expectedPeerNodeID: ACPSecurityNodeID? = nil,
                providerProvenance: ACPProviderProvenance,
                trustStore: ACPAppleTrustedPeerStore) {
        self.localIdentity = localIdentity.networkIdentity
        self.localCertificateChain = localIdentity.certificateChain
        self.localACPIdentity = localIdentity.acpIdentity; self.anchors = anchors
        self.trustDomainID = trustDomainID; self.expectedPeerNodeID = expectedPeerNodeID
        self.providerProvenance = providerProvenance; self.trustStore = trustStore
    }
}

public struct ACPAppleFullServerEndpoint: Sendable, Equatable {
    public let port: UInt16
    public let profile = "full"
    public let securityMode = "aurora_trust"
    public let tlsRequired = true
}

/// TLS client that owns authenticated HELLO construction and exporter binding.
public enum ACPAppleFullConnectionFactory {
    public static func connect(host: String, port: UInt16,
                               configuration: ACPAppleFullProviderConfiguration,
                               timeout: TimeInterval = 10) async throws -> ACPAuthenticatedConnection {
        try validateTimeout(timeout)
        let local = try validateLocal(configuration)
        let connection = NWConnection(host: NWEndpoint.Host(host), port: try endpointPort(port),
                                      using: parameters(configuration))
        do {
            try await startConnection(connection, timeout: timeout)
            let metadata = try tlsMetadata(connection)
            let peer = try validatePeer(metadata, configuration)
            let framed = ACPFramedConnection(connection: connection)
            let hello = try bind(authenticatedHello(configuration.localACPIdentity, local: local), metadata: metadata)
            try await framed.send(try ACPEncoding.encodeCBOR(hello), text: false)
            let proof = try evidence(for: peer, hello: hello.payload, metadata: metadata)
            try configuration.trustStore.recordAuthenticated(peer, displayName: nil)
            return try result(framed, proof: proof, peer: peer, configuration: configuration,
                              role: .clientHelloSent)
        } catch { connection.cancel(); throw error }
    }
}

public enum ACPAppleFullServerFactory {
    public static func makeListener(port: UInt16 = 0,
                                    configuration: ACPAppleFullProviderConfiguration) throws
        -> ACPAppleFullServerListener {
        try ACPAppleFullServerListener(port: port, configuration: configuration)
    }
}

/// Lifecycle-owned, fail-closed TLS listener. `accept` returns only after mTLS,
/// certificate policy, HELLO parsing, and exporter verification have succeeded.
public actor ACPAppleFullServerListener {
    private let listener: NWListener
    private let configuration: ACPAppleFullProviderConfiguration
    private var pending: [NWConnection] = []
    private var waiter: (id: UUID, continuation: CheckedContinuation<NWConnection, Error>)?
    private var started = false
    private var stopped = false

    package init(port: UInt16, configuration: ACPAppleFullProviderConfiguration) throws {
        _ = try validateLocal(configuration)
        self.configuration = configuration
        listener = try NWListener(using: parameters(configuration), on: try endpointPort(port))
    }

    public var endpoint: ACPAppleFullServerEndpoint { .init(port: listener.port?.rawValue ?? 0) }

    public func start(timeout: TimeInterval = 10) async throws {
        try validateTimeout(timeout)
        guard !started, !stopped else { throw ACPAppleSecurityError.listenerState }
        listener.newConnectionHandler = { connection in Task { await self.enqueue(connection) } }
        let startResult = await withTaskGroup(of: Result<Void, Error>.self) { group in
            group.addTask {
                do {
                    try await withCheckedThrowingContinuation { continuation in
                        let gate = CompletionGate()
                        self.listener.stateUpdateHandler = { state in
                            switch state {
                            case .ready: gate.run { continuation.resume() }
                            case .failed(let error): gate.run { continuation.resume(throwing: error) }
                            case .cancelled: gate.run { continuation.resume(throwing: ACPAppleSecurityError.listenerState) }
                            default: break
                            }
                        }
                        self.listener.start(queue: .global(qos: .userInitiated))
                    }
                    return .success(())
                } catch { return .failure(error) }
            }
            group.addTask {
                do { try await Task.sleep(nanoseconds: timeoutNS(timeout)); self.listener.cancel()
                    return .failure(ACPAppleSecurityError.timeout) }
                catch { return .failure(error) }
            }
            let first = await group.next()!; group.cancelAll(); return first
        }
        do {
            try startResult.get()
            listener.stateUpdateHandler = nil; started = true
        } catch {
            listener.stateUpdateHandler = nil; listener.cancel(); stopped = true
            throw error
        }
    }

    public func accept(timeout: TimeInterval = 10) async throws -> ACPAuthenticatedConnection {
        try validateTimeout(timeout)
        guard started, !stopped else { throw ACPAppleSecurityError.listenerState }
        let connection = try await next(timeout: timeout)
        do {
            do { try await startConnection(connection, timeout: timeout) }
            catch { throw ACPAppleSecurityError.tlsHandshake }
            let metadata = try tlsMetadata(connection)
            let peer = try validatePeer(metadata, configuration)
            let framed = ACPFramedConnection(connection: connection)
            let (data, text): (Data, Bool)
            do { (data, text) = try await receive(framed, connection: connection, timeout: timeout) }
            catch { throw ACPAppleSecurityError.helloReceive }
            let hello = text ? try ACPEncoding.decodeJSON(data) : try ACPEncoding.decodeCBOR(data)
            guard hello.type == "session.hello" else { throw ACPAppleSecurityError.invalidHello }
            let proof = try evidence(for: peer, hello: hello.payload, metadata: metadata)
            try configuration.trustStore.recordAuthenticated(peer, displayName: helloDisplayName(hello))
            return try result(framed, proof: proof, peer: peer, configuration: configuration,
                              role: .serverHelloReceived, prefetchedHello: hello)
        } catch { connection.cancel(); throw error }
    }

    public func shutdown() {
        guard !stopped else { return }
        stopped = true; listener.cancel(); pending.forEach { $0.cancel() }; pending.removeAll()
        waiter?.continuation.resume(throwing: ACPAppleSecurityError.listenerState); waiter = nil
    }

    private func enqueue(_ connection: NWConnection) {
        guard !stopped else { connection.cancel(); return }
        if let waiter { self.waiter = nil; waiter.continuation.resume(returning: connection) }
        else { pending.append(connection) }
    }

    private func next(timeout: TimeInterval) async throws -> NWConnection {
        if !pending.isEmpty { return pending.removeFirst() }
        let waiterID = UUID()
        let outcome = await withTaskGroup(of: Result<ConnectionBox, Error>.self) { group in
            group.addTask {
                do { return .success(try await withTaskCancellationHandler {
                    ConnectionBox(try await self.waitForConnection(id: waiterID))
                } onCancel: { Task { await self.cancelWaiter(id: waiterID) } }) }
                catch { return .failure(error) }
            }
            group.addTask {
                do { try await Task.sleep(nanoseconds: timeoutNS(timeout)); return .failure(ACPAppleSecurityError.timeout) }
                catch { return .failure(error) }
            }
            let first = await group.next()!; group.cancelAll(); return first
        }
        return try outcome.get().value
    }

    private func waitForConnection(id: UUID) async throws -> NWConnection {
        try await withCheckedThrowingContinuation { install(id: id, continuation: $0) }
    }

    private func install(id: UUID, continuation: CheckedContinuation<NWConnection, Error>) {
        guard waiter == nil, !stopped else { continuation.resume(throwing: ACPAppleSecurityError.listenerState); return }
        waiter = (id, continuation)
    }
    private func cancelWaiter(id: UUID) {
        guard waiter?.id == id else { return }
        waiter?.continuation.resume(throwing: CancellationError()); waiter = nil
    }
}

private func parameters(_ configuration: ACPAppleFullProviderConfiguration) -> NWParameters {
    let tls = NWProtocolTLS.Options(); let options = tls.securityProtocolOptions
    sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
    sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
    sec_protocol_options_set_peer_authentication_required(options, true)
    sec_protocol_options_set_tls_tickets_enabled(options, false)
    sec_protocol_options_set_tls_resumption_enabled(options, false)
    sec_protocol_options_set_local_identity(options, configuration.localIdentity)
    sec_protocol_options_set_verify_block(options, { metadata, _, complete in
        do {
            _ = try ACPAppleCertificatePolicy.validate(chain: certificateChain(metadata), anchors: configuration.anchors,
                expectedDomain: configuration.trustDomainID, expectedNode: configuration.expectedPeerNodeID,
                revocation: configuration.trustStore)
            complete(true)
        } catch { complete(false) }
    }, .global(qos: .userInitiated))
    return NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
}

private func validateLocal(_ configuration: ACPAppleFullProviderConfiguration) throws -> ACPAppleVerifiedCertificate {
    guard let node = ACPSecurityNodeID(rawValue: configuration.localACPIdentity.nodeID) else {
        throw ACPAppleSecurityError.localIdentityMismatch
    }
    return try ACPAppleCertificatePolicy.validate(chain: configuration.localCertificateChain,
        anchors: configuration.anchors, expectedDomain: configuration.trustDomainID,
        expectedNode: node, revocation: configuration.trustStore)
}

private func authenticatedHello(_ identity: ACPIdentity,
                                local: ACPAppleVerifiedCertificate) -> ACPEnvelope {
    ACPEnvelope(acp: "1.2", messageID: UUID().uuidString.lowercased(), type: "session.hello",
        source: .init(nodeID: identity.nodeID), timestampUTC: securityTimestamp(),
        qos: .reliable, payload: [
            "node": .object(["node_id": .string(identity.nodeID), "instance_id": .string(identity.instanceID),
                             "role": .string(identity.role), "name": .string(identity.name)]),
            "protocol": .object(["min": .string("1.0"), "max": .string("1.2")]),
            "encodings": .array([.string("cbor"), .string("json")]), "profiles": .array([.string("core")]),
            "capabilities": .array(ACPSession.defaultCapabilities.map {
                .object(["id": .string($0.id), "version": .string($0.version)])
            }),
            "auth": .object(["mode": .string("aurora_trust"),
                "trust_domain_id": .string(local.trustDomainID.rawValue),
                "credential_id": .string(local.credentialID.rawValue),
                "identity_key_id": .string(local.identityKeyID.rawValue),
                "security_capabilities": .array([.object(["id": .string("aurora-trust"),
                                                           "version": .string("1.0")])])])])
}

private func securityTimestamp(_ date: Date = Date()) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: date)
}

private func bind(_ hello: ACPEnvelope, metadata: sec_protocol_metadata_t) throws -> ACPEnvelope {
    let context = try ACPAuthenticatedTransport.helloExporterContext(hello.payload)
    guard let binding = export(metadata, context: context, length: 32) else { throw ACPAppleSecurityError.exporterFailure }
    var copy = hello
    guard case .object(var auth) = copy.payload["auth"] else { throw ACPAppleSecurityError.invalidHello }
    auth["channel_binding"] = .string(ACPSecurityContext.base64URLEncode(binding))
    copy.payload["auth"] = .object(auth); return copy
}

private func evidence(for peer: ACPAppleVerifiedCertificate, hello: [String: AnySendable],
                      metadata: sec_protocol_metadata_t) throws -> ACPTransportEvidence {
    let context = try ACPAuthenticatedTransport.helloExporterContext(hello)
    guard let exported = export(metadata, context: context, length: 32) else { throw ACPAppleSecurityError.exporterFailure }
    let handshake = ACPFullTLSHandshake(protocolVersion: "TLSv1.3", mutualAuthentication: true,
        isolatedTrustStore: true, peerCertificateValid: true, localCredentialSelected: true,
        peerSANExtracted: true, trustDomainID: peer.trustDomainID.rawValue, nodeID: peer.nodeID.rawValue,
        credentialID: peer.credentialID.rawValue, identityKeyID: peer.identityKeyID.rawValue,
        roleConstraints: [], credentialState: .active)
    return try ACPAuthenticatedTransport.fullEvidence(hello: hello, handshake: handshake,
        exporter: FixedExporter(value: exported, expectedContext: context))
}

private func result(_ transport: ACPFramedConnection, proof: ACPTransportEvidence,
                    peer: ACPAppleVerifiedCertificate, configuration: ACPAppleFullProviderConfiguration,
                    role: ACPAuthenticatedConnection.Role, prefetchedHello: ACPEnvelope? = nil) throws
    -> ACPAuthenticatedConnection {
    try ACPAuthenticatedConnection(transport: transport, evidence: proof,
        providerProvenance: configuration.providerProvenance, role: role, prefetchedHello: prefetchedHello,
        localNodeID: configuration.localACPIdentity.nodeID,
        observation: .init(protocolVersion: "TLSv1.3", claimedNodeID: peer.nodeID.rawValue,
                           claimedTrustDomainID: peer.trustDomainID.rawValue))
}

private func tlsMetadata(_ connection: NWConnection) throws -> sec_protocol_metadata_t {
    guard let tls = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
        throw ACPAppleSecurityError.providerUnavailable
    }
    let metadata = tls.securityProtocolMetadata
    guard sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata) == .TLSv13,
          !sec_protocol_metadata_get_early_data_accepted(metadata) else { throw ACPAppleSecurityError.earlyData }
    return metadata
}

private func validatePeer(_ metadata: sec_protocol_metadata_t,
                          _ configuration: ACPAppleFullProviderConfiguration) throws -> ACPAppleVerifiedCertificate {
    try ACPAppleCertificatePolicy.validate(chain: certificateChain(metadata), anchors: configuration.anchors,
        expectedDomain: configuration.trustDomainID, expectedNode: configuration.expectedPeerNodeID,
        revocation: configuration.trustStore)
}

private func helloDisplayName(_ hello: ACPEnvelope) -> String? {
    guard case .object(let node) = hello.payload["node"], case .string(let name) = node["name"],
          (1...128).contains(name.utf8.count) else { return nil }
    return name
}

private func startConnection(_ connection: NWConnection, timeout: TimeInterval) async throws {
    let outcome = await withTaskGroup(of: Result<Void, Error>.self) { group in
        group.addTask {
            do { try await withCheckedThrowingContinuation { continuation in
                let gate = CompletionGate(); connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready: gate.run { continuation.resume() }
                    case .failed(let error): gate.run { continuation.resume(throwing: error) }
                    case .cancelled: gate.run { continuation.resume(throwing: ACPAppleSecurityError.providerUnavailable) }
                    default: break
                    }
                }; connection.start(queue: .global(qos: .userInitiated))
            }; return .success(()) } catch { return .failure(error) }
        }
        group.addTask {
            do { try await Task.sleep(nanoseconds: timeoutNS(timeout)); connection.cancel()
                return .failure(ACPAppleSecurityError.timeout) }
            catch { return .failure(error) }
        }
        let first = await group.next()!; group.cancelAll(); return first
    }
    try outcome.get()
    connection.stateUpdateHandler = nil
}

private func receive(_ transport: ACPFramedConnection, connection: NWConnection,
                     timeout: TimeInterval) async throws -> (Data, Bool) {
    let outcome = await withTaskGroup(of: Result<ReceivedFrame, Error>.self) { group in
        group.addTask {
            do {
                let (data, text) = try await transport.recv()
                return .success(.init(data: data, text: text))
            } catch { return .failure(error) }
        }
        group.addTask {
            do {
                try await Task.sleep(nanoseconds: timeoutNS(timeout))
                connection.cancel()
                return .failure(ACPAppleSecurityError.timeout)
            } catch { return .failure(error) }
        }
        let first = await group.next()!
        group.cancelAll()
        return first
    }
    let frame = try outcome.get()
    return (frame.data, frame.text)
}

private func endpointPort(_ port: UInt16) throws -> NWEndpoint.Port {
    guard let value = NWEndpoint.Port(rawValue: port) else { throw ACPAppleSecurityError.listenerState }; return value
}
private func timeoutNS(_ timeout: TimeInterval) -> UInt64 { UInt64(max(timeout, 0.01) * 1_000_000_000) }
private func validateTimeout(_ timeout: TimeInterval) throws {
    guard timeout.isFinite, (0.01...3_600).contains(timeout) else {
        throw ACPAppleSecurityError.resourceLimit
    }
}

private func certificateChain(_ metadata: sec_protocol_metadata_t) -> [SecCertificate] {
    var result: [SecCertificate] = []
    sec_protocol_metadata_access_peer_certificate_chain(metadata) {
        result.append(sec_certificate_copy_ref($0).takeRetainedValue())
    }
    return result
}

private func export(_ metadata: sec_protocol_metadata_t, context: Data, length: Int) -> Data? {
    let label = Array(ACPHelloExporterLabel.utf8CString)
    return label.withUnsafeBufferPointer { labelBuffer in context.withUnsafeBytes { contextBuffer -> Data? in
        guard let secret = sec_protocol_metadata_create_secret_with_context(metadata, label.count - 1,
            labelBuffer.baseAddress!, length, contextBuffer.bindMemory(to: UInt8.self).baseAddress!, context.count)
        else { return nil }
        let dispatch = secret as DispatchData
        return dispatch.withUnsafeBytes { (pointer: UnsafePointer<UInt8>) in Data(bytes: pointer, count: dispatch.count) }
    } }
}

private struct FixedExporter: ACPTLSExporter {
    let value: Data; let expectedContext: Data
    func export(label: String, context: Data, length: Int) throws -> Data {
        guard label == ACPHelloExporterLabel, context == expectedContext, length == value.count
        else { throw ACPAppleSecurityError.exporterFailure }; return value
    }
}

private final class CompletionGate: @unchecked Sendable {
    private let lock = NSLock(); private var completed = false
    func run(_ operation: () -> Void) { lock.lock(); defer { lock.unlock() }; guard !completed else { return }; completed = true; operation() }
}

private struct ConnectionBox: @unchecked Sendable { let value: NWConnection; init(_ value: NWConnection) { self.value = value } }
private struct ReceivedFrame: Sendable { let data: Data; let text: Bool }
