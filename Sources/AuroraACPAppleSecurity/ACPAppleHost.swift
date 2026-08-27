import AuroraACP
import CryptoKit
import Foundation
import Security
import X509

/// Opaque, verified security context for one ACP Apple host.
public final class ACPAppleHost: @unchecked Sendable {
    private let initialProvisioningStatus: ACPAppleHostProvisioningStatus
    public var provisioningStatus: ACPAppleHostProvisioningStatus {
        resetLock.withLock {
            resetState == .active ? initialProvisioningStatus : .init(state: .resetRequired,
                nodeID: initialProvisioningStatus.nodeID)
        }
    }

    private let localIdentity: ACPAppleLocalIdentity
    private let anchor: SecCertificate
    private let trustStore: ACPAppleTrustedPeerStore
    private let enrollmentDecisions: ACPAppleEnrollmentDecisionService
    private let enrollmentCoordinator: ACPAppleEnrollmentCoordinator
    private let commissionerInstanceID: UUID
    private let authorityKeyID: ACPIdentityKeyID
    private let trustDomainID: ACPTrustDomainID
    private let providerProvenance: ACPProviderProvenance
    private let resetter: ACPAppleHostSecurityResetter
    private let enrollmentServiceLock = NSLock()
    private var enrollmentService: ACPAppleEnrollmentService?
    private var enrollmentServiceConfiguration: ACPAppleEnrollmentServiceConfiguration?
    private let resetLock = NSLock()
    private var pendingReset: ACPAppleLocalSecurityResetPlan?
    private enum ResetState { case active, resetting, resetFailed, reset }
    private var resetState: ResetState = .active

    package init(localIdentity: ACPAppleLocalIdentity, anchor: SecCertificate,
                 trustStore: ACPAppleTrustedPeerStore,
                 enrollmentDecisions: ACPAppleEnrollmentDecisionService,
                 enrollmentCoordinator: ACPAppleEnrollmentCoordinator,
                 commissionerInstanceID: UUID, authorityKeyID: ACPIdentityKeyID,
                 trustDomainID: ACPTrustDomainID,
                 providerProvenance: ACPProviderProvenance,
                 resetter: ACPAppleHostSecurityResetter,
                 status: ACPAppleHostProvisioningStatus) {
        self.localIdentity = localIdentity
        self.anchor = anchor
        self.trustStore = trustStore
        self.enrollmentDecisions = enrollmentDecisions
        self.enrollmentCoordinator = enrollmentCoordinator
        self.commissionerInstanceID = commissionerInstanceID
        self.authorityKeyID = authorityKeyID
        self.trustDomainID = trustDomainID
        self.providerProvenance = providerProvenance
        self.resetter = resetter
        initialProvisioningStatus = status
    }

    public func trustedPeers() -> [ACPAppleTrustedPeer] {
        resetLock.withLock { resetState == .active } ? trustStore.trustedPeers() : []
    }

    public func operationalStatus(now: Date = Date()) throws
        -> ACPAppleHostOperationalStatus {
        guard resetLock.withLock({ resetState == .active }) else {
            throw ACPAppleHostProvisioningError.resetRequired
        }
        guard let leaf = localIdentity.certificateChain.first else {
            throw ACPAppleHostProvisioningError.identityUnavailable
        }
        do {
            let certificate = try Certificate(
                derEncoded: Array(SecCertificateCopyData(leaf) as Data))
            return .init(credentialExpiresAt: certificate.notValidAfter, now: now)
        } catch {
            throw ACPAppleHostProvisioningError.corruptState
        }
    }

    public func revokePeer(
        credentialID: ACPCredentialID
    ) throws -> ACPAppleRevocationResult {
        guard resetLock.withLock({ resetState == .active }) else {
            throw ACPAppleHostProvisioningError.resetRequired
        }
        return try trustStore.revoke(credentialID, at: Date())
    }

    public func pendingEnrollmentRequests() async throws
        -> [ACPAppleEnrollmentRequestSummary] {
        guard resetLock.withLock({ resetState == .active }) else {
            throw ACPAppleHostProvisioningError.resetRequired
        }
        return try await enrollmentDecisions.pendingEnrollmentRequests()
    }

    /// Emits the current sanitized pending-request list immediately and after
    /// every durable submit, decision, or expiry transition.
    public func enrollmentRequestUpdates()
        async -> AsyncStream<[ACPAppleEnrollmentRequestSummary]> {
        if !resetLock.withLock({ resetState == .active }) {
            return AsyncStream { continuation in
                continuation.yield([]); continuation.finish()
            }
        }
        return await enrollmentDecisions.updates()
    }

    public func approveEnrollment(requestID: ACPEnrollmentAttemptID) async throws
        -> ACPAppleEnrollmentDecisionResult {
        guard resetLock.withLock({ resetState == .active }) else {
            throw ACPAppleHostProvisioningError.resetRequired
        }
        let result = try await enrollmentDecisions.approve(requestID: requestID)
        await currentEnrollmentService()?.decisionChanged()
        return result
    }

    public func rejectEnrollment(requestID: ACPEnrollmentAttemptID) async throws
        -> ACPAppleEnrollmentDecisionResult {
        guard resetLock.withLock({ resetState == .active }) else {
            throw ACPAppleHostProvisioningError.resetRequired
        }
        let result = try await enrollmentDecisions.reject(requestID: requestID)
        await currentEnrollmentService()?.decisionChanged()
        return result
    }

    public func cancelEnrollment(requestID: ACPEnrollmentAttemptID) async throws
        -> ACPAppleEnrollmentDecisionResult {
        guard resetLock.withLock({ resetState == .active }) else {
            throw ACPAppleHostProvisioningError.resetRequired
        }
        let result = try await enrollmentDecisions.cancel(requestID: requestID)
        await currentEnrollmentService()?.decisionChanged()
        return result
    }

    /// Returns the single enrollment service owned by this host. Repeated calls
    /// with the same configuration are idempotent; changing listener policy
    /// requires shutting down and reopening the host security graph.
    public func makeEnrollmentService(
        configuration: ACPAppleEnrollmentServiceConfiguration
    ) throws -> ACPAppleEnrollmentService {
        guard resetLock.withLock({ resetState == .active }) else {
            throw ACPAppleHostProvisioningError.resetRequired
        }
        return try enrollmentServiceLock.withLock {
            if let existing = enrollmentService {
                guard enrollmentServiceConfiguration == configuration else {
                    throw ACPAppleEnrollmentServiceError.invalidConfiguration
                }
                return existing
            }
            let created = try ACPAppleEnrollmentService(
                configuration: configuration,
                commissionerNodeID: initialProvisioningStatus.nodeID,
                commissionerInstanceID: commissionerInstanceID,
                trustDomainID: trustDomainID, authorityKeyID: authorityKeyID,
                decisions: enrollmentDecisions, coordinator: enrollmentCoordinator)
            enrollmentService = created
            enrollmentServiceConfiguration = configuration
            return created
        }
    }

    public func planLocalSecurityReset() throws -> ACPAppleLocalSecurityResetPlan {
        try resetLock.withLock {
            guard resetState == .active || resetState == .resetFailed else {
                throw ACPAppleHostProvisioningError.resetRequired
            }
            let plan = ACPAppleLocalSecurityResetPlan(
                nodeID: initialProvisioningStatus.nodeID, trustDomainID: trustDomainID)
            pendingReset = plan
            return plan
        }
    }

    /// Executes the exact most recently issued reset plan. The caller remains
    /// responsible for performing any platform-local user authentication
    /// before invoking this destructive operation.
    public func executeLocalSecurityReset(
        _ plan: ACPAppleLocalSecurityResetPlan
    ) async throws {
        let valid = resetLock.withLock {
            let matches = pendingReset?.resetID == plan.resetID
                && pendingReset?.nonce == plan.nonce
                && (resetState == .active || resetState == .resetFailed)
            if matches { pendingReset = nil; resetState = .resetting }
            return matches
        }
        guard valid else { throw ACPAppleHostProvisioningError.invalidConfiguration }
        if let service = currentEnrollmentService() { await service.shutdown() }
        do {
            try await resetter.execute()
            resetLock.withLock { resetState = .reset; pendingReset = nil }
        } catch {
            resetLock.withLock { resetState = .resetFailed }
            throw ACPAppleHostProvisioningError.storageFailure
        }
    }

    private func currentEnrollmentService() -> ACPAppleEnrollmentService? {
        enrollmentServiceLock.withLock { enrollmentService }
    }

    package var isReset: Bool { resetLock.withLock { resetState == .reset } }

    /// Returns a provider configuration only from the already verified host
    /// graph. The application receives no identity key or Keychain reference.
    public func makeFullProviderConfiguration(
        expectedPeerNodeID: ACPSecurityNodeID? = nil
    ) throws -> ACPAppleFullProviderConfiguration {
        guard resetLock.withLock({ resetState == .active }) else {
            throw ACPAppleHostProvisioningError.resetRequired
        }
        guard try !operationalStatus().credentialExpired else {
            throw ACPAppleHostProvisioningError.identityUnavailable
        }
        return ACPAppleFullProviderConfiguration(
            localIdentity: localIdentity, anchors: [anchor],
            trustDomainID: trustDomainID,
            expectedPeerNodeID: expectedPeerNodeID,
            providerProvenance: providerProvenance, trustStore: trustStore)
    }

    public func makeFullServerListener(port: UInt16 = 0) throws
        -> ACPAppleFullServerListener {
        guard resetLock.withLock({ resetState == .active }) else {
            throw ACPAppleHostProvisioningError.resetRequired
        }
        return try ACPAppleFullServerFactory.makeListener(
            port: port, configuration: makeFullProviderConfiguration())
    }
}

/// The sole public composition entry point for an ACP-managed Apple host.
public enum ACPAppleHostFactory {
    private static let opener = ACPAppleHostOpener()

    public static func openOrBootstrap(
        configuration: ACPAppleHostConfiguration
    ) async throws -> ACPAppleHost {
        try await opener.openOrBootstrap(configuration: configuration)
    }
}

private actor ACPAppleHostOpener {
    private struct Binding: Equatable {
        let nodeID, instanceID, role, name: String
        let provenance: ACPProviderProvenance
        let preferSecureEnclave, allowNonHardwareFallback: Bool
        init(_ configuration: ACPAppleHostConfiguration) {
            nodeID = configuration.identity.nodeID
            instanceID = configuration.identity.instanceID
            role = configuration.identity.role; name = configuration.identity.name
            provenance = configuration.providerProvenance
            preferSecureEnclave = configuration.preferSecureEnclave
            allowNonHardwareFallback = configuration.allowNonHardwareFallback
        }
    }
    private struct CachedHost { let binding: Binding; let host: ACPAppleHost }
    private var hosts: [String: CachedHost] = [:]

    func openOrBootstrap(configuration: ACPAppleHostConfiguration) async throws
        -> ACPAppleHost {
        let cacheKey = configuration.storageNamespace + "\u{1f}"
            + (configuration.keychainAccessGroup ?? "")
        if let cached = hosts[cacheKey], !cached.host.isReset {
            guard cached.binding == Binding(configuration) else {
                throw ACPAppleHostProvisioningError.invalidConfiguration
            }
            return cached.host
        }
        hosts.removeValue(forKey: cacheKey)
        do {
            let host = try await open(configuration)
            hosts[cacheKey] = .init(binding: Binding(configuration), host: host)
            return host
        } catch let error as ACPAppleHostProvisioningError {
            throw error
        } catch let error as ACPAppleSecureEnclaveOutcome {
            switch error {
            case .corruptState, .identityMismatch, .providerIntegrityFailure:
                throw ACPAppleHostProvisioningError.corruptState
            default:
                throw ACPAppleHostProvisioningError.authorityUnavailable
            }
        } catch let error as ACPAppleSecurityError {
            switch error {
            case .identityMissing, .privateKeyUnavailable, .localIdentityMismatch:
                throw ACPAppleHostProvisioningError.identityUnavailable
            case .keychainFailure, .trustStoreFailure:
                throw ACPAppleHostProvisioningError.storageFailure
            default:
                throw ACPAppleHostProvisioningError.corruptState
            }
        } catch {
            throw ACPAppleHostProvisioningError.storageFailure
        }
    }

    private func open(_ configuration: ACPAppleHostConfiguration) async throws
        -> ACPAppleHost {
        guard let nodeID = ACPSecurityNodeID(rawValue: configuration.identity.nodeID),
              let instanceID = UUID(uuidString: configuration.identity.instanceID) else {
            throw ACPAppleHostProvisioningError.invalidConfiguration
        }
        let namespace = configuration.storageNamespace
        let accessGroup = configuration.keychainAccessGroup
        let journal = try ACPAppleHostProvisioningJournal(
            service: namespace + ".host-provisioning", accessGroup: accessGroup)
        var record = try journal.loadOrReserve(nodeID: nodeID)

        let authorityStore = try ACPAppleTrustDomainAuthorityStore(
            applicationTag: Data((namespace + ".authority").utf8),
            metadataService: namespace + ".authority",
            keyMetadataService: namespace + ".authority-key",
            accessGroup: accessGroup)
        let authority = try await authorityStore.openOrCreate()
        try verify(record: record, authority: authority)
        if record.phase == .reserved {
            record = try journal.advance(record, to: .authorityCommitted, authority: authority)
        }

        guard let anchor = SecCertificateCreateWithData(nil, authority.anchorDER as CFData) else {
            throw ACPAppleHostProvisioningError.corruptState
        }
        let trustStore = try ACPAppleTrustedPeerStore(
            service: namespace + ".trust", account: "trusted-peers",
            accessGroup: accessGroup)
        let enrollmentDecisions = try await ACPAppleEnrollmentDecisionServiceRegistry.shared.open(
            service: namespace + ".enrollment-decisions", accessGroup: accessGroup)
        let identityStore = ACPAppleIdentityStore(
            anchors: [anchor], trustDomainID: authority.identity.trustDomainID,
            revocation: trustStore, referenceService: namespace + ".identity-reference",
            accessGroup: accessGroup)
        let lifecycle = try ACPAppleCredentialLifecycleStore(
            identityStore: identityStore, identity: configuration.identity,
            labelPrefix: namespace + ".host-identity",
            service: namespace + ".identity-lifecycle", accessGroup: accessGroup)
        let issuanceBackend = ACPAppleIssuanceJournalBackend(
            service: namespace + ".issuance-journal", account: "host",
            accessGroup: accessGroup)
        let issuanceJournal = try ACPIssuanceJournal(backend: issuanceBackend)
        let issuer = try ACPAppleCredentialIssuer(
            domain: authority.identity.trustDomainID,
            authorityKeyID: authority.identity.authorityKeyID,
            anchorDER: authority.anchorDER, signingKey: authority.signingKey,
            journal: issuanceJournal)
        let enrollmentCoordinator = try ACPAppleEnrollmentCoordinator(
            issuer: issuer, journal: issuanceJournal, trustStore: trustStore,
            anchors: [anchor], domain: authority.identity.trustDomainID)
        try await enrollmentCoordinator.recoverCommittedTrust()
        let recovery = try await lifecycle.recoverReportingDiscardedStaging()
        if recovery.discardedStaging {
            guard record.phase == .authorityCommitted else {
                throw ACPAppleHostProvisioningError.corruptState
            }
            record = try journal.rotateAttempt(record)
        }

        let active: ACPAppleActiveCredential
        if let recovered = recovery.active {
            active = recovered
        } else {
            guard record.phase == .authorityCommitted,
                  let enrollmentID = ACPEnrollmentID(rawValue: record.enrollmentID),
                  let attemptID = ACPEnrollmentAttemptID(rawValue: record.attemptID) else {
                throw ACPAppleHostProvisioningError.corruptState
            }
            let pending = try await identityStore.prepareCandidateKey(
                attemptID: attemptID,
                preferSecureEnclave: configuration.preferSecureEnclave,
                allowNonHardwareFallback: configuration.allowNonHardwareFallback,
                applicationTagPrefix: namespace + ".host-key")
            let now = Date()
            let transcript = Self.bootstrapTranscript(
                domain: authority.identity.trustDomainID, node: nodeID,
                identityKey: pending.identityKeyID)
            let facts = try ACPIssuanceCeremonyFacts(
                authorizationID: record.authorizationID,
                enrollmentID: enrollmentID, attemptID: attemptID,
                transcriptHash: transcript, candidateNodeID: nodeID,
                candidateInstanceID: instanceID,
                commissionerNodeID: nodeID, commissionerInstanceID: instanceID,
                trustDomainID: authority.identity.trustDomainID,
                authorityKeyID: authority.identity.authorityKeyID,
                candidatePublicKeySPKI: pending.publicKeySPKI,
                identityKeyID: pending.identityKeyID,
                requestedRole: configuration.identity.role,
                permissionsDigest: Self.noPermissionsDigest,
                approvalID: record.authorizationID, approvalTime: now,
                expiresAt: now.addingTimeInterval(3600), cancellationGeneration: 0)
            let authorization = ACPIssuanceAuthorization(validated: facts) { true }
            let package = try await issuer.issueCredential(authorization: authorization)
            let evidence = try await lifecycle.stage(
                package: package, pendingKey: pending,
                generation: record.attemptGeneration)
            active = try await lifecycle.activate(
                evidence, generation: record.attemptGeneration)
        }

        try verify(active: active, nodeID: nodeID, authority: authority)
        if record.phase == .authorityCommitted {
            record = try journal.advance(
                record, to: .identityActive, identity: active.identity.metadata)
        } else {
            try verify(record: record, identity: active.identity.metadata)
        }
        if record.phase == .identityActive {
            record = try journal.advance(record, to: .committed)
        }
        guard record.phase == .committed else {
            throw ACPAppleHostProvisioningError.recoveryRequired
        }

        let status = ACPAppleHostProvisioningStatus(
            state: .ready, nodeID: nodeID,
            trustDomainID: authority.identity.trustDomainID,
            credentialID: ACPCredentialID(rawValue: active.identity.metadata.credentialID),
            identityKeyID: ACPIdentityKeyID(rawValue: active.identity.metadata.identityKeyID))
        return ACPAppleHost(
            localIdentity: active.identity, anchor: anchor, trustStore: trustStore,
            enrollmentDecisions: enrollmentDecisions,
            enrollmentCoordinator: enrollmentCoordinator,
            commissionerInstanceID: instanceID,
            authorityKeyID: authority.identity.authorityKeyID,
            trustDomainID: authority.identity.trustDomainID,
            providerProvenance: configuration.providerProvenance,
            resetter: ACPAppleHostSecurityResetter(
                lifecycle: lifecycle, trustStore: trustStore,
                decisions: enrollmentDecisions, issuanceBackend: issuanceBackend,
                hostJournal: journal, authorityStore: authorityStore),
            status: status)
    }

    private func verify(record: ACPAppleHostProvisioningRecord,
                        authority: ACPAppleTrustDomainAuthority) throws {
        guard record.phase == .reserved || (
            record.trustDomainID == authority.identity.trustDomainID.rawValue
                && record.authorityKeyID == authority.identity.authorityKeyID.rawValue
                && record.anchorCredentialID
                    == authority.identity.trustAnchorCredentialID.rawValue) else {
            throw ACPAppleHostProvisioningError.corruptState
        }
    }

    private func verify(active: ACPAppleActiveCredential, nodeID: ACPSecurityNodeID,
                        authority: ACPAppleTrustDomainAuthority) throws {
        let metadata = active.identity.metadata
        guard active.generation > 0, metadata.nodeID == nodeID.rawValue,
              metadata.trustDomainID == authority.identity.trustDomainID.rawValue,
              ACPCredentialID(rawValue: metadata.credentialID) != nil,
              ACPIdentityKeyID(rawValue: metadata.identityKeyID) != nil else {
            throw ACPAppleHostProvisioningError.corruptState
        }
    }

    private func verify(record: ACPAppleHostProvisioningRecord,
                        identity: ACPAppleLocalIdentityMetadata) throws {
        guard record.credentialID == identity.credentialID,
              record.identityKeyID == identity.identityKeyID,
              record.nodeID == identity.nodeID,
              record.trustDomainID == identity.trustDomainID else {
            throw ACPAppleHostProvisioningError.corruptState
        }
    }

    private static func bootstrapTranscript(
        domain: ACPTrustDomainID, node: ACPSecurityNodeID,
        identityKey: ACPIdentityKeyID
    ) -> Data {
        Data(SHA256.hash(data: Data(
            "ACP Apple host bootstrap v1\u{0}\(domain.rawValue)\u{0}\(node.rawValue)\u{0}\(identityKey.rawValue)".utf8)))
    }

    private static let noPermissionsDigest = "sha256:" + SHA256.hash(data: Data()).map {
        String(format: "%02x", $0)
    }.joined()
}
