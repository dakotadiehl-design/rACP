import AuroraACP
@testable import AuroraACPAppleSecurity
import CryptoKit
import Foundation
import XCTest

final class ACPAppleEnrollmentServiceTests: XCTestCase {
    func testCompleteEnrollmentOverRealRestrictedTCPTransport() async throws {
        let fixture = try ServiceFixture()
        defer { fixture.cleanup() }
        let candidateNode = ACPSecurityNodeID(rawValue:
            "00112233-4455-4677-8899-aabbccddeeff")!
        let enrollmentID = ACPEnrollmentID(rawValue:
            "50617283-94a5-4b6c-9a4b-5c6d7e8f90a1")!
        let code = "00ZY07Y0820C20A1G7104GM2RC"
        let candidate = try ACPAppleEnrollmentCandidate(
            enrollmentID: enrollmentID, nodeID: candidateNode,
            displayName: "Loopback Candidate", requestedRole: "remote",
            bootstrapSecret: .highEntropyCode(code))
        let service = try ACPAppleEnrollmentService(
            configuration: try .init(maximumConcurrentAttempts: 2,
                connectionTimeout: 10),
            commissionerNodeID: fixture.commissioner,
            commissionerInstanceID: fixture.commissionerInstance,
            trustDomainID: fixture.domain, authorityKeyID: fixture.authority,
            decisions: fixture.decisions, coordinator: fixture.coordinator)
        let endpoint = try await service.start()
        defer { Task { await service.shutdown() } }

        let hostTask = Task { try await service.beginEnrollment(candidate) }
        let peerTask = Task {
            try await self.runCandidate(
                port: endpoint.port, code: code, enrollmentID: enrollmentID,
                candidateNode: candidateNode, fixture: fixture)
        }
        let request: ACPAppleEnrollmentRequestSummary
        do {
            request = try await waitForPending(fixture.decisions)
        } catch {
            let peerResult = await peerTask.result
            XCTFail("request never became pending; peer result: \(peerResult)")
            _ = try? await hostTask.value
            return
        }
        XCTAssertEqual(request.candidateNodeID, candidateNode)
        let decision = try await fixture.decisions.approve(requestID: request.requestID)
        XCTAssertEqual(decision, .applied)

        try await peerTask.value
        let outcome = try await hostTask.value
        XCTAssertEqual(outcome, .complete)
        let committed = await fixture.coordinator.wasCommitted()
        XCTAssertTrue(committed)
        let status = try await service.status()
        XCTAssertEqual(status.activeAttempts, 0)
        XCTAssertEqual(status.pendingDecisions, 0)
    }

    func testResourceLimitAndShutdownFailClosed() async throws {
        let fixture = try ServiceFixture(); defer { fixture.cleanup() }
        let service = try ACPAppleEnrollmentService(
            configuration: try .init(maximumConcurrentAttempts: 1,
                connectionTimeout: 10),
            commissionerNodeID: fixture.commissioner,
            commissionerInstanceID: fixture.commissionerInstance,
            trustDomainID: fixture.domain, authorityKeyID: fixture.authority,
            decisions: fixture.decisions, coordinator: fixture.coordinator)
        _ = try await service.start()
        let first = Task { try await service.beginEnrollment(try self.candidate()) }
        while (try await service.status()).activeAttempts == 0 { await Task.yield() }
        do {
            _ = try await service.beginEnrollment(try candidate())
            XCTFail("concurrent attempt exceeded the configured bound")
        } catch {
            XCTAssertEqual(error as? ACPAppleEnrollmentServiceError, .resourceLimit)
        }
        await service.shutdown()
        do {
            _ = try await first.value
            XCTFail("shutdown did not terminate the waiting attempt")
        } catch {
            XCTAssertEqual(error as? ACPAppleEnrollmentServiceError, .operationCancelled)
        }
        let status = try await service.status()
        XCTAssertEqual(status.state, .stopped)
    }

    private func candidate() throws -> ACPAppleEnrollmentCandidate {
        try .init(
            enrollmentID: ACPEnrollmentID(rawValue: UUID().uuidString.lowercased())!,
            nodeID: ACPSecurityNodeID(rawValue: UUID().uuidString.lowercased())!,
            requestedRole: "remote", bootstrapSecret: .manualNumericCode("12345678"))
    }

    private func waitForPending(_ decisions: ACPAppleEnrollmentDecisionService) async throws
        -> ACPAppleEnrollmentRequestSummary {
        for _ in 0..<200 {
            if let request = try await decisions.pendingEnrollmentRequests().first {
                return request
            }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        throw ACPAppleEnrollmentServiceError.failed
    }

    private func runCandidate(
        port: UInt16, code: String, enrollmentID: ACPEnrollmentID,
        candidateNode: ACPSecurityNodeID, fixture: ServiceFixture
    ) async throws {
        let transport = try await ACPFramedConnection.connect(
            host: "127.0.0.1", port: port, timeout: 5)
        defer { Task { await transport.close() } }
        let begin = try await receive(transport)
        let attempt = ACPEnrollmentAttemptID(rawValue: string(begin.payload, "attempt_id")!)!
        let candidateInstance = UUID()
        let key = P256.Signing.PrivateKey()
        let spki = key.publicKey.derRepresentation
        let keyID = ACPCredentialIdentifiers.identityKeyID(for: spki)
        let contextValues = context(
            begin: begin, attempt: attempt, candidateNode: candidateNode,
            candidateInstance: candidateInstance, keyID: keyID)
        let secret = try ACPAppleEnrollmentBootstrap.proverSecret(
            secret: .highEntropyCode(code), enrollmentID: enrollmentID,
            candidateNodeID: candidateNode, commissionerNodeID: fixture.commissioner)
        defer { secret.secret.clear() }
        let prover = try ACPAppleSPAKE2PlusProver(
            proverSecret: secret.secret, proverIdentity: uuidBytes(candidateNode.rawValue),
            verifierIdentity: uuidBytes(fixture.commissioner.rawValue),
            context: try ACPSecurityContext.canonicalEnrollment(contextValues))
        var challenge = contextValues.mapValues(AnySendable.string)
        for key in ["acp_version", "application", "extension_version", "purpose"] {
            challenge.removeValue(forKey: key)
        }
        challenge["identity_public_key"] = .bytes(spki)
        challenge["shareP"] = .bytes(try prover.generateShare())
        let challengeEnvelope = envelope(
            type: "security.enrollment.challenge", source: candidateNode,
            destination: fixture.commissioner, correlationID: begin.messageID,
            payload: challenge)
        try await send(challengeEnvelope, transport)
        let response = try await receive(transport)
        guard case .bytes(let share)? = response.payload["shareV"],
              case .bytes(let verifierConfirmation)? = response.payload["confirmV"] else {
            throw ACPAppleEnrollmentServiceError.failed
        }
        let result = try prover.processResponseAndConsumeKey(share + verifierConfirmation)
        try await send(envelope(
            type: "security.enrollment.confirm", source: candidateNode,
            destination: fixture.commissioner, correlationID: response.messageID,
            payload: ["attempt_id": .string(attempt.rawValue),
                      "confirmP": .bytes(result.confirmation)]), transport)
        let approval = try await receive(transport)
        XCTAssertEqual(approval.type, "security.enrollment.approval")
        let leaf = ServiceCoordinator.leaf
        var install: [String: AnySendable] = [
            "attempt_id": .string(attempt.rawValue), "status": .string("installed"),
            "credential_id": .string(
                ACPCredentialIdentifiers.credentialID(for: leaf).rawValue),
            "identity_key_id": .string(keyID.rawValue),
            "trust_domain_id": .string(fixture.domain.rawValue),
            "storage_posture": .object([
                "class": .string("os_protected"), "hardware_backed": .bool(false),
                "private_key_exportable": .bool(false),
            ]),
            "proof_of_possession": .bytes(Data([0x01])),
        ]
        let confirmationKey = result.key.withUnsafeBytes {
            ACPSecurityContext.deriveEnrollmentKeys(
                sharedKey: Data($0), transcriptHash: result.key.transcriptHash)[
                    "candidate confirm"]!
        }
        install["confirmation"] = .bytes(try ACPSecurityContext.installConfirmation(
            candidateConfirmKey: confirmationKey, values: install))
        try await send(envelope(
            type: "security.enrollment.install_result", source: candidateNode,
            destination: fixture.commissioner, correlationID: approval.messageID,
            payload: install), transport)
    }

    private func context(
        begin: ACPEnvelope, attempt: ACPEnrollmentAttemptID,
        candidateNode: ACPSecurityNodeID, candidateInstance: UUID,
        keyID: ACPIdentityKeyID
    ) -> [String: String] {[
        "acp_version": ACPModel.protocolVersion,
        "application": "Aurora Communications Protocol",
        "attempt_id": attempt.rawValue,
        "candidate_instance_id": candidateInstance.uuidString.lowercased(),
        "candidate_node_id": candidateNode.rawValue,
        "commissioner_instance_id": string(begin.payload, "commissioner_instance_id")!,
        "commissioner_node_id": string(begin.payload, "commissioner_node_id")!,
        "enrollment_id": string(begin.payload, "enrollment_id")!,
        "extension_version": "1.0", "identity_algorithm": "ecdsa_p256_sha256",
        "identity_key_id": keyID.rawValue, "purpose": "security.enrollment",
        "requested_permissions_digest": string(
            begin.payload, "requested_permissions_digest")!,
        "requested_role": string(begin.payload, "requested_role")!,
        "suite": string(begin.payload, "suite")!,
        "trust_domain_id": string(begin.payload, "trust_domain_id")!,
    ]}

    private func send(_ envelope: ACPEnvelope, _ transport: ACPFramedConnection) async throws {
        try await transport.send(try ACPEncoding.encodeCBOR(envelope), text: false)
    }
    private func receive(_ transport: ACPFramedConnection) async throws -> ACPEnvelope {
        let frame = try await transport.recv()
        return try frame.1 ? ACPEncoding.decodeJSON(frame.0) : ACPEncoding.decodeCBOR(frame.0)
    }
    private func string(_ values: [String: AnySendable], _ key: String) -> String? {
        guard case .string(let value)? = values[key] else { return nil }
        return value
    }
    private func uuidBytes(_ value: String) -> Data {
        var uuid = UUID(uuidString: value)!.uuid
        return withUnsafeBytes(of: &uuid) { Data($0) }
    }
    private func envelope(type: String, source: ACPSecurityNodeID,
                          destination: ACPSecurityNodeID, correlationID: String,
                          payload: [String: AnySendable]) -> ACPEnvelope {
        ACPEnvelope(acp: ACPModel.protocolVersion,
            messageID: UUID().uuidString.lowercased(), type: type,
            source: .init(nodeID: source.rawValue),
            destination: .init(nodeID: destination.rawValue),
            timestampUTC: "2026-08-27T14:00:00.000Z",
            correlationID: correlationID, qos: .reliable, payload: payload)
    }
}

private actor ServiceCoordinator: ACPAppleEnrollmentCoordinating {
    static let leaf = Data("real transport credential".utf8)
    private var package: ACPIssuedCredentialPackage?
    private var delivered = false
    private var committed = false

    func issue(authorization: ACPIssuanceAuthorization) async throws
        -> ACPIssuedCredentialPackage {
        let facts = try authorization.consume(now: Date())
        let value = try ACPIssuedCredentialPackage(
            authorizationID: facts.authorizationID, leafDER: Self.leaf,
            trustAnchorDER: Data("transport anchor".utf8),
            credentialID: ACPCredentialIdentifiers.credentialID(for: Self.leaf),
            identityKeyID: facts.identityKeyID, authorityKeyID: facts.authorityKeyID,
            trustDomainID: facts.trustDomainID, nodeID: facts.candidateNodeID,
            enrollmentID: facts.enrollmentID, attemptID: facts.attemptID,
            transcriptHash: facts.transcriptHash, serial: Data(repeating: 2, count: 16),
            notBefore: Date().addingTimeInterval(-1),
            expiresAt: Date().addingTimeInterval(3_600),
            rotationDeadline: Date().addingTimeInterval(1_800),
            replacesCredentialID: nil)
        package = value
        return value
    }
    func markDelivered(package: ACPIssuedCredentialPackage) async throws {
        guard package == self.package else { throw ACPSecurityErrorCode.storageFailed }
        delivered = true
    }
    func verifyInstallReceipt(package: ACPIssuedCredentialPackage,
        confirmation: ACPVerifiedEnrollmentInstallResult) async throws
        -> ACPAppleVerifiedInstallReceipt {
        guard delivered, package == self.package,
              confirmation.credentialID == package.credentialID else {
            throw ACPSecurityErrorCode.authenticationFailed
        }
        return .init(authorizationID: package.authorizationID, package: package,
            certificate: .init(
                trustDomainID: package.trustDomainID, nodeID: package.nodeID,
                credentialID: package.credentialID,
                identityKeyID: package.identityKeyID, leafDER: package.leafDER))
    }
    func commitTrust(_ receipt: ACPAppleVerifiedInstallReceipt,
                     displayName: String?) async throws { committed = true }
    func wasCommitted() -> Bool { committed }
}

private struct ServiceFixture {
    let service = "com.aurora.acp.service-test.\(UUID().uuidString.lowercased())"
    let commissioner = ACPSecurityNodeID(rawValue:
        "10213243-5465-4768-9a0b-1c2d3e4f5061")!
    let commissionerInstance = UUID(
        uuidString: "30415263-7485-496a-ba2b-3c4d5e6f7081")!
    let domain = ACPTrustDomainID(rawValue:
        "40516273-8495-4a6b-8a3b-4c5d6e7f8091")!
    let authority = ACPIdentityKeyID(rawValue:
        "sha256:" + String(repeating: "a", count: 64))!
    let decisions: ACPAppleEnrollmentDecisionService
    let coordinator = ServiceCoordinator()
    let backend: ACPKeychainCredentialBackend
    init() throws {
        decisions = try ACPAppleEnrollmentDecisionService(service: service)
        backend = ACPKeychainCredentialBackend(service: service)
    }
    func cleanup() { try? backend.delete(name: "enrollment-decisions") }
}
