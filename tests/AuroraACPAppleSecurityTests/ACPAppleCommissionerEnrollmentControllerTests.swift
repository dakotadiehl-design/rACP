import AuroraACP
@testable import AuroraACPAppleSecurity
import CryptoKit
import Foundation
import XCTest

final class ACPAppleCommissionerEnrollmentControllerTests: XCTestCase {
    private let candidate = ACPSecurityNodeID(
        rawValue: "00112233-4455-4677-8899-aabbccddeeff")!
    private let commissioner = ACPSecurityNodeID(
        rawValue: "10213243-5465-4768-9a0b-1c2d3e4f5061")!
    private let candidateInstance = UUID(
        uuidString: "20314253-6475-4869-aa1b-2c3d4e5f6071")!
    private let commissionerInstance = UUID(
        uuidString: "30415263-7485-496a-ba2b-3c4d5e6f7081")!
    private let domain = ACPTrustDomainID(
        rawValue: "40516273-8495-4a6b-8a3b-4c5d6e7f8091")!
    private let enrollment = ACPEnrollmentID(
        rawValue: "50617283-94a5-4b6c-9a4b-5c6d7e8f90a1")!
    private let attempt = ACPEnrollmentAttemptID(
        rawValue: "60718293-a4b5-4c6d-aa5b-6c7d8e9fa0b1")!
    private let permissions =
        "sha256:c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0"

    func testConfirmedCeremonyPublishesPendingDecision() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }
        let secret = ACPSecretBytes(Data(repeating: 7, count: 64))!
        let (controller, expiresAt) = try makeController(secret: secret, fixture: fixture)
        let begin = try await controller.begin(now: 1)
        XCTAssertEqual(begin.type, "security.enrollment.begin")

        let key = P256.Signing.PrivateKey().publicKey.derRepresentation
        let keyID = ACPCredentialIdentifiers.identityKeyID(for: key)
        let context = try ACPSecurityContext.canonicalEnrollment(contextValues(keyID: keyID))
        let prover = try ACPAppleSPAKE2PlusProver(
            proverSecret: secret, proverIdentity: uuidBytes(candidate.rawValue),
            verifierIdentity: uuidBytes(commissioner.rawValue), context: context)
        let challenge = envelope(type: "security.enrollment.challenge",
                                 correlationID: begin.messageID, payload: challengePayload(
                                    key: key, keyID: keyID,
                                    share: try prover.generateShare()))
        let response = try await controller.receiveChallenge(challenge, now: 2)
        guard case .bytes(let shareV)? = response.payload["shareV"],
              case .bytes(let confirmV)? = response.payload["confirmV"] else {
            return XCTFail("response fields")
        }
        let result = try prover.processResponseAndConsumeKey(shareV + confirmV)
        let confirm = envelope(type: "security.enrollment.confirm",
                               correlationID: response.messageID, payload: [
            "attempt_id": .string(attempt.rawValue),
            "confirmP": .bytes(result.confirmation),
        ])
        try await controller.receiveConfirm(confirm, now: 3)

        let pending = try await fixture.decisions.pendingEnrollmentRequests()
        XCTAssertEqual(pending, [.initForTest(
            requestID: attempt, candidateNodeID: candidate,
            displayName: "Candidate", requestedRole: "remote", expiresAt: expiresAt)])

        let approvalTask = Task {
            try await controller.awaitDecisionAndIssue(now: 4)
        }
        _ = try await fixture.decisions.approve(requestID: attempt)
        let action = try await approvalTask.value
        let approval = try XCTUnwrap(action.response)
        XCTAssertEqual(approval.type, "security.enrollment.approval")
        XCTAssertEqual(approval.correlationID, confirm.messageID)
        try await action.didSend?()
        let wasDelivered = await fixture.coordinator.wasDelivered()
        XCTAssertTrue(wasDelivered)

        let issued = await fixture.coordinator.currentPackage()
        let package = try XCTUnwrap(issued)
        var install: [String: AnySendable] = [
            "attempt_id": .string(attempt.rawValue), "status": .string("installed"),
            "credential_id": .string(package.credentialID.rawValue),
            "identity_key_id": .string(package.identityKeyID.rawValue),
            "trust_domain_id": .string(package.trustDomainID.rawValue),
            "storage_posture": .object([
                "class": .string("os_protected"), "hardware_backed": .bool(false),
                "private_key_exportable": .bool(false),
            ]),
            "proof_of_possession": .bytes(Data([1])),
        ]
        let candidateKey = result.key.withUnsafeBytes {
            ACPSecurityContext.deriveEnrollmentKeys(
                sharedKey: Data($0), transcriptHash: result.key.transcriptHash)["candidate confirm"]!
        }
        install["confirmation"] = .bytes(try ACPSecurityContext.installConfirmation(
            candidateConfirmKey: candidateKey, values: install))
        let receipt = envelope(type: "security.enrollment.install_result",
                               correlationID: approval.messageID, payload: install)
        try await controller.receiveInstallResult(receipt, now: 5)
        let wasCommitted = await fixture.coordinator.wasCommitted()
        XCTAssertTrue(wasCommitted)
    }

    func testChallengeMustCorrelateToBegin() async throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let secret = ACPSecretBytes(Data(repeating: 8, count: 64))!
        let (controller, _) = try makeController(secret: secret, fixture: fixture)
        _ = try await controller.begin(now: 1)
        let key = P256.Signing.PrivateKey().publicKey.derRepresentation
        let keyID = ACPCredentialIdentifiers.identityKeyID(for: key)
        let prover = try ACPAppleSPAKE2PlusProver(
            proverSecret: secret, proverIdentity: uuidBytes(candidate.rawValue),
            verifierIdentity: uuidBytes(commissioner.rawValue),
            context: try ACPSecurityContext.canonicalEnrollment(contextValues(keyID: keyID)))
        let challenge = envelope(type: "security.enrollment.challenge",
                                 correlationID: UUID().uuidString.lowercased(),
                                 payload: challengePayload(
                                    key: key, keyID: keyID, share: try prover.generateShare()))
        do {
            _ = try await controller.receiveChallenge(challenge, now: 2)
            XCTFail("uncorrelated challenge was accepted")
        } catch {
            XCTAssertEqual(error as? ACPAppleCommissionerEnrollmentError, .unexpectedMessage)
        }
    }

    private func makeController(secret: ACPSecretBytes, fixture: Fixture) throws
        -> (ACPAppleCommissionerEnrollmentController, Date) {
        let expires = Date().addingTimeInterval(60)
        let setup = try ACPAppleCommissionerEnrollmentSetup(
            enrollmentID: enrollment, attemptID: attempt, candidateNodeID: candidate,
            suite: .raw128, requestedRole: "remote",
            requestedPermissionsDigest: permissions,
            registrationRecord: ACPSecretBytes(
                try ACPAppleSPAKE2PlusRegistration.record(proverSecret: secret))!,
            displayName: "Candidate", expiresAt: expires)
        let authority = ACPIdentityKeyID(
            rawValue: "sha256:" + String(repeating: "a", count: 64))!
        return (try ACPAppleCommissionerEnrollmentController(
            commissionerNodeID: commissioner,
            commissionerInstanceID: commissionerInstance, trustDomainID: domain,
            authorityKeyID: authority, decisions: fixture.decisions,
            coordinator: fixture.coordinator,
            setup: setup, nowNanoseconds: 0), expires)
    }

    private func challengePayload(key: Data, keyID: ACPIdentityKeyID, share: Data)
        -> [String: AnySendable] {
        var payload = contextValues(keyID: keyID).mapValues(AnySendable.string)
        payload.removeValue(forKey: "acp_version")
        payload.removeValue(forKey: "application")
        payload.removeValue(forKey: "extension_version")
        payload.removeValue(forKey: "purpose")
        payload["identity_public_key"] = .bytes(key)
        payload["shareP"] = .bytes(share)
        return payload
    }

    private func contextValues(keyID: ACPIdentityKeyID) -> [String: String] {[
        "acp_version": "1.2", "application": "Aurora Communications Protocol",
        "attempt_id": attempt.rawValue,
        "candidate_instance_id": candidateInstance.uuidString.lowercased(),
        "candidate_node_id": candidate.rawValue,
        "commissioner_instance_id": commissionerInstance.uuidString.lowercased(),
        "commissioner_node_id": commissioner.rawValue,
        "enrollment_id": enrollment.rawValue, "extension_version": "1.0",
        "identity_algorithm": "ecdsa_p256_sha256", "identity_key_id": keyID.rawValue,
        "purpose": "security.enrollment", "requested_permissions_digest": permissions,
        "requested_role": "remote", "suite": ACPSecuritySuite.raw128.rawValue,
        "trust_domain_id": domain.rawValue,
    ]}

    private func envelope(type: String, correlationID: String,
                          payload: [String: AnySendable]) -> ACPEnvelope {
        ACPEnvelope(acp: "1.2", messageID: UUID().uuidString.lowercased(), type: type,
                    source: .init(nodeID: candidate.rawValue),
                    destination: .init(nodeID: commissioner.rawValue),
                    timestampUTC: "2026-08-27T14:00:00.000Z",
                    correlationID: correlationID, qos: .reliable, payload: payload)
    }
    private func uuidBytes(_ value: String) -> Data {
        var uuid = UUID(uuidString: value)!.uuid
        return withUnsafeBytes(of: &uuid) { Data($0) }
    }
}

private actor StubEnrollmentCoordinator: ACPAppleEnrollmentCoordinating {
    private var package: ACPIssuedCredentialPackage?
    private var delivered = false
    private var committed = false

    func issue(authorization: ACPIssuanceAuthorization) async throws
        -> ACPIssuedCredentialPackage {
        let facts = try authorization.consume(now: Date())
        let leaf = Data("test credential".utf8)
        let value = try ACPIssuedCredentialPackage(
            authorizationID: facts.authorizationID, leafDER: leaf,
            trustAnchorDER: Data("test anchor".utf8),
            credentialID: ACPCredentialIdentifiers.credentialID(for: leaf),
            identityKeyID: facts.identityKeyID, authorityKeyID: facts.authorityKeyID,
            trustDomainID: facts.trustDomainID, nodeID: facts.candidateNodeID,
            enrollmentID: facts.enrollmentID, attemptID: facts.attemptID,
            transcriptHash: facts.transcriptHash, serial: Data(repeating: 1, count: 16),
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
        let certificate = ACPAppleVerifiedCertificate(
            trustDomainID: package.trustDomainID, nodeID: package.nodeID,
            credentialID: package.credentialID, identityKeyID: package.identityKeyID,
            leafDER: package.leafDER)
        return .init(authorizationID: package.authorizationID,
                     package: package, certificate: certificate)
    }
    func commitTrust(_ receipt: ACPAppleVerifiedInstallReceipt,
                     displayName: String?) async throws { committed = true }
    func currentPackage() -> ACPIssuedCredentialPackage? { package }
    func wasDelivered() -> Bool { delivered }
    func wasCommitted() -> Bool { committed }
}

private struct Fixture {
    let service: String
    let decisions: ACPAppleEnrollmentDecisionService
    let backend: ACPKeychainCredentialBackend
    let coordinator = StubEnrollmentCoordinator()
    init() throws {
        service = "com.aurora.acp.controller-test.\(UUID().uuidString.lowercased())"
        decisions = try ACPAppleEnrollmentDecisionService(service: service)
        backend = ACPKeychainCredentialBackend(service: service)
    }
    func cleanup() { try? backend.delete(name: "enrollment-decisions") }
}

private extension ACPAppleEnrollmentRequestSummary {
    static func initForTest(requestID: ACPEnrollmentAttemptID,
                            candidateNodeID: ACPSecurityNodeID, displayName: String?,
                            requestedRole: String, expiresAt: Date) -> Self {
        .init(requestID: requestID, candidateNodeID: candidateNodeID,
              displayName: displayName, requestedRole: requestedRole, expiresAt: expiresAt)
    }
}
