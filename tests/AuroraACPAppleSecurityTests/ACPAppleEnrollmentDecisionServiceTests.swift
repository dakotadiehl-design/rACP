import AuroraACP
@testable import AuroraACPAppleSecurity
import Foundation
import XCTest

final class ACPAppleEnrollmentDecisionServiceTests: XCTestCase {
    func testApprovalIsIdempotentAndExcludesRejection() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }
        let request = try validatedRequest(expiresAt: Date().addingTimeInterval(60))
        try await fixture.service.submit(request)

        let firstApproval = try await fixture.service.approve(
            requestID: request.summary.requestID)
        let repeatedApproval = try await fixture.service.approve(
            requestID: request.summary.requestID)
        XCTAssertEqual(firstApproval, .applied)
        XCTAssertEqual(repeatedApproval, .alreadyApplied)
        do {
            _ = try await fixture.service.reject(requestID: request.summary.requestID)
            XCTFail("rejection replaced an approval")
        } catch {
            XCTAssertEqual(error as? ACPAppleEnrollmentDecisionError, .invalidState)
        }
        _ = try await fixture.service.consumeApproved(requestID: request.summary.requestID)
        do {
            _ = try await fixture.service.consumeApproved(requestID: request.summary.requestID)
            XCTFail("approval capability was consumed twice")
        } catch {
            XCTAssertEqual(error as? ACPAppleEnrollmentDecisionError, .invalidState)
        }
    }

    func testConcurrentApprovalHasOneAppliedOutcome() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }
        let request = try validatedRequest(expiresAt: Date().addingTimeInterval(60))
        try await fixture.service.submit(request)

        let results = try await withThrowingTaskGroup(
            of: ACPAppleEnrollmentDecisionResult.self
        ) { group in
            for _ in 0..<16 {
                group.addTask {
                    try await fixture.service.approve(requestID: request.summary.requestID)
                }
            }
            var values: [ACPAppleEnrollmentDecisionResult] = []
            for try await value in group { values.append(value) }
            return values
        }
        XCTAssertEqual(results.filter { $0 == .applied }.count, 1)
        XCTAssertEqual(results.filter { $0 == .alreadyApplied }.count, 15)
    }

    func testReopenExpiresRequestBecausePAKECapabilityIsNotPersisted() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }
        let request = try validatedRequest(expiresAt: Date().addingTimeInterval(60))
        try await fixture.service.submit(request)
        let pending = try await fixture.service.pendingEnrollmentRequests()
        XCTAssertEqual(pending.count, 1)

        let reopened = try ACPAppleEnrollmentDecisionService(service: fixture.serviceName)
        let recoveredPending = try await reopened.pendingEnrollmentRequests()
        XCTAssertTrue(recoveredPending.isEmpty)
        do {
            _ = try await reopened.approve(requestID: request.summary.requestID)
            XCTFail("reopened request retained a transient PAKE capability")
        } catch {
            XCTAssertEqual(error as? ACPAppleEnrollmentDecisionError, .expired)
        }
    }

    func testExpiredAndUnknownRequestsFailClosed() async throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }
        let expired = try validatedRequest(expiresAt: Date().addingTimeInterval(-1))
        do {
            try await fixture.service.submit(expired)
            XCTFail("expired request was accepted")
        } catch {
            XCTAssertEqual(error as? ACPAppleEnrollmentDecisionError, .expired)
        }
        do {
            _ = try await fixture.service.cancel(requestID: expired.summary.requestID)
            XCTFail("unknown request was cancelled")
        } catch {
            XCTAssertEqual(error as? ACPAppleEnrollmentDecisionError, .unknownRequest)
        }
    }

    func testRegistryReturnsSingleOwnerForNamespace() async throws {
        let serviceName = "com.aurora.acp.decision-registry.\(UUID().uuidString.lowercased())"
        let backend = ACPKeychainCredentialBackend(service: serviceName)
        defer { try? backend.delete(name: "enrollment-decisions") }
        let first = try await ACPAppleEnrollmentDecisionServiceRegistry.shared.open(
            service: serviceName)
        let second = try await ACPAppleEnrollmentDecisionServiceRegistry.shared.open(
            service: serviceName)
        XCTAssertTrue(first === second)
    }

    func testWaitingCeremonyResumesOnlyAfterDurableApproval() async throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let request = try validatedRequest(expiresAt: Date().addingTimeInterval(60))
        try await fixture.service.submit(request)
        let waiter = Task {
            try await fixture.service.awaitDecision(requestID: request.summary.requestID)
        }
        _ = try await fixture.service.approve(requestID: request.summary.requestID)
        guard case .approved(let approved) = try await waiter.value else {
            return XCTFail("approval did not resume ceremony")
        }
        XCTAssertTrue(approved.request === request)
    }

    func testWaitingCeremonyObservesRejectionWithoutCapability() async throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let request = try validatedRequest(expiresAt: Date().addingTimeInterval(60))
        try await fixture.service.submit(request)
        let waiter = Task {
            try await fixture.service.awaitDecision(requestID: request.summary.requestID)
        }
        _ = try await fixture.service.reject(requestID: request.summary.requestID)
        guard case .rejected = try await waiter.value else {
            return XCTFail("rejection did not resume ceremony")
        }
    }

    func testUpdateStreamPublishesDurablePendingAndTerminalSnapshots() async throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let stream = await fixture.service.updates()
        let request = try validatedRequest(expiresAt: Date().addingTimeInterval(60))
        let collector = Task { () -> [[ACPAppleEnrollmentRequestSummary]] in
            var values: [[ACPAppleEnrollmentRequestSummary]] = []
            for await value in stream {
                values.append(value)
                if values.count == 3 { break }
            }
            return values
        }
        try await fixture.service.submit(request)
        _ = try await fixture.service.reject(requestID: request.summary.requestID)
        let snapshots = await collector.value
        XCTAssertEqual(snapshots.map(\.count), [0, 1, 0])
        XCTAssertEqual(snapshots[1].first, request.summary)
    }

    private func validatedRequest(expiresAt: Date) throws
        -> ACPAppleValidatedEnrollmentRequest {
        let enrollmentID = ACPEnrollmentID(rawValue: UUID().uuidString.lowercased())!
        let attemptID = ACPEnrollmentAttemptID(rawValue: UUID().uuidString.lowercased())!
        let candidate = ACPSecurityNodeID(
            rawValue: "00112233-4455-4677-8899-aabbccddeeff")!
        let commissioner = ACPSecurityNodeID(
            rawValue: "10112233-4455-4677-8899-aabbccddeeff")!
        let domain = ACPTrustDomainID(rawValue: UUID().uuidString.lowercased())!
        let keyID = ACPIdentityKeyID(rawValue: "sha256:" + String(repeating: "1", count: 64))!
        let authorityID = ACPIdentityKeyID(rawValue: "sha256:" + String(repeating: "2", count: 64))!
        let transcript = Data(repeating: 3, count: 32)
        let facts = try ACPIssuanceCeremonyFacts(
            authorizationID: UUID(), enrollmentID: enrollmentID, attemptID: attemptID,
            transcriptHash: transcript, candidateNodeID: candidate,
            candidateInstanceID: UUID(), commissionerNodeID: commissioner,
            commissionerInstanceID: UUID(), trustDomainID: domain,
            authorityKeyID: authorityID, candidatePublicKeySPKI: Data(repeating: 4, count: 91),
            identityKeyID: keyID, requestedRole: "remote",
            permissionsDigest: "sha256:" + String(repeating: "5", count: 64),
            approvalID: UUID(), approvalTime: expiresAt.addingTimeInterval(-60),
            expiresAt: expiresAt, cancellationGeneration: 0)
        let summary = ACPAppleEnrollmentRequestSummary(
            requestID: attemptID, candidateNodeID: candidate,
            displayName: "Test Remote", requestedRole: "remote", expiresAt: expiresAt)
        return try ACPAppleValidatedEnrollmentRequest(
            summary: summary, facts: facts,
            confirmedKey: ACPConfirmedSPAKE2PlusKey(
                secret: ACPSecretBytes(Data(repeating: 6, count: 32))!,
                transcriptHash: transcript))
    }
}

private struct Fixture {
    let serviceName: String
    let service: ACPAppleEnrollmentDecisionService
    let backend: ACPKeychainCredentialBackend

    init() throws {
        serviceName = "com.aurora.acp.decision-test.\(UUID().uuidString.lowercased())"
        service = try ACPAppleEnrollmentDecisionService(service: serviceName)
        backend = ACPKeychainCredentialBackend(service: serviceName)
    }

    func cleanup() { try? backend.delete(name: "enrollment-decisions") }
}
