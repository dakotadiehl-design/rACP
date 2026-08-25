import XCTest
@testable import AuroraACP

final class ACPEnrollmentTests: XCTestCase {
    private let enrollment = ACPEnrollmentID(rawValue: "50617283-94a5-4b6c-9a4b-5c6d7e8f90a1")!
    private func attempt(_ n: Int) -> ACPEnrollmentAttemptID {
        ACPEnrollmentAttemptID(rawValue: String(format: "60718293-a4b5-4c6d-aa5b-%012x", n))!
    }

    func testCandidateRequiresDurableInstallAndRejectsReplay() async throws {
        let machine = ACPCandidateEnrollment(enrollmentID: enrollment, suites: [.raw128], limits: .init(concurrentAttempts: 2), openedAtNanoseconds: 0)
        let id = attempt(1)
        try await machine.begin(id, suite: .raw128, now: 1)
        var operation: any ACPSPAKE2PlusOperation = FixtureSPAKE2Plus()
        let response = try await machine.processPeerShare(id, operation: &operation, encodedShare: Data("share".utf8), now: 2)
        XCTAssertEqual(response, Data("share".utf8))
        try await machine.verifyKeyConfirmation(id, operation: &operation, confirmation: Data("valid".utf8), now: 2)
        try await machine.awaitApproval(id, now: 3)
        try await machine.credentialStaged(id, now: 4)
        do { try await machine.complete(id, now: 5); XCTFail("completed without durable read-back") }
        catch { XCTAssertEqual(error as? ACPSecurityErrorCode, .storageFailed) }
        try await machine.durableInstallVerified(id, now: 5)
        try await machine.complete(id, now: 6)
        let completedState = await machine.state
        XCTAssertEqual(completedState, .enrolled)
        do { try await machine.verifyKeyConfirmation(id, operation: &operation, confirmation: Data("valid".utf8), now: 7); XCTFail("replay accepted") }
        catch { XCTAssertEqual(error as? ACPSecurityErrorCode, .enrollmentReplayed) }
    }

    func testConcurrencyRestartAndLockoutAreBounded() async throws {
        let machine = ACPCandidateEnrollment(enrollmentID: enrollment, suites: [.raw128], limits: .init(concurrentAttempts: 2), openedAtNanoseconds: 0)
        try await machine.begin(attempt(1), suite: .raw128, now: 1)
        try await machine.begin(attempt(2), suite: .raw128, now: 1)
        do { try await machine.begin(attempt(3), suite: .raw128, now: 1); XCTFail("limit bypass") }
        catch { XCTAssertEqual(error as? ACPSecurityErrorCode, .resourceLimit) }
        await machine.restart()
        let restartedState = await machine.state
        XCTAssertEqual(restartedState, .failed)

        let lock = ACPCandidateEnrollment(enrollmentID: enrollment, suites: [.raw128], limits: .init(concurrentAttempts: 1), openedAtNanoseconds: 0)
        for n in 1...5 { try await lock.begin(attempt(n), suite: .raw128, now: UInt64(n)); await lock.cryptographicFailure(attempt(n)) }
        let lockedState = await lock.state
        XCTAssertEqual(lockedState, .locked)
    }

    func testCommissionerNeedsBothInstallProofs() throws {
        var illegal = ACPCommissionerEnrollment(enrollmentID: enrollment, attemptID: attempt(7), deadlineNanoseconds: 100)
        XCTAssertThrowsError(try illegal.transition(from: .idle, to: .complete, now: 1))
        var machine = ACPCommissionerEnrollment(enrollmentID: enrollment, attemptID: attempt(1), deadlineNanoseconds: 100)
        let path: [(ACPCommissionerEnrollmentState, ACPCommissionerEnrollmentState)] = [
            (.idle, .candidateSelected), (.candidateSelected, .secretAcquired), (.secretAcquired, .negotiating),
            (.negotiating, .keyConfirmed), (.keyConfirmed, .awaitingOperatorApproval),
            (.awaitingOperatorApproval, .issuingCredential), (.issuingCredential, .awaitingInstallReceipt),
        ]
        for (from, to) in path { try machine.transition(from: from, to: to, now: 1) }
        try machine.completeVerifiedInstall(now: 2, hmacValid: true, proofValid: true)
        XCTAssertEqual(machine.state, .complete); XCTAssertTrue(machine.consumed)
    }

    func testFrozenApprovalAADAndInstallationVectors() throws {
        let transcript = Data(hexM3: "1713be11b1b0ef86de03b3eca4dbc6d1ae1309f4dda0b0c842b9e9b442b673ba")!
        let keyID = "sha256:f3c9d135604346824a568ba09251f3118e0184b417fae972a66668ff3f93d75d"
        let aad: [String: AnySendable] = [
            "message_type": .string("security.enrollment.approval"), "attempt_id": .string("60718293-a4b5-4c6d-aa5b-6c7d8e9fa0b1"),
            "enrollment_id": .string(enrollment.rawValue), "candidate_node_id": .string("00112233-4455-4677-8899-aabbccddeeff"),
            "commissioner_node_id": .string("10213243-5465-4768-9a0b-1c2d3e4f5061"),
            "trust_domain_id": .string("40516273-8495-4a6b-8a3b-4c5d6e7f8091"), "acp_version": .string("1.2"),
            "extension_version": .string("1.0"), "suite": .string(ACPSecuritySuite.raw128.rawValue),
            "identity_algorithm": .string("ecdsa_p256_sha256"), "identity_key_id": .string(keyID), "transcript_hash": .bytes(transcript),
        ]
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let approvalJSON = try JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("vectors/security/approval/primary.json"))) as! [String: Any]
        let expectedAAD = Data(hexM3: approvalJSON["aad_cbor_hex"] as! String)!
        XCTAssertEqual(try ACPSecurityContext.canonicalApprovalAAD(aad), expectedAAD)

        let proof = Data(hexM3: "3044022001f7249f487466affc030f01cc1602bfc139bf440abd6be74775ee1cc8152556022032b67a886964fdd22c7f3027c70bd42eb49388b603c854735549c2b2c642f657")!
        let install: [String: AnySendable] = [
            "attempt_id": .string("60718293-a4b5-4c6d-aa5b-6c7d8e9fa0b1"), "status": .string("installed"),
            "credential_id": .string("sha256:466363fece7088b31d8e677611eab7caab29f8aef3bfd4e207c63c17bd4cfb20"),
            "identity_key_id": .string(keyID), "trust_domain_id": .string("40516273-8495-4a6b-8a3b-4c5d6e7f8091"),
            "storage_posture": .object(["class": .string("os_protected"), "hardware_backed": .bool(false), "private_key_exportable": .bool(false)]),
            "proof_of_possession": .bytes(proof),
        ]
        let installJSON = try JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("vectors/security/installation/primary.json"))) as! [String: Any]
        let expectedInstall = Data(hexM3: installJSON["install_without_confirmation_cbor_hex"] as! String)!
        XCTAssertEqual(try ACPSecurityContext.canonicalInstallResultWithoutConfirmation(install), expectedInstall)
        let confirmKey = Data(hexM3: "2e6621403e7994557bcfe9fd9e7b2be4c20fad8ca91d95f7603e5d3016c1d190")!
        XCTAssertEqual(try ACPSecurityContext.installConfirmation(candidateConfirmKey: confirmKey, values: install), Data(hexM3: "e204af445fbacd23bc18b3d2b9af27dd8edcbd9b842239c2920a6affc2ab9421"))
    }

    func testSuiteIntersectionAndDeadlineOverflowFailClosed() async throws {
        XCTAssertEqual(try ACPSelectEnrollmentSuite(preferred: [.pbkdf2_100K, .raw128], supported: [.raw128]), .raw128)
        XCTAssertThrowsError(try ACPSelectEnrollmentSuite(preferred: [.pbkdf2_100K], supported: [.raw128]))
        let machine = ACPCandidateEnrollment(enrollmentID: enrollment, suites: [.raw128], limits: .init(concurrentAttempts: 1), openedAtNanoseconds: 0)
        do { try await machine.begin(attempt(1), suite: .raw128, now: UInt64.max); XCTFail("overflow accepted") }
        catch { XCTAssertEqual(error as? ACPSecurityErrorCode, .enrollmentExpired) }
    }

    func testApprovalKeyIsOneShot() async throws {
        let protector = ACPOneShotApprovalProtector(aead: FixtureAEAD(), random: DeterministicSecurityRandom(Data(repeating: 7, count: 12)))
        let key = try XCTUnwrap(ACPSecretBytes(Data(repeating: 1, count: 32)))
        let plaintext = try XCTUnwrap(ACPSecretBytes(Data([2])))
        let sealed = try await protector.seal(attemptID: attempt(1), key: key, plaintext: plaintext, associatedData: Data([3]))
        XCTAssertEqual(sealed.nonce.count, 12)
        do { _ = try await protector.seal(attemptID: attempt(1), key: key, plaintext: plaintext, associatedData: Data([3])); XCTFail("nonce/key reuse") }
        catch { XCTAssertEqual(error as? ACPSecurityErrorCode, .enrollmentReplayed) }
    }

    func testMissingAndDuplicatePeerSharesConsumeAttempt() async throws {
        let missing = ACPCandidateEnrollment(enrollmentID: enrollment, suites: [.raw128], limits: .init(concurrentAttempts: 1), openedAtNanoseconds: 0)
        let missingID = attempt(8)
        try await missing.begin(missingID, suite: .raw128, now: 1)
        var operation: any ACPSPAKE2PlusOperation = FixtureSPAKE2Plus()
        do { try await missing.verifyKeyConfirmation(missingID, operation: &operation, confirmation: Data("valid".utf8), now: 2); XCTFail("missing share accepted") }
        catch { XCTAssertEqual(error as? ACPSecurityErrorCode, .authenticationFailed) }

        let duplicate = ACPCandidateEnrollment(enrollmentID: enrollment, suites: [.raw128], limits: .init(concurrentAttempts: 1), openedAtNanoseconds: 0)
        let duplicateID = attempt(9)
        try await duplicate.begin(duplicateID, suite: .raw128, now: 1)
        _ = try await duplicate.processPeerShare(duplicateID, operation: &operation, encodedShare: Data("share".utf8), now: 2)
        do { _ = try await duplicate.processPeerShare(duplicateID, operation: &operation, encodedShare: Data("share".utf8), now: 3); XCTFail("duplicate share accepted") }
        catch { XCTAssertEqual(error as? ACPSecurityErrorCode, .authenticationFailed) }
    }
}

private extension Data {
    init?(hexM3: String) {
        guard hexM3.count.isMultiple(of: 2) else { return nil }
        var result = Data(); var index = hexM3.startIndex
        while index < hexM3.endIndex { let next = hexM3.index(index, offsetBy: 2); guard let byte = UInt8(hexM3[index..<next], radix: 16) else { return nil }; result.append(byte); index = next }
        self = result
    }
}
