import XCTest
@testable import AuroraACP
@testable import AuroraACPAppleSecurity

final class ACPAppleSPAKE2PlusTests: XCTestCase {
    private let proverID = Data("client".utf8)
    private let verifierID = Data("server".utf8)
    private let context = Data("SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors".utf8)

    private func secret() throws -> ACPSecretBytes {
        try XCTUnwrap(ACPSecretBytes(Data(hexAppleSPAKE:
            "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3" +
            "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba")!))
    }

    func testRestrictedProverVerifierAgreementAndTerminalStates() throws {
        let registration = try ACPAppleSPAKE2PlusRegistration.record(proverSecret: secret())
        let prover = try ACPAppleSPAKE2PlusProver(
            proverSecret: secret(), proverIdentity: proverID, verifierIdentity: verifierID, context: context)
        let verifier = try ACPAppleSPAKE2PlusVerifier(
            registrationRecord: registration, proverIdentity: proverID,
            verifierIdentity: verifierID, context: context)

        let share = try prover.generateShare()
        let response = try verifier.receive(peerShare: share)
        let proverResult = try prover.processResponseAndConsumeKey(response)
        let verifierKey = try verifier.verifyAndConsumeKey(confirmation: proverResult.confirmation)
        let proverBytes = proverResult.key.withUnsafeBytes { Data($0) }
        let verifierBytes = verifierKey.withUnsafeBytes { Data($0) }
        XCTAssertEqual(proverBytes, verifierBytes)
        XCTAssertEqual(proverBytes.count, 32)
        let expectedTranscriptHash = ACPSecurityContext.sha256(
            try ACPSecurityContext.canonicalTranscript([
                context, share, Data(response.prefix(65)),
                Data(response.dropFirst(65)), proverResult.confirmation,
            ]))
        XCTAssertEqual(proverResult.key.transcriptHash, expectedTranscriptHash)
        XCTAssertEqual(verifierKey.transcriptHash, expectedTranscriptHash)

        XCTAssertThrowsError(try prover.generateShare())
        XCTAssertThrowsError(try verifier.verifyAndConsumeKey(confirmation: proverResult.confirmation))
    }

    func testWrongConfirmationAndMalformedInputsFailClosed() throws {
        var zero = Data(repeating: 0, count: 64)
        let zeroSecret = try XCTUnwrap(ACPSecretBytes(zero))
        XCTAssertThrowsError(try ACPAppleSPAKE2PlusRegistration.record(proverSecret: zeroSecret))
        zero.resetBytes(in: zero.indices)

        let registration = try ACPAppleSPAKE2PlusRegistration.record(proverSecret: secret())
        XCTAssertThrowsError(try ACPAppleSPAKE2PlusVerifier(
            registrationRecord: registration.dropLast(), proverIdentity: proverID,
            verifierIdentity: verifierID, context: context))
        XCTAssertThrowsError(try ACPAppleSPAKE2PlusVerifier(
            registrationRecord: registration, proverIdentity: Data(repeating: 1, count: 256),
            verifierIdentity: verifierID, context: context))

        let prover = try ACPAppleSPAKE2PlusProver(
            proverSecret: secret(), proverIdentity: proverID, verifierIdentity: verifierID, context: context)
        let verifier = try ACPAppleSPAKE2PlusVerifier(
            registrationRecord: registration, proverIdentity: proverID,
            verifierIdentity: verifierID, context: context)
        let response = try verifier.receive(peerShare: prover.generateShare())
        let proverResult = try prover.processResponseAndConsumeKey(response)
        var wrong = proverResult.confirmation
        wrong[0] ^= 1
        XCTAssertThrowsError(try verifier.verifyAndConsumeKey(confirmation: wrong))
        XCTAssertThrowsError(try verifier.verifyAndConsumeKey(confirmation: proverResult.confirmation))
    }
}

private extension Data {
    init?(hexAppleSPAKE value: String) {
        guard value.count.isMultiple(of: 2) else { return nil }
        var output = Data(); var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
            output.append(byte); index = next
        }
        self = output
    }
}
