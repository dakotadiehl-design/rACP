import AuroraACP
import Foundation

final class FixtureConfirmation: ACPSPAKE2PlusOperation, @unchecked Sendable {
    private var terminal = false
    func receive(peerShare: Data) -> Data { peerShare }
    func verifyAndConsumeKey(confirmation: Data) throws -> ACPConfirmedSPAKE2PlusKey {
        guard !terminal else { throw ACPSecurityErrorCode.authenticationFailed }
        terminal = true
        guard confirmation == Data("valid".utf8),
              let secret = ACPSecretBytes(Data(repeating: 0xA5, count: 32)) else {
            throw ACPSecurityErrorCode.authenticationFailed
        }
        return ACPConfirmedSPAKE2PlusKey(
            secret: secret, transcriptHash: Data(repeating: 0x5a, count: 32))
    }
}

@main struct EnrollmentFixture {
    static func main() async throws {
        let enrollment = ACPEnrollmentID(rawValue: "50617283-94a5-4b6c-9a4b-5c6d7e8f90a1")!
        let attempt = ACPEnrollmentAttemptID(rawValue: "60718293-a4b5-4c6d-aa5b-6c7d8e9fa0b1")!
        let candidate = ACPCandidateEnrollment(
            enrollmentID: enrollment, suites: [.raw128], limits: .profile(.full), openedAtNanoseconds: 0
        )
        var operation: any ACPSPAKE2PlusOperation = FixtureConfirmation()
        try await candidate.begin(attempt, suite: .raw128, now: 1)
        _ = try await candidate.processPeerShare(
            attempt, operation: &operation, encodedShare: Data("share".utf8), now: 2
        )
        try await candidate.verifyKeyConfirmation(
            attempt, operation: &operation, confirmation: Data("valid".utf8), now: 2
        )
        try await candidate.awaitApproval(attempt, now: 3)
        try await candidate.credentialStaged(attempt, now: 4)
        try await candidate.durableInstallVerified(attempt, now: 5)
        try await candidate.complete(attempt, now: 6)
        var commissioner = ACPCommissionerEnrollment(
            enrollmentID: enrollment, attemptID: attempt, deadlineNanoseconds: 100
        )
        let path: [(ACPCommissionerEnrollmentState, ACPCommissionerEnrollmentState)] = [
            (.idle, .candidateSelected), (.candidateSelected, .secretAcquired),
            (.secretAcquired, .negotiating), (.negotiating, .keyConfirmed),
            (.keyConfirmed, .awaitingOperatorApproval),
            (.awaitingOperatorApproval, .issuingCredential),
            (.issuingCredential, .awaitingInstallReceipt),
        ]
        for (from, to) in path { try commissioner.transition(from: from, to: to, now: 1) }
        try commissioner.completeVerifiedInstall(now: 6, hmacValid: true, proofValid: true)
        let candidateState = await candidate.state.rawValue
        print("{\"candidate\":\"\(candidateState)\",\"commissioner\":\"\(commissioner.state.rawValue)\"}")
    }
}
