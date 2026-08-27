import AuroraACP
import Foundation

package enum ACPAppleEnrollmentSessionFailure: Error, Sendable {
    case credentialIssuance
    case receiptOrTrustCommit
}

/// Binds one commissioner controller to one restricted connection. It has no
/// authenticated-session conversion path and closes after every outcome.
package actor ACPAppleCommissionerEnrollmentSession {
    private let connection: ACPEnrollmentRestrictedConnection
    private let controller: ACPAppleCommissionerEnrollmentController
    private let now: @Sendable () -> UInt64
    private let wallClock: @Sendable () -> Date

    package init(connection: ACPEnrollmentRestrictedConnection,
                 controller: ACPAppleCommissionerEnrollmentController,
                 now: @escaping @Sendable () -> UInt64 = {
                    DispatchTime.now().uptimeNanoseconds
                 }, wallClock: @escaping @Sendable () -> Date = { Date() }) {
        self.connection = connection; self.controller = controller
        self.now = now; self.wallClock = wallClock
    }

    package func run() async throws {
        do {
            let begin = try await controller.begin(now: now(), timestamp: wallClock())
            try await connection.run(initial: begin) { [controller, now, wallClock] envelope in
                switch envelope.type {
                case "security.enrollment.challenge":
                    return .init(response: try await controller.receiveChallenge(
                        envelope, now: now(), timestamp: wallClock()))
                case "security.enrollment.confirm":
                    try await controller.receiveConfirm(
                        envelope, now: now(), wallClock: wallClock())
                    return try await controller.awaitDecisionAndIssue(
                        now: now(), wallClock: wallClock(), timestamp: wallClock())
                case "security.enrollment.install_result":
                    try await controller.receiveInstallResult(envelope, now: now())
                    return .init(terminal: true)
                case "security.enrollment.cancel", "error.report":
                    await controller.cancel()
                    return .init(terminal: true)
                default:
                    throw ACPEnrollmentRestrictedError.messageNotAllowed
                }
            }
        } catch {
            let failedState = await controller.state
            await controller.cancel()
            if failedState == .issuingCredential {
                throw ACPAppleEnrollmentSessionFailure.credentialIssuance
            }
            if failedState == .awaitingInstallReceipt {
                throw ACPAppleEnrollmentSessionFailure.receiptOrTrustCommit
            }
            throw error
        }
    }
}
