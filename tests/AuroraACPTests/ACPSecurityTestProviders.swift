import Foundation
@testable import AuroraACP

final class DeterministicSecurityRandom: ACPSecureRandomProvider, @unchecked Sendable {
    private var fixture: Data
    init(_ fixture: Data) { self.fixture = fixture }
    func bytes(count: Int) throws -> ACPSecretBytes {
        guard count > 0, fixture.count >= count else { throw ACPSecurityErrorCode.resourceLimit }
        let value = fixture.prefix(count); fixture.removeFirst(count)
        return ACPSecretBytes(Data(value))!
    }
}

struct DeterministicSecurityClock: ACPSecurityClock {
    let monotonicNanoseconds: UInt64
    let utcTimestamp: String?
    let trustState: ACPClockTrustState
}

final class CapturingSecurityAuditSink: ACPAuditSink, @unchecked Sendable {
    private(set) var events: [(String, [String: String])] = []
    func record(event: String, publicFields: [String: String]) { events.append((event, publicFields)) }
}

final class InMemorySecurityIdentityStore: ACPIdentityStore, @unchecked Sendable {
    private(set) var staged: ACPCredentialID?
    private(set) var active: ACPCredentialID?
    func stage(credentialID: ACPCredentialID, credential: Data, key: any ACPSigningKeyHandle) {
        staged = credentialID
    }
    func commit(credentialID: ACPCredentialID) throws {
        guard staged == credentialID else { throw ACPSecurityErrorCode.storageFailed }
        active = staged; staged = nil
    }
    func rollback() { staged = nil }
}
