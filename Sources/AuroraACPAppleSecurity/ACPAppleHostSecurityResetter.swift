import Foundation

/// Package-owned destructive executor. Keeping this orchestration opaque
/// prevents applications from selecting only the records whose removal would
/// weaken the authority/identity/trust invariants.
package actor ACPAppleHostSecurityResetter {
    private let lifecycle: ACPAppleCredentialLifecycleStore
    private let trustStore: ACPAppleTrustedPeerStore
    private let decisions: ACPAppleEnrollmentDecisionService
    private let issuanceBackend: ACPAppleIssuanceJournalBackend
    private let hostJournal: ACPAppleHostProvisioningJournal
    private let authorityStore: ACPAppleTrustDomainAuthorityStore

    package init(
        lifecycle: ACPAppleCredentialLifecycleStore,
        trustStore: ACPAppleTrustedPeerStore,
        decisions: ACPAppleEnrollmentDecisionService,
        issuanceBackend: ACPAppleIssuanceJournalBackend,
        hostJournal: ACPAppleHostProvisioningJournal,
        authorityStore: ACPAppleTrustDomainAuthorityStore
    ) {
        self.lifecycle = lifecycle; self.trustStore = trustStore
        self.decisions = decisions; self.issuanceBackend = issuanceBackend
        self.hostJournal = hostJournal; self.authorityStore = authorityStore
    }

    package func execute() async throws {
        try await decisions.reset()
        try trustStore.reset()
        try await lifecycle.reset()
        try issuanceBackend.reset()
        try hostJournal.reset()
        // Authority custody is removed last. Every partial ordering above is
        // fail-closed on reopen and this operation itself is safely retryable.
        try await authorityStore.reset()
    }
}
