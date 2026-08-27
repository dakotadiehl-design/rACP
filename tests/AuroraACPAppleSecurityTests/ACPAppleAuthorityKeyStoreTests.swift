import XCTest
@testable import AuroraACPAppleSecurity

final class ACPAppleAuthorityKeyStoreTests: XCTestCase {
    func testOnlyFrozenUnsupportedOutcomesPermitFallback() throws {
        for outcome in [
            ACPAppleSecureEnclaveOutcome.unsupportedPlatform,
            .unsupportedRequiredOperation,
        ] {
            var fallbackCount = 0
            let selected: String = try ACPAppleAuthorityKeyStore.selectCustody(
                secureEnclave: { throw outcome },
                keychain: { fallbackCount += 1; return "keychain" })
            XCTAssertEqual(selected, "keychain")
            XCTAssertEqual(fallbackCount, 1)
        }
    }

    func testEveryIntegrityOrAvailabilityFailureFailsClosedWithoutFallback() {
        let denied: [ACPAppleSecureEnclaveOutcome] = [
            .accessDenied, .storageLocked, .corruptState, .identityMismatch,
            .duplicateState, .entitlementFailure, .providerIntegrityFailure,
            .unexpected(-1),
        ]
        for outcome in denied {
            var fallbackCount = 0
            let operation: () throws -> String = {
                try ACPAppleAuthorityKeyStore.selectCustody(
                    secureEnclave: { throw outcome },
                    keychain: { fallbackCount += 1; return "keychain" })
            }
            XCTAssertThrowsError(try operation()) {
                XCTAssertEqual($0 as? ACPAppleSecureEnclaveOutcome, outcome)
            }
            XCTAssertEqual(fallbackCount, 0)
        }
    }

    func testSuccessfulSecureEnclaveNeverInvokesFallback() throws {
        var fallbackCount = 0
        let selected = try ACPAppleAuthorityKeyStore.selectCustody(
            secureEnclave: { "secure-enclave" },
            keychain: { fallbackCount += 1; return "keychain" })
        XCTAssertEqual(selected, "secure-enclave")
        XCTAssertEqual(fallbackCount, 0)
    }
}
