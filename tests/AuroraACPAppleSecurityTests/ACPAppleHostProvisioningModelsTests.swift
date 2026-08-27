import AuroraACP
import AuroraACPAppleSecurity
import XCTest

final class ACPAppleHostProvisioningModelsTests: XCTestCase {
    func testAcceptsQualifiedFullAppleConfiguration() throws {
        let configuration = try ACPAppleHostConfiguration(
            identity: ACPIdentity(
                nodeID: "00112233-4455-4677-8899-aabbccddeeff",
                instanceID: "11112233-4455-4677-8899-aabbccddeeff",
                role: "host",
                name: "Test Host"),
            storageNamespace: "com.aurora.acp.test-host",
            providerProvenance: try provenance())

        XCTAssertEqual(configuration.storageNamespace, "com.aurora.acp.test-host")
        XCTAssertTrue(configuration.preferSecureEnclave)
        XCTAssertFalse(configuration.allowNonHardwareFallback)
    }

    func testRejectsInvalidNamespace() throws {
        XCTAssertThrowsError(try configuration(namespace: "Com Aurora Host")) { error in
            XCTAssertEqual(error as? ACPAppleHostProvisioningError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try configuration(namespace: "com..aurora")) { error in
            XCTAssertEqual(error as? ACPAppleHostProvisioningError, .invalidConfiguration)
        }
    }

    func testRejectsMalformedIdentity() throws {
        XCTAssertThrowsError(try ACPAppleHostConfiguration(
            identity: ACPIdentity(nodeID: "not-a-node", role: "host", name: "Host"),
            storageNamespace: "com.aurora.host",
            providerProvenance: try provenance())) { error in
                XCTAssertEqual(error as? ACPAppleHostProvisioningError, .invalidConfiguration)
            }
    }

    func testRejectsProviderWithoutFullProfile() throws {
        XCTAssertThrowsError(try configuration(
            namespace: "com.aurora.host",
            provenance: try provenance(profile: "lightweight"))) { error in
                XCTAssertEqual(error as? ACPAppleHostProvisioningError, .invalidConfiguration)
            }
    }

    private func configuration(
        namespace: String,
        provenance: ACPProviderProvenance? = nil
    ) throws -> ACPAppleHostConfiguration {
        try ACPAppleHostConfiguration(
            identity: ACPIdentity(
                nodeID: "00112233-4455-4677-8899-aabbccddeeff",
                instanceID: "11112233-4455-4677-8899-aabbccddeeff",
                role: "host", name: "Host"),
            storageNamespace: namespace,
            providerProvenance: try provenance ?? self.provenance())
    }

    private func provenance(profile: String = "full") throws -> ACPProviderProvenance {
        let json = """
        {"schema_version":"1.0","adapter_id":"apple.network-framework.full","source_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provider":{"name":"Network.framework","version":"macOS"},"target_triple":"arm64-apple-macosx","profiles":["\(profile)"],"key_storage_classes":["secure_enclave","keychain"],"qualification":{"status":"PASS","artifact_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
        """
        return try ACPProviderProvenance(jsonData: Data(json.utf8))
    }
}
